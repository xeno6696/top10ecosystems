"""Situation report: one CVE ID in, a picture of what is publicly known about it out.

OSV is the warehouse's source of truth, but a CVE can exist for hours or days before OSV has a record under its own ID
(CVE-2026-109618 existed only as Debian, Ubuntu and Bitnami records at first), and --timeline can only start from OSV.
--sitrep asks a configurable list of trusted sources about the CVE in one pass and lays out what each says:

  - the CVE record and CVSS scores (cve.org, NVD), exploitation signals (KEV, EPSS, CISA's SSVC, public repositories),
  - who ships a fix (Debian, Ubuntu, Red Hat), what OSV itself has, and which layers of our warehouse it has reached,
  - a timeline across all of it, with the CLOCK behind every time (a source's own timestamp, when a feed ingested it,
    an email's Date header, or a time read from prose), because those are not comparable and none of them predicts which
    channel hears first.

It makes no judgment about urgency. A source that is silent shows as silent in the coverage list, never as "nothing
happened", and sources that disagree (CVSS 9.2 vs 9.8 vs 8.1) are shown side by side, never merged.

Sources are data (sitrep_sources.json, plus an optional sitrep_sources.local.json for personal changes), not code: the
config is the allow-list, only HTTPS GET is made, redirects must stay on the same host, and fetched text is only ever
parsed, never followed as instructions. Links found inside source records are fetched only when their host is listed
under follow_hosts. Network access is injected (`fetch`), so the tests run against saved real responses.
"""
import concurrent.futures
import datetime
import email.utils
import html
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from collections import OrderedDict, namedtuple
from urllib.parse import quote, urljoin, urlparse

import requests

import report_color
import sitrep_progress
import timeline
from osv_ecosystems import clean_ecosystem_tag, get_artifact_layer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "sitrep_sources.json")
LOCAL_CONFIG = os.path.join(HERE, "sitrep_sources.local.json")

PATHS = ("upstream", "records", "registry", "distro", "vendor", "exploitation", "community", "osv")   # how a fact reached us
TRUSTS = ("primary", "secondary", "lead")    # primary: the authority for what it states; lead: a pointer to go and read
KINDS = ("builtin", "link", "json")
CLOCKS = ("declared", "ingested", "header", "approximate")
JSON_FIELDS = ("published", "severity", "state", "title")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
SOURCE_ID = re.compile(r"^[a-z][a-z0-9_-]{1,40}$")

USER_AGENT = "top10ecosystems-sitrep/1.0 (+https://github.com/xeno6696/top10ecosystems)"
DEFAULT_TIMEOUT = 20
DEFAULT_MAX_BYTES = 5_000_000
MAX_REDIRECTS = 3
MAX_FOLLOW = 6          # most referenced links fetched per CVE
WIDTH = 124

Fetch = namedtuple("Fetch", "status text headers url error")


class ConfigError(ValueError):
    """The sources configuration is unusable; the message lists every problem."""


# --------------------------------------------------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------------------------------------------------

def parse_when(value):
    """(iso string, precision) in UTC from an ISO timestamp, a date, or an RFC 2822 date, or None.
    Naive timestamps are read as UTC; a bare date keeps day precision."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        try:
            datetime.date.fromisoformat(text)
        except ValueError:
            return None
        return text, "day"
    iso = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00"))
    try:
        moment = datetime.datetime.fromisoformat(iso)
    except ValueError:
        try:
            moment = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    moment = moment.astimezone(datetime.timezone.utc)
    if re.search(r"T00:00:00(\.0+)?(Z|[+-]00:?00)?$", text):
        return moment.strftime("%Y-%m-%d"), "day"   # sources that only know the day write it as midnight; do not invent an hour
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ"), "second"


def _event(value, clock, text):
    parsed = parse_when(value)
    if not parsed:
        return None
    return {"when": parsed[0], "precision": parsed[1], "clock": clock, "text": text}


def _sort_key(event):
    when = event["when"]
    return (when[:10], 0 if event["precision"] == "day" else 1, when)


def show_when(event) -> str:
    when = event["when"]
    return when[:10] + " (date only)" if event["precision"] == "day" else when[:10] + " " + when[11:16] + " UTC"


# --------------------------------------------------------------------------------------------------------------------
# Configuration: sources are data
# --------------------------------------------------------------------------------------------------------------------

def host_is_safe(host) -> bool:
    """False for hosts a source must never point at: localhost, private/loopback/link-local addresses, and internal names."""
    host = (host or "").strip().lower().rstrip(".")
    if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".corp")):
        return False
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return "." in host
    return not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast
                or address.is_reserved or address.is_unspecified)


def _url_problem(url) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "must be https"
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        return "must not carry credentials"
    if parsed.port not in (None, 443):
        return "must use the standard https port"
    if not host_is_safe(parsed.hostname):
        return f"host '{parsed.hostname}' is not allowed (private, local or internal)"
    return ""


def validate_source(source) -> list:
    """Every problem with one source definition, as readable strings."""
    problems = []
    name = source.get("id", "?") if isinstance(source, dict) else "?"
    if not isinstance(source, dict):
        return ["a source must be an object"]
    if not SOURCE_ID.match(str(source.get("id", ""))):
        problems.append(f"{name}: id must be lowercase letters, digits, - or _ (2-41 characters)")
    kind = source.get("kind")
    if kind not in KINDS:
        problems.append(f"{name}: kind must be one of {', '.join(KINDS)}")
    if kind == "builtin" and source.get("parser") not in PARSERS:
        problems.append(f"{name}: unknown parser '{source.get('parser')}' (known: {', '.join(sorted(PARSERS))})")
    url = source.get("url")
    if not isinstance(url, str) or not url:
        problems.append(f"{name}: url is required")
    else:
        needs_cve = not (kind == "builtin" and source.get("parser") in PARSERS and not PARSERS[source["parser"]][1])
        if needs_cve and "{cve}" not in url:
            problems.append(f"{name}: url must contain {{cve}}")
        issue = _url_problem(url.replace("{cve}", "CVE-2000-0000"))
        if issue:
            problems.append(f"{name}: url {issue}")
    if source.get("path") not in PATHS:
        problems.append(f"{name}: path must be one of {', '.join(PATHS)}")
    if source.get("trust") not in TRUSTS:
        problems.append(f"{name}: trust must be one of {', '.join(TRUSTS)}")
    for key, low, high in (("min_interval", 0, 120), ("timeout", 1, 60), ("max_bytes", 1000, 20_000_000)):
        value = source.get(key, None)
        if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool) or not low <= value <= high):
            problems.append(f"{name}: {key} must be a number from {low} to {high}")
    if kind == "json":
        fields = source.get("fields")
        if not isinstance(fields, dict) or not fields or any(k not in JSON_FIELDS or not isinstance(v, str) for k, v in fields.items()):
            problems.append(f"{name}: a json source needs 'fields' mapping some of {', '.join(JSON_FIELDS)} to dotted paths")
    if "ecosystems" in source and not (isinstance(source["ecosystems"], list) and all(isinstance(e, str) and e.strip() for e in source["ecosystems"])):
        problems.append(f"{name}: ecosystems must be a list of ecosystem names, e.g. [\"Debian\"]")
    if "must_mention" in source and not isinstance(source["must_mention"], bool):
        problems.append(f"{name}: must_mention must be true or false")
    if "watch_every" in source and (not isinstance(source["watch_every"], int) or isinstance(source["watch_every"], bool) or source["watch_every"] < 1):
        problems.append(f"{name}: watch_every must be a whole number of polls, 1 or more")
    if "profiles" in source and not (isinstance(source["profiles"], list) and all(isinstance(p, str) for p in source["profiles"])):
        problems.append(f"{name}: profiles must be a list of names")
    if source.get("token_env") is not None and not re.fullmatch(r"[A-Z][A-Z0-9_]{1,60}", str(source["token_env"])):
        problems.append(f"{name}: token_env must be an environment variable name like GITHUB_TOKEN")
    return problems


def validate_follow_hosts(follow_hosts) -> list:
    problems = []
    if not isinstance(follow_hosts, dict):
        return ["follow_hosts must be an object mapping a host to {label, path}"]
    for host, info in follow_hosts.items():
        if not host_is_safe(host):
            problems.append(f"follow_hosts: '{host}' is not allowed (private, local or internal)")
        if not isinstance(info, dict) or info.get("path") not in PATHS or not info.get("label"):
            problems.append(f"follow_hosts: '{host}' needs a label and a path from {', '.join(PATHS)}")
    return problems


def _read_config(path, required):
    if not os.path.exists(path):
        if required:
            raise ConfigError(f"sources file not found: {path}")
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{path}: {exc}")
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: the top level must be an object")
    return data


def load_config(default_path=None, local_path=None):
    """(sources in order, follow_hosts) from the shipped file with the optional local file layered on top. A local source
    with a known id overrides just the fields it names (so {"id": "github_repos", "enabled": false} switches one off);
    a new id adds a source; follow_hosts are added to. Raises ConfigError listing every problem."""
    shipped, local = _read_config(default_path or DEFAULT_CONFIG, True), _read_config(local_path or LOCAL_CONFIG, False)
    sources = OrderedDict()
    problems = []
    for origin, data in (("shipped", shipped), ("local", local)):
        entries = data.get("sources", [])
        if not isinstance(entries, list):
            problems.append(f"{origin} file: 'sources' must be a list")
            continue
        for entry in entries:
            if not isinstance(entry, dict) or "id" not in entry:
                problems.append(f"{origin} file: every source needs an id")
                continue
            sources[entry["id"]] = dict(sources.get(entry["id"], {}), **entry)
    follow = dict(shipped.get("follow_hosts", {}))
    follow.update(local.get("follow_hosts", {}))
    for source in sources.values():
        problems.extend(validate_source(source))
    problems.extend(validate_follow_hosts(follow))
    if problems:
        raise ConfigError("; ".join(problems))
    return list(sources.values()), follow


def select_sources(sources, expression=None):
    """Which sources to query. `expression` is comma-separated: profile names ("core" is the default when none is given, "all" is
    everything enabled; several are combined), then +id to add a source or -id to drop one, applied in order.
    Returns (selected in config order, notes)."""
    tokens = [t.strip() for t in (expression or "core").split(",") if t.strip()]
    by_id = {s["id"]: s for s in sources}
    known_profiles = {p for s in sources for p in s.get("profiles", [])}
    profiles = [t for t in tokens if t[0] not in "+-"] or ["core"]
    for profile in profiles:
        if profile != "all" and profile not in known_profiles:
            raise ConfigError(f"unknown profile '{profile}' (known: all, {', '.join(sorted(known_profiles)) or 'none'})")
    chosen = {s["id"] for s in sources if s.get("enabled", True) and ("all" in profiles or set(profiles) & set(s.get("profiles", [])))}
    for token in (t for t in tokens if t[0] in "+-"):
        if token[1:] not in by_id:
            raise ConfigError(f"unknown source '{token}' (known: {', '.join(by_id)})")
        (chosen.add if token[0] == "+" else chosen.discard)(token[1:])
    return [s for s in sources if s["id"] in chosen], []


# --------------------------------------------------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------------------------------------------------

def _read_limited(response, max_bytes):
    body, size = [], 0
    for chunk in response.iter_content(65536):
        size += len(chunk)
        if size > max_bytes:
            response.close()
            return None, f"response larger than {max_bytes:,} bytes"
        body.append(chunk)
    return b"".join(body).decode(response.encoding or "utf-8", errors="replace"), None


def make_fetcher(sleep=time.sleep, clock=time.monotonic, retries=1):
    """The real network access: HTTPS GET only, a size cap, redirects only within the same host, a minimum interval per
    host, and an optional token from the environment sent only to the source's own host."""
    lock, next_slot = threading.Lock(), {}

    def pace(host, interval):
        if interval <= 0:
            return
        with lock:
            now = clock()
            slot = max(now, next_slot.get(host, 0))
            next_slot[host] = slot + interval
        if slot > now:
            hook = getattr(sitrep_progress.ACTIVE, "hook", None)
            if hook:
                hook("waiting", f"for {host}'s rate limit ({slot - now:.0f} s)")
            sleep(slot - now)
            if hook:
                hook("contacting", host)

    def fetch(url, source=None) -> Fetch:
        source = source or {}
        issue = _url_problem(url)
        if issue:
            return Fetch(None, "", {}, url, f"refused: url {issue}")
        timeout = source.get("timeout", DEFAULT_TIMEOUT)
        max_bytes = int(source.get("max_bytes", DEFAULT_MAX_BYTES))
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/html;q=0.8, */*;q=0.5"}
        token = os.environ.get(source["token_env"]) if source.get("token_env") else None
        if token:
            headers[source.get("token_header", "Authorization")] = source.get("token_prefix", "Bearer ") + token
        origin = urlparse(url).hostname
        current, last_error = url, "request failed"
        for attempt in range(retries + 1):
            current = url
            for _ in range(MAX_REDIRECTS + 1):
                if _url_problem(current) or urlparse(current).hostname != origin:
                    return Fetch(None, "", {}, current, f"refused redirect to {current}")
                pace(origin, source.get("min_interval", 0))
                try:
                    response = requests.get(current, headers=headers, timeout=timeout, stream=True, allow_redirects=False)
                except requests.RequestException as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    break
                if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("Location"):
                    current = urljoin(current, response.headers["Location"])
                    response.close()
                    continue
                if response.status_code >= 500 and attempt < retries:
                    last_error = f"HTTP {response.status_code}"
                    response.close()
                    break
                text, error = _read_limited(response, max_bytes)
                response.close()
                if error:
                    return Fetch(response.status_code, "", {}, current, error)
                return Fetch(response.status_code, text, {k.lower(): v for k, v in response.headers.items()}, current, None)
            else:
                return Fetch(None, "", {}, current, "too many redirects")
            sleep(0.5 * (attempt + 1))
        return Fetch(None, "", {}, current, last_error)

    return fetch


# --------------------------------------------------------------------------------------------------------------------
# Parsers: one per built-in source. Each takes (cve, Fetch) and returns {"found", "facts", "events", "refs"}.
# A fact is {"kind": state|severity|exploitation|fix|affected|detail, "text", optional "score"}; an event is _event(...).
# --------------------------------------------------------------------------------------------------------------------

def _json(fetch):
    try:
        return json.loads(fetch.text), None
    except ValueError:
        return None, "response was not valid JSON"


def _clip(text, limit=220):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 3].rstrip() + "..."


def _result(found=False, facts=None, events=None, refs=None, error=None, reflinks=None):
    return {"found": found, "facts": facts or [], "events": [e for e in (events or []) if e], "refs": refs or [], "reflinks": reflinks or [], "error": error}


# What a record's references say they are, most useful to a responder first. cve.org and NVD tag them (in different spellings).
CATEGORY_ORDER = ("vendor-advisory", "patch", "mitigation", "third-party-advisory", "government-resource", "exploit", "technical-description",
                  "release-notes", "issue-tracking", "mailing-list", "product", "other", "untagged")
MAX_REFERENCES_SHOWN = 30
# Pages about this very CVE on sources sitrep already queries; listed as a count, not as to-dos.
COVERED_PAGES = (("nvd.nist.gov", "/vuln/detail/"), ("www.cve.org", "/cverecord"), ("cve.mitre.org", ""), ("www.cisa.gov", "/known-exploited-vulnerabilities"),
                 ("github.com", "/advisories/"), ("security-tracker.debian.org", "/tracker/"), ("ubuntu.com", "/security/"),
                 ("access.redhat.com", "/security/cve"), ("api.osv.dev", ""), ("osv.dev", "/vulnerability/"), ("www.first.org", ""))


def _normalize_tag(tag) -> str:
    tag = str(tag).strip().lower().replace("_", "-").replace(" ", "-")
    return "government-resource" if tag == "us-government-resource" else tag


def _ref_key(url) -> str:
    """The same page however it was written: scheme and fragment ignored, host lowercased, trailing slash dropped."""
    parsed = urlparse(url.strip())
    return f"{(parsed.hostname or '').lower()}{parsed.path.rstrip('/') or '/'}" + (f"?{parsed.query}" if parsed.query else "")


def _https(url) -> str:
    return "https://" + url.strip()[7:] if url.strip().lower().startswith("http://") else url.strip()


def _covered(url) -> bool:
    parsed = urlparse(url.strip())
    return any((parsed.hostname or "").lower() == host and parsed.path.lower().startswith(prefix) for host, prefix in COVERED_PAGES)


def _category(tags, url) -> str:
    for category in CATEGORY_ORDER[:-2]:
        if category in tags:
            return category
    if tags:
        return "other"
    parsed = urlparse(url)
    path, host = parsed.path.lower(), (parsed.hostname or "").lower()
    if "/commit/" in path or "/pull/" in path:
        return "patch"
    if "/issues/" in path or "bugzilla" in host:
        return "issue-tracking"
    if "oss-security" in path or host.startswith("lists."):
        return "mailing-list"
    return "untagged"


def build_references(entries, followed) -> dict:
    """A checklist of every page the records point at, one row per page however many sources listed it, grouped by what the records say
    it is. status: read (sitrep fetched it, see LEADS), failed (it tried and could not), unread (left for the analyst). Pages about this
    CVE on sources already queried are returned as `covered`, not as to-dos."""
    seen = {}
    for entry in entries:
        for link in entry.get("reflinks", []):
            url = str(link.get("url", "")).strip()
            if not url.lower().startswith(("http://", "https://")):
                continue
            slot = seen.setdefault(_ref_key(url), {"url": _https(url), "tags": set(), "sources": []})
            slot["tags"].update(_normalize_tag(t) for t in link.get("tags") or [])
            if entry["label"] not in slot["sources"]:
                slot["sources"].append(entry["label"])
    fetched = {_ref_key(e["url"]): e for e in followed}
    rows, covered = [], []
    for key, slot in seen.items():
        if _covered(slot["url"]):
            covered.append(slot["url"])
            continue
        page = fetched.get(key)
        rows.append({"url": slot["url"], "host": urlparse(slot["url"]).hostname, "tags": sorted(slot["tags"]), "category": _category(slot["tags"], slot["url"]),
                     "sources": slot["sources"], "status": "unread" if not page else ("read" if page["status"] == "found" else "failed")})
    rows.sort(key=lambda r: (CATEGORY_ORDER.index(r["category"]), -len(r["sources"]), r["url"]))
    return {"references": rows, "covered": covered}


def _cvss_label(key):
    return {"cvssV4_0": "CVSS 4.0", "cvssV3_1": "CVSS 3.1", "cvssV3_0": "CVSS 3.0", "cvssV2_0": "CVSS 2.0",
            "cvssMetricV40": "CVSS 4.0", "cvssMetricV31": "CVSS 3.1", "cvssMetricV30": "CVSS 3.0", "cvssMetricV2": "CVSS 2.0"}.get(key, key)


def parse_cve_org(cve, fetch):
    data, error = _json(fetch)
    if error or not isinstance(data, dict) or "cveMetadata" not in data:
        return _result(error=error or "not a CVE record")
    meta, containers = data["cveMetadata"], data.get("containers", {})
    cna = containers.get("cna", {})
    state, assigner = meta.get("state", "unknown"), meta.get("assignerShortName", "unknown CNA")
    facts = [{"kind": "state", "text": f"CVE record {state} (CNA: {assigner})" + (f" - {cna['title']}" if cna.get("title") else "")}]
    events = [_event(meta.get("dateReserved"), "declared", "CVE ID reserved"),
              _event(meta.get("datePublished"), "declared", f"CVE record published by {assigner}")]
    if meta.get("dateUpdated") and meta.get("dateUpdated") != meta.get("datePublished"):
        events.append(_event(meta["dateUpdated"], "declared", "CVE record last updated"))
    for block in cna.get("metrics", []):
        for key, value in block.items():
            if key.startswith("cvssV") and isinstance(value, dict) and "baseScore" in value:
                facts.append({"kind": "severity", "score": float(value["baseScore"]),
                              "text": f"{value['baseScore']} {value.get('baseSeverity', '')} ({_cvss_label(key)}, scored by the CNA: {assigner})".replace("  ", " ")})
    for adp in containers.get("adp", []):
        who = adp.get("providerMetadata", {}).get("shortName", "ADP")
        for block in adp.get("metrics", []):
            ssvc = (block.get("other") or {}) if isinstance(block, dict) else {}
            if ssvc.get("type") == "ssvc":
                options = {k: v for option in ssvc.get("content", {}).get("options", []) for k, v in option.items()}
                facts.append({"kind": "exploitation", "text": f"{who} SSVC: " + "; ".join(f"{k} {v}" for k, v in options.items())})
                events.append(_event(ssvc.get("content", {}).get("timestamp"), "declared", f"{who} SSVC assessment"))
            for key, value in block.items():
                if key.startswith("cvssV") and isinstance(value, dict) and "baseScore" in value:
                    facts.append({"kind": "severity", "score": float(value["baseScore"]),
                                  "text": f"{value['baseScore']} {value.get('baseSeverity', '')} ({_cvss_label(key)}, scored by {who})".replace("  ", " ")})
    affected = []
    for item in cna.get("affected", []):
        versions = ", ".join(f"{v.get('version')}" + (f" (fixed in {v['lessThan']})" if v.get("lessThan") else "")
                             for v in item.get("versions", []) if v.get("status") == "affected")
        affected.append(f"{item.get('vendor', '')} {item.get('product', '')}: {versions}".strip())
    if affected:
        facts.append({"kind": "affected", "text": "; ".join(affected)})
    refs = [r["url"] for r in cna.get("references", []) if r.get("url")]
    refs += [r["url"] for adp in containers.get("adp", []) for r in adp.get("references", []) if r.get("url")]
    reflinks = [{"url": r["url"], "tags": r.get("tags", [])} for r in cna.get("references", []) if r.get("url")]
    reflinks += [{"url": r["url"], "tags": r.get("tags", [])} for adp in containers.get("adp", []) for r in adp.get("references", []) if r.get("url")]
    return _result(True, facts, events, refs, reflinks=reflinks)


def parse_nvd(cve, fetch):
    data, error = _json(fetch)
    if error or not isinstance(data, dict):
        return _result(error=error or "unexpected response")
    entries = data.get("vulnerabilities") or []
    if not entries:
        return _result()
    item = entries[0].get("cve", {})
    facts = [{"kind": "state", "text": f"NVD status: {item.get('vulnStatus', 'unknown')}"}]
    for key, scores in (item.get("metrics") or {}).items():
        for score in scores:
            cvss = score.get("cvssData") or {}
            if "baseScore" in cvss:
                facts.append({"kind": "severity", "score": float(cvss["baseScore"]),
                              "text": f"{cvss['baseScore']} {cvss.get('baseSeverity', '')} ({_cvss_label(key)}, {str(score.get('type', '')).lower()}, scored by {score.get('source', 'unknown')})".replace("  ", " ")})
    events = [_event(item.get("published"), "declared", "NVD record published"), _event(item.get("lastModified"), "declared", "NVD record last modified")]
    references = [r for r in item.get("references", []) if r.get("url")]
    return _result(True, facts, events, [r["url"] for r in references], reflinks=[{"url": r["url"], "tags": r.get("tags", [])} for r in references])


def parse_redhat(cve, fetch):
    data, error = _json(fetch)
    if error or not isinstance(data, dict) or "name" not in data:
        return _result(error=error or "not a Red Hat CVE record")
    facts = [{"kind": "severity", "text": f"Red Hat rating: {data.get('threat_severity', 'not rated')}"}]
    score = (data.get("cvss3") or {}).get("cvss3_base_score")
    if score:
        facts.append({"kind": "severity", "score": float(score), "text": f"{score} (CVSS 3.x, scored by Red Hat)"})
    events = [_event(data.get("public_date"), "declared", "Red Hat public date")]
    releases = OrderedDict()
    for release in data.get("affected_release", []):
        releases.setdefault(release.get("product_name", "?"), []).append(release)
    if releases:
        facts.append({"kind": "fix", "text": "fixes shipped: " + "; ".join(
            f"{product}: {', '.join(sorted({r.get('advisory', '?') for r in group}))}" for product, group in releases.items())})
        first = min((r["release_date"] for group in releases.values() for r in group if r.get("release_date")), default=None)
        events.append(_event(first, "declared", "Red Hat first fix advisory released"))
    states = OrderedDict()
    for state in data.get("package_state", []):
        states.setdefault(state.get("fix_state", "?"), []).append(state.get("product_name", "?").replace("Red Hat Enterprise Linux", "RHEL"))
    if states:
        facts.append({"kind": "fix", "text": "other products: " + "; ".join(f"{name}: {', '.join(products)}" for name, products in states.items())})
    if data.get("statement"):
        facts.append({"kind": "detail", "text": "Red Hat statement: " + _clip(data["statement"], 260)})
    return _result(True, facts, events)


def parse_ubuntu(cve, fetch):
    data, error = _json(fetch)
    if error or not isinstance(data, dict) or "id" not in data:
        return _result(error=error or "not an Ubuntu CVE record")
    facts = [{"kind": "severity", "text": f"Ubuntu priority: {data.get('priority', 'unrated')}"}]
    events = [_event(data.get("published"), "declared", "Ubuntu CVE page published")]
    for notice in data.get("notices", []):
        events.append(_event(notice.get("published"), "declared", f"Ubuntu notice {notice.get('id', '?')} published"))
    released, counts = [], OrderedDict()
    for package in data.get("packages", []):
        for status in package.get("statuses", []):
            state = status.get("status", "?")
            counts[state] = counts.get(state, 0) + 1
            if state == "released" and status.get("description"):
                released.append(f"{status.get('release_codename', '?')}: {package.get('name', '?')} {status['description']}")
    if released:
        facts.append({"kind": "fix", "text": "Ubuntu fixes: " + "; ".join(released[:8]) + (f"; +{len(released) - 8} more" if len(released) > 8 else "")})
    if counts:
        facts.append({"kind": "detail", "text": "Ubuntu package states: " + ", ".join(f"{state} x{n}" for state, n in counts.items())})
    return _result(True, facts, events, [r for r in data.get("references", []) if isinstance(r, str)])


def parse_debian(cve, fetch):
    text = fetch.text or ""
    if "Vulnerable and fixed packages" not in text and "<h1>" not in text:
        return _result()
    start = text.find("Vulnerable and fixed packages")
    table = re.search(r"<table>(.*?)</table>", text[start:], re.S) if start >= 0 else None
    fixed, vulnerable, package = [], [], ""
    for row in re.findall(r"<tr>(.*?)</tr>", table.group(1) if table else "", re.S):
        cells = [html.unescape(re.sub(r"<[^>]+>", "", c)).strip() for c in re.findall(r"<td>(.*?)</td>", row, re.S)]
        if len(cells) != 4:
            continue
        package = re.sub(r"\s*\(PTS\)", "", cells[0]) or package
        release, version, status = cells[1], cells[2], cells[3]
        (fixed if status == "fixed" else vulnerable).append(f"{release}: {package} {version}")
    facts = []
    if fixed:
        facts.append({"kind": "fix", "text": "Debian fixed: " + "; ".join(fixed)})
    if vulnerable:
        facts.append({"kind": "detail", "text": "Debian still vulnerable (older versions): " + "; ".join(vulnerable)})
    advisories = sorted(set(re.findall(r"/tracker/((?:DSA|DLA)-\d+-\d+)", text)))
    if advisories:
        facts.append({"kind": "fix", "text": "Debian advisories: " + ", ".join(advisories)})
    if not facts:
        facts.append({"kind": "state", "text": "Debian tracker lists the CVE but no package states"})
    refs = re.findall(r'<pre>(.*?)</pre>', text, re.S)
    return _result(True, facts, [], re.findall(r'href="(https?://[^"]+)"', refs[0]) if refs else [])


def parse_github_repos(cve, fetch):
    data, error = _json(fetch)
    if error or not isinstance(data, dict) or "total_count" not in data:
        return _result(error=error or "unexpected response")
    total = data["total_count"]
    if not total:
        return _result(facts=[{"kind": "exploitation", "text": "no public GitHub repository mentions this CVE ID"}])
    items = data.get("items", [])
    shown = "; ".join(f"{i['full_name']} ({i['stargazers_count']} stars, created {i['created_at'][:10]})" for i in items[:3])
    facts = [{"kind": "exploitation", "text": f"{total:,} public GitHub repositories mention this CVE ID (unvetted: names alone prove nothing, and such repositories can be fake or malicious; never run their code). Top matches: {shown}"}]
    return _result(True, facts)


def parse_github_oldest(cve, fetch):
    """GitHub cannot sort repositories by creation date, so this samples the ones with the OLDEST ACTIVITY and reports the
    earliest creation time among them: a hint of how early public repositories named the CVE, not a proven first."""
    data, error = _json(fetch)
    if error or not isinstance(data, dict) or "total_count" not in data:
        return _result(error=error or "unexpected response")
    items = data.get("items", [])
    if not items:
        return _result()
    earliest = min(items, key=lambda i: i["created_at"])
    shown = "; ".join(f"{i['full_name']} (created {i['created_at'][:16].replace('T', ' ')} UTC, {i['stargazers_count']} stars)" for i in items[:3])
    facts = [{"kind": "exploitation", "text": f"sample of repositories with the oldest activity (GitHub cannot sort by creation date, and these are unvetted): {shown}"}]
    return _result(True, facts, [_event(earliest["created_at"], "declared", f"earliest repository creation among {len(items)} sampled: {earliest['full_name']} (unvetted)")])


def parse_epss(cve, fetch):
    data, error = _json(fetch)
    if error:
        return _result(error=error)
    series = timeline.parse_epss(data)
    if not series:
        return _result()
    last = series[-1]
    facts = [{"kind": "exploitation", "text": f"EPSS {last['score'] * 100:.1f}% (percentile {last['percentile'] * 100:.1f}) as of {last['date']}"
              + (f"; first scored {series[0]['date']}" if len(series) == 1 else f"; {series[0]['score'] * 100:.1f}% on {series[0]['date']}")}]
    # FIRST keeps 30 days of history: beyond that the first date is only the start of a rolling window, not an event.
    first_score = [_event(series[0]["date"], "declared", "first EPSS score")] if len(series) < 30 else []
    return _result(True, facts, first_score)


def parse_kev(cve, fetch):
    data, error = _json(fetch)
    if error or not isinstance(data, dict):
        return _result(error=error or "unexpected response")
    entry = next((v for v in data.get("vulnerabilities", []) if str(v.get("cveID", "")).upper() == cve.upper()), None)
    if not entry:
        return _result(facts=[{"kind": "exploitation", "text": f"CISA KEV: not listed (catalog {data.get('catalogVersion', 'version unknown')})"}])
    facts = [{"kind": "exploitation", "text": f"CISA KEV: LISTED - {entry.get('vulnerabilityName', '')}; due {entry.get('dueDate', '?')}; known ransomware use: {entry.get('knownRansomwareCampaignUse', 'unknown')}"}]
    return _result(True, facts, [_event(entry.get("dateAdded"), "declared", "added to the CISA KEV catalog")])


def parse_osv_cve(cve, fetch):
    data, error = _json(fetch)
    if error or not isinstance(data, dict) or "id" not in data:
        return _result(error=error or "not an OSV record")
    facts = [{"kind": "state", "text": f"OSV has a record under this ID (aliases: {', '.join(data.get('aliases') or []) or 'none'})"}]
    return _result(True, facts, [_event(data.get("published"), "declared", "OSV record published"), _event(data.get("modified"), "declared", "OSV record last modified")])


def parse_arch(cve, fetch):
    data, error = _json(fetch)
    if error or not isinstance(data, dict) or "name" not in data:
        return _result(error=error or "not an Arch security record")
    rating = data.get("severity", "not rated")
    kind = ", ".join(x for x in (data.get("type"), data.get("vector", "").lower() if data.get("vector") else "") if x)
    facts = [{"kind": "severity", "text": f"Arch rating: {rating}" + (f" ({kind})" if kind else "")}]
    if data.get("packages"):
        facts.append({"kind": "affected", "text": "Arch packages: " + ", ".join(data["packages"])})
    if data.get("advisories"):
        facts.append({"kind": "fix", "text": "Arch advisories: " + ", ".join(sorted(data["advisories"]))})
    elif data.get("packages"):
        facts.append({"kind": "detail", "text": "Arch lists no advisory for this CVE yet"})
    return _result(True, facts, [], [r for r in data.get("references", []) if isinstance(r, str)])


def parse_github_advisories(cve, fetch):
    """GitHub's advisory database, which aggregates npm, PyPI, Maven, NuGet, Go, RubyGems, Packagist, crates.io and more."""
    data, error = _json(fetch)
    if error or not isinstance(data, list):
        return _result(error=error or "unexpected response")
    if not data:
        return _result(facts=[{"kind": "detail", "text": "no GitHub advisory is indexed under this CVE ID"}])
    facts, events, refs = [], [], []
    for advisory in data[:5]:
        ghsa = advisory.get("ghsa_id", "?")
        score = (advisory.get("cvss") or {}).get("score")
        label = f"{advisory.get('severity', 'unrated')}" + (f", CVSS {score}" if score else "")
        facts.append({"kind": "detail", "text": f"GitHub advisory {ghsa} ({advisory.get('type', '?')}): {_clip(advisory.get('summary', ''), 120)} - {label}"})
        if score:
            facts.append({"kind": "severity", "score": float(score), "text": f"{score} ({str(advisory.get('severity', '')).upper()}, scored in GitHub advisory {ghsa})"})
        fixed = []
        for vulnerability in advisory.get("vulnerabilities") or []:
            package = vulnerability.get("package") or {}
            if vulnerability.get("first_patched_version"):
                fixed.append(f"{package.get('ecosystem', '?')}/{package.get('name', '?')} {vulnerability['first_patched_version']}")
        if fixed:
            facts.append({"kind": "fix", "text": f"GitHub {ghsa} patched in: " + "; ".join(fixed[:6]) + (f"; +{len(fixed) - 6} more" if len(fixed) > 6 else "")})
        events += [_event(advisory.get("published_at"), "declared", f"GitHub advisory {ghsa} published"),
                   _event(advisory.get("github_reviewed_at"), "declared", f"GitHub advisory {ghsa} reviewed")]
        refs += [r for r in (advisory.get("references") or []) if isinstance(r, str)]
    if len(data) > 5:
        facts.append({"kind": "detail", "text": f"{len(data) - 5} more GitHub advisories are indexed under this CVE"})
    return _result(True, facts, events, refs)


PARSERS = {   # name -> (function, needs {cve} in the url)
    "cve_org": (parse_cve_org, True), "nvd": (parse_nvd, True), "redhat": (parse_redhat, True), "ubuntu": (parse_ubuntu, True),
    "debian": (parse_debian, True), "github_repos": (parse_github_repos, True), "github_oldest": (parse_github_oldest, True), "epss": (parse_epss, True),
    "kev": (parse_kev, False), "osv_cve": (parse_osv_cve, True), "arch": (parse_arch, True), "github_advisories": (parse_github_advisories, True),
}


def _title_of(text):
    match = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.S | re.I)
    return _clip(html.unescape(match.group(1)), 160) if match else ""


def _page_date(text):
    """A publication time a page states about ITSELF: an email archive's Date: line or an Open Graph/article time. Not the HTTP
    Last-Modified header (a dynamic page reports "now") and not the first <time> tag (on an index page that is some other entry),
    because a wrong time on the timeline is worse than none."""
    plain = html.unescape(re.sub(r"<[^>]+>", "", text or ""))
    match = re.search(r"(?im)^\s*Date:\s*(.+)$", plain)
    if match and parse_when(match.group(1).strip()):
        return match.group(1).strip(), "header"
    for pattern in (r'property="article:published_time"\s+content="([^"]+)"', r'content="([^"]+)"\s+property="article:published_time"'):
        match = re.search(pattern, text or "", re.I)
        if match and parse_when(match.group(1)):
            return match.group(1), "declared"
    return None, None


def _author_of(text):
    plain = html.unescape(re.sub(r"<[^>]+>", "", text or ""))
    match = re.search(r"(?m)^\s*From:\s*([^<\n]+?)\s*(?:<|$)", plain)
    return match.group(1).strip() if match else ""


def parse_link(source, fetch, cve=None):
    """A page we only point at: its title and, when the page says, its date. A lead, never a verified fact. With
    must_mention set, the page counts as found only if it names the CVE, so a generic or placeholder page for a CVE the site
    has never heard of is not mistaken for a hit."""
    if not fetch.text:
        return _result()
    if source.get("must_mention") and cve and cve.upper() not in fetch.text.upper():
        return _result()
    title = _title_of(fetch.text) or "(no title)"
    when, clock = _page_date(fetch.text)
    author = _author_of(fetch.text)
    lead = {"title": title, "author": author, "when": parse_when(when)[0] if when and parse_when(when) else None, "clock": clock, "url": fetch.url}
    events = [_event(when, clock, f"{source.get('label', source['id'])}: {title}" + (f" ({author})" if author else ""))] if when else []
    return dict(_result(True, [], events), lead=lead)


def _dotted(data, path):
    for part in path.split("."):
        if isinstance(data, list) and part.isdigit() and int(part) < len(data):
            data = data[int(part)]
        elif isinstance(data, dict) and part in data:
            data = data[part]
        else:
            return None
    return data


def parse_json_fields(source, fetch):
    data, error = _json(fetch)
    if error:
        return _result(error=error)
    values = {name: _dotted(data, path) for name, path in source["fields"].items()}
    if all(v is None for v in values.values()):
        return _result()
    facts = [{"kind": kind, "text": f"{source.get('label', source['id'])}: {values[name]}"}
             for name, kind in (("state", "state"), ("severity", "severity")) if values.get(name) is not None]
    events = [_event(str(values["published"]), "declared", f"{source.get('label', source['id'])} published")] if values.get("published") else []
    result = _result(True, facts, events)
    if values.get("title"):
        result["lead"] = {"title": _clip(values["title"], 160), "author": "", "when": None, "clock": None, "url": fetch.url}
    return result


# --------------------------------------------------------------------------------------------------------------------
# The warehouse's view: which layers this CVE has reached
# --------------------------------------------------------------------------------------------------------------------

LAYER_NAMES = {"Container Base Image": "container", "App Software Registry": "app"}


def warehouse_reach(db_path, cve):
    """Records the warehouse holds that mention the CVE, grouped by layer. None when there is no warehouse to ask."""
    if not db_path or not os.path.exists(db_path):
        return None
    pattern = f"%{cve.upper()}%"
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            rows = conn.execute("SELECT advisory_id, package_name, ecosystems, published_date, last_modified FROM vulnerabilities "
                                "WHERE cve_alias = ? OR aliases LIKE ? OR advisory_id LIKE ?", (cve.upper(), pattern, pattern)).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    layers, records = {"container": set(), "app": set(), "other": set()}, []
    for advisory_id, package, ecosystems, published, modified in rows:
        try:
            names = json.loads(ecosystems) if ecosystems else []
        except ValueError:
            names = []
        for name in names:
            clean = clean_ecosystem_tag(name)
            layers[LAYER_NAMES.get(get_artifact_layer(clean), "other")].add(clean)
        records.append({"id": advisory_id, "package": package, "ecosystems": names, "published": published, "modified": modified})
    return {"records": len(records), "layers": {k: sorted(v) for k, v in layers.items()}, "list": sorted(records, key=lambda r: r["id"])}


# --------------------------------------------------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------------------------------------------------

def _eco_key(name) -> str:
    """A comparable key for an ecosystem name: lowercase, without the release suffix OSV adds ("Debian:11" -> "debian")."""
    base = str(name).split(":")[0].strip().lower()
    return re.sub(r"[\s\d.]+$", "", base)


def coverage_gaps(reach, sources, entries) -> dict:
    """Set the warehouse's records for this CVE against the sources that speak for each ecosystem, both ways:
    ecosystems that have warehouse records but no configured source, and ecosystem-specific sources that answered while the
    warehouse holds nothing for their ecosystem (OSV has not ingested them, or this tool does not track them).
    Not checked when there is no warehouse to ask."""
    if reach is None:
        return {"checked": False, "records_without_source": [], "sources_without_records": []}
    declared = {}
    for source in sources:
        for eco in source.get("ecosystems", []):
            declared.setdefault(_eco_key(eco), []).append(source["id"])
    counts, names = {}, {}
    for record in reach["list"]:
        for key, raw in {_eco_key(e): str(e).split(":")[0].strip() for e in record["ecosystems"]}.items():
            counts[key] = counts.get(key, 0) + 1
            names.setdefault(key, raw)
    status = {e["id"]: e["status"] for e in entries}
    return {
        "checked": True,
        "records_without_source": [{"ecosystem": names[k], "records": n} for k, n in sorted(counts.items(), key=lambda kv: names[kv[0]]) if k not in declared],
        "sources_without_records": [src.get("label", src["id"]) for src in sources
                                    if src.get("ecosystems") and status.get(src["id"]) == "found" and not any(_eco_key(e) in counts for e in src["ecosystems"])],
    }


OUTCOMES = {"found": "ok", "not_found": "nothing", "error": "error", "blocked": "blocked"}


def _note(state, detail=""):
    """Tell the live status what this thread's source is doing."""
    hook = getattr(sitrep_progress.ACTIVE, "hook", None)
    if hook:
        hook(state, detail)


def _query_source(cve, source, fetch, progress=None):
    started = time.monotonic()
    sitrep_progress.ACTIVE.hook = progress.hook_for(source["id"]) if progress else None
    try:
        entry = _query_source_inner(cve, source, fetch)
    finally:
        sitrep_progress.ACTIVE.hook = None
    entry["seconds"] = round(time.monotonic() - started, 1)
    if progress:
        detail = entry["detail"] or {"found": "found", "not_found": "nothing there"}.get(entry["status"], entry["status"])
        progress.finish(source["id"], OUTCOMES[entry["status"]], detail)
    return entry


SLOW_SECONDS = 10


def slow_notes(entries, threshold=SLOW_SECONDS) -> list:
    """A note for each source that took long, so a slow one can be dropped with --sources core,-id."""
    slow = [e for e in entries if e.get("seconds", 0) >= threshold]
    if len(slow) >= 3:      # several at once is the network or DNS on this machine, not several slow servers
        low, high = min(e["seconds"] for e in slow), max(e["seconds"] for e in slow)
        return [f"{len(slow)} sources ({', '.join(e['label'] for e in slow)}) each took {low:.0f}-{high:.0f} s in the same run; that usually means slow DNS or "
                f"network on this machine, not slow sources"]
    return [f"{e['label']} took {e['seconds']:.0f} s; --sources \"core,-{e['id']}\" skips it" for e in slow]


def _query_source_inner(cve, source, fetch):
    url = source["url"].replace("{cve}", quote(cve))
    entry = {"id": source["id"], "label": source.get("label", source["id"]), "path": source["path"], "trust": source["trust"],
             "url": url, "status": "error", "detail": "", "facts": [], "events": [], "refs": [], "reflinks": [], "lead": None}
    _note("contacting", urlparse(url).hostname)
    response = fetch(url, source)
    _note("reading", "")
    if response.status is None or response.error:   # transport failures and oversize responses; HTTP statuses carry no error
        entry["detail"] = response.error or "request failed"
        entry["status"] = "blocked" if (response.error or "").startswith("refused") else "error"
        return entry
    if response.status == 404:
        entry.update(status="not_found", detail="no record for this CVE")
        if source.get("kind") == "builtin" and source.get("parser") == "osv_cve":
            entry["facts"] = [{"kind": "state", "text": "OSV has no record under this CVE ID (vendor records that mention it may exist)"}]
        return entry
    if response.status != 200:
        entry["detail"] = f"HTTP {response.status}"
        return entry
    if source["kind"] == "builtin":
        parsed = PARSERS[source["parser"]][0](cve, response)
    elif source["kind"] == "json":
        parsed = parse_json_fields(source, response)
    else:
        parsed = parse_link(source, response, cve)
    if parsed["error"]:
        entry["detail"] = parsed["error"]
        return entry
    entry.update(status="found" if parsed["found"] else "not_found", facts=parsed["facts"], events=parsed["events"], refs=parsed["refs"], lead=parsed.get("lead"),
                 reflinks=parsed.get("reflinks") or [{"url": u, "tags": []} for u in parsed["refs"]])
    entry["detail"] = "" if parsed["found"] else "answered, but nothing about this CVE"
    return entry


def _follow(cve, entries, follow_hosts, fetch, progress=None):
    """Fetch pages the records point at, when their host is on the follow list, as leads (title and date only)."""
    seen = {e["url"] for e in entries}
    candidates, labels = [], {e["id"]: e["label"] for e in entries}
    for entry in entries:
        for ref in entry["refs"]:
            parsed = urlparse(ref)
            if parsed.hostname in follow_hosts and parsed.scheme in ("http", "https"):
                url = "https://" + parsed.netloc + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
                if url not in seen:
                    seen.add(url)
                    candidates.append((url, follow_hosts[parsed.hostname], entry["id"], url + ("#" + parsed.fragment if parsed.fragment else "")))
    results = []
    for url, info, via, shown in candidates[:MAX_FOLLOW]:
        source = {"id": "link-" + urlparse(url).hostname, "label": info["label"], "kind": "link", "path": info["path"], "trust": "lead"}
        key = "link:" + shown
        if progress:
            progress.add(key, "linked: " + urlparse(url).hostname)
            progress.update(key, "contacting", urlparse(url).hostname)
        response = fetch(url, {"timeout": DEFAULT_TIMEOUT})
        entry = {"id": source["id"], "label": f"{info['label']} (linked from {labels.get(via, via)})", "path": info["path"], "trust": "lead", "url": url,
                 "status": "error", "detail": "", "facts": [], "events": [], "refs": [], "lead": None}
        if response.status == 200 and response.text:
            parsed = parse_link(source, response)
            entry.update(status="found", events=parsed["events"], lead=dict(parsed["lead"], url=shown))   # keep the #fragment the record pointed at
        else:
            entry["detail"] = response.error or f"HTTP {response.status}"
        if progress:
            progress.finish(key, OUTCOMES[entry["status"]], entry["detail"] or "found")
        results.append(entry)
    skipped = len(candidates) - MAX_FOLLOW
    return results, (f"{skipped} more linked page(s) on followed hosts were not fetched (limit {MAX_FOLLOW})" if skipped > 0 else "")


def build_sitrep(cve, sources, follow_hosts, fetch, db_path=None, today=None, workers=4, progress=None):
    """The structured report for one CVE ID. Sources are queried in the same pass (no channel is assumed to go first);
    one failing source never hides the others."""
    cve = timeline.validate_id(cve).upper()
    if not CVE_PATTERN.match(cve):
        raise ValueError(f"'{cve}' is not a CVE ID (expected CVE-YYYY-NNNN...)")
    now = today or datetime.datetime.now(datetime.timezone.utc)
    notes = []
    started = time.monotonic()
    if progress:
        progress.begin(f"{cve}: asking {len(sources)} sources" + (" and the warehouse" if db_path else ""))
        for source in sources:
            progress.add(source["id"], source.get("label", source["id"]))
        if db_path:
            progress.add("warehouse", "warehouse (reach)")

    def read_warehouse():
        if progress:
            progress.update("warehouse", "reading", os.path.basename(db_path))
        found_reach = warehouse_reach(db_path, cve)
        if progress:
            progress.finish("warehouse", "ok" if found_reach else "nothing", f"{found_reach['records']} record(s)" if found_reach else "unavailable")
        return found_reach

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers + 1) as pool:
            reach_future = pool.submit(read_warehouse) if db_path else None
            entries = list(pool.map(lambda s: _query_source(cve, s, fetch, progress), sources))
            reach = reach_future.result() if reach_future else None
        followed, skipped_note = _follow(cve, entries, follow_hosts, fetch, progress)
    finally:
        if progress:
            progress.end(f"  asked {len(sources)} sources for {cve} in {time.monotonic() - started:.1f} s")
    if skipped_note:
        notes.append(skipped_note)
    entries_all = entries + followed
    facts, events, leads = [], [], []
    for entry in entries_all:
        meta = {"source": entry["id"], "label": entry["label"], "path": entry["path"], "trust": entry["trust"], "url": entry["url"]}
        facts += [dict(f, **meta) for f in entry["facts"]]
        events += [dict(e, **meta) for e in entry["events"]]
        if entry["lead"]:
            leads.append(dict(meta, **entry["lead"]))   # the lead's own url (which may carry a #fragment) wins over the source's
    events.sort(key=_sort_key)
    scores = {round(f["score"], 1) for f in facts if f["kind"] == "severity" and "score" in f}
    if db_path and reach is None and os.path.exists(db_path):
        notes.append("the warehouse could not be read, so its view of this CVE is missing")
    found = any(e["status"] == "found" for e in entries_all) or bool(reach and reach["records"])
    notes += slow_notes(entries)
    errors = [e for e in entries_all if e["status"] in ("error", "blocked")]
    if errors:
        notes.append(f"{len(errors)} source(s) could not be read (see the coverage list); their silence is not evidence")
    if any(e["id"] == "osv" and e["status"] == "not_found" for e in entries) and not (reach and reach["records"]):
        notes.append("OSV has no record under this CVE ID and the warehouse holds none that mention it; try a vendor ID with --timeline if one is known")
    gaps = coverage_gaps(reach, sources, entries)
    references = build_references(entries, followed)
    return {
        "cve": cve, "fetched_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "found": found, "gaps": gaps,
        "coverage": [{k: e.get(k) for k in ("id", "label", "path", "trust", "status", "detail", "url", "seconds")} for e in entries_all],
        "state": [f for f in facts if f["kind"] == "state"], "severity": [f for f in facts if f["kind"] == "severity"],
        "severity_disagree": len(scores) > 1, "exploitation": [f for f in facts if f["kind"] == "exploitation"],
        "fixes": [f for f in facts if f["kind"] == "fix"], "affected": [f for f in facts if f["kind"] == "affected"],
        "details": [f for f in facts if f["kind"] == "detail"], "events": events, "leads": leads, "reach": reach, "notes": notes,
        "references": references["references"], "references_covered": references["covered"],
    }


CAUTION = ("This lists what each source publishes, with the clock behind every time. It makes no judgment about urgency: sources lag one "
           "another, disagree, and none is assumed to hear first. Silence from a source is not evidence.")
STATUS_MARK = {"found": "[ok]", "not_found": "[--]", "error": "[!!]", "blocked": "[xx]"}


def _wrap(prefix, text, width=WIDTH):
    import textwrap
    pad = " " * len(prefix)
    lines = textwrap.wrap(text, width=width - len(prefix), break_on_hyphens=False, break_long_words=False) or [""]
    return [prefix + lines[0]] + [pad + line for line in lines[1:]]


def render_sitrep(result, color=False) -> str:
    """The console report. With color=True the same text gets colour (see termcolor.py); nothing but escape codes is added."""
    rule = "=" * WIDTH
    out = [rule, f"  SITREP  {result['cve']}    (fetched {result['fetched_at'][:10]} {result['fetched_at'][11:16]} UTC)", rule]
    out += _wrap("  ", CAUTION)
    out.append("")
    if not result["found"]:
        out.append(f"  Nothing found for {result['cve']} in any queried source.")
    for fact in result["state"]:
        out += _wrap("  STATE      ", f"{fact['text']}  [{fact['label']}]")
    reach = result["reach"]
    if reach is None:
        out.append("  REACH      not checked (no warehouse available)")
    elif not reach["records"]:
        out.append("  REACH      the warehouse holds no record that mentions this CVE")
    else:
        layers = "; ".join(f"{name}: {', '.join(eco) if eco else 'none'}" for name, eco in reach["layers"].items() if name != "other" or eco)
        out += _wrap("  REACH      ", f"{reach['records']} warehouse record(s) mention it - {layers}")
    if result["severity"]:
        out.append("  SEVERITY   " + ("sources disagree, shown side by side:" if result["severity_disagree"] else "as scored:"))
        for fact in result["severity"]:
            out += _wrap("               ", f"{fact['text']}  [{fact['label']}]")
    for fact in result["exploitation"]:
        out += _wrap("  EXPLOIT    ", f"{fact['text']}  [{fact['label']}]")
    for fact in result["affected"]:
        out += _wrap("  AFFECTED   ", f"{fact['text']}  [{fact['label']}]")
    for fact in result["fixes"]:
        out += _wrap("  FIXES      ", f"{fact['text']}  [{fact['label']}]")
    for fact in result["details"]:
        out += _wrap("  DETAIL     ", f"{fact['text']}  [{fact['label']}]")
    out += ["", "  SOURCES    [ok] found  [--] nothing there  [!!] error  [xx] blocked"]
    for path in PATHS:
        rows = [c for c in result["coverage"] if c["path"] == path]
        if rows:
            out += _wrap(f"    {path:<13}", "  ".join(f"{STATUS_MARK[c['status']]} {c['label']}" + (f" ({c['detail']})" if c["status"] in ("error", "blocked") else "") for c in rows))
    gaps = result["gaps"]
    if gaps["checked"]:
        out.append("")
        if not (gaps["records_without_source"] or gaps["sources_without_records"]):
            out.append("  COVERAGE GAPS   none: every ecosystem with warehouse records has a configured source, and every ecosystem-specific source that answered has records")
        else:
            out.append("  COVERAGE GAPS   (the warehouse's records for this CVE set against the sources configured)")
            if gaps["records_without_source"]:
                listed = ", ".join(f"{g['ecosystem']} ({g['records']} record{'s' if g['records'] != 1 else ''})" for g in gaps["records_without_source"])
                out += _wrap("    Records, no source of their own:  ", f"{listed}. They are seen only through OSV and the warehouse; add a source if you need the publisher's own timing.")
            if gaps["sources_without_records"]:
                out += _wrap("    Sources answered, no warehouse records:  ", ", ".join(gaps["sources_without_records"])
                             + ". Either OSV has not ingested them yet, or this tool does not track those ecosystems.")
    if result["events"]:
        out += ["", "  TIMELINE   (UTC; the clock says what kind of time it is: declared = the source's own timestamp, header = an email/HTTP date,",
                "              ingested = when a feed picked it up, approximate = read from prose. Times on different clocks are not directly comparable.)",
                f"    {'WHEN':<26}{'CLOCK':<10}{'PATH':<14}EVENT"]
        for event in result["events"]:
            out += _wrap(f"    {show_when(event):<26}{event['clock']:<10}{event['path']:<14}", f"{event['text']}  [{event['label']}]")
    if result["leads"]:
        out += ["", "  LEADS      pages the records point at (read them yourself; title and date only)"]
        for lead in result["leads"]:
            out += _wrap("    ", f"{lead['title']}" + (f" - {lead['author']}" if lead["author"] else "") + f"  [{lead['label']}]")
            out.append(f"      {lead['url']}")
    references = result["references"]
    if references or result["references_covered"]:
        out += ["", "  REFERENCES  what the records point at, by what they say it is: a checklist.   [ ] not read   [x] read above (see LEADS)   [!!] could not be fetched"]
        category = None
        for row in references[:MAX_REFERENCES_SHOWN]:
            if row["category"] != category:
                category = row["category"]
                out.append(f"    {category}")
            out += _wrap("      " + {"unread": "[ ]", "read": "[x]", "failed": "[!!]"}[row["status"]].ljust(5), f"{row['url']}  ({', '.join(row['sources'])})")
        if len(references) > MAX_REFERENCES_SHOWN:
            out.append(f"    +{len(references) - MAX_REFERENCES_SHOWN} more (see --json)")
        if result["references_covered"]:
            hosts = sorted({urlparse(u).hostname for u in result["references_covered"]})
            out += _wrap("    ", f"Already queried above: {', '.join(hosts)} ({len(result['references_covered'])} link(s))")
    for note in result["notes"]:
        out += _wrap("  [!] ", note)
    out.append(rule)
    return "\n".join(report_color.colorize_sitrep(out) if color else out)


def run(ids, sources_expression=None, as_json=False, fetch=None, db_path=None, out=print, config=None, today=None, show_progress=False, color=False) -> int:
    """CLI entry. show_progress: False (the default, for callers and tests), "auto" (a live status on stderr when it is a terminal), or a
    sitrep_progress.Progress. Exit code 0 when anything was found for at least one ID, 1 when nothing was, 2 for a bad request or config."""
    try:
        sources, follow = config if config is not None else load_config()
        selected, _ = select_sources(sources, sources_expression)
    except ConfigError as exc:
        out(f"[-] sources configuration problem: {exc}")
        return 2
    fetch = fetch or make_fetcher()
    progress = sitrep_progress.Progress.auto(keep=True) if show_progress == "auto" else (show_progress if isinstance(show_progress, sitrep_progress.Progress) else None)
    results = []
    for raw in ids:
        try:
            result = build_sitrep(raw, selected, follow, fetch, db_path=db_path, today=today, progress=progress)
        except ValueError as exc:
            out(f"[-] {exc}")
            continue
        results.append(result)
        if not as_json:
            out(render_sitrep(result, color=color))
    if as_json and results:
        out(json.dumps(results, indent=2, default=str))
    if not results:
        return 2
    return 0 if any(r["found"] for r in results) else 1
