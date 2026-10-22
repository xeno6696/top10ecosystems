"""Vulnerability timeline: one CVE or advisory ID in, a dated history of what happened to it out.

Everything is fetched live, so it needs the network (the same hosts a warehouse sync already reaches,
plus FIRST for EPSS history):
  - api.osv.dev            the record(s): published / modified / withdrawn, aliases, severity vectors,
                           fixed versions, references, and the review/NVD dates inside database_specific
  - CISA KEV feed          when it was added to the exploited list, due date, ransomware flag
  - api.first.org (EPSS)   the last 30 days of exploitation-probability scores

What it cannot show: what changed at each MODIFIED date. OSV and KEV keep only the latest version of a
record, so field-level diffs (CVSS rescoring, range edits) would need NVD history or upstream git, and
FIRST only serves 30 days of EPSS. The output says so rather than implying a full audit trail.

Network access is injected (`get`), so the tests run against saved real responses with no network.
"""
import concurrent.futures
import datetime
import json
import re
import textwrap
import time
from collections import Counter, OrderedDict, namedtuple
from urllib.parse import quote

import requests

import timeline_signals

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

MAX_RECORDS = 25        # most OSV records fetched in full per ID
MAX_PER_TRACKER = 3     # of those, most from any one tracker, so e.g. 70 Bitnami records can't use up the cap
EPSS_STEP = 0.01        # a score change at least this big (1 point) earns its own EPSS row
WIDTH = 124

# OSV IDs are letters, digits and . _ : - (e.g. "SUSE-SU-2026:22689-1"); anything else is refused before it can
# reach a URL.
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")

BOLD, RED, GREEN, YELLOW, RESET = "\033[1m", "\033[91m", "\033[92m", "\033[93m", "\033[0m"

Response = namedtuple("Response", "status data error")

_KIND_RANK = {"PUBLISHED": 0, "REVIEWED": 1, "SCORED": 2, "EXPLOITED": 3, "WITHDRAWN": 4, "MODIFIED": 5}
_KIND_COLOR = {"EXPLOITED": RED, "WITHDRAWN": YELLOW}
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}))?")


def validate_id(raw: str) -> str:
    """The ID, trimmed, or ValueError. IDs go into a URL, so the pattern is strict."""
    candidate = (raw or "").strip()
    if not ID_PATTERN.match(candidate):
        raise ValueError(f"'{raw}' doesn't look like a CVE or advisory ID (letters, digits and . _ : - only)")
    return candidate


def tracker_of(record_id: str) -> str:
    """The tracker an ID belongs to: its prefix before the first '-' (CVE, GHSA, PYSEC, DEBIAN, BIT, ...)."""
    return record_id.split("-", 1)[0].upper()


def split_ts(value):
    """('YYYY-MM-DD', 'HH:MM') from an OSV/KEV timestamp or date; ('', '') if it isn't one. OSV timestamps carry
    up to nanoseconds, which datetime can't parse, so only the leading date and minute are read."""
    match = _TS.match(value or "")
    return (match.group(1), match.group(2) or "") if match else ("", "")


def to_date(value):
    date_part = split_ts(value)[0]
    return datetime.date.fromisoformat(date_part) if date_part else None


def default_get(url, params=None, timeout=20, retries=2) -> Response:
    """GET returning (status, parsed JSON or None, error text or None). Retries timeouts and 5xx a couple of times."""
    last_error = None
    for attempt in range(retries + 1):
        try:
            response = requests.get(url, params=params, timeout=timeout)
        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.5 * (attempt + 1))
            continue
        if response.status_code >= 500 and attempt < retries:
            last_error = f"HTTP {response.status_code}"
            time.sleep(0.5 * (attempt + 1))
            continue
        if response.status_code != 200:
            return Response(response.status_code, None, f"HTTP {response.status_code}")
        try:
            return Response(200, response.json(), None)
        except ValueError:
            return Response(200, None, "response was not valid JSON")
    return Response(None, None, last_error or "request failed")


def _safe(get):
    """Wrap an injected/real get so an unexpected exception becomes a failed Response instead of aborting the lookup."""
    def call(url, params=None):
        try:
            return get(url, params) if params is not None else get(url)
        except Exception as exc:
            return Response(None, None, f"{type(exc).__name__}: {exc}")
    return call


def record_links(record: dict) -> list:
    """IDs a record points at: aliases, related, and upstream."""
    links = []
    for field in ("aliases", "related", "upstream"):
        links.extend(record.get(field) or [])
    return links


def gather_records(root_id, get, max_records=MAX_RECORDS, max_per_tracker=MAX_PER_TRACKER, workers=8):
    """Breadth-first walk of the alias graph from root_id. Returns (fetched, failed, known): fetched maps
    ID -> OSV record, failed maps ID -> error text, known lists every ID seen (so IDs skipped by the caps can
    still be counted). At most max_records are fetched in full and at most max_per_tracker per tracker, root
    exempt, so a CVE linked to dozens of near-identical per-image records can't crowd out everything else."""
    fetched, failed = OrderedDict(), OrderedDict()
    known = OrderedDict([(root_id, True)])
    taken = Counter()
    pending = [root_id]
    while pending and len(fetched) + len(failed) < max_records:
        room = max_records - len(fetched) - len(failed)
        batch = []
        for record_id in pending:
            tracker = tracker_of(record_id)
            if len(batch) < room and (record_id == root_id or taken[tracker] < max_per_tracker):
                batch.append(record_id)
                taken[tracker] += 1
        if not batch:
            break
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            responses = list(pool.map(lambda rid: get(OSV_VULN_URL + quote(rid, safe="")), batch))
        pending = []
        for record_id, response in zip(batch, responses):
            if response.status == 200 and isinstance(response.data, dict):
                fetched[record_id] = response.data
                for link in record_links(response.data):
                    if link not in known:
                        known[link] = True
                        pending.append(link)
            else:
                failed[record_id] = response.error or f"HTTP {response.status}"
    return fetched, failed, list(known)


def find_cves(root_id, fetched, known) -> list:
    """Every CVE ID in the alias graph, most relevant first: the ID asked about, then its own aliases, then the rest.
    A record can link several CVEs (one advisory covering two CVEs), so the caller picks which one to follow."""
    ordered = []

    def add(candidate):
        candidate = candidate.upper()
        if candidate.startswith("CVE-") and candidate not in ordered:
            ordered.append(candidate)

    add(root_id)
    for link in record_links(fetched.get(root_id) or {}):
        add(link)
    for record in fetched.values():
        for link in record_links(record):
            add(link)
    for record_id in known:
        add(record_id)
    return ordered


def cvss_score(record: dict):
    """(version label, base score) from the record's severity vectors, newest CVSS version first, computed with
    the cvss library (OSV gives the vector, not the number). (None, None) if there is none or it won't parse."""
    from cvss import CVSS2, CVSS3, CVSS4
    by_type = {entry.get("type"): entry.get("score") for entry in record.get("severity") or []}
    for kind, parser in (("CVSS_V4", CVSS4), ("CVSS_V3", CVSS3), ("CVSS_V2", CVSS2)):
        vector = by_type.get(kind)
        if not vector:
            continue
        try:
            parsed = parser(vector)
            score = float(parsed.base_score)
            label = {"CVSS_V4": "4.0", "CVSS_V2": "2.0"}.get(kind) or (vector.split("/")[0].split(":")[1] if vector.startswith("CVSS:") else "3.x")
            return label, round(score, 1)
        except Exception:
            continue
    return None, None


def fixed_versions(records) -> OrderedDict:
    """{(ecosystem, package): [fixed versions]} from ECOSYSTEM/SEMVER ranges. GIT ranges hold commit hashes, not
    versions, so they're skipped."""
    out = OrderedDict()
    for record in records:
        for affected in record.get("affected") or []:
            package = affected.get("package") or {}
            if not package.get("name"):
                continue
            key = (package.get("ecosystem", "?"), package["name"])
            for rng in affected.get("ranges") or []:
                if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                for event in rng.get("events") or []:
                    version = event.get("fixed")
                    if version and version not in out.setdefault(key, []):
                        out[key].append(version)
    return OrderedDict((k, v) for k, v in out.items() if v)


def unfixed_packages(records) -> list:
    """Packages with at least one ECOSYSTEM/SEMVER range still open (an `introduced` or `last_affected` event with no
    `fixed` after it) and NO fixed version anywhere in any record. Deliberately conservative: a package with a fix on
    one branch and an open range on another is not listed, so the signal isn't raised on ambiguous data."""
    open_ranges, fixed = OrderedDict(), set()
    for record in records:
        for affected in record.get("affected") or []:
            package = affected.get("package") or {}
            if not package.get("name"):
                continue
            key = (package.get("ecosystem", "?"), package["name"])
            for rng in affected.get("ranges") or []:
                if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                state = None
                for event in rng.get("events") or []:
                    if event.get("fixed"):
                        fixed.add(key)
                        state = "fixed"
                    elif "introduced" in event or "last_affected" in event:
                        state = "open"
                if state == "open":
                    open_ranges.setdefault(key, True)
    return [{"ecosystem": e, "package": p} for (e, p) in open_ranges if (e, p) not in fixed]


def reference_summary(records, listed=5) -> dict:
    """Unique reference URLs counted by type, with the FIX and EVIDENCE ones listed (capped) -- the 'is there a fix
    commit / public exploit write-up' answer."""
    seen, counts, lists = set(), Counter(), {"FIX": [], "EVIDENCE": []}
    for record in records:
        for ref in record.get("references") or []:
            url, kind = ref.get("url"), ref.get("type", "WEB")
            if not url or url in seen:
                continue
            seen.add(url)
            counts[kind] += 1
            if kind in lists and len(lists[kind]) < listed:
                lists[kind].append(url)
    return {"counts": dict(counts), "fix": lists["FIX"], "evidence": lists["EVIDENCE"]}


def record_summary(record_id, record) -> dict:
    ecosystems = sorted({(a.get("package") or {}).get("ecosystem") for a in record.get("affected") or [] if (a.get("package") or {}).get("ecosystem")})
    label, score = cvss_score(record)
    return {
        "id": record_id, "tracker": tracker_of(record_id), "ecosystems": ecosystems,
        "published": record.get("published"), "modified": record.get("modified"), "withdrawn": record.get("withdrawn"),
        "cvss_version": label, "cvss": score,
    }


def tracker_table(summaries, known, today) -> list:
    """One row per tracker: records fetched out of records known, first published, days after the very first
    publication, latest modified."""
    first_overall = min((d for d in (to_date(s["published"]) for s in summaries) if d), default=None)
    totals = Counter(tracker_of(i) for i in known)
    rows = []
    for tracker in OrderedDict.fromkeys(s["tracker"] for s in summaries):
        mine = [s for s in summaries if s["tracker"] == tracker]
        published = min((d for d in (to_date(s["published"]) for s in mine) if d), default=None)
        modified = max((split_ts(s["modified"])[0] for s in mine if s["modified"]), default="")
        rows.append({
            "tracker": tracker, "fetched": len(mine), "known": totals[tracker],
            "first_published": published.isoformat() if published else "",
            "lag_days": (published - first_overall).days if published and first_overall else None,
            "latest_modified": modified,
        })
    rows.sort(key=lambda r: (r["first_published"] or "9999", r["tracker"]))
    return rows


def compress_epss(series, step=EPSS_STEP) -> list:
    """Rows worth showing from an oldest-first EPSS series: the first point, every point whose score moved at
    least `step` since the last shown one, and the latest point."""
    shown, last, last_date = [], None, None
    for index, point in enumerate(series):
        score = point["score"]
        is_latest = index == len(series) - 1
        if last is None or abs(score - last) >= step or is_latest:
            delta = None if last is None else score - last
            unchanged_since = last_date if (is_latest and delta is not None and abs(delta) < step) else None
            shown.append(dict(point, delta=delta, unchanged_since=unchanged_since))
            last, last_date = score, point["date"]
    return shown


def parse_epss(payload) -> list:
    """Oldest-first [{'date','score','percentile'}] from FIRST's time-series response, or [].
    FIRST answers a CVE with history with a "time-series" list, but a CVE it scored for the first time gets one flat
    row (that day's score, same fields, no list); both are read, so a day-old CVE still shows its first score."""
    try:
        row = payload["data"][0]
        raw = row["time-series"] if "time-series" in row else [row]
        series = [{"date": p["date"], "score": float(p["epss"]), "percentile": float(p["percentile"])} for p in raw]
    except (KeyError, IndexError, TypeError, ValueError):
        return []
    return sorted(series, key=lambda p: p["date"])


def _pct(value) -> str:
    return f"{value * 100:.1f}%"


def _eco_label(ecosystems, limit=2) -> str:
    if not ecosystems:
        return ""
    more = f", +{len(ecosystems) - limit}" if len(ecosystems) > limit else ""
    return f" ({', '.join(ecosystems[:limit])}{more})"


def build_events(summaries, fetched, kev, epss_series, cve_id, root_id=None):
    """Every dated event, sorted. The record you asked about and the main CVE record always get their own rows. Other
    records collapse to one PUBLISHED row per tracker (earliest, with a count -- that is where distro lag shows), and
    ONE rolled-up MODIFIED row for the latest update among them, so a CVE linked to dozens of per-image records
    stays readable."""
    events = []
    primary = {root_id, cve_id}
    by_group = OrderedDict()
    for s in summaries:
        by_group.setdefault(s["id"] if s["id"] in primary else s["tracker"], []).append(s)

    def add(date_value, kind, text, record, source):
        date_part, time_part = split_ts(date_value)
        if date_part:
            events.append({"date": date_part, "time": time_part, "kind": kind, "text": text, "record": record, "source": source})

    nvd_events = []
    others_modified = []
    for group, mine in by_group.items():
        many = len(mine) > 1
        label = f"{group} x{len(mine)} records" if many else mine[0]["id"]
        published = [s for s in mine if s["published"]]
        if published:
            first = min(published, key=lambda s: s["published"])
            add(first["published"], "PUBLISHED", ("First of %d records published" % len(mine) if many else "Published") + _eco_label(first["ecosystems"]), label, "OSV")
        modified = [s for s in mine if s["modified"]]
        if modified:
            latest = max(modified, key=lambda s: s["modified"])
            if group in primary:
                add(latest["modified"], "MODIFIED", "Last updated (what changed: unknown)", label, "OSV")
            else:
                others_modified.append((latest["modified"], label, len(mine)))
        for s in mine:
            if s["withdrawn"]:
                add(s["withdrawn"], "WITHDRAWN", "Withdrawn", s["id"], "OSV")
            db = (fetched[s["id"]].get("database_specific") or {})
            if db.get("github_reviewed_at"):
                add(db["github_reviewed_at"], "REVIEWED", "GitHub review completed", s["id"], "OSV")
            if db.get("nvd_published_at"):
                nvd_events.append((db["nvd_published_at"], s["id"]))

    if others_modified:
        latest_ts, latest_label, _ = max(others_modified)
        count = sum(n for _, _, n in others_modified)
        text = "Last updated (what changed: unknown)" if count == 1 else f"Latest update among {count} other records (what changed: unknown)"
        add(latest_ts, "MODIFIED", text, latest_label, "OSV")

    published_days = {e["date"]: e for e in events if e["kind"] == "PUBLISHED"}
    for nvd_ts, record_id in nvd_events:
        day = split_ts(nvd_ts)[0]
        if day in published_days:
            if "NVD" not in published_days[day]["text"]:
                published_days[day]["text"] += "; NVD same day"
        else:
            add(nvd_ts, "PUBLISHED", "Published in NVD", record_id, "OSV")
            published_days[day] = events[-1]

    if kev:
        due = f"; remediation due {kev['dueDate']}" if kev.get("dueDate") else ""
        ransom = "; known ransomware use" if str(kev.get("knownRansomwareCampaignUse", "")).lower() == "known" else ""
        add(kev.get("dateAdded"), "EXPLOITED", "Added to CISA KEV" + due + ransom, cve_id, "CISA KEV")

    for point in compress_epss(epss_series):
        if point["delta"] is None:
            extra = "  (start of FIRST's 30-day history)"
        elif point["unchanged_since"]:
            extra = f"  (latest; unchanged since {point['unchanged_since']})"
        else:
            extra = f"  ({point['delta'] * 100:+.1f} pts)"
        add(point["date"], "SCORED", f"EPSS {_pct(point['score'])}{extra}", cve_id, "FIRST EPSS")

    events.sort(key=lambda e: (e["date"], _KIND_RANK[e["kind"]], e["time"]))
    return events


def build_timeline(raw_id, get=default_get, today=None, max_records=MAX_RECORDS, max_per_tracker=MAX_PER_TRACKER):
    """The full structured timeline for one ID, or None if nothing at all could be found for it. Partial results
    (say EPSS is down but OSV answers) are returned with a note in result['notes'], never silently dropped."""
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    get = _safe(get)
    root = validate_id(raw_id)
    notes = []
    fetched, failed, known = gather_records(root, get, max_records, max_per_tracker)
    for record_id, error in failed.items():
        notes.append(f"OSV record {record_id} unavailable ({error})")
    if not fetched and root.upper().startswith("CVE-"):
        notes.append("OSV has no record under this CVE ID. That is normal for a CVE only vendors have published so far: their records "
                     "mention the CVE, but OSV cannot be searched from the CVE side. Try a vendor ID (for example DEBIAN-" + root.upper() + ") "
                     "or look the CVE up in the warehouse.")

    candidates = find_cves(root, fetched, known)
    cve_id, kev, epss_series = (candidates[0] if candidates else None), None, []
    if candidates:
        kev_response = get(KEV_FEED_URL)
        if kev_response.status == 200 and isinstance(kev_response.data, dict):
            in_kev = {v.get("cveID", "").upper(): v for v in kev_response.data.get("vulnerabilities", [])}
            # Several CVEs can be linked; follow one that is actually on the exploited list if any is.
            cve_id = next((c for c in candidates if c in in_kev), candidates[0])
            kev = in_kev.get(cve_id)
        else:
            notes.append(f"CISA KEV feed unavailable ({kev_response.error}); exploited status not shown")
        other_cves = [c for c in candidates if c != cve_id]
        if other_cves:
            notes.append(f"This timeline follows {cve_id}; also linked: " + ", ".join(other_cves[:5]) + (f", +{len(other_cves) - 5} more" if len(other_cves) > 5 else ""))
        epss_response = get(EPSS_API_URL, {"cve": cve_id, "scope": "time-series"})
        if epss_response.status == 200:
            epss_series = parse_epss(epss_response.data)
        else:
            notes.append(f"FIRST EPSS unavailable ({epss_response.error}); exploitation scores not shown")
    else:
        notes.append("No CVE ID is linked to this record, so KEV and EPSS (which are keyed by CVE) were skipped")

    if not fetched and not kev and not epss_series:
        return None

    summaries = [record_summary(rid, rec) for rid, rec in fetched.items()]
    events = build_events(summaries, fetched, kev, epss_series, cve_id, root)
    first_day = to_date(events[0]["date"]) if events else None
    for event in events:
        event["day"] = (to_date(event["date"]) - first_day).days if first_day else None

    skipped = Counter(tracker_of(i) for i in known if i not in fetched and i not in failed)
    scores = {s["id"]: s["cvss"] for s in summaries if s["cvss"] is not None}
    due = to_date(kev.get("dueDate")) if kev else None
    kev_added = to_date(kev.get("dateAdded")) if kev else None
    last_epss = epss_series[-1] if epss_series else None
    first_pub = min((d for d in (to_date(s["published"]) for s in summaries) if d), default=None)
    last_mod = max((split_ts(s["modified"])[0] for s in summaries if s["modified"]), default="")
    withdrawn = [s["id"] for s in summaries if s["withdrawn"]]

    result = {
        "id": root, "cve": cve_id, "fetched_at": today.isoformat(), "records": summaries,
        "trackers": tracker_table(summaries, known, today), "not_fetched": dict(skipped),
        "events": events, "fixed_versions": [{"ecosystem": e, "package": p, "versions": v} for (e, p), v in fixed_versions(fetched.values()).items()],
        "references": reference_summary(fetched.values()), "unfixed_packages": unfixed_packages(fetched.values()),
        "epss_series": epss_series, "cvss_scores": scores,
        "cvss_disagree": len({round(v, 1) for v in scores.values()}) > 1,
        "kev": None if not kev else {
            "name": kev.get("vulnerabilityName"), "vendor": kev.get("vendorProject"), "product": kev.get("product"),
            "added": kev.get("dateAdded"), "due": kev.get("dueDate"), "ransomware": kev.get("knownRansomwareCampaignUse"),
            "required_action": kev.get("requiredAction"), "cwes": kev.get("cwes"),
            "overdue_days": (today - due).days if due and today > due else 0,
            "days_until_due": (due - today).days if due and today <= due else None,
        },
        "epss": None if not last_epss else {
            "score": last_epss["score"], "percentile": last_epss["percentile"], "date": last_epss["date"],
            "window_start_score": epss_series[0]["score"], "window_start_date": epss_series[0]["date"],
            "week_ago_score": epss_series[max(0, len(epss_series) - 8)]["score"],
        },
        "summary": next((r.get("summary") for r in fetched.values() if r.get("summary")), None),
        "glance": {
            "first_publication": first_pub.isoformat() if first_pub else None,
            "first_publication_to_kev_days": (kev_added - first_pub).days if kev_added and first_pub else None,
            "last_modified": last_mod, "withdrawn": withdrawn,
        },
        "notes": notes,
    }
    result["signals"] = timeline_signals.build_signals(result, today)
    result["signals_caveat"] = timeline_signals.CAVEAT
    return result


def _trunc(text, width):
    return text if len(text) <= width else text[:width - 1] + "…"


def _trend(epss) -> str:
    if not epss:
        return ""
    move = epss["score"] - epss["week_ago_score"]
    return "rising" if move >= 0.02 else "falling" if move <= -0.02 else "flat"


def render_signals(signals) -> list:
    """The TRIAGE SIGNALS block: direction tag, the finding with its evidence, and what it usually means. No verdict,
    tally or recommendation -- that call belongs to whoever is reading it."""
    lines = ["  TRIAGE SIGNALS  (what the dated events suggest, with the evidence; the judgment is yours)"]
    caveat = textwrap.wrap(timeline_signals.CAVEAT, width=WIDTH - 10)
    lines.append(f"  {YELLOW}[!] {caveat[0]}{RESET}")
    lines.extend(f"      {YELLOW}{extra}{RESET}" for extra in caveat[1:])
    if not signals:
        lines.append("    (no signals triggered)")
    tags = {"raises": ("[RAISES]", RED), "lowers": ("[LOWERS]", GREEN), "context": ("[CONTEXT]", "")}
    for signal in signals:
        tag, color = tags[signal["direction"]]
        label = f"{tag:<10}"
        label = f"{color}{label}{RESET}" if color else label
        text = textwrap.wrap(signal["text"], width=WIDTH - 17)
        lines.append(f"    {label} {text[0]}")
        lines.extend(" " * 15 + extra for extra in text[1:])
        lines.extend(" " * 15 + chunk for chunk in textwrap.wrap(signal["meaning"], width=WIDTH - 17))
    lines.append("")
    return lines


def render_timeline(result, today=None) -> str:
    """The console report for one build_timeline() result."""
    lines = []
    cve, kev, epss = result["cve"], result["kev"], result["epss"]
    title = (kev or {}).get("name") or result["summary"] or result["id"]
    badges = ("  [CISA KEV]" if kev else "") + (f"  [EPSS {_pct(epss['score'])}]" if epss else "")
    lines += ["", "=" * WIDTH, f"  {BOLD}TIMELINE  {cve or result['id']}{RESET} -- \"{_trunc(title, 70)}\"{badges}", "=" * WIDTH]
    lines.append(f"  Fetched live: api.osv.dev, CISA KEV feed, api.first.org (EPSS)    {result['fetched_at']}")
    if result["id"] != (cve or result["id"]):
        lines.append(f"  Started from {result['id']}; aliases followed to the CVE and other trackers.")
    lines.append("")
    lines += render_signals(result.get("signals", []))

    shown = result["records"][:8]
    lines.append(f"  Records for this vulnerability ({len(result['records'])} fetched" + (f", {sum(result['not_fetched'].values())} more not fetched" if result["not_fetched"] else "") + "):")
    for s in shown:
        score = f"CVSS {s['cvss_version']}: {s['cvss']}" if s["cvss"] is not None else "no CVSS"
        eco = f"   {', '.join(s['ecosystems'])}" if s["ecosystems"] else ""
        wd = f"   {YELLOW}WITHDRAWN {split_ts(s['withdrawn'])[0]}{RESET}" if s["withdrawn"] else ""
        lines.append(f"    {s['id']:<30} published {split_ts(s['published'])[0] or '?':<10}  modified {split_ts(s['modified'])[0] or '?':<10}  {score:<16}{eco}{wd}")
    if len(result["records"]) > len(shown):
        lines.append(f"    ... {len(result['records']) - len(shown)} more (see the tracker table)")
    if result["cvss_disagree"]:
        groups = OrderedDict()
        for record_id, score in result["cvss_scores"].items():
            groups.setdefault(score, []).append(record_id)
        parts = [f"{score}: {ids[0]}" + (f" +{len(ids) - 1} more" if len(ids) > 1 else "") for score, ids in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:3]]
        lines.append(f"    {YELLOW}[!] Trackers disagree on severity -- " + "; ".join(parts) + f"{RESET}")
    lines.append("")

    lines.append(f"  {'DATE':<10}  {'DAY':>7}  {'EVENT':<64}  {'RECORD':<24}  SOURCE")
    lines.append(f"  {'-' * 10}  {'-' * 7}  {'-' * 64}  {'-' * 24}  {'-' * 10}")
    for e in result["events"]:
        day = "0" if e["day"] == 0 else f"+{e['day']:,}"
        kind = f"{e['kind']:<10}"
        kind = f"{_KIND_COLOR[e['kind']]}{kind}{RESET}" if e["kind"] in _KIND_COLOR else kind
        text = _trunc(e["text"], 53)
        lines.append(f"  {e['date']:<10}  {day:>7}  {kind} {text:<53}  {_trunc(e['record'], 24):<24}  {e['source']}")
    lines.append("")

    if len(result["trackers"]) > 1:
        lines.append(f"  TRACKERS   {'tracker':<12} {'records':<14} {'first published':<16} {'after first publication':<24} latest update")
        for t in result["trackers"]:
            lag = "-" if t["lag_days"] is None else ("first" if t["lag_days"] == 0 else f"+{t['lag_days']:,} days")
            have = f"{t['fetched']} of {t['known']}" if t["known"] > t["fetched"] else str(t["fetched"])
            lines.append(f"             {t['tracker']:<12} {have:<14} {t['first_published'] or '?':<16} {lag:<24} {t['latest_modified'] or '?'}")
        lines.append("")

    if result["fixed_versions"]:
        lines.append("  FIXED VERSIONS (the record gives versions, not dates)")
        for fv in result["fixed_versions"][:6]:
            lines.append(f"    {fv['ecosystem']:<14} {_trunc(fv['package'], 40):<40} {' | '.join(fv['versions'][:8])}")
        if len(result["fixed_versions"]) > 6:
            lines.append(f"    ... {len(result['fixed_versions']) - 6} more packages")
        lines.append("")

    refs = result["references"]
    if refs["counts"]:
        lines.append("  REFERENCES   " + "   ".join(f"{k} {v}" for k, v in sorted(refs["counts"].items())))
        for label, urls in (("fix", refs["fix"]), ("evidence", refs["evidence"])):
            for url in urls:
                lines.append(f"    {label:<9} {_trunc(url, WIDTH - 16)}")
        lines.append("")

    if kev:
        lines.append(f"  CISA KEV    {kev['vendor']} {kev['product']}; ransomware use: {kev['ransomware'] or 'unknown'}; CWEs: {', '.join(kev['cwes'] or []) or 'n/a'}")
        lines.append(f"    required action: {_trunc((kev['required_action'] or '').replace(chr(10), ' '), WIDTH - 22)}")
        lines.append("")

    g = result["glance"]
    lines.append("  AT A GLANCE")
    if kev:
        if kev["overdue_days"] and kev["overdue_days"] <= 30:
            due_text = f"{RED}OVERDUE by {kev['overdue_days']:,} days{RESET} (was due {kev['due']})"
        elif kev["overdue_days"]:
            due_text = f"federal remediation deadline passed {kev['overdue_days']:,} days ago ({kev['due']})"
        elif kev["days_until_due"] == 0:
            due_text = f"{YELLOW}due today{RESET}"
        elif kev["days_until_due"] is not None:
            due_text = f"due in {kev['days_until_due']:,} days ({kev['due']})"
        else:
            due_text = ""
        lines.append(f"    Exploited:    yes (CISA KEV, added {kev['added']}) -- {due_text}")
    else:
        lines.append("    Exploited:    not on the CISA KEV list" if cve else "    Exploited:    unknown (no CVE ID to look up)")
    if g["first_publication_to_kev_days"] is not None:
        lines.append(f"    First publication -> KEV:  {g['first_publication_to_kev_days']:,} days ({g['first_publication_to_kev_days'] / 365.25:.1f} years)")
    if epss:
        lines.append(f"    EPSS:         {_pct(epss['score'])} (percentile {epss['percentile'] * 100:.1f}), {_trend(epss)} over the last week; "
                     f"{_pct(epss['window_start_score'])} at {epss['window_start_date']}")
    fixed_in = sorted({fv["ecosystem"] for fv in result["fixed_versions"]})
    fix_text = "available in " + ", ".join(fixed_in[:5]) + (f", +{len(fixed_in) - 5} more" if len(fixed_in) > 5 else "") if fixed_in else ("no fixed version in the records" if result["records"] else "unknown (no OSV records to read fixes from)")
    lines.append(f"    Fix:          {fix_text}")
    withdrawn_text = ("yes (" + ", ".join(g["withdrawn"]) + ")" if g["withdrawn"] else "no") if result["records"] else "unknown (no OSV records)"
    lines.append(f"    Withdrawn:    {withdrawn_text}")
    lines.append("")
    for note in result["notes"]:
        lines.append(f"  {YELLOW}[!] {note}{RESET}")
    lines.append("  Not shown: what changed at each MODIFIED date. OSV and KEV keep only the latest version of a record, so")
    lines.append("             field-level diffs (CVSS rescoring, range edits) would need NVD history or upstream git.")
    lines.append("             EPSS history is limited to the last 30 days by FIRST.")
    lines.append("=" * WIDTH)
    return "\n".join(lines)


def run(ids, as_json=False, get=default_get, today=None, out=print) -> int:
    """CLI entry point. Returns 0 if every ID produced a timeline, else 1. With as_json the output is a single JSON
    array of the structured results (ANSI-free), so it can be piped."""
    results, code = [], 0
    for raw in ids:
        try:
            result = build_timeline(raw, get=get, today=today)
            error = None if result is not None else f"Nothing found for {raw}: not in OSV, and not a CVE that is in KEV or has an EPSS score."
        except ValueError as exc:
            result, error = None, str(exc)
        if error:
            code = 1
            if as_json:
                results.append({"id": raw, "error": error})
            else:
                out(f"{RED}[-] {error}{RESET}")
            continue
        results.append(result)
        if not as_json:
            out(render_timeline(result, today))
    if as_json:
        out(json.dumps(results, indent=2))
    return code
