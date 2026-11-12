"""Tell me when CISA's KEV catalog changes -- the whole catalog, not just the part our OSV window covers.

The warehouse's kev_catalog table is overwritten from CISA's JSON on every refresh, so it has no memory: the only way to know
what CHANGED since yesterday is to keep yesterday's copy. This module is that copy. Each run fetches CISA's live catalog,
compares it with the baseline saved by the previous run, writes a digest of the differences, and saves the new catalog as the
next baseline. The first run only records a baseline.

What counts as a change:
  new entry          a CVE CISA added since the last run -- any vendor, whether or not OSV has a record of it.  ALERT
  ransomware         an existing entry whose known-ransomware flag became "Known".                              ALERT
  due date           CISA moved an entry's remediation due date.                                                digest
  edited             an entry's required action or notes text changed.                                          digest
  removed            an entry CISA took out of the catalog.                                                     digest
ALERT items are what the daily runner makes a sound for; digest items are only written down.

Safeguards: a fetch that fails, or that returns a catalog under half the size of the baseline, is reported as an error and
leaves the baseline untouched (a flaky download must not look like "CISA removed everything" and then like "CISA re-added
everything" on the next run). Every run that sees changes also appends one line per change to history.jsonl, which is the honest
record of WHEN WE first saw each bump (CISA's dateAdded is when they listed it, not when we noticed).

Exit codes with --once semantics (this is a one-shot command): 0 nothing new or baseline recorded, 10 digest-only changes,
11 alert changes, 2 fetch error. Network access and the clock are injected so the tests run with neither.
"""
import argparse
import datetime
import json
import os
import sys

STATE_DIR = os.path.join("output", "kev_watch")
BASELINE_NAME = "baseline.json"
HISTORY_NAME = "history.jsonl"
DIGEST_NAME = "latest_digest.txt"
EXIT_QUIET, EXIT_DIGEST, EXIT_ALERT, EXIT_ERROR = 0, 10, 11, 2
ALERT_KINDS = ("new", "ransomware")
MIN_SHRINK_RATIO = 0.5          # a catalog smaller than this fraction of the baseline is a bad fetch, not a purge
# The fields kept per entry: enough to describe a change and to notice an edit, nothing that bloats the baseline.
KEPT_FIELDS = ("vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate", "knownRansomwareCampaignUse", "requiredAction", "notes")


class KevFetchError(Exception):
    """The live catalog could not be fetched or was not a usable catalog."""


def fetch_catalog(timeout: int = 60) -> dict:
    """CISA's live catalog as parsed JSON. Raises KevFetchError rather than returning something half-usable."""
    import requests
    from db_warehouse import KEV_FEED_URL
    try:
        response = requests.get(KEV_FEED_URL, timeout=timeout)
        response.raise_for_status()
        catalog = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise KevFetchError(f"could not fetch the KEV catalog: {exc}") from exc
    return catalog


def entries_from_catalog(catalog) -> dict:
    """{CVE id: kept fields} from a catalog payload. Raises KevFetchError if the payload has no vulnerabilities list."""
    vulns = catalog.get("vulnerabilities") if isinstance(catalog, dict) else None
    if not isinstance(vulns, list) or not vulns:
        raise KevFetchError("the KEV payload has no 'vulnerabilities' list")
    entries = {}
    for item in vulns:
        cve = str(item.get("cveID", "")).strip().upper()
        if cve:
            entries[cve] = {field: (item.get(field) or "").strip() if isinstance(item.get(field), str) else item.get(field) for field in KEPT_FIELDS}
    if not entries:
        raise KevFetchError("the KEV payload has no usable entries")
    return entries


def diff(old: dict, new: dict) -> list:
    """Changes from the old entries to the new, as [{kind, cve, ...entry fields, detail}], ALERT kinds first, then by CVE."""
    changes = []
    for cve, entry in new.items():
        before = old.get(cve)
        if before is None:
            changes.append(dict(entry, kind="new", cve=cve, detail=f"added to KEV {entry.get('dateAdded') or '?'}"))
            continue
        if before.get("knownRansomwareCampaignUse") != entry.get("knownRansomwareCampaignUse") and entry.get("knownRansomwareCampaignUse") == "Known":
            changes.append(dict(entry, kind="ransomware", cve=cve, detail=f"ransomware use: {before.get('knownRansomwareCampaignUse') or '?'} -> Known"))
        if before.get("dueDate") != entry.get("dueDate"):
            changes.append(dict(entry, kind="due date", cve=cve, detail=f"due date {before.get('dueDate') or '?'} -> {entry.get('dueDate') or '?'}"))
        if before.get("requiredAction") != entry.get("requiredAction") or before.get("notes") != entry.get("notes"):
            changes.append(dict(entry, kind="edited", cve=cve, detail="required action or notes text changed"))
    for cve, entry in old.items():
        if cve not in new:
            changes.append(dict(entry, kind="removed", cve=cve, detail="no longer in the catalog"))
    order = {"new": 0, "ransomware": 1, "due date": 2, "edited": 3, "removed": 4}
    changes.sort(key=lambda c: (order[c["kind"]], c["cve"]))
    return changes


def format_digest(changes: list, observed_at: str, catalog_version, total: int) -> str:
    """Plain-text digest. ALERT items first; each line carries what a person needs to decide whether to look further."""
    alerts = [c for c in changes if c["kind"] in ALERT_KINDS]
    lines = [f"KEV catalog check {observed_at} (catalog version {catalog_version or '?'}, {total:,} entries)"]
    if not changes:
        return "\n".join(lines + ["No changes since the last check."]) + "\n"
    lines.append(f"{len(alerts)} alert-worthy, {len(changes) - len(alerts)} other change(s).")
    for c in changes:
        ransom = "  [ransomware: Known]" if c.get("knownRansomwareCampaignUse") == "Known" else ""
        lines += ["", f"{'ALERT' if c['kind'] in ALERT_KINDS else 'note '} {c['kind'].upper():10} {c['cve']}  {c.get('vendorProject') or '?'} / {c.get('product') or '?'}{ransom}",
                  f"      {c.get('vulnerabilityName') or 'unnamed'}", f"      {c['detail']}; due {c.get('dueDate') or '?'}"]
    return "\n".join(lines) + "\n"


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def check(state_dir: str = STATE_DIR, fetch=fetch_catalog, now=None) -> dict:
    """One run. Returns {"exit": code, "changes": [...], "digest": text, "baselined": bool, "error": str|None}.
    Writes the digest file and history, and advances the baseline, only when the fetch was good."""
    observed_at = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    os.makedirs(state_dir, exist_ok=True)
    baseline_path = os.path.join(state_dir, BASELINE_NAME)
    try:
        catalog = fetch()
        new = entries_from_catalog(catalog)
    except KevFetchError as exc:
        return {"exit": EXIT_ERROR, "changes": [], "digest": f"KEV check {observed_at} FAILED: {exc}\n", "baselined": False, "error": str(exc)}
    version, total = catalog.get("catalogVersion"), len(new)

    baseline = _read_json(baseline_path)
    old = baseline.get("entries") if isinstance(baseline, dict) else None
    if old and total < len(old) * MIN_SHRINK_RATIO:
        message = f"the catalog returned {total:,} entries against a baseline of {len(old):,}; treating it as a bad fetch and keeping the baseline"
        return {"exit": EXIT_ERROR, "changes": [], "digest": f"KEV check {observed_at} FAILED: {message}\n", "baselined": False, "error": message}

    def save_baseline():
        with open(baseline_path, "w", encoding="utf-8") as handle:
            json.dump({"fetched_at": observed_at, "catalog_version": version, "entries": new}, handle)

    if not old:
        save_baseline()
        digest = f"KEV catalog check {observed_at}: baseline recorded ({total:,} entries, catalog version {version or '?'}). Changes are reported from the next run.\n"
        _write(state_dir, DIGEST_NAME, digest)
        return {"exit": EXIT_QUIET, "changes": [], "digest": digest, "baselined": True, "error": None}

    changes = diff(old, new)
    digest = format_digest(changes, observed_at, version, total)
    _write(state_dir, DIGEST_NAME, digest)
    if changes:
        with open(os.path.join(state_dir, HISTORY_NAME), "a", encoding="utf-8") as handle:
            for c in changes:
                handle.write(json.dumps(dict(c, observed_at=observed_at)) + "\n")
    save_baseline()
    code = EXIT_ALERT if any(c["kind"] in ALERT_KINDS for c in changes) else (EXIT_DIGEST if changes else EXIT_QUIET)
    return {"exit": code, "changes": changes, "digest": digest, "baselined": False, "error": None}


def _write(state_dir, name, text):
    with open(os.path.join(state_dir, name), "w", encoding="utf-8") as handle:
        handle.write(text)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Compare CISA's live KEV catalog with the last run's copy and report what changed.")
    parser.add_argument("--state-dir", default=STATE_DIR, help=f"Where the baseline, digest and history live (default {STATE_DIR}).")
    args = parser.parse_args(argv)
    result = check(args.state_dir)
    sys.stdout.write(result["digest"])
    return result["exit"]


if __name__ == "__main__":
    sys.exit(main())
