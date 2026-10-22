"""Watch a CVE: poll --sitrep on a schedule and say what CHANGED since the last look.

OSV, KEV and the other sources keep only their latest state, so a change is visible only if somebody remembered the previous state.
This module is that memory. Each poll builds a digest of the situation report (its timeline events, the CVE record's state, severity
scores, exploitation signals, fixes, which sources now answer, which warehouse records exist, which pages are linked), compares it with
the baseline stored from earlier polls, and reports what is new or different. The first poll only records the baseline.

What counts as a change is deliberately narrower than "the output differs": the GitHub repository count grows by the minute, the
elapsed seconds and fetch time differ every run, and a source that times out is not a source that retracted. So:
  - anything worth a row on the timeline is a change (a new event, or the same event with a new time, like "CVE record last updated");
  - the CVE record's state, severity scores, fix statements and SSVC assessment are changes when their text changes;
  - EPSS is a change when it moves by at least a point; the public-repository count when the first repository appears and then each time
    it at least doubles; KEV only when it becomes LISTED; a source only when it starts answering;
  - a source that fails keeps its last good value (and is noted as degraded after three failed polls in a row), never a "removal";
  - a source that had never answered before (it timed out during the baseline poll) is filled into the baseline silently the first time
    it does answer: we cannot tell new from merely late, and a flaky network must not look like news.

Every change has a class. Exploitation and disclosure changes are IMMEDIATE (a terminal bell and a banner); exposure, severity, fix and
records changes are listed as digest. --alert chooses the immediate classes. Each item also remembers when WE first saw it, which is the
honest "ingested" clock for who told us first.

Network access, the clock and sleeping are injected, so the tests run a whole sequence of polls with no network and no waiting.
"""
import datetime
import json
import os
import re
import sys
import time

import report_color
import sitrep
import sitrep_progress

CLASSES = ("exploitation", "disclosure", "exposure", "severity", "fix", "records")
DEFAULT_ALERT = ("exploitation", "disclosure")
STATE_DIR = os.path.join("output", "watch")
FAILURES_BEFORE_DEGRADED = 3
EPSS_STEP_POINTS = 1.0          # EPSS (in percentage points) must move this much to count
MIN_EVERY_MINUTES = 1.0
EXIT_QUIET, EXIT_DIGEST, EXIT_IMMEDIATE = 0, 10, 11
WIDTH = 124


# --------------------------------------------------------------------------------------------------------------------
# The digest: what we compare between polls
# --------------------------------------------------------------------------------------------------------------------

def _event_class(event) -> str:
    text, path = event["text"].lower(), event["path"]
    if "last modified" in text or "last updated" in text:
        return "records"
    if path == "exploitation":
        return "exploitation"
    if path in ("distro", "vendor"):
        return "fix"
    if path == "registry":
        return "exposure"
    return "disclosure"        # upstream, records, osv, community: the CVE becoming, or being written about as, public


def _severity_key(text) -> str:
    inner = re.search(r"\((.*)\)", text)
    return inner.group(1) if inner else text.split(":")[0][:40]


def _number(pattern, text):
    match = re.search(pattern, text)
    return float(match.group(1).replace(",", "")) if match else None


def build_items(result) -> dict:
    """{key: item} from a sitrep result. An item is {class, text, value, source, label, when, clock}."""
    items = {}

    def put(key, cls, text, value, fact=None, when=None, clock=None):
        fact = fact or {}
        items[key] = {"class": cls, "text": text, "value": value, "source": fact.get("source", ""), "label": fact.get("label", ""), "when": when, "clock": clock}

    for event in result["events"]:
        put(f"event|{event['source']}|{event['text']}", _event_class(event), event["text"], event["when"], event, event["when"], event["clock"])
    for fact in result["state"]:
        put(f"state|{fact['source']}", "disclosure", fact["text"], fact["text"], fact)
    for fact in result["severity"]:
        put(f"severity|{fact['source']}|{_severity_key(fact['text'])}", "severity", fact["text"], fact["text"], fact)
    for fact in result["fixes"]:
        put(f"fix|{fact['source']}|{fact['text'].split(':')[0][:40]}", "fix", fact["text"], fact["text"], fact)
    for fact in result["exploitation"]:
        text = fact["text"]
        if text.startswith("CISA KEV:"):
            put("exploitation|kev", "exploitation", text, "LISTED" if "LISTED" in text else "not listed", fact)
        elif "SSVC" in text:
            put("exploitation|ssvc", "exploitation", text, text, fact)
        elif text.startswith("EPSS"):
            score = _number(r"EPSS ([\d.]+)%", text)
            if score is not None:
                put("exploitation|epss", "exploitation", text, score, fact)
        elif "public GitHub repositories mention" in text:
            put("exploitation|repos", "exploitation", text, int(_number(r"^([\d,]+) public GitHub", text) or 0), fact)
        elif text.startswith("no public GitHub repository"):
            put("exploitation|repos", "exploitation", text, 0, fact)
    for entry in result["coverage"]:
        if entry["id"].startswith("link-"):
            continue
        cls = "disclosure" if entry["path"] in ("upstream", "records", "osv") else "exposure"
        put(f"coverage|{entry['id']}", cls, f"{entry['label']} now has an entry for this CVE", entry["status"],
            {"source": entry["id"], "label": entry["label"]})
    reach = result.get("reach")
    if reach:
        for record in reach["list"]:
            put(f"reach|{record['id']}", "exposure", f"warehouse record {record['id']} ({', '.join(record['ecosystems']) or 'no ecosystem'})", record["id"],
                {"source": "warehouse", "label": "warehouse"})
        if reach["layers"].get("app"):
            put("reach|layer|app", "exposure", "an application registry is now reached: " + ", ".join(reach["layers"]["app"]), ",".join(reach["layers"]["app"]),
                {"source": "warehouse", "label": "warehouse"})
    for lead in result["leads"]:
        # A page is only a lead; if it states a date it also has a timeline event (which carries the class), so the lead itself is digest.
        put(f"lead|{lead['url']}", "records", f"page: {lead['title']}", lead["url"], lead, lead.get("when"), lead.get("clock"))
    return items


def _changed(key, old, new) -> bool:
    before, after = old["value"], new["value"]
    if key == "exploitation|epss":
        return abs(after - before) >= EPSS_STEP_POINTS
    if key == "exploitation|repos":
        return (before == 0 and after > 0) or (before > 0 and after >= 2 * before)
    if key == "exploitation|kev":
        return after == "LISTED" and before != "LISTED"
    if key.startswith("coverage|"):
        return before != "found" and after == "found"
    return before != after


def diff(baseline, items, now, failed_sources=(), silent_sources=(), silent_labels=()):
    """(changes, new_baseline). Items for sources that failed this poll are ignored, so their last good values survive. Nothing is ever
    reported as gone. The baseline keeps the value last REPORTED for noisy signals, so slow growth accumulates until it counts."""
    changes, updated = [], {k: dict(v) for k, v in baseline.items()}
    for key, item in items.items():
        if item["source"] in failed_sources:
            continue
        old = baseline.get(key)
        entry = dict(item, first_seen=now, last_seen=now)
        if old is None:
            silent = (key.startswith("coverage|") and item["value"] != "found") or (key == "exploitation|repos" and item["value"] == 0) \
                or (key == "exploitation|kev" and item["value"] != "LISTED") or item["source"] in silent_sources \
                or any(f"(linked from {label})" in item["label"] for label in silent_labels)
            updated[key] = entry
            if baseline and not silent:
                changes.append(dict(item, key=key, kind="new", was=None, first_seen=now))
            continue
        if _changed(key, old, item):
            kind = "updated" if key.startswith("event|") else "changed"
            changes.append(dict(item, key=key, kind=kind, was=old["text"] if kind == "changed" else old["value"], first_seen=old.get("first_seen", now)))
            updated[key] = dict(entry, first_seen=old.get("first_seen", now))
        else:
            keep = dict(old, last_seen=now)
            if key.startswith("coverage|") and old["value"] == "found":
                pass                                  # found stays found; a failed or empty answer later is not a retraction
            updated[key] = keep
    return changes, updated


# --------------------------------------------------------------------------------------------------------------------
# State on disk
# --------------------------------------------------------------------------------------------------------------------

def _paths(cve, state_dir):
    return os.path.join(state_dir, f"{cve}.json"), os.path.join(state_dir, f"{cve}.history.jsonl")


def load_state(cve, state_dir=STATE_DIR):
    """The stored state for a CVE, or a fresh one. A corrupt file is moved aside (never silently overwritten)."""
    path, _ = _paths(cve, state_dir)
    fresh = {"cve": cve, "polls": 0, "baseline": {}, "failures": {}, "answered": [], "last_poll": None}
    if not os.path.exists(path):
        return fresh, None
    try:
        with open(path, encoding="utf-8") as handle:
            state = json.load(handle)
        if not isinstance(state, dict) or not isinstance(state.get("baseline"), dict):
            raise ValueError("unexpected shape")
        return dict(fresh, **state), None
    except (OSError, ValueError) as exc:
        aside = f"{path}.corrupt-{int(time.time())}"
        try:
            os.replace(path, aside)
        except OSError:
            aside = path
        return fresh, f"the stored state for {cve} was unreadable ({exc}); moved to {os.path.basename(aside)} and starting a new baseline"


def save_state(cve, state, state_dir=STATE_DIR):
    path, _ = _paths(cve, state_dir)
    os.makedirs(state_dir, exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=1, sort_keys=True)
    os.replace(temp, path)


def append_history(cve, record, state_dir=STATE_DIR):
    _, path = _paths(cve, state_dir)
    os.makedirs(state_dir, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


# --------------------------------------------------------------------------------------------------------------------
# One poll
# --------------------------------------------------------------------------------------------------------------------

def due_sources(selected, poll_index):
    """Sources to ask on this poll: each source's optional watch_every means 'every Nth poll' (slow or rate-limited ones)."""
    return [s for s in selected if poll_index % int(s.get("watch_every", 1)) == 0]


def poll(cve, selected, follow, fetch, db_path=None, state_dir=STATE_DIR, alert=DEFAULT_ALERT, now=None, progress=None):
    """Poll once, compare with the stored baseline, store the new baseline, and return the poll record."""
    cve = sitrep.timeline.validate_id(cve).upper()
    if not sitrep.CVE_PATTERN.match(cve):
        raise ValueError(f"'{cve}' is not a CVE ID (expected CVE-YYYY-NNNN...)")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    state, state_note = load_state(cve, state_dir)
    asked = due_sources(selected, state["polls"])
    result = sitrep.build_sitrep(cve, asked, follow, fetch, db_path=db_path, today=now, progress=progress)
    failed = {c["id"] for c in result["coverage"] if c["status"] in ("error", "blocked")}
    failures = dict(state.get("failures", {}))
    for entry in result["coverage"]:
        if entry["id"].startswith("link-"):
            continue
        failures[entry["id"]] = failures.get(entry["id"], 0) + 1 if entry["id"] in failed else 0
    first = not state["baseline"]
    answered_before = set(state.get("answered", []))
    answered_now = {c["id"] for c in result["coverage"] if c["status"] in ("found", "not_found") and not c["id"].startswith("link-")}
    late = set() if first else {s for s in answered_now if s not in answered_before}
    late_labels = [sitrep_label(selected, s) for s in sorted(late)]
    changes, baseline = diff(state["baseline"], build_items(result), stamp, failed, late, late_labels)
    alert = tuple(alert)
    for change in changes:
        change["immediate"] = change["class"] in alert
    notes = [state_note] if state_note else []
    notes += [f"{label} answered for the first time (it had not answered before); its current state was added to the baseline without alerting" for label in late_labels]
    notes += [f"{sitrep_label(selected, source)} has failed {n} polls in a row; its last good values are being kept"
              for source, n in sorted(failures.items()) if n == FAILURES_BEFORE_DEGRADED]
    record = {"cve": cve, "polled_at": stamp, "poll": state["polls"] + 1, "baseline": first, "asked": [s["id"] for s in asked], "items": len(baseline),
              "changes": [] if first else changes, "notes": notes, "previous_poll": state["last_poll"], "found": result["found"]}
    save_state(cve, dict(state, polls=state["polls"] + 1, baseline=baseline, failures=failures, last_poll=stamp,
                         answered=sorted(answered_before | answered_now)), state_dir)
    if record["changes"]:
        append_history(cve, record, state_dir)
    return record


def sitrep_label(selected, source_id):
    return next((s.get("label", s["id"]) for s in selected if s["id"] == source_id), source_id)


# --------------------------------------------------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------------------------------------------------

def _wrap(prefix, text):
    import textwrap
    pad = " " * len(prefix)
    lines = textwrap.wrap(text, width=WIDTH - len(prefix), break_on_hyphens=False, break_long_words=False) or [""]
    return [prefix + lines[0]] + [pad + line for line in lines[1:]]


def render_poll(record, alert=DEFAULT_ALERT, color=False) -> str:
    """The console text for one poll: a quiet line when nothing changed, a banner when something did. color=True adds colour only."""
    plain = _render_poll_plain(record, alert)
    return "\n".join(report_color.colorize_watch(plain.split("\n"))) if color else plain


def _render_poll_plain(record, alert=DEFAULT_ALERT) -> str:
    when = record["polled_at"][:10] + " " + record["polled_at"][11:16] + " UTC"
    if record["baseline"]:
        known = f"{record['items']} item(s)" if record["found"] else "nothing found yet"
        return "\n".join([f"  WATCH {record['cve']}: baseline recorded at {when} ({known}). Alerting immediately on: {', '.join(alert)}; other changes are listed quietly."]
                         + [f"  [!] {n}" for n in record["notes"]])
    changes = record["changes"]
    if not changes:
        return "\n".join([f"  WATCH {record['cve']}: poll {record['poll']} at {when}: no change."] + [f"  [!] {n}" for n in record["notes"]])
    immediate = [c for c in changes if c["immediate"]]
    rule = "=" * WIDTH
    out = [rule, f"  WATCH  {record['cve']}   {len(changes)} change(s) since {(record['previous_poll'] or '?')[:10]} {(record['previous_poll'] or '?')[11:16]} UTC"
           f"   (polled {when}; {len(immediate)} immediate)", rule]
    for label, group in (("IMMEDIATE", immediate), ("digest", [c for c in changes if not c["immediate"]])):
        if group:
            out.append(f"  {'!! ' if label == 'IMMEDIATE' else ''}{label}")
            for change in sorted(group, key=lambda c: (CLASSES.index(c["class"]), c["text"])):
                verb = {"new": "new", "changed": "changed", "updated": "updated"}[change["kind"]]
                line = f"{change['class'].upper():<13}{verb}: {change['text']}  [{change['label'] or change['source']}]"
                if change["kind"] == "changed":
                    line += f"  (was: {_short(change['was'])})"
                if change["kind"] == "updated":
                    line += f"  (was {change['was']})"
                if change.get("when") and change["kind"] == "new":
                    line += f"  (event time {change['when'][:16].replace('T', ' ')} UTC, {change['clock']}; first seen by us {change['first_seen'][11:16]} UTC)"
                else:
                    line += f"  (first seen by us {change['first_seen'][11:16]} UTC)"
                out += _wrap("    ", line)
    out += [f"  [!] {n}" for n in record["notes"]]
    out.append(rule)
    return "\n".join(out)


def _short(text, limit=90):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


# --------------------------------------------------------------------------------------------------------------------
# The command
# --------------------------------------------------------------------------------------------------------------------

# TODO(notify): alerts only reach a terminal (a bell and a banner), which suits an analyst in the chair. When nobody is watching the
# window, send the diff somewhere: email is the likely first channel (SMTP settings and recipients in a git-ignored local file, never
# in the repo; credentials from environment variables, like sitrep's tokens; one message per poll that had immediate changes, with the
# digest changes in the same body and a subject like "[watch] CVE-2026-109618: 2 immediate"). A generic on_change command hook that
# receives the poll record as JSON on stdin would cover toast/Slack/Teams/etc. without a new integration each time. Either would be fed
# from `record` in run() right where the bell is rung, must never put fetched text on a command line, and needs a --test-notify flag
# that sends a harmless sample so the channel can be checked before it matters.

def parse_alert(expression):
    classes = tuple(c.strip() for c in (expression or ",".join(DEFAULT_ALERT)).split(",") if c.strip())
    unknown = [c for c in classes if c not in CLASSES]
    if unknown:
        raise sitrep.ConfigError(f"unknown alert class '{unknown[0]}' (known: {', '.join(CLASSES)})")
    return classes


def exit_code(records) -> int:
    changes = [c for r in records for c in r["changes"]]
    if any(c["immediate"] for c in changes):
        return EXIT_IMMEDIATE
    return EXIT_DIGEST if changes else EXIT_QUIET


def run(ids, every=10.0, once=False, alert_expression=None, sources_expression=None, as_json=False, fetch=None, db_path=None, state_dir=STATE_DIR,
        out=print, config=None, sleep=time.sleep, clock=None, max_polls=None, show_progress=False, bell=True, stderr=None, color=False) -> int:
    """CLI entry. --once: one poll per ID and an exit code (0 quiet or baseline, 10 digest changes, 11 immediate changes, 2 bad request).
    Otherwise poll every `every` minutes until interrupted, printing only what changed, with a live countdown to the next poll."""
    stderr = stderr if stderr is not None else sys.stderr
    try:
        alert = parse_alert(alert_expression)
        sources, follow = config if config is not None else sitrep.load_config()
        selected, _ = sitrep.select_sources(sources, sources_expression)
        if not once and every < MIN_EVERY_MINUTES:
            raise sitrep.ConfigError(f"--every must be at least {MIN_EVERY_MINUTES:g} minute(s): the sources are rate limited")
    except sitrep.ConfigError as exc:
        out(f"[-] {exc}")
        return 2
    fetch = fetch or sitrep.make_fetcher()
    ids = [sitrep.timeline.validate_id(i).upper() if re.match(r"^[A-Za-z0-9._:-]{3,128}$", str(i)) else str(i) for i in ids]
    progress = sitrep_progress.Progress.auto() if show_progress == "auto" else (show_progress if isinstance(show_progress, sitrep_progress.Progress) else None)
    live = sitrep_progress.ansi_ok(stderr) if not once and hasattr(stderr, "isatty") and stderr.isatty() else False
    if not once and not as_json:
        out(f"  Watching {', '.join(ids)} every {every:g} minute(s). Alerting immediately on: {', '.join(alert)}. Ctrl-C to stop.")
    records, polls = [], 0
    try:
        while True:
            round_records = []
            for raw in ids:
                try:
                    record = poll(raw, selected, follow, fetch, db_path=db_path, state_dir=state_dir, alert=alert, progress=progress, now=clock() if clock else None)
                except ValueError as exc:
                    out(f"[-] {exc}")
                    return 2
                round_records.append(record)
                if not as_json:
                    if bell and any(c["immediate"] for c in record["changes"]):
                        stderr.write("\a")
                        stderr.flush()
                    out(render_poll(record, alert, color=color))
            records = round_records
            polls += 1
            if once or (max_polls is not None and polls >= max_polls):
                break
            _countdown(every * 60, sleep, stderr, live)
    except KeyboardInterrupt:
        if live:
            stderr.write("\n")
        out("  Stopped. State is kept; run again to continue from the same baseline.")
        return 0
    if as_json:
        out(json.dumps(records, indent=2, default=str))
    return exit_code(records) if once else 0


def _countdown(seconds, sleep, stderr, live):
    """Sleep for `seconds`, showing the time to the next poll in place on a terminal."""
    remaining = int(seconds)
    while remaining > 0:
        if live:
            stderr.write(f"\r  next poll in {remaining // 60:02d}:{remaining % 60:02d}   (Ctrl-C to stop)   ")
            stderr.flush()
        step = min(1, remaining)
        sleep(step)
        remaining -= step
    if live:
        stderr.write("\r" + " " * 50 + "\r")
        stderr.flush()
