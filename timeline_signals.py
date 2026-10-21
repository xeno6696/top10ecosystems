"""Triage signals for a --timeline result: what its dated events suggest, each with the evidence behind it.

This deliberately stops short of a verdict. It states facts and what they usually mean (RAISES or LOWERS
concern, or CONTEXT where it points neither way) and never combines them into a recommendation or a score:
whether to escalate, hold or de-escalate is a decision for the analyst or incident-response team reading it.

Every rule works only from what the timeline already fetched (the OSV records, the CISA KEV entry and FIRST's
30-day EPSS series), so it can describe relationships between dated events -- "EPSS kept rising after KEV
listing" -- but never field changes such as a CVSS rescore, which OSV and KEV don't keep a history of.

Thresholds live in the constants below so a team can tune them as it sees real cases.
"""
import datetime
from urllib.parse import urlparse

EPSS_TOP_PERCENTILE = 0.99   # "top-tier likelihood" at or above this percentile
EPSS_JUMP = 0.10             # one step this large (10 points) is worth calling out
EPSS_MOVE = 0.01             # a rise/fall this big (1 point) after KEV listing is reported
EPSS_TREND = 0.05            # sustained rise/fall over the whole 30-day window (5 points)
EPSS_LOW = 0.01              # "low" EPSS: under 1%
OLD_FLAW_YEARS = 2           # KEV-listed this long after first publication reads as an old flaw back in use
FRESH_DAYS = 14              # published this recently counts as new
RECENT_UPDATE_DAYS = 7       # any record updated this recently is flagged (what changed is unknown)
MANY_TRACKERS = 5            # carried by at least this many trackers counts as widely packaged
MAX_JUMPS = 2                # at most this many EPSS jumps are listed (the largest)

# Printed under the TRIAGE SIGNALS heading and carried in the JSON, so nobody reads the signals as more than they are.
CAVEAT = ("Caution: the thresholds behind these signals are starting guesses that have not been checked against real "
          "incident outcomes. Treat them as guidelines for discussion, not calibrated findings.")

RAISES, LOWERS, CONTEXT = "raises", "lowers", "context"
_ORDER = {RAISES: 0, LOWERS: 1, CONTEXT: 2}


def _date(value):
    try:
        return datetime.date.fromisoformat((value or "")[:10])
    except ValueError:
        return None


def _delta(earlier: float, later: float) -> float:
    """later - earlier rounded to EPSS's own 5 decimals, so a true 10-point move isn't read as 9.999... by float error."""
    return round(later - earlier, 5)


def _pct(value) -> str:
    return f"{value * 100:.1f}%"


def _pts(value) -> str:
    return f"{value * 100:+.1f} pts"


def _days(n: int) -> str:
    return f"{n:,} day" + ("" if n == 1 else "s")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _names(items, limit=3) -> str:
    items = list(items)
    return ", ".join(items[:limit]) + (f", +{len(items) - limit} more" if len(items) > limit else "")


def _domains(urls, limit=3) -> str:
    seen = []
    for url in urls:
        host = urlparse(url).netloc.lower().removeprefix("www.")
        if host and host not in seen:
            seen.append(host)
    return _names(seen, limit)


def build_signals(result: dict, today: datetime.date) -> list:
    """Signals for one build_timeline() result: [{'direction', 'id', 'text', 'meaning'}], ordered RAISES, LOWERS,
    CONTEXT and, within each, in rule order. Empty if nothing triggered."""
    out = []

    def add(direction, signal_id, text, meaning):
        out.append({"direction": direction, "id": signal_id, "text": text, "meaning": meaning})

    kev, epss = result.get("kev"), result.get("epss")
    series = result.get("epss_series") or []
    glance = result.get("glance") or {}
    first_pub = _date(glance.get("first_publication"))
    kev_added = _date(kev["added"]) if kev else None
    evidence = (result.get("references") or {}).get("counts", {}).get("EVIDENCE", 0)

    # ---- exploitation confirmed ------------------------------------------------------------------------------
    if kev:
        since = f", {_days((today - kev_added).days)} ago" if kev_added and today >= kev_added else ""
        age_years = (kev_added - first_pub).days / 365.25 if kev_added and first_pub else None
        if age_years is not None and age_years >= OLD_FLAW_YEARS:
            add(RAISES, "kev_listed", f"On the CISA KEV list: exploited in the wild (added {kev['added']}{since}), {age_years:.1f} years after first publication",
                "An old flaw back in active use usually means new scanning or a campaign.")
        else:
            add(RAISES, "kev_listed", f"On the CISA KEV list: exploited in the wild (added {kev['added']}{since})",
                "CISA has confirmed exploitation in the wild.")
        if str(kev.get("ransomware") or "").lower() == "known":
            add(RAISES, "ransomware", "CISA records known ransomware campaigns using this flaw",
                "Exposure can mean a ransomware incident, not just a vulnerability finding.")

    # ---- exploitation likelihood (EPSS) ----------------------------------------------------------------------
    if epss and epss["percentile"] >= EPSS_TOP_PERCENTILE:
        add(RAISES, "epss_top", f"Top-tier exploitation likelihood: EPSS {_pct(epss['score'])}, {epss['percentile'] * 100:.1f}th percentile of all CVEs",
            "FIRST's model ranks it among the CVEs most likely to be exploited in the next 30 days.")

    jumps = sorted(((_delta(a["score"], b["score"]), b["date"]) for a, b in zip(series, series[1:]) if _delta(a["score"], b["score"]) >= EPSS_JUMP), reverse=True)[:MAX_JUMPS]
    for delta, day in sorted(jumps, key=lambda j: j[1]):
        jump_day = _date(day)
        if kev_added and jump_day and jump_day < kev_added:
            add(RAISES, "epss_jump", f"EPSS jumped {_pts(delta)} on {day}, {_days((kev_added - jump_day).days)} before KEV listed it",
                "In hindsight this was an early warning of the KEV listing.")
        elif kev_added and jump_day:
            add(RAISES, "epss_jump", f"EPSS jumped {_pts(delta)} on {day}, {_days((jump_day - kev_added).days)} after KEV listing",
                "Predicted exploitation accelerated after confirmation.")
        else:
            add(RAISES, "epss_jump", f"EPSS jumped {_pts(delta)} on {day}; not on the KEV list",
                "Predicted exploitation accelerated, but CISA has not confirmed exploitation (yet).")

    if kev and series:
        at_kev = next((p for p in reversed(series) if _date(p["date"]) and kev_added and _date(p["date"]) <= kev_added), None)
        if at_kev is None:
            add(CONTEXT, "kev_before_window", f"KEV listing ({kev['added']}) predates FIRST's 30-day EPSS history",
                "EPSS before and after the listing can't be compared.")
        else:
            delta = _delta(at_kev["score"], series[-1]["score"])
            if delta >= EPSS_MOVE:
                add(RAISES, "epss_after_kev", f"EPSS kept rising after KEV listing: {_pct(at_kev['score'])} -> {_pct(series[-1]['score'])} ({_pts(delta)})",
                    "Predicted exploitation grew after confirmation (consistent with more attacker activity).")
            elif delta <= -EPSS_MOVE:
                add(LOWERS, "epss_fell_after_kev", f"EPSS fell after KEV listing: {_pct(at_kev['score'])} -> {_pct(series[-1]['score'])} ({_pts(delta)})",
                    "The model sees less exploitation activity than at the time of listing.")
    elif series and not kev:
        change = _delta(series[0]["score"], series[-1]["score"])
        if change >= EPSS_TREND:
            add(RAISES, "epss_rising", f"EPSS rising over {len(series)} days: {_pct(series[0]['score'])} -> {_pct(series[-1]['score'])} ({_pts(change)}); not on the KEV list",
                "Predicted exploitation is growing, but CISA has not confirmed exploitation.")
        elif change <= -EPSS_TREND:
            add(LOWERS, "epss_falling", f"EPSS falling over {len(series)} days: {_pct(series[0]['score'])} -> {_pct(series[-1]['score'])} ({_pts(change)})",
                "The model sees less exploitation activity than a month ago.")

    # ---- public exploit material -----------------------------------------------------------------------------
    if evidence:
        sites = _domains((result.get("references") or {}).get("evidence", []))
        add(RAISES, "public_exploit", f"Public exploit/evidence links: {evidence}" + (f" ({sites})" if sites else ""),
            "Working exploit code or write-ups lower the skill needed to attack it.")

    # ---- remediation ----------------------------------------------------------------------------------------
    unfixed = result.get("unfixed_packages") or []
    if unfixed:
        add(RAISES, "no_fix", f"No fixed version recorded for {_plural(len(unfixed), 'package')}: " + _names(f"{p['ecosystem']} {p['package']}" for p in unfixed),
            "Remediation may mean a mitigation or replacement, not an upgrade.")

    fixed = result.get("fixed_versions") or []
    if fixed:
        ecosystems = sorted({f["ecosystem"] for f in fixed})
        add(LOWERS, "fix_available", f"A fixed version exists in {_plural(len(ecosystems), 'ecosystem')}: {_names(ecosystems)}",
            "Remediation is an upgrade; remaining exposure is wherever it hasn't been applied.")

    withdrawn = glance.get("withdrawn") or []
    if withdrawn:
        rest = len(result.get("records") or []) - len(withdrawn)
        add(LOWERS, "withdrawn", f"Withdrawn by its tracker: {_names(withdrawn)}" + (f" ({_plural(rest, 'other fetched record')} still active)" if rest > 0 else ""),
            "A retracted record is often a duplicate or invalid; confirm before spending effort.")

    if epss and not kev and not evidence and epss["score"] < EPSS_LOW and (not series or abs(_delta(series[0]["score"], series[-1]["score"])) < EPSS_TREND):
        add(LOWERS, "no_exploit_signals", f"No exploitation indicators found: EPSS {_pct(epss['score'])}, not on the KEV list, no exploit evidence links",
            "None of the exploitation signals this tool checks are present (this can change).")

    # ---- context ----------------------------------------------------------------------------------------------
    if result.get("cvss_disagree"):
        scores = result.get("cvss_scores") or {}
        hi, lo = max(scores, key=scores.get), min(scores, key=scores.get)
        add(CONTEXT, "severity_disagreement", f"Trackers disagree on severity: highest {scores[hi]} ({hi}), lowest {scores[lo]} ({lo})",
            "Different trackers rate it differently; read the highest-rated record before assuming the lower score.")

    if kev and kev.get("due"):
        due = _date(kev["due"])
        if due:
            when = f"passed {_days((today - due).days)} ago" if today > due else ("is today" if today == due else f"is in {_days((due - today).days)}")
            add(CONTEXT, "kev_deadline", f"Federal remediation deadline {kev['due']} {when}",
                "The deadline binds US federal agencies; for anyone else it is an outside benchmark, not a requirement.")

    trackers = result.get("trackers") or []
    if len(trackers) >= MANY_TRACKERS:
        add(CONTEXT, "widely_packaged", f"Carried by {len(trackers)} trackers: {_names((t['tracker'] for t in trackers), 6)}",
            "Widely packaged; check which of your base images and packages inherit it.")

    if first_pub and 0 <= (today - first_pub).days <= FRESH_DAYS:
        add(CONTEXT, "fresh", f"Published {_days((today - first_pub).days)} ago",
            "Little history to judge from; EPSS and KEV tend to lag new disclosures.")

    recent = sorted(((r["modified"], r["id"]) for r in result.get("records") or []
                     if _date(r["modified"]) and 0 <= (today - _date(r["modified"])).days <= RECENT_UPDATE_DAYS), reverse=True)
    if recent:
        add(CONTEXT, "recently_updated", f"Updated in the last {RECENT_UPDATE_DAYS} days: {_names(rid for _, rid in recent)} (latest {recent[0][0][:10]})",
            "Something changed recently, but this tool can't tell what; check the upstream record's history.")

    if series and series[0]["score"] >= 0.5 and (result.get("epss") or {}).get("window_start_date"):
        add(CONTEXT, "epss_window", f"EPSS was already {_pct(series[0]['score'])} when FIRST's 30-day history begins ({series[0]['date']})",
            "Earlier movement isn't visible, so a sharp rise before that date wouldn't show here.")

    out.sort(key=lambda s: _ORDER[s["direction"]])
    return out
