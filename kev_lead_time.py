"""
KEV lead time: how many days passed between a CVE's earliest known publish date and CISA adding it to the KEV
catalog.

Everything is read straight from the warehouse at report time (load_lead_times), not from the daily snapshot
archive, so a change to the definition never needs the archive regenerated. build_section() draws Section III of
the --report page as two views of the same measurement:

  - our recording period: one point per snapshot, cumulative from the archive's first day, because short-term
    lead time is what matters for response;
  - the lifetime view: one point per quarter of KEV listing from 2023, with CISA's 2021-2022 launch backfill
    held apart, to show whether the recording period looks like the years before it.

What it cannot show: it is a supply-chain view (application-registry advisories only, a small slice of the KEV
catalog) and keyed on CISA's listing date, which is not when exploitation started. Quarters hold only a handful
of CVEs, so one quarter's median is noisy; the page says so.
"""

import base64
import collections
import datetime
import functools
import html
import io
import json
import os
import re
import sqlite3
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as mplplt

import chart_axes
from osv_ecosystems import clean_ecosystem_tag, get_artifact_layer

APP_LAYER = "App Software Registry"
JUNK_DATES = {"1970-01-01", "0001-01-01", None, ""}   # OSV's "no date" default, and a Debian-sourced placeholder
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# CISA launched the catalog in November 2021 with a backfill of long-published flaws, so listings before this date
# describe the backfill, not CISA's later day-to-day listing practice.
BACKFILL_END = "2023-01-01"
MIN_POINT_N = 5           # a quarter with fewer CVEs than this is drawn as a hollow marker

LeadTimes = collections.namedtuple("LeadTimes", "rows kev_total")   # rows: sorted [(KEV added YYYY-MM-DD, lead days)]


@functools.lru_cache(maxsize=None)
def _is_app_layer(ecosystems_json) -> bool:
    try:
        ecosystems = json.loads(ecosystems_json) if ecosystems_json else []
    except (TypeError, ValueError):
        return False
    return any(get_artifact_layer(clean_ecosystem_tag(e)) == APP_LAYER for e in ecosystems if isinstance(e, str))


def load_lead_times(db_path: str) -> LeadTimes:
    """
    For every KEV-catalog CVE that has at least one application-registry advisory in the warehouse, the days between
    the CVE's earliest known published date (across its application-registry advisories) and kev_catalog.date_added.
    CVE resolution is cve_alias, falling back to a CVE ID embedded in advisory_id for synthetic entries that carry no
    alias (the same approach --crosscheck uses).

    Not limited to advisories touched in any window: a flaw CISA lists years after publishing it counts in the period it
    was LISTED even if its OSV record has not been edited since. Missing/sentinel published dates and negative lead
    times (KEV before the earliest published date, which happens for records OSV has since rewritten) are excluded;
    they are missing data, not lookback distance.

    Returns LeadTimes(rows=[], kev_total=0) when the database or its tables are absent.
    """
    if not db_path or not os.path.exists(db_path):
        return LeadTimes([], 0)
    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.Error:
        return LeadTimes([], 0)
    try:
        kev = {cve_id: date_added[:10] for cve_id, date_added in conn.execute("SELECT cve_id, date_added FROM kev_catalog") if date_added}
        earliest = {}

        def consider(cve_id, published, ecosystems_json):
            if cve_id not in kev or published in JUNK_DATES or not _is_app_layer(ecosystems_json):
                return
            published = published[:10]
            if cve_id not in earliest or published < earliest[cve_id]:
                earliest[cve_id] = published

        for cve_id, published, ecosystems_json in conn.execute(
                "SELECT cve_alias, published_date, ecosystems FROM vulnerabilities WHERE cve_alias IN (SELECT cve_id FROM kev_catalog)"):
            consider(cve_id, published, ecosystems_json)
        for advisory_id, published, ecosystems_json in conn.execute(
                "SELECT advisory_id, published_date, ecosystems FROM vulnerabilities "
                "WHERE (cve_alias IS NULL OR cve_alias = '') AND advisory_id LIKE '%CVE-%'"):
            match = CVE_PATTERN.search(advisory_id or "")
            if match:
                consider(match.group(0).upper(), published, ecosystems_json)
    except sqlite3.Error:
        return LeadTimes([], 0)
    finally:
        conn.close()

    rows = []
    for cve_id, published in earliest.items():
        try:
            lead = (datetime.date.fromisoformat(kev[cve_id]) - datetime.date.fromisoformat(published)).days
        except ValueError:
            continue
        if lead >= 0:
            rows.append((kev[cve_id], lead))
    return LeadTimes(sorted(rows), len(kev))


def summarize(lead_days) -> dict:
    """Mean, median, sample count and buckets (under 30 days / 30 days to 1 year / 1 to 3 years / over 3 years) of a
    list of lead times in days. None when the list is empty."""
    lead_days = sorted(lead_days)
    if not lead_days:
        return None
    n = len(lead_days)
    return {
        "mean_days": round(sum(lead_days) / n, 1),
        "median_days": round(statistics.median(lead_days), 1),
        "sample_count": n,
        "buckets": {
            "under_30d": sum(1 for d in lead_days if d < 30),
            "d30_to_1y": sum(1 for d in lead_days if 30 <= d < 365),
            "y1_to_3y": sum(1 for d in lead_days if 365 <= d < 1095),
            "over_3y": sum(1 for d in lead_days if d >= 1095),
        },
    }


def within_year_share(lead_days) -> float:
    lead_days = list(lead_days)
    return sum(1 for d in lead_days if d < 365) / len(lead_days)


def cumulative_points(rows, start: str, snapshot_dates) -> list:
    """[(date, summary)] for each snapshot date: every CVE CISA added from `start` through that date, cumulative,
    skipping dates with nothing measured (not zeroed: 0 would read as an instant lead time)."""
    points = []
    for day in snapshot_dates:
        summary = summarize([lead for added, lead in rows if start <= added <= day])
        if summary:
            points.append((day, summary))
    return points


def _quarter_start(day: datetime.date) -> datetime.date:
    return datetime.date(day.year, 3 * ((day.month - 1) // 3) + 1, 1)


def _next_quarter(day: datetime.date) -> datetime.date:
    return datetime.date(day.year + (day.month + 2) // 12, (day.month + 2) % 12 + 1, 1)


def quarter_bins(rows, archive_start, end: str) -> list:
    """
    The lifetime view's bins over KEV listing date, each {"label", "lead_days", "backfill", "recorded"}: one bin for
    everything listed before BACKFILL_END, then calendar quarters through `end`. The quarter containing the day we
    began recording (`archive_start`, or None) is split in two at that day, so the recording period starts on a bin
    boundary instead of mid-quarter, and the quarter containing `end` is labelled as partial.
    """
    end_day = datetime.date.fromisoformat(end)
    start_day = datetime.date.fromisoformat(archive_start) if archive_start else None
    bins = [{"label": "2021-22 backfill", "lead_days": [lead for added, lead in rows if added < BACKFILL_END],
             "backfill": True, "recorded": False}]
    cursor = datetime.date.fromisoformat(BACKFILL_END)
    while cursor <= end_day:
        quarter_end = _next_quarter(cursor)
        name = f"{cursor.year}-Q{(cursor.month - 1) // 3 + 1}"
        edges = [cursor]
        if start_day and cursor < start_day < quarter_end:
            edges.append(start_day)
        edges.append(quarter_end)
        for lo, hi in zip(edges, edges[1:]):
            if lo > end_day:
                continue
            last_day = hi - datetime.timedelta(days=1)
            notes = []
            if len(edges) == 3 and lo == start_day:
                notes.append(f"from {lo:%m-%d}")
            if last_day > end_day:
                notes.append(f"to {end_day:%m-%d}")
            elif len(edges) == 3 and lo != start_day:
                notes.append(f"to {last_day:%m-%d}")
            label = f"{name} ({' '.join(notes)})" if notes else name
            bins.append({"label": label,
                         "lead_days": [lead for added, lead in rows if lo.isoformat() <= added < hi.isoformat()],
                         "backfill": False, "recorded": bool(start_day and lo >= start_day)})
        cursor = quarter_end
    return bins


BUCKETS = (("under_30d", "Under 30 days", "#2e9e5b"), ("d30_to_1y", "30 days to 1 year", "#d9b13b"),
           ("y1_to_3y", "1 to 3 years", "#e08a3c"), ("over_3y", "Over 3 years", "#d64545"))

BUCKET_CSS = """
        .bucketbar { display: flex; height: 26px; border-radius: 4px; overflow: hidden; margin: 8px 0; }
        .bucketbar span { color: #111111; font-size: 12px; font-weight: 600; text-align: center; line-height: 26px; overflow: hidden; }
        .bucketlegend { font-size: 12px; color: #aaaaaa; display: flex; gap: 18px; flex-wrap: wrap; margin-bottom: 6px; }
        .bucketlegend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; }
"""


def bucket_bar_html(buckets) -> str:
    """A stacked bar and legend of how long before KEV listing each measured CVE was first published, from a
    summary's `buckets`. Empty when there are none or nothing was measured."""
    if not buckets:
        return ""
    total = sum(buckets.get(key, 0) for key, _, _ in BUCKETS)
    if not total:
        return ""
    segments, legend = [], []
    for key, label, color in BUCKETS:
        n = buckets.get(key, 0)
        share = n / total * 100
        if n:
            text = f"{share:.0f}%" if share >= 8 else ""
            segments.append(f'<span style="width:{share:.1f}%;background:{color}" title="{html.escape(label)}: {n}">{text}</span>')
        legend.append(f'<span><i style="background:{color}"></i>{html.escape(label)}: {n} ({share:.0f}%)</span>')
    return (f'<p class="lm-key-title">Latest point ({total} CVEs): how long before KEV listing each was first published</p>'
            f'<div class="bucketbar">{"".join(segments)}</div><div class="bucketlegend">{"".join(legend)}</div>')


def _style_axes(ax):
    ax.set_facecolor('#1e1e1e')
    ax.tick_params(colors='#bbbbbb', labelsize=10)
    ax.grid(True, linestyle='--', alpha=0.15, color='#ffffff')


def _png_base64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight', facecolor=fig.get_facecolor())
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def _render_period_chart(points) -> str:
    """Our recording period: median (solid), mean (lighter, dashed) and a bar for how many CVEs each point holds."""
    dates = [p[0] for p in points]
    means = [p[1]["mean_days"] for p in points]
    medians = [p[1]["median_days"] for p in points]
    counts = [p[1]["sample_count"] for p in points]

    fig, ax = mplplt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor('#1e1e1e')
    _style_axes(ax)

    # Sample size as faint bars on a second axis, behind the lines, so a point built on 3 CVEs doesn't look as
    # solid as one built on 40.
    ax_bars = ax.twinx()
    ax_bars.bar(dates, counts, color='#8aa9d6', alpha=0.18, width=0.8, label="CVEs measured (right axis)")
    ax_bars.set_ylim(0, max(counts) * 3)
    ax_bars.set_ylabel("CVEs measured (bars)", color='#8aa9d6')
    ax_bars.tick_params(colors='#8aa9d6', labelsize=9)
    ax.set_zorder(ax_bars.get_zorder() + 1)
    ax.patch.set_visible(False)

    ax.plot(dates, means, linestyle='--', linewidth=1.5, color='#ff9a9a', alpha=0.7, label="Mean (pulled up by a few very old CVEs)")
    ax.plot(dates, medians, marker='o', linewidth=2.5, color='#ff5555', label="Median")
    ax.set_ylim(bottom=0)
    ax.set_title("Our recording period: KEV lead time (median days, publish -> KEV addition)", color='#ffffff', fontsize=14, pad=15)
    ax.set_ylabel("Lead Time (Days)", color='#bbbbbb')
    ax.set_xlabel("Snapshot Boundary Timeline", color='#bbbbbb')
    handles, labels = ax.get_legend_handles_labels()
    bar_handles, bar_labels = ax_bars.get_legend_handles_labels()
    ax.legend(handles + bar_handles, labels + bar_labels, facecolor='#1e1e1e', edgecolor='#333333', labelcolor='#ffffff', loc='upper left')
    chart_axes.thin_date_ticks(ax, dates)
    mplplt.tight_layout()
    image = _png_base64(fig)
    mplplt.close(fig)
    return image


def _render_lifetime_chart(bins, baseline_median) -> str:
    """The lifetime view: per-bin median with its interquartile range, n as bars, the backfill held apart, the
    recording period shaded, and the pre-recording median as a reference line."""
    fig, ax = mplplt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor('#1e1e1e')
    _style_axes(ax)
    ax.set_yscale('symlog', linthresh=10)

    xs = list(range(len(bins)))
    counts = [len(b["lead_days"]) for b in bins]
    ax_bars = ax.twinx()
    ax_bars.bar(xs, counts, color='#8aa9d6', alpha=0.18, width=0.8, label="CVEs measured (right axis)")
    ax_bars.set_ylim(0, max(max(counts), 1) * 3)
    ax_bars.set_ylabel("CVEs measured (bars)", color='#8aa9d6')
    ax_bars.tick_params(colors='#8aa9d6', labelsize=9)
    ax.set_zorder(ax_bars.get_zorder() + 1)
    ax.patch.set_visible(False)

    recorded = [x for x, b in zip(xs, bins) if b["recorded"]]
    if recorded:
        ax.axvspan(recorded[0] - 0.5, recorded[-1] + 0.5, color='#ffffff', alpha=0.06, label="Our recording period")
    if bins and bins[0]["backfill"]:
        ax.axvline(0.5, color='#ffffff', linestyle=':', alpha=0.4)
    if baseline_median is not None:
        ax.axhline(baseline_median, color='#8aa9d6', linestyle='--', linewidth=1, alpha=0.8,
                   label=f"Median, 2023 to before recording ({baseline_median:.0f} days)")

    measured = [(x, b["lead_days"]) for x, b in zip(xs, bins) if b["lead_days"]]
    for x, days in measured:
        if len(days) >= 2:
            q1, _, q3 = statistics.quantiles(days, n=4, method="inclusive")
            ax.vlines(x, q1, q3, color='#ff9a9a', linewidth=2, alpha=0.5)
    solid = [(x, statistics.median(d)) for x, d in measured if len(d) >= MIN_POINT_N]
    hollow = [(x, statistics.median(d)) for x, d in measured if len(d) < MIN_POINT_N]
    if solid:
        ax.scatter([x for x, _ in solid], [m for _, m in solid], color='#ff5555', s=60, zorder=5, label=f"Median ({MIN_POINT_N}+ CVEs)")
    if hollow:
        ax.scatter([x for x, _ in hollow], [m for _, m in hollow], facecolors='none', edgecolors='#ff5555', s=60, zorder=5,
                   linewidths=1.5, label=f"Median (fewer than {MIN_POINT_N} CVEs: noisy)")
    ax.set_xticks(xs)
    ax.set_xticklabels([b["label"] for b in bins], rotation=30, ha="right")
    ax.set_xlim(-0.6, len(bins) - 0.4)
    ax.set_ylabel("Lead Time (Days, log-like scale)", color='#bbbbbb')
    ax.set_title("Lifetime view: KEV lead time by quarter CISA listed the CVE (median and interquartile range)", color='#ffffff', fontsize=14, pad=15)
    handles, labels = ax.get_legend_handles_labels()
    bar_handles, bar_labels = ax_bars.get_legend_handles_labels()
    ax.legend(handles + bar_handles, labels + bar_labels, facecolor='#1e1e1e', edgecolor='#333333', labelcolor='#ffffff', loc='upper center',
              bbox_to_anchor=(0.5, -0.42), ncol=3, fontsize=9)
    mplplt.tight_layout()
    image = _png_base64(fig)
    mplplt.close(fig)
    return image


def build_section(snapshots: list, db_path: str) -> str:
    """Section III of the --report page. Empty when the warehouse holds no measurable KEV lead times (or is absent),
    so a report built without a warehouse simply has no such section."""
    data = load_lead_times(db_path)
    if not data.rows or not snapshots:
        return ""
    metadata = snapshots[0].get("metadata", {}) or {}
    archive_start = metadata.get("interval_from")
    dates = [(s.get("metadata", {}) or {}).get("interval_to") for s in snapshots]
    dates = [d for d in dates if d]
    if not dates:
        return ""
    end = max(dates)
    start_text = html.escape(str(archive_start or "the start of the archive"))

    period_html = ""
    points = cumulative_points(data.rows, archive_start, dates) if archive_start else []
    if points:
        counts = [p[1]["sample_count"] for p in points]
        period_html = f"""
        <h3>Our recording period</h3>
        <p>For CVEs that CISA added to KEV from {start_text} through each snapshot's date (each point is cumulative, based on {min(counts)}-{max(counts)} CVEs), the days between the CVE's earliest known publish date and its KEV addition: how much runway prioritization work actually had before each one became urgent. The solid line is the <strong>median</strong>; the lighter dashed line is the mean, which a handful of very old CVEs pull up (a flaw published a decade ago and only now listed counts as a ten-year lead time). The bars show how many CVEs each point is based on.</p>
        <div class="chart">
            <img src="data:image/png;base64,{_render_period_chart(points)}" alt="KEV Lead Time, recording period" />
        </div>
        {bucket_bar_html(points[-1][1]["buckets"])}"""

    bins = quarter_bins(data.rows, archive_start, end)
    baseline = [lead for added, lead in data.rows if BACKFILL_END <= added < (archive_start or end)]
    recorded = [lead for added, lead in data.rows if archive_start and archive_start <= added <= end]
    backfill = [lead for added, lead in data.rows if added < BACKFILL_END]
    baseline_median = statistics.median(baseline) if baseline else None
    sizes = [len(b["lead_days"]) for b in bins if not b["backfill"] and b["lead_days"]]

    comparison = ""
    if baseline and recorded:
        comparison = (f" From {BACKFILL_END} to the day before recording began, the median was {statistics.median(baseline):.0f} days across "
                      f"{len(baseline)} CVEs, with {within_year_share(baseline):.0%} listed within a year of publication; since {start_text} it is "
                      f"{statistics.median(recorded):.0f} days across {len(recorded)} CVEs, with {within_year_share(recorded):.0%} listed within a year.")
    backfill_note = ""
    if backfill:
        backfill_note = (f" CISA launched the catalog in late 2021 with a backfill of long-published flaws ({len(backfill)} measurable CVEs, median "
                         f"{statistics.median(backfill):.0f} days), so they sit apart on the left and are left out of the reference line.")
    noise_note = (f" Quarters hold only {min(sizes)}-{max(sizes)} CVEs each, so one quarter's median is noisy (hollow markers have fewer than {MIN_POINT_N}); "
                  f"read a difference as real only when it is large next to the spread within a quarter, and do not read a single quarter as a trend." if sizes else "")
    lifetime_html = f"""
        <h3>Lifetime view</h3>
        <p>The same measurement for every CVE CISA has listed, grouped by the quarter it was listed, to show whether our recording period looks like the years before it. The shaded band is the recording period, the red vertical lines are each quarter's interquartile range, and the faint blue bars are the number of CVEs.{comparison}{backfill_note}{noise_note}</p>
        <div class="chart">
            <img src="data:image/png;base64,{_render_lifetime_chart(bins, baseline_median)}" alt="KEV Lead Time, lifetime view" />
        </div>"""

    return f"""
        <h2>III. KEV Lead Time Trend</h2>
        <p><strong>Scope and gaps.</strong> This is a supply-chain view: only CVEs with an advisory in an application-registry ecosystem (npm, PyPI, Maven and the like) count, which is {len(data.rows):,} of the {data.kev_total:,} entries in CISA's catalog. Most KEV entries are for products outside package registries (operating systems, network appliances, desktop software), so this is a small slice of the catalog. A CVE counts in the period CISA listed it, whether or not its OSV record was edited since. A KEV date is when CISA listed the CVE, not when exploitation began, so each lead time is an upper bound on the runway defenders actually had.</p>{period_html}{lifetime_html}"""
