"""
KEV lead time: how many days passed between a CVE's earliest known publish date and CISA adding it to the KEV
catalog.

compute_stats() produces the figure stored in each exported snapshot (`kev_lead_time`); build_section() draws
Section III of the --report page from those stored figures; bucket_bar_html() and BUCKET_CSS render the
latest-snapshot bucket bar.

What it cannot show: it is a supply-chain view (application-registry advisories only, a small slice of the KEV
catalog), restricted to CVEs CISA added since the snapshot archive began, and keyed on CISA's listing date,
which is not when exploitation started. Section III's description says all of this so a reader does not take
one cohort's numbers for the whole catalog.
"""

import base64
import datetime
import html
import io
import re
import sqlite3

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as mplplt

import chart_axes


def compute_stats(db_path: str, session_advisory_ids: set, window_start: str = None, window_end: str = None) -> dict:
    """
    For advisories in session_advisory_ids that are confirmed CISA KEV-catalog entries, computes
    the lead time (days) between the CVE's earliest known OSV published_date (across all of its
    constituent advisory records in scope, not just one) and kev_catalog.date_added -- "how much
    warning did we actually have before this became actively exploited." CVE resolution reuses
    the same approach as --crosscheck: cve_alias, falling back to a CVE pattern embedded in
    advisory_id for ROOT-APP-* synthetic entries that carry no cve_alias.

    Rows with a missing/sentinel published_date are excluded -- both OSV's own "1970-01-01"
    default for absent data, and the literal "0001-01-01" placeholder some Debian-sourced records
    carry upstream -- since including them would swamp the mean with multi-decade "lead times"
    that are really just missing data, not real advance warning. Negative lead times (KEV added
    before our earliest published_date, which can happen for a record OSV has since rewritten)
    are excluded for the same reason: they don't represent a real lookback distance.

    window_start / window_end (YYYY-MM-DD), when given, keep only CVEs that CISA ADDED to the KEV catalog
    inside that window. Without them every KEV-listed CVE whose advisories were merely touched in the window
    counted -- so a flaw listed in 2023 whose OSV record was edited last week produced a lead time in a 2026
    snapshot, which made the number a statement about which old records got edited, not about this period's
    KEV listings.

    Returns None if there's no KEV overlap in scope, else {"mean_days", "median_days", "sample_count",
    "buckets"}. The mean is easily dominated by a few very old CVEs (a decade-old flaw only now listed), so the
    median and the buckets (under 30 days / 30 days to 1 year / 1 to 3 years / over 3 years) are what to read.
    """
    if not session_advisory_ids:
        return None

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    junk_dates = {"1970-01-01", "0001-01-01", None, ""}

    try:
        id_list = list(session_advisory_ids)
        chunk_size = 500

        earliest_published = {}
        for i in range(0, len(id_list), chunk_size):
            chunk = id_list[i:i + chunk_size]
            placeholders = ",".join("?" * len(chunk))
            cursor.execute(
                f"SELECT advisory_id, cve_alias, published_date FROM vulnerabilities WHERE advisory_id IN ({placeholders})",
                chunk
            )
            for advisory_id, cve_alias, published_date in cursor.fetchall():
                cve_id = cve_alias
                if not cve_id:
                    match = cve_pattern.search(advisory_id or "")
                    if match:
                        cve_id = match.group(0).upper()
                if not cve_id or published_date in junk_dates:
                    continue
                p_clean = published_date[:10]
                if cve_id not in earliest_published or p_clean < earliest_published[cve_id]:
                    earliest_published[cve_id] = p_clean

        if not earliest_published:
            return None

        cve_ids = list(earliest_published.keys())
        kev_dates = {}
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]
            placeholders = ",".join("?" * len(chunk))
            cursor.execute(f"SELECT cve_id, date_added FROM kev_catalog WHERE cve_id IN ({placeholders})", chunk)
            for cve_id, date_added in cursor.fetchall():
                if not date_added:
                    continue
                if window_start and date_added[:10] < window_start:
                    continue
                if window_end and date_added[:10] > window_end:
                    continue
                kev_dates[cve_id] = date_added
    finally:
        conn.close()

    lead_days = []
    for cve_id, p_clean in earliest_published.items():
        date_added = kev_dates.get(cve_id)
        if not date_added:
            continue
        try:
            p_dt = datetime.date.fromisoformat(p_clean)
            k_dt = datetime.date.fromisoformat(date_added[:10])
        except ValueError:
            continue
        delta = (k_dt - p_dt).days
        if delta >= 0:
            lead_days.append(delta)

    if not lead_days:
        return None

    lead_days.sort()
    n = len(lead_days)
    mid = n // 2
    median = lead_days[mid] if n % 2 else (lead_days[mid - 1] + lead_days[mid]) / 2
    return {
        "mean_days": round(sum(lead_days) / n, 1),
        "median_days": round(median, 1),
        "sample_count": n,
        "buckets": {
            "under_30d": sum(1 for d in lead_days if d < 30),
            "d30_to_1y": sum(1 for d in lead_days if 30 <= d < 365),
            "y1_to_3y": sum(1 for d in lead_days if 365 <= d < 1095),
            "over_3y": sum(1 for d in lead_days if d >= 1095),
        }
    }


BUCKETS = (("under_30d", "Under 30 days", "#2e9e5b"), ("d30_to_1y", "30 days to 1 year", "#d9b13b"),
                ("y1_to_3y", "1 to 3 years", "#e08a3c"), ("over_3y", "Over 3 years", "#d64545"))

BUCKET_CSS = """
        .bucketbar { display: flex; height: 26px; border-radius: 4px; overflow: hidden; margin: 8px 0; }
        .bucketbar span { color: #111111; font-size: 12px; font-weight: 600; text-align: center; line-height: 26px; overflow: hidden; }
        .bucketlegend { font-size: 12px; color: #aaaaaa; display: flex; gap: 18px; flex-wrap: wrap; margin-bottom: 6px; }
        .bucketlegend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; }
"""


def bucket_bar_html(buckets) -> str:
    """A stacked bar and legend of how long before KEV listing each measured CVE was first published, from the latest
    snapshot's `buckets`. Empty when the snapshot has none (older exports) or nothing was measured."""
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


def build_section(snapshots: list) -> str:
    """Section III of the --report page: the lead-time trend chart, its description and the bucket bar.
    Empty when no snapshot carries `kev_lead_time` (older exports, or a window with no KEV overlap)."""
    # Chart 3: KEV Lead Time Trend -- NOT a delta chart like the other two. kev_lead_time
    # is already a point-in-time distribution stat (as of that day's data: the mean days
    # between a KEV-flagged CVE's earliest known publish and its KEV addition), so plotting
    # it raw is correct -- diffing it day-over-day would just be noise on top of noise. Only
    # snapshots actually carrying the field (requires --export, and
    # postdate this chart being added) contribute a point; older snapshots are skipped, not
    # zeroed, since 0 would misleadingly read as "instant lead time" rather than "no data."
    kev_lead_points = [
        (snap.get("metadata", {}).get("interval_to"), snap["kev_lead_time"]["mean_days"],
         snap["kev_lead_time"].get("median_days", snap["kev_lead_time"]["mean_days"]), snap["kev_lead_time"]["sample_count"])
        for snap in snapshots
        if snap.get("kev_lead_time")
    ]

    img_str_kev_lead = None
    kev_lead_caption = ""
    if kev_lead_points:
        kev_dates_x = [p[0] for p in kev_lead_points]
        kev_means_y = [p[1] for p in kev_lead_points]
        kev_medians_y = [p[2] for p in kev_lead_points]
        sample_counts = [p[3] for p in kev_lead_points]
        kev_lead_caption = f" (each point is based on {min(sample_counts)}-{max(sample_counts)} CVEs)"

        fig3, ax3 = mplplt.subplots(figsize=(12, 5))
        fig3.patch.set_facecolor('#1e1e1e')
        ax3.set_facecolor('#1e1e1e')

        # Sample size as faint bars on a second axis, behind the lines, so a point built on 3 CVEs doesn't look as
        # solid as one built on 40.
        ax3b = ax3.twinx()
        ax3b.bar(kev_dates_x, sample_counts, color='#8aa9d6', alpha=0.18, width=0.8, label="CVEs measured (right axis)")
        ax3b.set_ylim(0, max(sample_counts) * 3)
        ax3b.set_ylabel("CVEs measured (bars)", color='#8aa9d6')
        ax3b.tick_params(colors='#8aa9d6', labelsize=9)
        ax3.set_zorder(ax3b.get_zorder() + 1)
        ax3.patch.set_visible(False)

        ax3.plot(kev_dates_x, kev_means_y, linestyle='--', linewidth=1.5, color='#ff9a9a', alpha=0.7, label="Mean (pulled up by a few very old CVEs)")
        ax3.plot(kev_dates_x, kev_medians_y, marker='o', linewidth=2.5, color='#ff5555', label="Median")

        ax3.set_title("KEV Lead Time Trend (median days: publish -> KEV addition)", color='#ffffff', fontsize=14, pad=15)
        ax3.set_ylabel("Lead Time (Days)", color='#bbbbbb')
        ax3.set_xlabel("Snapshot Boundary Timeline", color='#bbbbbb')
        ax3.tick_params(colors='#bbbbbb', labelsize=10)
        ax3.grid(True, linestyle='--', alpha=0.15, color='#ffffff')
        handles, labels = ax3.get_legend_handles_labels()
        bar_handles, bar_labels = ax3b.get_legend_handles_labels()
        ax3.legend(handles + bar_handles, labels + bar_labels, facecolor='#1e1e1e', edgecolor='#333333', labelcolor='#ffffff', loc='upper left')
        chart_axes.thin_date_ticks(ax3, kev_dates_x)
        mplplt.tight_layout()

        buf3 = io.BytesIO()
        fig3.savefig(buf3, format='png', bbox_inches='tight', facecolor=fig3.get_facecolor())
        buf3.seek(0)
        img_str_kev_lead = base64.b64encode(buf3.read()).decode('utf-8')
        mplplt.close(fig3)

    # Conditional -- an older snapshot directory, or a window with zero KEV overlap, simply
    # doesn't get the section, rather than rendering an empty/misleading one.
    kev_lead_section = ""
    if img_str_kev_lead:
        latest_kev = next((snap["kev_lead_time"] for snap in reversed(snapshots) if snap.get("kev_lead_time")), None)
        bucket_html = bucket_bar_html((latest_kev or {}).get("buckets"))
        archive_start = (snapshots[0].get("metadata", {}) or {}).get("interval_from") or "the start of the archive"
        kev_lead_section = f"""
    <h2>III. KEV Lead Time Trend</h2>
    <p>For CVEs that CISA added to its KEV list during the window (and whose advisories were touched in it), the days between the CVE's earliest known publish date and its KEV addition{kev_lead_caption} -- how much runway prioritization work actually had before each one became urgent. The solid line is the <strong>median</strong>; the lighter dashed line is the mean, which a handful of very old CVEs pull up (a flaw published a decade ago and only now listed counts as a ten-year lead time). Each point is cumulative from {html.escape(str(archive_start))} to that day, and the bars show how many CVEs it is based on.</p>
    <p><strong>Scope and gaps.</strong> This is a supply-chain view: only advisories in application-registry ecosystems (npm, PyPI, Maven and the like) count. Most KEV entries are for products outside package registries (operating systems, network appliances, desktop software), so this is a small slice of CISA's catalog, not the whole of it. It also covers only CVEs CISA added to KEV since {html.escape(str(archive_start))}, so it describes recent listings and does not summarize the catalog's history: older listing cohorts, including CISA's 2021-2022 backfill of long-published flaws, show far longer lead times. A KEV date is when CISA listed the CVE, not when exploitation began, so each lead time is an upper bound on the runway defenders actually had.</p>
    <div class="chart">
        <img src="data:image/png;base64,{img_str_kev_lead}" alt="KEV Lead Time Trend Chart" />
    </div>
    {bucket_html}"""
    return kev_lead_section
