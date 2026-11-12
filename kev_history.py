"""
KEV vs EPSS over the full history: the CVSS-vs-EPSS scatter and triage comparison of Sections V and VI, drawn from every
CVE in the warehouse instead of only the advisories touched inside the report's snapshot window.

Sections V and VI describe one snapshot, which holds the advisories OSV modified between the archive's first day and the
snapshot date. A CVE CISA listed years ago, whose OSV record has not been edited since, is outside that window even
though it is exactly the kind of case the chart exists to show. This section reads the warehouse directly (like Section
III) so --from/--to do not change it:

  - the unit is the CVE, not the advisory: KEV lists CVEs, and one CVE often has an advisory per package or ecosystem,
    which would count the same listing several times. A CVE's CVSS is the highest among its advisories;
  - only the registries the report charts (osv_ecosystems.REPORT_ECOSYSTEMS) count;
  - a CVE is resolved from cve_alias, falling back to a CVE ID embedded in advisory_id for synthetic entries that carry no
    alias (the same approach Section III and --crosscheck use). As of 2026-11 the fallback adds no KEV CVE the alias route
    misses (the synthetic ROOT-APP-* entries describe CVEs that also have an aliased advisory); it is kept so the two
    sections resolve CVEs the same way if that stops being true.

What it cannot show: EPSS is today's score (the warehouse keeps one), not the score an analyst saw when the CVE was
listed, and a KEV listing is itself something that pushes a CVE's EPSS up, so the separation here flatters EPSS. Only CVEs
with a CVE ID have EPSS at all (about 8% of the warehouse). The page says both.
"""

import collections
import html
import json
import os
import random
import sqlite3
import statistics
import functools

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as mplplt

import epss_triage
from kev_lead_time import CVE_PATTERN, _png_base64, _style_axes
from osv_ecosystems import REPORT_ECOSYSTEMS, clean_ecosystem_tag

MAX_CROWD_DOTS = 4000     # ordinary (non-KEV) dots drawn; every KEV star is always drawn
CVSS_FLOOR_EPSS = 5e-5    # the log axis cannot show an EPSS of exactly 0

# points: [(cve_id, cvss, epss, KEV listing date 'YYYY-MM-DD' or None)]; stats: counts for the page's scope note
Population = collections.namedtuple("Population", "points stats")
_EMPTY = Population([], {})


@functools.lru_cache(maxsize=None)
def _charted(ecosystems_json) -> frozenset:
    """The charted registries named in one ecosystems JSON value (empty when none, or when the value is unreadable)."""
    try:
        raw = json.loads(ecosystems_json) if ecosystems_json else []
    except (TypeError, ValueError):
        return frozenset()
    names = {clean_ecosystem_tag(e.strip().lower()) for e in raw if isinstance(e, str)}
    return frozenset(names & set(REPORT_ECOSYSTEMS))


def load_population(db_path: str, ecosystems=REPORT_ECOSYSTEMS) -> Population:
    """
    Every CVE with an advisory in `ecosystems` that has both a CVSS score and EPSS data, as (cve_id, cvss, epss, KEV date or
    None), plus the counts behind it (stats): how many CVEs have an advisory in the charted registries at all, how many
    lack CVSS or EPSS, how many KEV-listed CVEs that leaves unplotted, and the EPSS model date.

    Not limited to advisories touched in any window. Returns an empty Population when the database or its tables are absent.
    """
    if not db_path or not os.path.exists(db_path):
        return _EMPTY
    wanted = set(ecosystems)
    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.Error:
        return _EMPTY
    try:
        merged = {}   # cve -> [highest cvss]
        rows = conn.execute("SELECT advisory_id, cve_alias, cvss_score, ecosystems FROM vulnerabilities "
                            "WHERE (cve_alias IS NOT NULL AND cve_alias <> '') OR advisory_id LIKE '%CVE-%'")
        for advisory_id, alias, cvss, ecosystems_json in rows:
            if not (_charted(ecosystems_json) & wanted):
                continue
            if alias:
                cve = alias
            else:
                match = CVE_PATTERN.search(advisory_id or "")
                if not match:
                    continue
                cve = match.group(0).upper()
            best = merged.get(cve)
            score = cvss if cvss and cvss > 0 else 0.0
            if best is None or score > best:
                merged[cve] = score
        epss = {cve_id: score for cve_id, score in conn.execute("SELECT cve_id, epss_score FROM epss_scores") if cve_id in merged and score is not None}
        kev = {cve_id: added[:10] for cve_id, added in conn.execute("SELECT cve_id, date_added FROM kev_catalog") if added}
        kev_catalog_total = len(kev)
        try:
            model_date = conn.execute("SELECT MAX(model_date) FROM epss_scores").fetchone()[0]
        except sqlite3.Error:
            model_date = None
    except sqlite3.Error:
        return _EMPTY
    finally:
        conn.close()

    points, no_cvss, no_epss = [], 0, 0
    for cve, cvss in merged.items():
        if cvss <= 0:
            no_cvss += 1
        elif cve not in epss:
            no_epss += 1
        else:
            points.append((cve, cvss, epss[cve], kev.get(cve)))
    points.sort()
    kev_in_charted = sum(1 for cve in merged if cve in kev)
    stats = {"charted_cves": len(merged), "no_cvss": no_cvss, "no_epss": no_epss, "plotted": len(points),
             "kev_plotted": sum(1 for p in points if p[3]), "kev_in_charted": kev_in_charted, "kev_catalog_total": kev_catalog_total,
             "model_date": (model_date or "")[:10] or None}
    return Population(points, stats)


def crowd_sample(points, limit: int = MAX_CROWD_DOTS):
    """Every KEV-listed point, plus a fixed-seed random sample of at most `limit` ordinary points (the same points every run)."""
    kev = [p for p in points if p[3]]
    other = [p for p in points if not p[3]]
    if len(other) > limit:
        other = random.Random(0).sample(other, limit)
    return kev, other


def by_listing_year(points) -> dict:
    """{year CISA listed the CVE: [epss, ...]} for the KEV-listed points, years ascending."""
    years = collections.defaultdict(list)
    for _, _, epss, added in points:
        if added:
            years[added[:4]].append(epss)
    return dict(sorted(years.items()))


def _render_scatter(points, trend, kev_n) -> str:
    kev, crowd = crowd_sample(points)
    fig, ax = mplplt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor('#1e1e1e')
    _style_axes(ax)
    ax.scatter([p[1] for p in crowd], [max(p[2], CVSS_FLOOR_EPSS) for p in crowd], alpha=0.30, s=14, color='#8aa9d6',
               label=f"CVE (n={len(crowd):,} of {len(points) - kev_n:,} drawn)")
    ax.scatter([p[1] for p in kev], [max(p[2], CVSS_FLOOR_EPSS) for p in kev], marker='*', s=140, color='#ff5555', edgecolors='#ffffff',
               linewidths=0.6, zorder=5, label=f"KEV-listed (n={len(kev)})")
    if trend:
        xs = [t["mean_cvss"] for t in trend]
        ax.fill_between(xs, [max(t["q1"], CVSS_FLOOR_EPSS) for t in trend], [max(t["q3"], CVSS_FLOOR_EPSS) for t in trend],
                        color='#ffffff', alpha=0.10, zorder=3, label="Middle half of EPSS (all CVEs)")
        ax.plot(xs, [max(t["median_epss"], CVSS_FLOOR_EPSS) for t in trend], color='#ffffff', linewidth=2.2, marker='o', markersize=5,
                zorder=4, label="Median EPSS per CVSS band (all CVEs)")
    ax.set_yscale('log')
    ax.set_ylim(CVSS_FLOOR_EPSS, 1.5)
    ax.set_title("Full history: CVSS vs EPSS, one dot per CVE (log scale, KEV-listed as stars)", color='#ffffff', fontsize=14, pad=15)
    ax.set_xlabel("CVSS Score (highest among the CVE's advisories)", color='#bbbbbb')
    ax.set_ylabel("EPSS today (probability of exploitation, log scale)", color='#bbbbbb')
    ax.legend(facecolor='#1e1e1e', edgecolor='#333333', labelcolor='#ffffff', markerscale=1.5)
    mplplt.tight_layout()
    image = _png_base64(fig)
    mplplt.close(fig)
    return image


def _render_triage(points, triage) -> str:
    fig, (ax_a, ax_b) = mplplt.subplots(1, 2, figsize=(14, 5), gridspec_kw={"width_ratios": [1, 1.25]})
    fig.patch.set_facecolor('#1e1e1e')
    for ax in (ax_a, ax_b):
        ax.set_facecolor('#1e1e1e')
    jitter = random.Random(0)
    kev, crowd = crowd_sample(points)
    ax_a.scatter([p[1] + jitter.uniform(-0.08, 0.08) for p in crowd], [jitter.random() for _ in crowd], s=10, alpha=0.12, color='#8aa9d6',
                 label="CVE (EPSS hidden)")
    ax_a.scatter([p[1] + jitter.uniform(-0.08, 0.08) for p in kev], [jitter.random() for _ in kev], marker='*', s=140, color='#ff5555',
                 edgecolors='#ffffff', linewidths=0.6, zorder=5, label="KEV-listed")
    for cut in (4, 7, 9):
        ax_a.axvline(cut, linestyle='--', linewidth=1, color='#ffffff', alpha=0.3)
    ax_a.set_xlim(0, 10.6)
    ax_a.set_yticks([])
    ax_a.set_xlabel("CVSS Score", color='#bbbbbb')
    ax_a.set_title("Without EPSS: CVSS alone", color='#ffffff', fontsize=13, pad=12)
    ax_a.tick_params(colors='#bbbbbb', labelsize=10)
    ax_a.legend(facecolor='#1e1e1e', edgecolor='#333333', labelcolor='#ffffff', loc='lower left', markerscale=1.3)

    rules = triage["rules"]
    ypos = list(range(len(rules)))[::-1]
    total, kev_total = triage["total"], triage["kev_total"]
    queue_share = [r["queue"] / total for r in rules]
    kev_share = [(r["kev_caught"] / kev_total) if kev_total else 0 for r in rules]
    ax_b.barh([y + 0.2 for y in ypos], queue_share, height=0.38, color='#8aa9d6', label="Share of all CVEs you would work")
    ax_b.barh([y - 0.2 for y in ypos], kev_share, height=0.38, color='#ff5555', label="Share of KEV-listed CVEs reached")
    for y, r, qs, ks in zip(ypos, rules, queue_share, kev_share):
        ax_b.text(qs + 0.01, y + 0.2, f"{r['queue']:,} ({qs:.0%})", va='center', color='#dddddd', fontsize=9)
        ax_b.text(ks + 0.01, y - 0.2, f"{r['kev_caught']}/{kev_total}", va='center', color='#ffb3b3', fontsize=9)
    ax_b.set_yticks(ypos)
    ax_b.set_yticklabels([r["label"] for r in rules], color='#ffffff')
    ax_b.set_xlim(0, 1.3)
    ax_b.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax_b.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
    ax_b.tick_params(colors='#bbbbbb', labelsize=10)
    ax_b.set_title("Queue size vs KEV reached, by triage rule", color='#ffffff', fontsize=13, pad=12)
    ax_b.legend(facecolor='#1e1e1e', edgecolor='#333333', labelcolor='#ffffff', loc='upper center', bbox_to_anchor=(0.5, -0.08), ncol=2)
    for ax in (ax_a, ax_b):
        for spine in ax.spines.values():
            spine.set_color('#444444')
    mplplt.tight_layout()
    image = _png_base64(fig)
    mplplt.close(fig)
    return image


def _render_by_year(years) -> str:
    fig, ax = mplplt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor('#1e1e1e')
    _style_axes(ax)
    jitter = random.Random(0)
    labels = list(years)
    for x, year in enumerate(labels):
        values = years[year]
        ax.scatter([x + jitter.uniform(-0.18, 0.18) for _ in values], [max(v, CVSS_FLOOR_EPSS) for v in values], marker='*', s=90,
                   color='#ff5555', edgecolors='#ffffff', linewidths=0.4, alpha=0.85, zorder=4)
        ax.hlines(max(statistics.median(values), CVSS_FLOOR_EPSS), x - 0.32, x + 0.32, color='#ffffff', linewidth=2.2, zorder=5)
    ax.set_yscale('log')
    lowest = min((max(v, CVSS_FLOOR_EPSS) for values in years.values() for v in values), default=CVSS_FLOOR_EPSS)
    ax.set_ylim(max(CVSS_FLOOR_EPSS, lowest / 3), 1.5)   # no empty decades below the lowest star
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels([f"{y}\n(n={len(years[y])})" for y in labels])
    ax.set_xlim(-0.6, len(labels) - 0.4)
    ax.set_ylabel("EPSS today (log scale)", color='#bbbbbb')
    ax.set_xlabel("Year CISA listed the CVE", color='#bbbbbb')
    ax.set_title("EPSS today of KEV-listed CVEs, by the year CISA listed them (white bar = median)", color='#ffffff', fontsize=14, pad=15)
    mplplt.tight_layout()
    image = _png_base64(fig)
    mplplt.close(fig)
    return image


def build_section(db_path: str) -> str:
    """Section VII of the --report page. Empty when the warehouse holds no KEV-listed CVE with both CVSS and EPSS in the
    charted registries (or is absent), so a report built without a warehouse simply has no such section."""
    population = load_population(db_path)
    points, stats = population.points, population.stats
    if not points or not stats.get("kev_plotted"):
        return ""
    kev_total = stats["kev_plotted"]
    triage = epss_triage.triage_comparison((cvss, epss, bool(added)) for _, cvss, epss, added in points)
    trend = epss_triage.cvss_epss_trend((cvss, epss, bool(added)) for _, cvss, epss, added in points)
    years = by_listing_year(points)
    by_label = {r["label"]: r for r in triage["rules"]}
    cvss7, epss10, epss1 = by_label["CVSS ≥ 7"], by_label["EPSS ≥ 10%"], by_label["EPSS ≥ 1%"]
    total = triage["total"]
    pct = lambda r: f"{r['queue'] / total:.0%}"

    kev_epss = [p[2] for p in points if p[3]]
    other_epss = [p[2] for p in points if not p[3]]
    median_note = (f"The median EPSS of KEV-listed CVEs is {statistics.median(kev_epss):.1%} against {statistics.median(other_epss):.2%} for the rest."
                   if other_epss else f"The median EPSS of KEV-listed CVEs is {statistics.median(kev_epss):.1%}; no other CVE has both CVSS and EPSS to compare with.")
    unplotted = stats["kev_in_charted"] - kev_total
    unplotted_note = (f" {unplotted} more KEV-listed CVEs have an advisory in a charted registry but no CVSS score or no EPSS, so they are not plotted."
                      if unplotted > 0 else "")
    model = f" (EPSS model date {html.escape(stats['model_date'])})" if stats.get("model_date") else ""
    year_counts = ", ".join(f"{y}: {len(v)}" for y, v in years.items())
    recent_note = ""
    if len(years) >= 2:
        *earlier_years, latest = years
        latest_low = sum(1 for v in years[latest] if v < 0.5)
        earlier = [v for y in earlier_years for v in years[y]]
        earlier_low = sum(1 for v in earlier if v < 0.5)
        recent_note = (f" The most recent year has the weakest separation: {latest_low} of the {len(years[latest])} CVEs listed in {latest} score below 50% today, against "
                       f"{earlier_low} of {len(earlier)} listed earlier. That is what you would see if EPSS takes time to catch up with a listing, but small counts "
                       f"cannot rule out chance.")

    return f"""
        <h2>VII. Full-History KEV vs EPSS</h2>
        <p><strong>Scope.</strong> Sections V and VI describe the advisories OSV modified inside the snapshot window. This section ignores the report window and
        looks at every CVE in the warehouse that has an advisory in a charted registry, with CVSS and EPSS: {total:,} CVEs, {kev_total} of them on CISA's KEV list
        (the catalog has {stats['kev_catalog_total']:,} entries; most are products outside package registries).{unplotted_note} The unit is the CVE, not the advisory:
        KEV lists CVEs, and one CVE often has an advisory per package, so counting advisories would count one listing several times. A CVE's CVSS is the highest among its
        advisories. Only CVEs with a CVE ID have EPSS at all (about 8% of the warehouse), so this is the subset where exploitation likelihood is actually known.</p>
        <p><strong>Read it with hindsight in mind.</strong> EPSS here is today's score{model}, not the score an analyst saw when the CVE was listed, and being exploited
        widely enough to reach KEV is itself something that pushes EPSS up. The separation below therefore flatters EPSS: it shows how well EPSS describes known-exploited CVEs now,
        not how well it would have flagged them in advance.</p>
        <div class="chart">
            <img src="data:image/png;base64,{_render_scatter(points, trend, kev_total)}" alt="Full-history CVSS vs EPSS scatter" />
        </div>
        <p>{median_note} The white line is the median EPSS in each
        one-point CVSS band across every CVE, with the shaded band covering the middle half; it is computed from the full population, not from the dots, which are thinned to
        {MAX_CROWD_DOTS:,} ordinary points (every KEV star is drawn, so the stars look denser against the crowd than they really are).</p>
        <div class="chart">
            <img src="data:image/png;base64,{_render_triage(points, triage)}" alt="Full-history triage queue comparison" />
        </div>
        <p>Priced across the full history: a CVSS &ge; 7 rule queues {cvss7['queue']:,} CVEs ({pct(cvss7)}) to reach {cvss7['kev_caught']} of the {kev_total}; EPSS &ge; 10% queues
        {epss10['queue']:,} ({pct(epss10)}) and reaches {epss10['kev_caught']}. {kev_total - epss1['kev_caught']} KEV-listed CVEs score below 1%.</p>
        <div class="chart">
            <img src="data:image/png;base64,{_render_by_year(years)}" alt="EPSS of KEV-listed CVEs by listing year" />
        </div>
        <p>KEV-listed CVEs by the year CISA listed them ({year_counts}). CISA launched the catalog in late 2021 with a backfill of long-published flaws, so the early years are not a
        year's worth of new listings. A year's median is noisy when it holds few CVEs.{recent_note}</p>"""
