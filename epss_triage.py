"""
The "what does EPSS buy you over CVSS alone" arithmetic, shared by the windowed report sections (V and VI) and the
full-history section (VII), so both are computed by the same rules.

Everything here works on plain (cvss, epss, is_kev) points and imports nothing from the report, so it can be used on
its own.
"""

import collections
import statistics

# A triage rule is a CVSS cut-off or an EPSS cut-off, inclusive.
TRIAGE_RULES = (("CVSS ≥ 9", "cvss", 9.0), ("CVSS ≥ 7", "cvss", 7.0), ("CVSS ≥ 4", "cvss", 4.0),
                ("EPSS ≥ 10%", "epss", 0.1), ("EPSS ≥ 1%", "epss", 0.01))

TREND_MIN_N = 30   # a CVSS band holding fewer advisories than this gets no trend point


def triage_comparison(points) -> dict:
    """
    For (cvss, epss, is_kev) points, how big a work queue each simple triage rule produces and how many
    KEV-listed advisories it reaches: the "what does EPSS buy you over CVSS alone" comparison behind the
    --report triage chart. Rules are TRIAGE_RULES (a CVSS cut-off or an EPSS cut-off, inclusive).
    """
    points = list(points)
    rules = []
    for label, kind, threshold in TRIAGE_RULES:
        index = 0 if kind == "cvss" else 1
        hits = [p for p in points if p[index] >= threshold]
        rules.append({"label": label, "kind": kind, "threshold": threshold, "queue": len(hits), "kev_caught": sum(1 for p in hits if p[2])})
    return {"total": len(points), "kev_total": sum(1 for p in points if p[2]), "rules": rules}


def cvss_epss_trend(points, min_n: int = TREND_MIN_N) -> list:
    """
    The typical EPSS at each severity, from EVERY (cvss, epss, is_kev) point (not the plotted dots): per one-point CVSS band
    (4.0-4.9, 5.0-5.9, ..., 10.0), the count, mean CVSS, median EPSS, the quartiles around it and how many are KEV-listed.
    A scatter thins its ordinary dots but draws every KEV star, so the eye over-weights the stars; this line is the
    unthinned counterfactual. Bands under `min_n` points are left out as too thin to read.
    """
    bands = collections.defaultdict(list)
    for cvss, epss, kev in points:
        bands[min(int(cvss), 10)].append((cvss, epss, kev))
    trend = []
    for band in sorted(bands):
        in_band = bands[band]
        if len(in_band) < min_n:
            continue
        q1, median, q3 = statistics.quantiles(sorted(epss for _, epss, _ in in_band), n=4, method="inclusive")
        trend.append({"band": band, "n": len(in_band), "mean_cvss": round(sum(c for c, _, _ in in_band) / len(in_band), 2),
                      "median_epss": median, "q1": q1, "q3": q3, "kev": sum(1 for _, _, kev in in_band if kev)})
    return trend
