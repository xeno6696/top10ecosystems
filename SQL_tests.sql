SELECT 
    v.cve_alias,
    v.package_name,
    v.ecosystems,
    MAX(v.cvss_score)              AS cvss_score,
    e.epss_score,
    ROUND(e.percentile * 100.0, 2) AS epss_percentile_pct,
    e.model_date,
    GROUP_CONCAT(v.advisory_id, ', ') AS matched_advisories
FROM vulnerabilities v
INNER JOIN epss_scores e ON v.cve_alias = e.cve_id
WHERE v.ecosystems LIKE '%PyPI%'
  AND v.withdrawn_date IS NULL
GROUP BY v.cve_alias, v.package_name
ORDER BY e.epss_score DESC
LIMIT 15;