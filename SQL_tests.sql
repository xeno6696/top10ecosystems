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

--1. Enterprise Triage Summary Rollup (Executive / CoP Metrics)
WITH advisory_prioritization AS (
    SELECT 
        v.advisory_id,
        v.package_name,
        v.ecosystems,
        v.cvss_score,
        v.blast_radius,
        e.epss_score,
        COALESCE(e.percentile, 0.0) AS epss_percentile,
        CASE
            -- P0: Supply-chain malware campaigns & zero-day backdoors
            WHEN v.advisory_id LIKE 'MAL-%' OR v.threat_profile LIKE '%Malware%'
                THEN 'P0 - Out-of-Band (Malware/Payload)'
            -- P1: High severity with active mass exploitation (EPSS >= 95th %)
            WHEN v.cvss_score >= 7.0 AND COALESCE(e.percentile, 0.0) >= 0.95
                THEN 'P1 - Weaponized Critical'
            -- P2: Lower severity but actively targeted/automated in the wild
            WHEN v.cvss_score < 7.0 AND COALESCE(e.percentile, 0.0) >= 0.95
                THEN 'P2 - Mass Opportunism'
            -- P3: High theoretical impact with low active threat telemetry
            WHEN v.cvss_score >= 7.0 AND COALESCE(e.percentile, 0.0) < 0.95
                THEN 'P3 - Latent Critical'
            -- P4: Low severity and low exploitation probability
            ELSE 'P4 - Routine Hygiene'
        END AS priority_tier,
        CASE
            WHEN v.advisory_id LIKE 'MAL-%' OR v.threat_profile LIKE '%Malware%' THEN 0
            WHEN v.cvss_score >= 7.0 AND COALESCE(e.percentile, 0.0) >= 0.95 THEN 1
            WHEN v.cvss_score < 7.0 AND COALESCE(e.percentile, 0.0) >= 0.95 THEN 2
            WHEN v.cvss_score >= 7.0 AND COALESCE(e.percentile, 0.0) < 0.95 THEN 3
            ELSE 4
        END AS tier_rank
    FROM vulnerabilities v
    LEFT JOIN epss_scores e ON v.cve_alias = e.cve_id
    WHERE v.withdrawn_date IS NULL
)
SELECT 
    priority_tier,
    COUNT(*) AS total_advisories,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM vulnerabilities WHERE withdrawn_date IS NULL), 2) AS catalog_pct,
    ROUND(AVG(cvss_score), 2) AS avg_cvss,
    ROUND(AVG(epss_percentile) * 100.0, 1) AS avg_epss_percentile_pct
FROM advisory_prioritization
GROUP BY priority_tier, tier_rank
ORDER BY tier_rank ASC;


--2. High-Priority Actionable Dispatch Queue (P0 & P1 Release Blockers)
SELECT 
    v.advisory_id,
    COALESCE(v.cve_alias, 'N/A') AS cve_id,
    v.package_name,
    v.ecosystems,
    v.cvss_score,
    COALESCE(ROUND(e.epss_score * 100.0, 2), 0.0) || '%' AS epss_prob,
    COALESCE(ROUND(e.percentile * 100.0, 1), 0.0) || 'th' AS epss_pct,
    v.blast_radius,
    v.cwe_ids,
    CASE 
        WHEN v.advisory_id LIKE 'MAL-%' OR v.threat_profile LIKE '%Malware%' THEN 'P0: IMMEDIATE BLOCK'
        ELSE 'P1: 72H SLA BLOCK'
    END AS triage_verdict
FROM vulnerabilities v
LEFT JOIN epss_scores e ON v.cve_alias = e.cve_id
WHERE v.withdrawn_date IS NULL
  AND (
      v.advisory_id LIKE 'MAL-%' 
      OR v.threat_profile LIKE '%Malware%'
      OR (v.cvss_score >= 7.0 AND e.percentile >= 0.95)
  )
ORDER BY 
    CASE WHEN v.advisory_id LIKE 'MAL-%' OR v.threat_profile LIKE '%Malware%' THEN 1 ELSE 2 END,
    e.epss_score DESC, 
    v.cvss_score DESC
LIMIT 25;
