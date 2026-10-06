#!/usr/bin/env python3
# Copyright (C) 2026 xeno6696
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import unittest
from unittest.mock import patch
import sys
import io
import os
import datetime
import inspect
import sqlite3

# Import your command line application module
import top10ecosystems
import db_warehouse
import json

# -----------------------------------------------------------------------------
# 1. INTERCEPT CUSTOM CLI FLAGS BEFORE PASSING CONTROL TO UNITTEST
# -----------------------------------------------------------------------------
UPDATE_GOLDEN_MASTERS = False
if "--update" in sys.argv:
    UPDATE_GOLDEN_MASTERS = True
    sys.argv.remove("--update")  # Stripped so unittest engine doesn't choke

SKIP_EPSS = False
if "--skip-epss" in sys.argv:
    SKIP_EPSS = True
    sys.argv.remove("--skip-epss")  # Stripped so unittest engine doesn't choke

SKIP_KEV = False
if "--skip-kev" in sys.argv:
    SKIP_KEV = True
    sys.argv.remove("--skip-kev")  # Stripped so unittest engine doesn't choke

# -----------------------------------------------------------------------------
# 2. TEST CASE SUITE INTEGRATION RUNNER
# -----------------------------------------------------------------------------
class TestThreatStreamScanner(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Executes once before the suite starts. Clean binary operational fork."""
        print("[*] Initializing Global Testing Harness...")
        print("[*] Executing test engine against the SQLite warehouse index.")
        cls.ghsa_lookup = top10ecosystems.build_ghsa_from_db()
        
        if not cls.ghsa_lookup:
            raise ValueError("[!] CRITICAL: Global advisory index mapping initialized completely empty.")
            
        #   CACHE THE 750K ROW STREAM: Avoid reading a massive CSV from disk repeatedly
        cls.frozen_csv_path = os.path.join("src", "test", "resources", "frozen_modified_id.csv")
        cls.cached_stream_lines = []
        if os.path.exists(cls.frozen_csv_path):
            print("[*] Pre-loading frozen stream index rows into memory block...")
            with open(cls.frozen_csv_path, 'rb') as f:
                cls.cached_stream_lines = f.readlines()

        print(f"[+] Harness Setup Complete. Indexed {len(cls.ghsa_lookup):,} global advisories.\n")

    def verify_production_target_signature(self, func_name: str, expected_args_count: int):
        """Reflective helper to verify function survival and signature bounds."""
        self.assertTrue(
            hasattr(top10ecosystems, func_name), 
            f"❌ HALLUCINATION REGRESSION: Function '{func_name}' has vanished from top10ecosystems.py!"
        )
        func = getattr(top10ecosystems, func_name)
        self.assertTrue(
            callable(func), 
            f"❌ STRUCTURAL FAILURE: '{func_name}' is no longer recognized as a callable function block."
        )
        signature = inspect.signature(func)
        params = [p for p in signature.parameters.values() if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        self.assertEqual(
            len(params), expected_args_count,
            f"⚠️  SIGNATURE MUTATION: '{func_name}' argument count changed. Expected {expected_args_count}, found {len(params)}."
        )

    # -------------------------------------------------------------------------
    # 0. ANTI-HALLUCINATION PRIORITY BLOCKS (EXECUTED FIRST VIA ASCII ORDER)
    # -------------------------------------------------------------------------
    def test_000_a_anti_hallucination_guard_for_trend_briefing_engine(self):
        """[INTEGRITY] Guards against the deletion of the master CLI trend briefing block."""
        self.verify_production_target_signature("generate_ecosystem_trend_briefing", expected_args_count=5)

    def test_000_a_anti_hallucination_guard_for_html_timeline_report(self):
        """[INTEGRITY] Guards against the deletion of the time-series HTML chart renderer."""
        self.verify_production_target_signature("generate_html_report", expected_args_count=3)

    def test_000_a_anti_hallucination_guard_for_snapshot_loader(self):
        """[INTEGRITY] Guards against the deletion of the snapshot log folder parser."""
        self.verify_production_target_signature("load_snapshots_from_dir", expected_args_count=1)

    def test_000_a_anti_hallucination_guard_for_cli_main_entrypoint(self):
        """[INTEGRITY] Guards against the deletion of the primary argument router entrypoint."""
        self.verify_production_target_signature("main", expected_args_count=0)

    def test_000_a_anti_hallucination_guard_for_retraction_stats_display(self):
        """[INTEGRITY] Guards against the deletion of the all-time retraction stats display
        (previously deleted silently in commit fd31fd2 with no test coverage to catch it)."""
        self.verify_production_target_signature("display_all_time_retraction_stats", expected_args_count=1)

    def test_000_a_anti_hallucination_guard_for_supply_chain_crosscheck(self):
        """[INTEGRITY] Guards against the deletion of the KEV/EPSS/OSV cross-check dispatch engine."""
        self.verify_production_target_signature("generate_supply_chain_crosscheck", expected_args_count=5)

    def test_000_a_anti_hallucination_guard_for_velocity_matrix_engine(self):
        """[INTEGRITY] Guards against the deletion of the CSV/terminal-plot velocity aggregation
        engine (previously deleted silently in commit 1df05c7 -- the call site in
        run_velocity_update() remained, calling an undefined function, until a later commit
        quietly deleted the call too instead of restoring the function it pointed to)."""
        self.verify_production_target_signature("generate_velocity_matrix", expected_args_count=3)

    def test_000_a_anti_hallucination_guard_for_snapshot_filename_builder(self):
        """[INTEGRITY] Guards against the deletion of the per-window --velocity snapshot
        filename builder."""
        self.verify_production_target_signature("build_snapshot_filename", expected_args_count=3)

    def test_000_a_anti_hallucination_guard_for_velocity_update_dispatcher(self):
        """[INTEGRITY] Guards against the deletion of the --velocity CLI dispatcher itself."""
        self.verify_production_target_signature("run_velocity_update", expected_args_count=1)

    def test_000_b_meta_guard_against_missing_test_methods_in_test_runner_itself(self):
        """[INTEGRITY] Reviews test_runner.py to ensure no verification tests were deleted or dropped."""
        expected_test_methods = {
            "test_000_a_anti_hallucination_guard_for_trend_briefing_engine",
            "test_000_a_anti_hallucination_guard_for_html_timeline_report",
            "test_000_a_anti_hallucination_guard_for_snapshot_loader",
            "test_000_a_anti_hallucination_guard_for_cli_main_entrypoint",
            "test_000_b_meta_guard_against_missing_test_methods_in_test_runner_itself",
            "test_console_and_export_telemetry_parity",
            "test_03_retraction_hunt_parameter_matrix",
            "test_04_retraction_hunt_scrubbed_metadata_resilience",
            "test_export_snapshot_generation_persistence",
            "test_pypi_clean_manifest",
            "test_pypi_dynamic_range_block",
            "test_maven_clean_tree",
            "test_maven_breach_intercept",
            "test_maven_dynamic_operator_block",
            "test_cyclonedx_clean_sbom",
            "test_cyclonedx_breach_intercept",
            "test_cyclonedx_empty_version_block",
            "test_maven_real_world_cli_noise",
            "test_get_artifact_layer_routing",
            "test_generate_leaderboard_stream_aggregation",
            "test_global_advisory_index_volume_baseline",
            "test_compare_snapshots_golden_master_deltas",
            "test_compare_snapshots_strict_text_alignment_good_match",
            "test_compare_snapshots_strict_text_alignment_bad_mismatch",
            "test_epss_table_schema_and_indexes",
            "test_epss_known_cve_scores_ingestion",
            "test_epss_vulnerabilities_cve_alias_parity",
            "test_000_a_anti_hallucination_guard_for_retraction_stats_display",
            "test_000_a_anti_hallucination_guard_for_supply_chain_crosscheck",
            "test_kev_table_schema_and_indexes",
            "test_kev_known_cve_ingestion",
            "test_kev_vulnerabilities_cve_alias_parity",
            "test_crosscheck_kev_epss_priority_ordering",
            "test_000_a_anti_hallucination_guard_for_velocity_matrix_engine",
            "test_000_a_anti_hallucination_guard_for_snapshot_filename_builder",
            "test_000_a_anti_hallucination_guard_for_velocity_update_dispatcher",
            "test_velocity_matrix_csv_and_delta_math",
            "test_velocity_snapshot_dedup_prefers_default_over_priority_sort",
            "test_velocity_filename_no_clobber_between_default_and_priority_sort",
            "test_registry_filter_applies_to_raw_leaderboard_counting_pass",
            "test_priority_sort_flag_wired_to_main_execution_path",
            "test_000_a_anti_hallucination_guard_for_cross_registry_pair_classifier",
            "test_000_a_anti_hallucination_guard_for_cross_registry_advisory_classifier",
            "test_000_a_anti_hallucination_guard_for_cross_registry_ranker",
            "test_cross_registry_webjars_purl_forces_repackaged",
            "test_cross_registry_repo_anchor_recognizes_native_release",
            "test_cross_registry_exact_name_match_without_wrapping_is_cross_compiled",
            "test_cross_registry_substring_wrap_is_repackaged",
            "test_cross_registry_unrelated_names_return_none",
            "test_cross_registry_advisory_can_land_in_both_tables",
            "test_rank_cross_registry_tables_filters_single_ecosystem_advisories",
            "test_rank_cross_registry_tables_ranks_by_ecosystem_span_then_cvss",
            "test_sync_manifest_path_id_extraction_preserves_colons_in_advisory_ids",
            "test_sync_baseline_uses_high_water_mark_not_cache_zip_mtime",
            "test_sync_baseline_legacy_anchor_falls_back_only_to_a_valid_zip",
            "test_modification_feed_keeps_newest_timestamp_per_id_and_honours_since",
            "test_verify_flags_missing_and_stale_but_not_changes_inside_the_resync_window",
            "test_feed_cache_expiry_is_not_reported_as_a_forced_refresh",
            "test_master_archive_download_never_leaves_a_truncated_zip_at_the_cache_path",
            "test_incremental_sync_requests_true_colon_ids_and_holds_high_water_for_failures",
            "test_stream_path_parser_keeps_colons_inside_advisory_ids",
            "test_stream_colon_id_rows_are_classified_from_the_lookup_not_the_fallback",
            "test_ecosystem_tag_bucketing_has_one_shared_memoized_implementation",
            "test_top_records_for_ecosystem_matches_the_naive_full_sort",
            "test_lookup_loads_light_fields_up_front_and_hydrates_heavy_details_on_demand",
            "test_project_alert_order_is_deterministic",
            "test_scatter_pair_export_is_deterministic_and_capped",
            "test_ingest_cvss_malware_override",
            "test_ingest_cvss_v3_vector_scores_via_first_library",
            "test_ingest_cvss_empty_severity_is_zero",
            "test_ingest_advisory_id_with_colon_is_preserved",
            "test_ingest_malware_classifier_trusts_keywords_only_when_cwes_corroborate",
            "test_ingest_suse_public_cloud_does_not_become_the_pub_ecosystem",
            "test_ingest_unrecognised_ecosystems_land_in_other_never_in_android",
            "test_db_health_android_is_not_a_catch_all_bucket",
            "test_ingest_cve_mirror_reference_is_not_a_repo_anchor",
            "test_ingest_republished_record_is_new_entry_and_aged_record_is_update",
            "test_ingest_withdrawn_record_is_classified_withdrawn",
            "test_ingest_blast_radius_is_enumerated_version_count_and_zero_for_range_only_records",
            "test_missing_warehouse_is_a_hard_error_not_a_silent_zip_fallback",
            "test_db_health_no_advisory_ids_contain_a_slash",
            "test_db_health_repo_anchor_is_not_polluted_by_the_cve_mirror",
            "test_db_health_no_suse_advisory_is_tagged_pub",
            "test_db_health_classification_columns_are_well_formed",
            "test_db_health_no_record_is_modified_in_the_future",
            "test_db_health_sync_high_water_mark_is_consistent_with_the_data"
        }
        
        actual_test_methods = {
            item for item in dir(self) 
            if item.startswith("test_") and callable(getattr(self, item))
        }
        
        missing_tests = expected_test_methods - actual_test_methods
        self.assertEqual(
            len(missing_tests), 0,
            f"❌ TEST RUNNER INTEGRITY VIOLATION: Verification tests have vanished from test_runner.py! "
            f"Missing test blocks: {missing_tests}"
        )

    def test_epss_vulnerabilities_cve_alias_parity(self):
        """
        [PARITY GATE] Verifies 1:1 join symmetry and baseline coverage between 
        vulnerabilities.cve_alias and epss_scores.cve_id.
        """
        if SKIP_EPSS:
            self.skipTest("[!] --skip-epss active: Skipping EPSS-to-OSV parity checks.")

        test_db = "database/threat_stream.db"
        if not os.path.exists(test_db):
            self.skipTest("[!] Relational test warehouse missing. Skipping parity verification.")

        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        # 1. Verify tables are populated before evaluating parity
        cursor.execute("SELECT COUNT(*) FROM epss_scores;")
        epss_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities;")
        vuln_count = cursor.fetchone()[0]

        if epss_count == 0 or vuln_count == 0:
            conn.close()
            self.skipTest(
                f"[!] Incomplete tables (epss_scores: {epss_count:,}, vulnerabilities: {vuln_count:,}). "
                f"Run 'python db_warehouse.py' first."
            )

        # 2. Assert 1:1 distinct key symmetry on the JOIN intersection
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT v.cve_alias) AS unique_cves_in_vulns_matched,
                COUNT(DISTINCT e.cve_id)    AS unique_cves_in_epss_matched,
                COUNT(*)                    AS total_joined_records
            FROM vulnerabilities v
            JOIN epss_scores e ON v.cve_alias = e.cve_id
            WHERE v.cve_alias IS NOT NULL AND v.cve_alias != '';
        """)
        vuln_matched, epss_matched, total_joined = cursor.fetchone()

        self.assertGreater(
            vuln_matched, 0, 
            "[!] CRITICAL: Zero vulnerability records matched against EPSS scores."
        )
        self.assertEqual(
            vuln_matched, epss_matched,
            f"[!] PARITY DRIFT: Asymmetric unique CVE counts in join! "
            f"vulnerabilities distinct: {vuln_matched:,} vs. epss_scores distinct: {epss_matched:,}"
        )

        # 3. Assert minimum baseline match rate against total distinct CVEs in OSV (>= 85%)
        cursor.execute("""
            SELECT COUNT(DISTINCT cve_alias) 
            FROM vulnerabilities 
            WHERE cve_alias IS NOT NULL AND cve_alias != '';
        """)
        total_distinct_osv_cves = cursor.fetchone()[0]

        match_ratio = (vuln_matched / total_distinct_osv_cves) if total_distinct_osv_cves > 0 else 0.0
        self.assertGreaterEqual(
            match_ratio, 0.85,
            f"[!] EPSS COVERAGE DRIFT: Only {match_ratio * 100:.1f}% ({vuln_matched:,}/{total_distinct_osv_cves:,}) "
            f"of distinct OSV CVEs resolved to EPSS records (Expected >= 85.0%)."
        )

        conn.close()

    # -------------------------------------------------------------------------
    # EPSS PREDICTIVE SCORING & WAREHOUSE ENRICHMENT MATRIX
    # -------------------------------------------------------------------------
    def test_epss_table_schema_and_indexes(self):
        """Validates that epss_scores table and its lookup index exist in the warehouse."""
        if SKIP_EPSS:
            self.skipTest("[!] --skip-epss active: Skipping EPSS schema checks.")

        test_db = "database/threat_stream.db"
        if not os.path.exists(test_db):
            self.skipTest("[!] Relational test warehouse missing. Skipping EPSS schema check.")

        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        # 1. Assert table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='epss_scores';")
        self.assertIsNotNone(cursor.fetchone(), "Table 'epss_scores' does not exist in database.")

        # 2. Assert required schema columns exist
        cursor.execute("PRAGMA table_info(epss_scores);")
        columns = {row[1] for row in cursor.fetchall()}
        expected_cols = {"cve_id", "epss_score", "percentile", "model_date"}
        self.assertTrue(
            expected_cols.issubset(columns),
            f"Missing required columns in epss_scores. Expected {expected_cols}, found {columns}"
        )

        # 3. Assert index exists for score lookups
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_epss_score';")
        self.assertIsNotNone(cursor.fetchone(), "Index 'idx_epss_score' does not exist on epss_scores.")
        conn.close()

    def test_epss_known_cve_scores_ingestion(self):
        """Queries warehouse for high-profile benchmark CVEs to verify EPSS probabilities and percentiles."""
        if SKIP_EPSS:
            self.skipTest("[!] --skip-epss active: Skipping EPSS known CVE ingestion check.")

        test_db = "database/threat_stream.db"
        if not os.path.exists(test_db):
            self.skipTest("[!] Relational test warehouse missing. Skipping EPSS data check.")

        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        # Verify table contains data prior to record querying
        cursor.execute("SELECT COUNT(*) FROM epss_scores;")
        total_records = cursor.fetchone()[0]
        if total_records == 0:
            conn.close()
            self.skipTest("[!] 'epss_scores' table is empty. Run 'python db_warehouse.py --epss' first.")

        # High-profile benchmark CVE targets
        famous_cves = [
            "CVE-2021-44228",  # Log4Shell
            "CVE-2014-0160",   # Heartbleed
            "CVE-2017-0144",   # EternalBlue
            "CVE-2019-0708",   # BlueKeep
            "CVE-2020-1472"    # Zerologon
        ]

        placeholders = ",".join(["?"] * len(famous_cves))
        cursor.execute(f"""
            SELECT cve_id, epss_score, percentile, model_date
            FROM epss_scores
            WHERE cve_id IN ({placeholders})
        """, famous_cves)

        results = {row[0]: (row[1], row[2], row[3]) for row in cursor.fetchall()}
        conn.close()

        # Validate presence and mathematical boundaries
        for cve in famous_cves:
            self.assertIn(cve, results, f"Benchmark CVE '{cve}' missing from epss_scores table.")
            score, percentile, model_date = results[cve]

            self.assertIsInstance(score, float, f"EPSS score for {cve} must be float.")
            self.assertTrue(0.0 <= score <= 1.0, f"EPSS score out of probability bounds [0.0, 1.0] for {cve}: {score}")
            self.assertTrue(0.0 <= percentile <= 1.0, f"EPSS percentile out of bounds [0.0, 1.0] for {cve}: {percentile}")
            self.assertRegex(model_date, r"^\d{4}-\d{2}-\d{2}", f"Invalid model_date format for {cve}: '{model_date}'")

    # -------------------------------------------------------------------------
    # KEV (CISA KNOWN EXPLOITED VULNERABILITIES) ENRICHMENT MATRIX
    # -------------------------------------------------------------------------
    def test_kev_table_schema_and_indexes(self):
        """Validates that kev_catalog table and its lookup indexes exist in the warehouse."""
        if SKIP_KEV:
            self.skipTest("[!] --skip-kev active: Skipping KEV schema checks.")

        test_db = "database/threat_stream.db"
        if not os.path.exists(test_db):
            self.skipTest("[!] Relational test warehouse missing. Skipping KEV schema check.")

        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kev_catalog';")
        self.assertIsNotNone(cursor.fetchone(), "Table 'kev_catalog' does not exist in database.")

        cursor.execute("PRAGMA table_info(kev_catalog);")
        columns = {row[1] for row in cursor.fetchall()}
        expected_cols = {
            "cve_id", "vendor_project", "product", "vulnerability_name", "date_added",
            "short_description", "required_action", "due_date", "known_ransomware_use",
            "notes", "cwes", "catalog_version"
        }
        self.assertTrue(
            expected_cols.issubset(columns),
            f"Missing required columns in kev_catalog. Expected {expected_cols}, found {columns}"
        )

        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_kev_date_added';")
        self.assertIsNotNone(cursor.fetchone(), "Index 'idx_kev_date_added' does not exist on kev_catalog.")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_kev_due_date';")
        self.assertIsNotNone(cursor.fetchone(), "Index 'idx_kev_due_date' does not exist on kev_catalog.")

        conn.close()

    def test_kev_known_cve_ingestion(self):
        """Queries warehouse for high-profile benchmark CVEs to verify KEV catalog fields."""
        if SKIP_KEV:
            self.skipTest("[!] --skip-kev active: Skipping KEV known CVE ingestion check.")

        test_db = "database/threat_stream.db"
        if not os.path.exists(test_db):
            self.skipTest("[!] Relational test warehouse missing. Skipping KEV data check.")

        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM kev_catalog;")
        total_records = cursor.fetchone()[0]
        if total_records == 0:
            conn.close()
            self.skipTest("[!] 'kev_catalog' table is empty. Run 'python db_warehouse.py' first.")

        # High-profile benchmark CVEs long-established in the KEV catalog
        famous_cves = [
            "CVE-2021-44228",  # Log4Shell
            "CVE-2017-0144",   # EternalBlue
            "CVE-2020-1472",   # Zerologon
        ]

        placeholders = ",".join(["?"] * len(famous_cves))
        cursor.execute(f"""
            SELECT cve_id, vendor_project, product, date_added, due_date
            FROM kev_catalog
            WHERE cve_id IN ({placeholders})
        """, famous_cves)
        results = {row[0]: (row[1], row[2], row[3], row[4]) for row in cursor.fetchall()}
        conn.close()

        for cve in famous_cves:
            self.assertIn(cve, results, f"Benchmark KEV CVE '{cve}' missing from kev_catalog table.")
            vendor, product, date_added, due_date = results[cve]
            self.assertTrue(vendor, f"KEV entry for {cve} missing vendor_project.")
            self.assertRegex(date_added, r"^\d{4}-\d{2}-\d{2}", f"Invalid date_added format for {cve}: '{date_added}'")

    def test_kev_vulnerabilities_cve_alias_parity(self):
        """
        [PARITY GATE] Verifies at least a subset of vulnerabilities.cve_alias values
        resolve against kev_catalog.cve_id. Unlike EPSS (near-universal CVE coverage),
        KEV is intentionally a small, curated subset (~1,500 of hundreds of thousands
        of CVEs) so this asserts presence and join correctness, not a coverage floor.
        """
        if SKIP_KEV:
            self.skipTest("[!] --skip-kev active: Skipping KEV-to-OSV parity checks.")

        test_db = "database/threat_stream.db"
        if not os.path.exists(test_db):
            self.skipTest("[!] Relational test warehouse missing. Skipping parity verification.")

        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM kev_catalog;")
        kev_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities;")
        vuln_count = cursor.fetchone()[0]

        if kev_count == 0 or vuln_count == 0:
            conn.close()
            self.skipTest(
                f"[!] Incomplete tables (kev_catalog: {kev_count:,}, vulnerabilities: {vuln_count:,}). "
                f"Run 'python db_warehouse.py' first."
            )

        cursor.execute("""
            SELECT COUNT(DISTINCT v.cve_alias)
            FROM vulnerabilities v
            JOIN kev_catalog k ON v.cve_alias = k.cve_id
            WHERE v.cve_alias IS NOT NULL AND v.cve_alias != '';
        """)
        matched = cursor.fetchone()[0]
        conn.close()

        self.assertGreater(
            matched, 0,
            "[!] CRITICAL: Zero vulnerability records matched against the KEV catalog. "
            "Check the cve_alias/cve_id join key or KEV ingestion."
        )

    def test_crosscheck_kev_epss_priority_ordering(self):
        """
        [ORDERING GATE] Verifies the --crosscheck dispatch list's core sort contract,
        run directly against the same query shape generate_supply_chain_crosscheck()
        uses: every KEV-confirmed advisory must rank before every non-KEV advisory,
        and EPSS score must be non-increasing within the KEV tier.
        """
        if SKIP_KEV or SKIP_EPSS:
            self.skipTest("[!] --skip-kev or --skip-epss active: Skipping crosscheck ordering gate.")

        test_db = "database/threat_stream.db"
        if not os.path.exists(test_db):
            self.skipTest("[!] Relational test warehouse missing. Skipping crosscheck ordering check.")

        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                (k.cve_id IS NOT NULL) AS is_kev,
                COALESCE(e.epss_score, 0.0) AS epss_score
            FROM vulnerabilities v
            LEFT JOIN epss_scores e ON v.cve_alias = e.cve_id
            LEFT JOIN kev_catalog k ON v.cve_alias = k.cve_id
            WHERE v.withdrawn_date IS NULL AND v.ecosystems LIKE '%npm%'
            ORDER BY
                (k.cve_id IS NOT NULL) DESC,
                COALESCE(e.epss_score, 0.0) DESC,
                v.cvss_score DESC,
                v.blast_radius DESC,
                v.advisory_id ASC
            LIMIT 500
        """)
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            self.skipTest("[!] No npm advisories available to validate crosscheck ordering.")

        seen_non_kev = False
        for is_kev, epss_score in rows:
            if is_kev:
                self.assertFalse(
                    seen_non_kev,
                    "[!] ORDERING VIOLATION: A KEV-confirmed advisory ranked after a non-KEV advisory."
                )
            else:
                seen_non_kev = True

        kev_epss_values = [epss for is_kev, epss in rows if is_kev]
        for i in range(len(kev_epss_values) - 1):
            self.assertGreaterEqual(
                kev_epss_values[i], kev_epss_values[i + 1],
                "[!] ORDERING VIOLATION: EPSS score is not non-increasing within the KEV tier."
            )

    # -------------------------------------------------------------------------
    # 3. CORE FUNCTIONAL REGRESSION CHECKS
    # -------------------------------------------------------------------------
    def test_console_and_export_telemetry_parity(self):
        """
        [PARITY GATE] Asserts character-by-character metric alignment between 
        the human-readable stdout display tables and the serialized JSON schema.
        """
        import json
        import re

        # 1. Initialize destination path constraints
        temp_dir = "./output"
        os.makedirs(temp_dir, exist_ok=True)
        temp_export_path = os.path.join(temp_dir, "parity_gate_verification.json")
        
        if os.path.exists(temp_export_path):
            os.remove(temp_export_path)

        # Ensure isolated file system cleanup at test teardown
        self.addCleanup(lambda: os.remove(temp_export_path) if os.path.exists(temp_export_path) else None)

        # 2. Trigger an authentic telemetry generation profile over a frozen 1-day window
        mock_flags = [
            '--from', '2026-05-18',
            '--to', '2026-05-19',
            '--export', temp_export_path
        ]
        exit_code, stdout_capture = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 0, f"Execution failed under parity compilation: {stdout_capture}")
        
        # 3. Extract the exported JSON tracking payload
        with open(temp_export_path, 'r', encoding='utf-8') as f:
            export_payload = json.load(f)

        # 4. PARITY GATE A: Validate Ecosystem Leaderboard Counts
        for eco_name, json_count in export_payload.get("leaderboard", {}).items():
            escaped_name = re.escape(eco_name)
            leaderboard_regex = re.compile(rf"{escaped_name}\s*\|\s*([0-9,]+)")
            match = leaderboard_regex.search(stdout_capture)
            
            if match:
                console_count = int(match.group(1).replace(",", ""))
                self.assertEqual(
                    console_count, json_count,
                    f"[!] TELEMETRY PARITY DRIFT: Leaderboard count mismatch for '{eco_name}'. "
                    f"Console reported '{console_count:,}' while Export contains '{json_count:,}'."
                )

        # 5. PARITY GATE B: Validate Malware Attack Vector Breakdowns
        for vector_name, json_vcount in export_payload.get("malware_vectors", {}).items():
            escaped_vector = re.escape(vector_name)
            vector_regex = re.compile(rf"->\s*{escaped_vector}\s*\|\s*([0-9,]+)")
            match = vector_regex.search(stdout_capture)
            
            if match:
                console_vcount = int(match.group(1).replace(",", ""))
                self.assertEqual(
                    console_vcount, json_vcount,
                    f"[!] TELEMETRY PARITY DRIFT: Malware attack vector mismatch for '{vector_name}'. "
                    f"Console reported '{console_vcount:,}' while Export contains '{json_vcount:,}'."
                )

        # 6. PARITY GATE C: The legacy "intel_architecture_matrix" export key is retained
        # unchanged for --velocity trend-diff backward compatibility (see
        # "VIII. HARDWARE ARCHITECTURE COMPILATION MATRIX VARIANCE ANALYSIS" in the --velocity
        # report), even though it is no longer rendered in the main dashboard's console output --
        # Section VIII there was replaced with the identity-correlation sub-tables below. So this
        # gate now only confirms the export key itself survived, not a console/export comparison.
        self.assertIn(
            "intel_architecture_matrix", export_payload,
            "[!] REGRESSION: 'intel_architecture_matrix' export key vanished -- this would break "
            "--velocity trend-diff parity against any snapshot exported before Section VIII's "
            "cross-registry rework."
        )

        # 6b. Blast radius (affected-version count) is retired from the console: Section V (which
        # ranked by it) is gone entirely, Section IV shows EPSS/KEV instead, and Sections VI/VII show
        # the EPSS/KEV column in every run, not only --priority-sort ones.
        self.assertNotIn("CRITICAL OUTLIER", stdout_capture, "[!] Section V is retired but still rendering.")
        self.assertNotIn("Blast Radius", stdout_capture, "[!] Blast radius is still printed in the console dashboard.")
        self.assertIn("Avg EPSS (n)", stdout_capture)
        self.assertIn("VI. NEW ARRIVALS", stdout_capture)
        self.assertIn("VII. SYSTEMIC RISK", stdout_capture)
        self.assertGreaterEqual(stdout_capture.count("EPSS / KEV"), 2, "[!] Sections VI/VII must show the EPSS / KEV column by default.")
        self.assertFalse(hasattr(top10ecosystems, "print_section_v_outlier_pools"))

        # 7. PARITY GATE D: Section VIII's three identity-correlation sub-tables render with the
        # expected headers -- A (cross-compiled) and B (repackaged) look WITHIN one advisory's own
        # listing (rendered as Package A/Package B identity columns), C (cross-tracker CVE
        # correlation, consolidated from the former separate Section IX) looks ACROSS independent
        # advisory records sharing a CVE ID (rendered as an ecosystem-presence grid).
        self.assertIn("VIII. IS THIS THE SAME VULNERABILITY SHOWING UP MORE THAN ONCE?", stdout_capture)
        sub_headers = [
            "VIII-A. TRUE CROSS-COMPILED",
            "VIII-B. REPACKAGED-AS-IS",
            "VIII-C. CROSS-TRACKER CVE CORRELATION",
        ]
        for header in sub_headers:
            self.assertIn(header, stdout_capture)

        # All three sub-tables now live inside ONE box (a single "="*125 pair wraps the whole
        # section; internal dividers between A/B/C are "-"*125), so a zone is bounded by
        # consecutive sub-header positions, with the final zone running to the closing "="*125.
        sub_positions = [stdout_capture.index(h) for h in sub_headers]
        section_end = stdout_capture.index("=" * 125, sub_positions[-1])
        zone_bounds = sub_positions + [section_end]
        zone_a = stdout_capture[zone_bounds[0]:zone_bounds[1]]
        zone_b = stdout_capture[zone_bounds[1]:zone_bounds[2]]
        zone_c = stdout_capture[zone_bounds[2]:zone_bounds[3]]

        # A: status grid, same presence/F-U-? model as C (independent native releases are peers
        # with no dependency direction, so the useful thing to show is which of this advisory's
        # ecosystems are still unfixed, not one representative name pair). Every listed advisory
        # row must carry >= 2 marked columns, matching the >= 2 ecosystems invariant enforced at
        # the data layer by rank_cross_registry_tables (a row only lands in table_a when it spans
        # 2+ registries to begin with).
        if "Zero advisories" not in zone_a:
            a_grid_lines = zone_a.splitlines()
            a_header_idx = next((i for i, l in enumerate(a_grid_lines) if "Advisory ID" in l and "Conf" in l), None)
            self.assertIsNotNone(a_header_idx, "[!] REGRESSION: Section VIII-A grid header not found where expected.")
            a_expected_pipes = a_grid_lines[a_header_idx].count("|")
            for line in a_grid_lines[a_header_idx + 2:]:  # skip the header row and its divider
                stripped = line.strip()
                if not stripped or stripped.startswith("=") or stripped.startswith("-") or line.count("|") < a_expected_pipes:
                    break
                cells = line.split("|")
                marked_count = sum(1 for c in cells[2:] if c.strip())  # cells[0]=Advisory ID, [1]=Conf
                self.assertGreaterEqual(
                    marked_count, 2,
                    f"[!] REGRESSION: Section VIII-A grid row '{stripped}' has fewer than 2 marked "
                    f"ecosystem columns -- rank_cross_registry_tables should only ever populate "
                    f"table_a for advisories spanning >= 2 distinct registries."
                )

        # B: repackaged pairs DO have a dependency direction (downstream waits on upstream), so
        # this table keeps two package cells, now labeled Downstream/Upstream instead of A/B.
        if "Zero advisories" not in zone_b:
            for row_match in re.finditer(
                r"^(GHSA|CVE|PYSEC|MAL|RUSTSEC|GO|CGA)\S*\s*\|\s*(CONFIRMED|HIGH|MEDIUM|LOW)\s*\|\s*(\S.*?)\s*\|\s*(\S.*)$",
                zone_b, re.MULTILINE
            ):
                pkg_down, pkg_up = row_match.group(3), row_match.group(4)
                self.assertTrue(
                    pkg_down.strip() and pkg_up.strip(),
                    f"[!] REGRESSION: Section VIII-B row '{row_match.group(0).strip()}' is missing its "
                    f"Downstream or Upstream package identifier."
                )

        # C: status grid -- every listed CVE row must carry >= 2 marked (F/U/?) columns, matching
        # the >= 2 distinct ecosystems invariant enforced by find_cross_ecosystem_cve_correlations().
        # A raw numeric field can no longer be regex-matched here the way A/B once were: the grid's
        # first number column is "Rec" (advisory-record count), a different metric NOT guaranteed
        # to be >= 2 (e.g. a single GHSA record that itself lists 5 ecosystems is 1 record spanning
        # 5 ecosystems). Rows are distinguished from footnote/legend lines by pipe count rather
        # than specific wording, so this doesn't need updating every time a new note is added.
        if "0 CVEs confirmed" not in zone_c:
            grid_lines = zone_c.splitlines()
            header_idx = next((i for i, l in enumerate(grid_lines) if "CVE ID" in l and "Rec" in l), None)
            self.assertIsNotNone(header_idx, "[!] REGRESSION: Section VIII-C grid header not found where expected.")
            # A real data row has exactly as many "|" separators as the header (same cell count);
            # footnote/legend lines below the grid won't reliably have fewer -- a two-pipe legend
            # line ("F = ... | U = ... | ? = ...") is exactly the kind of near-miss that broke a
            # fixed "< 2" threshold here previously -- so compare against the header's own count
            # instead of guessing a number that has to be re-tuned every time a note is added.
            expected_pipes = grid_lines[header_idx].count("|")
            for line in grid_lines[header_idx + 2:]:  # skip the header row and its divider
                stripped = line.strip()
                if not stripped or stripped.startswith("=") or line.count("|") < expected_pipes:
                    break
                cells = line.split("|")
                # A present ecosystem cell holds F/U/?, optionally ANSI-red-wrapped for a registry
                # ecosystem (see _render_cross_ecosystem_grid) -- an absent one is pure whitespace,
                # so "any non-whitespace content" reliably distinguishes present from absent
                # regardless of which status letter or color wrapping is in play.
                marked_count = sum(1 for c in cells[2:] if c.strip())  # cells[0]=CVE ID, [1]=Rec
                self.assertGreaterEqual(
                    marked_count, 2,
                    f"[!] REGRESSION: Section VIII-C grid row '{stripped}' has fewer than 2 marked "
                    f"ecosystem columns -- find_cross_ecosystem_cve_correlations() should only ever "
                    f"surface CVEs spanning >= 2 distinct ecosystems."
                )

    def run_scanner_with_args(self, mock_args):
        """Helper utility to simulate an authentic CLI execution and capture output. Mocks
        requests.get against the frozen local CSV snapshot (self.cached_stream_lines, loaded once
        in setUpClass) instead of letting main() hit the live OSV modified_id.csv feed over the
        network -- every caller of this helper was previously making a real HTTP call to Google
        Cloud Storage on every single test run, which is both why this suite was slow (tens of
        seconds of network I/O per test) and non-deterministic (assertions could drift with
        whatever rows the live feed happens to contain that day). test_historical_golden_masters
        already had to work around this itself with its own requests.get mock; this generalizes
        that same fix to every other test going through run_scanner_with_args."""
        base_args = ['top10ecosystems.py', '--layer', 'app', '--from', '2020-01-01']
        full_args = base_args + mock_args
        captured_output = io.StringIO()

        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        mock_response.iter_lines.return_value = self.cached_stream_lines

        with patch.object(sys, 'argv', full_args), \
             patch('sys.stdout', captured_output), \
             patch('top10ecosystems.build_ghsa_from_db', return_value=self.ghsa_lookup), \
             patch('requests.get', return_value=mock_response):
            try:
                top10ecosystems.main()
            except SystemExit as e:
                return e.code, captured_output.getvalue()

        return 0, captured_output.getvalue()

    def test_03_retraction_hunt_parameter_matrix(self):
        """Validates that extract_suspicious_retractions cleanly processes all target layer inputs."""
        from top10ecosystems import extract_suspicious_retractions
        test_db = "database/threat_stream.db"
        if not os.path.exists(test_db):
            self.skipTest("[!] Relational test warehouse missing. Skipping parameters matrix verification.")

        try:
            for target_layer in ["all", "app", "os"]:
                extract_suspicious_retractions(
                    db_path=test_db,
                    from_date="2019-01-01",
                    to_date="2026-05-28",
                    layer=target_layer
                )
        except Exception as e:
            self.fail(f"[!] Regression Detected: Retraction hunt failed during layer matrix execution: {e}")

    def test_04_retraction_hunt_scrubbed_metadata_resilience(self):
        """Ensures the hunt engine safely processes completely uncapped, un-bounded time windows."""
        from top10ecosystems import extract_suspicious_retractions
        test_db = "database/threat_stream.db"
        if not os.path.exists(test_db):
            self.skipTest("[!] Relational test warehouse missing. Skipping resilience verification.")

        try:
            extract_suspicious_retractions(
                db_path=test_db,
                from_date=None,
                to_date=None,
                layer="all"
            )
        except Exception as e:
            self.fail(f"[!] Regression Detected: Open window retraction hunt crashed: {e}")

    def test_export_snapshot_generation_persistence(self):
        """[REGRESSION GATE] Verifies the snapshot export compilation pipeline outputs robust json arrays."""
        import json
        temp_dir = "./output"
        os.makedirs(temp_dir, exist_ok=True)
        target_export_path = os.path.join(temp_dir, "regression_gate_export_verify.json")
        
        if os.path.exists(target_export_path):
            os.remove(target_export_path)
            
        mock_flags = [
            '--from', '2026-05-18',
            '--to', '2026-05-19',
            '--export', target_export_path
        ]
        self.addCleanup(lambda: os.remove(target_export_path) if os.path.exists(target_export_path) else None)
        exit_code, output = self.run_scanner_with_args(mock_flags)
        
        self.assertEqual(exit_code, 0, f"Export execution failed under test harness with stdout:\n{output}")
        self.assertTrue(os.path.exists(target_export_path), "[!] CRITICAL REGRESSION: JSON export payload was not persisted to disk.")
        
        with open(target_export_path, 'r', encoding='utf-8') as f:
            payload = json.load(f)
            
        required_schema_nodes = [
            "metadata", "leaderboard", "threat_profile", "layer_profile_matrix", 
            "malware_vectors", "profile_matrix", "cvss_epss_pairs"
        ]
        for node in required_schema_nodes:
            self.assertIn(node, payload, f"[!] SCHEMA CORRUPTION: Saved snapshot file is missing key '{node}' root data node.")

    # -------------------------------------------------------------------------
    # PYPI / REQUIREMENTS.TXT STRATEGY MATRIX
    # -------------------------------------------------------------------------
    def test_pypi_clean_manifest(self):
        """Ensures a standard pinned requirements file returns a clean bill of health."""
        mock_flags = ['--project-file', 'src/test/resources/cleanrequirements.txt']
        exit_code, output = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 0)
        self.assertIn("Clean Bill of Health", output)

    def test_pypi_dynamic_range_block(self):
        """Verifies the regex guardrail flags loose mathematical ranges immediately."""
        mock_flags = ['--project-file', 'src/test/resources/dynamic_requirements.txt']
        exit_code, output = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 1)
        self.assertIn("Configuration Error", output)

    # -------------------------------------------------------------------------
    # MAVEN / DEPENDENCY:TREE STRATEGY MATRIX
    # -------------------------------------------------------------------------
    def test_maven_clean_tree(self):
        """Verifies clean, formatted Java dependency trees pass silently."""
        mock_flags = ['--project-format', 'maven_tree', '--project-file', 'src/test/resources/clean_maven_tree.txt']
        exit_code, output = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 0)
        self.assertIn("Clean Bill of Health", output)

    def test_maven_breach_intercept(self):
        """Validates that a bad tree file hits the index and pops a breach alert table."""
        mock_flags = ['--project-format', 'maven_tree', '--project-file', 'src/test/resources/bad_maven_tree.txt']
        exit_code, output = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 0)
        self.assertIn("BREACH ALERT", output)

    def test_maven_dynamic_operator_block(self):
        """Ensures dynamic ranges like [5.3.0,6.0.0) or LATEST keywords drop execution."""
        mock_flags = ['--project-format', 'maven_tree', '--project-file', 'src/test/resources/dynamic_maven_tree.txt']
        exit_code, output = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 1)
        self.assertIn("MAVEN TREE LINTING FAILURE", output)

    # -------------------------------------------------------------------------
    # CYCLONEDX / JSON SBOM STRATEGY MATRIX
    # -------------------------------------------------------------------------
    def test_cyclonedx_clean_sbom(self):
        """Verifies a fully frozen machine-generated SBOM outputs a clean status banner."""
        mock_flags = ['--project-file', 'src/test/resources/clean_cyclonedx.json']
        exit_code, output = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 0)
        self.assertIn("Clean Bill of Health", output)

    def test_cyclonedx_breach_intercept(self):
        """Ensures case-insensitive structural matching triggers the alert grid for SBOM assets."""
        mock_flags = ['--project-file', 'src/test/resources/bad_cyclonedx.json']
        exit_code, output = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 0)
        self.assertIn("BREACH ALERT", output)

    def test_cyclonedx_empty_version_block(self):
        """Confirms that uncompiled or placeholder components throw a linting exception."""
        mock_flags = ['--project-file', 'src/test/resources/dynamic_cyclonedx.json']
        exit_code, output = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 1)
        self.assertIn("SBOM LINTING FAILURE", output)
        
    def test_maven_real_world_cli_noise(self):
        """Verifies the parser successfully strips Maven CLI noise, optional modifiers, and summary footers."""
        mock_flags = ['--project-format', 'maven_tree', '--project-file', 'src/test/resources/esapi_dependency_tree.txt']
        exit_code, output = self.run_scanner_with_args(mock_flags)
        self.assertEqual(exit_code, 0)
        self.assertNotIn("LINTING FAILURE", output)
        self.assertNotIn("Configuration Error", output)
        
    # -------------------------------------------------------------------------
    # UNIT TESTS: CVSS EXTRACTOR ENGINE
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # UNIT TESTS: SECTION VIII CROSS-REGISTRY CLASSIFICATION
    # (replaces the old "HARDWARE ARCHITECTURE COMPILATION CROSS-POLLINATION MATRIX" -- see
    # rank_cross_registry_tables / classify_advisory_cross_registry / classify_cross_registry_pair
    # )
    # -------------------------------------------------------------------------
    def test_000_a_anti_hallucination_guard_for_cross_registry_pair_classifier(self):
        """[INTEGRITY] Guards against the deletion of the pairwise cross-registry classifier."""
        self.verify_production_target_signature("classify_cross_registry_pair", expected_args_count=5)

    def test_000_a_anti_hallucination_guard_for_cross_registry_advisory_classifier(self):
        """[INTEGRITY] Guards against the deletion of the whole-advisory cross-registry classifier."""
        self.verify_production_target_signature("classify_advisory_cross_registry", expected_args_count=3)

    def test_000_a_anti_hallucination_guard_for_cross_registry_ranker(self):
        """[INTEGRITY] Guards against the deletion of the Section VIII table ranking engine."""
        self.verify_production_target_signature("rank_cross_registry_tables", expected_args_count=3)

    def test_cross_registry_webjars_purl_forces_repackaged(self):
        """[REGRESSION] A Maven 'org.webjars' purl on either side must always classify as
        'repackaged', even when the names would otherwise look like an exact cross-compiled
        match -- webjars mechanically wraps the JS package byte-identically under Maven
        coordinates, it never represents an independent native Maven release."""
        verdict = top10ecosystems.classify_cross_registry_pair(
            "dset", "pkg:npm/dset",
            "dset", "pkg:maven/org.webjars.npm/dset",
            None
        )
        self.assertEqual(verdict, "repackaged")

    def test_cross_registry_repo_anchor_recognizes_native_release(self):
        """[REGRESSION] Two dissimilar names that both trace back to the same GitHub repo anchor
        (e.g. 'pyspark' and 'org.apache.spark:spark-core_2.12', both anchored to apache/spark)
        must classify as 'cross_compiled', not fall through to the substring/no-match branches."""
        verdict = top10ecosystems.classify_cross_registry_pair(
            "org.apache.spark:spark-core_2.12", "pkg:maven/org.apache.spark/spark-core_2.12",
            "pyspark", "pkg:pypi/pyspark",
            "apache/spark"
        )
        self.assertEqual(verdict, "cross_compiled")

    def test_cross_registry_exact_name_match_without_wrapping_is_cross_compiled(self):
        """[REGRESSION] Identical normalized names across ecosystems with no webjars/repo-anchor
        evidence either way should read as parallel native releases (cross_compiled), not as
        one repackaging the other."""
        verdict = top10ecosystems.classify_cross_registry_pair(
            "bootstrap", "pkg:npm/bootstrap",
            "Bootstrap", "pkg:nuget/Bootstrap",
            None
        )
        self.assertEqual(verdict, "cross_compiled")

    def test_cross_registry_substring_wrap_is_repackaged(self):
        """[REGRESSION] A decorated/prefixed name that contains another entry's name in full
        (e.g. Debian-style 'python3-jinja2' wrapping 'jinja2') should read as repackaged."""
        verdict = top10ecosystems.classify_cross_registry_pair(
            "jinja2", "pkg:pypi/jinja2",
            "python3-jinja2", "",
            None
        )
        self.assertEqual(verdict, "repackaged")

    def test_cross_registry_unrelated_names_return_none(self):
        """[REGRESSION] Two genuinely unrelated package names with no repo-anchor evidence must
        not be forced into either bucket."""
        verdict = top10ecosystems.classify_cross_registry_pair(
            "left-pad", "pkg:npm/left-pad",
            "django", "pkg:pypi/django",
            None
        )
        self.assertIsNone(verdict)

    def test_cross_registry_advisory_can_land_in_both_tables(self):
        """[REGRESSION] An advisory can legitimately exhibit BOTH patterns across different
        ecosystem pairs (e.g. Bootstrap: natively ported to npm/NuGet/RubyGems AND separately
        vendored into Maven via webjars) -- classify_advisory_cross_registry must report both
        booleans independently rather than forcing a single verdict per advisory."""
        names_by_eco = {
            "npm": ["bootstrap"],
            "NuGet": ["bootstrap"],
            "Maven (Java)": ["org.webjars:bootstrap"],
        }
        purls_by_eco = {
            "npm": ["pkg:npm/bootstrap"],
            "NuGet": ["pkg:nuget/bootstrap"],
            "Maven (Java)": ["pkg:maven/org.webjars/bootstrap"],
        }
        is_cross_compiled, is_repackaged = top10ecosystems.classify_advisory_cross_registry(
            names_by_eco, purls_by_eco, None
        )
        self.assertTrue(is_cross_compiled)
        self.assertTrue(is_repackaged)

    def test_rank_cross_registry_tables_filters_single_ecosystem_advisories(self):
        """[REGRESSION] An advisory touching only one ecosystem can never be 'cross-registry' by
        definition -- rank_cross_registry_tables must exclude it even if present in ghsa_lookup
        and session_advisory_ids."""
        ghsa_lookup = {
            "GHSA-single-eco": {
                "cvss_score": 9.0,
                "package_names_by_ecosystem": {"npm": ["solo-package"]},
                "purls_by_ecosystem": {"npm": ["pkg:npm/solo-package"]},
                "repo_anchor": None,
            }
        }
        table_a, table_b = top10ecosystems.rank_cross_registry_tables(ghsa_lookup, {"GHSA-single-eco"})
        self.assertEqual(table_a, [])
        self.assertEqual(table_b, [])

    def test_rank_cross_registry_tables_ranks_by_ecosystem_span_then_cvss(self):
        """[REGRESSION] Ranking order must be ecosystem span (desc) first, CVSS (desc) as the
        tiebreaker -- a 2-registry advisory with a higher CVSS must NOT outrank a 3-registry
        advisory with a lower CVSS."""
        ghsa_lookup = {
            "GHSA-two-eco-high-cvss": {
                "cvss_score": 9.9,
                "package_names_by_ecosystem": {"npm": ["pkg-a"], "PyPI": ["pkg-a"]},
                "purls_by_ecosystem": {"npm": ["pkg:npm/pkg-a"], "PyPI": ["pkg:pypi/pkg-a"]},
                "repo_anchor": None,
            },
            "GHSA-three-eco-low-cvss": {
                "cvss_score": 4.0,
                "package_names_by_ecosystem": {"npm": ["pkg-b"], "PyPI": ["pkg-b"], "NuGet": ["pkg-b"]},
                "purls_by_ecosystem": {"npm": ["pkg:npm/pkg-b"], "PyPI": ["pkg:pypi/pkg-b"], "NuGet": ["pkg:nuget/pkg-b"]},
                "repo_anchor": None,
            },
        }
        session_ids = {"GHSA-two-eco-high-cvss", "GHSA-three-eco-low-cvss"}
        table_a, _ = top10ecosystems.rank_cross_registry_tables(ghsa_lookup, session_ids)
        self.assertEqual(table_a[0][0], "GHSA-three-eco-low-cvss")
        self.assertEqual(table_a[1][0], "GHSA-two-eco-high-cvss")

    # -------------------------------------------------------------------------
    # UNIT TESTS: ARTIFACT LAYER ROUTING
    # -------------------------------------------------------------------------
    def test_get_artifact_layer_routing(self):
        """Ensures ecosystems are deterministically bucketed into the correct architectural layers."""
        self.assertEqual(top10ecosystems.get_artifact_layer("Debian"), "Container Base Image")
        self.assertEqual(top10ecosystems.get_artifact_layer("npm"), "App Software Registry")
        self.assertEqual(top10ecosystems.get_artifact_layer("GIT"), "Source Control (SCM)")
        self.assertEqual(top10ecosystems.get_artifact_layer("UnknownFramework"), "Global Baseline Noise")

    # -------------------------------------------------------------------------
    # INTEGRATION TESTS: LEADERBOARD GENERATION ENGINE
    # -------------------------------------------------------------------------
    @patch('requests.get')
    def test_generate_leaderboard_stream_aggregation(self, mock_requests_get):
        """Mocks the live OSV CSV stream to verify ecosystem counter parsing alignment."""
        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        mock_csv_lines = [
            b"2026-04-20T10:00:00Z,npm/GHSA-mock-1111.json",
            b"2026-04-20T11:00:00Z,Debian/CVE-mock-2222.json",
            b"2026-04-20T11:30:00Z,Debian/CVE-mock-3333.json",
            b"2026-04-20T12:00:00Z,npm/MAL-mock-4444.json" 
        ]
        mock_response.iter_lines.return_value = mock_csv_lines
        mock_requests_get.return_value = mock_response

        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            top10ecosystems.generate_enterprise_threat_leaderboard(
                start_date=datetime.datetime(2026, 4, 18, tzinfo=datetime.timezone.utc),
                end_date=datetime.datetime(2026, 4, 25, tzinfo=datetime.timezone.utc),
                target_layer=None, 
                debug_mode=False, 
                ghsa_lookup={} 
            )
        output = captured_output.getvalue()

        self.assertIn("VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD", output)
        self.assertRegex(output, r"Debian\s+\|\s+2")
        self.assertRegex(output, r"npm\s+\|\s+2")
        self.assertIn("Raw Entry Stream Items:    4", output)

    def test_stream_path_parser_keeps_colons_inside_advisory_ids(self):
        """
        [REGRESSION] Real Red Hat/SUSE/openSUSE/Rocky advisory IDs contain colons. The dashboard
        used to treat any path containing a colon as a legacy "ID:ecosystem" form, turning
        "Red Hat/RHSA-2026:1234" into the advisory "Red Hat/RHSA-2026" and a bogus ecosystem
        "1234" -- ~74K feed rows and ~29K distinct garbage ecosystem tags. Only "/" separates the
        ecosystem from the ID.
        """
        cases = {
            "Red Hat/RHSA-2026:1234": ("RHSA-2026:1234", "Red Hat"),
            "openSUSE/openSUSE-SU-2026:11976-1": ("openSUSE-SU-2026:11976-1", "openSUSE"),
            "SUSE/SUSE-SU-2025:3305-1": ("SUSE-SU-2025:3305-1", "SUSE"),
            "npm/MAL-2026-1234.json": ("MAL-2026-1234", "npm"),
            "Debian/DEBIAN-CVE-2026-71891": ("DEBIAN-CVE-2026-71891", "Debian"),
            "GHSA-abcd-efgh-ijkl": ("GHSA-abcd-efgh-ijkl", None),
            "root/GHSA-abcd-efgh-ijkl": ("GHSA-abcd-efgh-ijkl", None),
        }
        for path, expected in cases.items():
            self.assertEqual(top10ecosystems.parse_stream_path(path), expected, f"[!] Wrong parse of stream path {path!r}.")

    def test_stream_colon_id_rows_are_classified_from_the_lookup_not_the_fallback(self):
        """
        [REGRESSION] A colon-bearing advisory's stream row must resolve to its TRUE advisory ID,
        so its classification comes from the warehouse. The old parser produced a garbage ID that
        was never in the lookup, so every such row was counted as the "Vulnerability Fix (Update)"
        fallback regardless of what it really was.
        """
        chosen = next(((k, v) for k, v in self.ghsa_lookup.items()
                       if ":" in k and k.startswith("SUSE-SU-") and v["type"] != "Vulnerability Fix (Update)"), None)
        if chosen is None:
            self.skipTest("[!] No SUSE advisory with a non-fallback classification in this warehouse to discriminate with.")
        advisory_id, meta = chosen

        export_path = os.path.join("output", "colon_id_regression_export.json")
        self.addCleanup(lambda: os.path.exists(export_path) and os.remove(export_path))
        with patch('sys.stdout', io.StringIO()):
            top10ecosystems.generate_enterprise_threat_leaderboard(
                start_date=datetime.datetime(2026, 4, 18, tzinfo=datetime.timezone.utc),
                end_date=datetime.datetime(2026, 4, 25, tzinfo=datetime.timezone.utc),
                target_layer=None, debug_mode=False, custom_export_arg=export_path,
                ghsa_lookup={advisory_id: meta},   # one real entry: keeps this test from ranking/looping over all 2M
                manifest_rows=[["2026-04-20T10:00:00Z", f"SUSE/{advisory_id}"]],
            )
        with open(export_path, "r", encoding="utf-8") as f:
            exported = json.load(f)

        self.assertEqual(exported["threat_profile"].get(meta["type"]), 1,
                         f"[!] {advisory_id} was not classified from the lookup as {meta['type']!r}: {exported['threat_profile']}")
        self.assertEqual(sum(exported["threat_profile"].values()), 1)
        import re as _re
        garbage = [k for k in exported["leaderboard"] if _re.fullmatch(r"[\d\-]+", k)]
        self.assertEqual(garbage, [], f"[!] Version-number fragments leaked into the ecosystem leaderboard: {garbage}")

    @patch('requests.get')
    def test_registry_filter_applies_to_raw_leaderboard_counting_pass(self, mock_requests_get):
        """
        [REGRESSION] --registry has always filtered ghsa_lookup (via build_ghsa_from_db) but,
        until this fix, was never applied to generate_enterprise_threat_leaderboard()'s own raw
        manifest-stream counting pass -- the loop that produces Sections I/II/III and
        total_raw_rows walked the FULL unfiltered OSV stream regardless of --registry, so a bare
        --registry run (no --layer) looked "dead": container OS churn swamped the unfiltered
        top-10 and the requested registries never surfaced. This locks in the fix and proves the
        default (target_registries omitted) path is unaffected.
        """
        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        mock_csv_lines = [
            b"2026-04-20T10:00:00Z,npm/MAL-mock-1111.json",
            b"2026-04-20T11:00:00Z,PyPI/GHSA-mock-2222.json",
            b"2026-04-20T11:30:00Z,Debian/GHSA-mock-3333.json",
            b"2026-04-20T12:00:00Z,Chainguard/GHSA-mock-4444.json",
        ]
        mock_response.iter_lines.return_value = mock_csv_lines
        mock_requests_get.return_value = mock_response

        window = dict(
            start_date=datetime.datetime(2026, 4, 18, tzinfo=datetime.timezone.utc),
            end_date=datetime.datetime(2026, 4, 25, tzinfo=datetime.timezone.utc),
            target_layer=None, debug_mode=False, ghsa_lookup={}
        )

        # 1. Default path (no --registry): every ecosystem still counts -- zero impact.
        captured_default = io.StringIO()
        with patch('sys.stdout', captured_default):
            top10ecosystems.generate_enterprise_threat_leaderboard(**window)
        default_output = captured_default.getvalue()
        self.assertRegex(default_output, r"npm\s+\|\s+1")
        self.assertRegex(default_output, r"Debian\s+\|\s+1")
        self.assertRegex(default_output, r"Chainguard\s+\|\s+1")

        # 2. --registry npm,PyPI: only npm/PyPI should register non-zero counts; container
        #    ecosystems must drop to zero rather than silently keeping their unfiltered totals.
        captured_filtered = io.StringIO()
        with patch('sys.stdout', captured_filtered):
            top10ecosystems.generate_enterprise_threat_leaderboard(target_registries=["npm", "PyPI"], **window)
        filtered_output = captured_filtered.getvalue()
        self.assertRegex(filtered_output, r"npm\s+\|\s+1")
        self.assertRegex(filtered_output, r"PyPI\s+\|\s+1")
        self.assertRegex(
            filtered_output, r"Debian\s+\|\s+0",
            "[!] --registry regressed: Debian should be excluded from the raw counting pass."
        )
        self.assertRegex(
            filtered_output, r"Chainguard\s+\|\s+0",
            "[!] --registry regressed: Chainguard should be excluded from the raw counting pass."
        )

    def test_priority_sort_flag_wired_to_main_execution_path(self):
        """
        [REGRESSION] --priority-sort was threaded into build_ghsa_from_db() and into
        run_velocity_update()'s call to generate_enterprise_threat_leaderboard(), but the
        primary (non-velocity) CLI call site in main() never actually passed
        priority_sort_active=args.priority_sort through -- so --priority-sort silently did
        nothing outside of --velocity runs. This greps main()'s own source for the call rather
        than re-running the CLI, since the behavioral effect (KEV/EPSS-aware ranking) is already
        covered by test_crosscheck_kev_epss_priority_ordering and the Section V/VI/VII banner
        tests; this guards specifically against the wiring gap regressing again.
        """
        import inspect
        main_source = inspect.getsource(top10ecosystems.main)

        # Isolate the plain-path call (the one NOT inside run_velocity_update), i.e. the last
        # generate_enterprise_threat_leaderboard(...) call in main()'s own source.
        call_start = main_source.rfind("generate_enterprise_threat_leaderboard(")
        self.assertNotEqual(call_start, -1, "[!] main() no longer calls generate_enterprise_threat_leaderboard directly.")
        call_block = main_source[call_start:call_start + 700]

        self.assertIn(
            "priority_sort_active=args.priority_sort", call_block,
            "[!] --priority-sort is no longer wired into main()'s primary execution path."
        )
        self.assertIn(
            "target_registries=target_registries", call_block,
            "[!] --registry is no longer wired into main()'s primary execution path."
        )

    def test_global_advisory_index_volume_baseline(self):
        """Validates that the parsed global memory index does not suffer silent truncation regressions."""
        total_indexed_records = len(self.ghsa_lookup) if hasattr(self, 'ghsa_lookup') else 0
        minimum_safe_threshold = 560000
        self.assertGreaterEqual(
            total_indexed_records, minimum_safe_threshold,
            msg=f"\n\n⚠️ INDEX TRUNCATION DETECTED: {total_indexed_records:,} vs Floor: {minimum_safe_threshold:,}\n"
        )

    def test_velocity_matrix_csv_and_delta_math(self):
        """
        [REGRESSION] Verifies generate_velocity_matrix() (restored this cycle -- see the
        anti-hallucination guard above) produces a correct CSV time-series matrix, and that
        its terminal-plot delta series reflects true period-over-period velocity (net new
        mutations since the previous snapshot), not cumulative totals.
        """
        import json
        import csv
        import shutil

        temp_dir = "./output/velocity_matrix_test"
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(temp_dir, ignore_errors=True))

        fixtures = [
            ("2026-08-01", {"npm": 100, "PyPI": 40}, {"Malware (New Entry)": 10}),
            ("2026-08-08", {"npm": 150, "PyPI": 55}, {"Malware (New Entry)": 15}),
            ("2026-08-15", {"npm": 90, "PyPI": 60}, {"Malware (New Entry)": 5}),
        ]
        for interval_to, leaderboard, threat_profile in fixtures:
            payload = {
                "metadata": {
                    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "interval_from": "2026-07-25",
                    "interval_to": interval_to,
                    "target_layer_filter": "app",
                    "priority_sort_active": False
                },
                "leaderboard": leaderboard,
                "threat_profile": threat_profile,
                "malware_vectors": {},
                "profile_matrix": {},
                "outliers_leaderboards": {}
            }
            with open(os.path.join(temp_dir, f"snap_{interval_to}.json"), 'w', encoding='utf-8') as f:
                json.dump(payload, f)

        output_csv = os.path.join(temp_dir, "velocity_matrix.csv")
        top10ecosystems.generate_velocity_matrix(target_dir=temp_dir, output_path=output_csv, render_terminal_plot=False)

        self.assertTrue(os.path.exists(output_csv), "[!] Velocity matrix CSV was not written to disk.")

        with open(output_csv, newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))

        self.assertEqual(len(rows), 3, "[!] Expected exactly one CSV row per snapshot.")
        self.assertEqual([r["Date_End"] for r in rows], ["2026-08-01", "2026-08-08", "2026-08-15"])
        self.assertEqual(int(rows[1]["npm"]), 150)

        # Independently recompute the delta series the same way the terminal plot does
        npm_totals = [int(r["npm"]) for r in rows]
        npm_deltas = [npm_totals[0]] + [npm_totals[i] - npm_totals[i - 1] for i in range(1, len(npm_totals))]
        self.assertEqual(
            npm_deltas, [100, 50, -60],
            "[!] Velocity delta math regressed -- must reflect period-over-period churn, not cumulative totals."
        )

    def test_velocity_snapshot_dedup_prefers_default_over_priority_sort(self):
        """
        [REGRESSION] Verifies load_snapshots_from_dir() collapses a --priority-sort snapshot
        and a default snapshot for the same date/layer into a single entry instead of
        double-counting the same day, and prefers the default (non-priority-sort) file when
        both exist on disk.
        """
        import json
        import shutil

        temp_dir = "./output/velocity_dedup_test"
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(temp_dir, ignore_errors=True))

        def make_payload(priority_active):
            return {
                "metadata": {
                    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "interval_from": "2026-08-25",
                    "interval_to": "2026-09-01",
                    "target_layer_filter": "app",
                    "priority_sort_active": priority_active
                },
                "leaderboard": {"npm": 42},
                "threat_profile": {},
                "malware_vectors": {},
                "profile_matrix": {},
                "outliers_leaderboards": {}
            }

        with open(os.path.join(temp_dir, "default.json"), 'w', encoding='utf-8') as f:
            json.dump(make_payload(False), f)
        with open(os.path.join(temp_dir, "default_priority.json"), 'w', encoding='utf-8') as f:
            json.dump(make_payload(True), f)

        snapshots = top10ecosystems.load_snapshots_from_dir(temp_dir)

        self.assertEqual(len(snapshots), 1, "[!] Same-day default + priority-sort snapshots were not de-duplicated.")
        self.assertFalse(
            snapshots[0]["metadata"]["priority_sort_active"],
            "[!] Dedup should prefer the default (non-priority-sort) snapshot when both exist."
        )

    def test_velocity_filename_no_clobber_between_default_and_priority_sort(self):
        """
        [REGRESSION] Verifies build_snapshot_filename() produces distinct filenames for a
        --priority-sort run vs. a default run of the same date window/layer, so --velocity
        snapshots from each mode can coexist on disk without overwriting each other, while
        the default (flag-off) filename shape is unchanged from its historical form.
        """
        start = datetime.datetime(2026, 8, 25, tzinfo=datetime.timezone.utc)
        end = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)

        default_name = top10ecosystems.build_snapshot_filename(start, end, "app")
        priority_name = top10ecosystems.build_snapshot_filename(start, end, "app", priority_sort_active=True)

        self.assertNotEqual(
            default_name, priority_name,
            "[!] --priority-sort snapshot filename collides with the default filename."
        )
        self.assertEqual(
            default_name, "25-08-26_to_01-09-26_app.json",
            "[!] Default filename format regressed away from its historical shape."
        )

    def test_compare_snapshots_golden_master_deltas(self):
        """Validates the comparison engine's delta arithmetic and rank shifts."""
        file_base = os.path.join("src", "test", "resources", "threat_landscape_2026-05-18_app.json")
        file_current = os.path.join("src", "test", "resources", "threat_landscape_2026-05-21_app.json")

        if not os.path.exists(file_base) or not os.path.exists(file_current):
            self.skipTest(f"Snapshot delta verification skipped. Missing: {file_base}")

        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            top10ecosystems.compare_snapshots(file_base=file_base, file_current=file_current, html_output=None)

        output = captured_output.getvalue()
        self.assertNotIn("Snapshot comparison failed", output, "[!] CRITICAL: Engine crashed internally during run!")
        self.assertIn("SECURITY THREAT INTELLIGENCE STREAM MOVEMENT COMPARISON", output)
        self.assertIn("I. ECOSYSTEM ACTIVITY & RANK SHIFTS", output)
        self.assertIn("II. THREAT BEHAVIOR VARIANCE", output)
        self.assertIn("VI. RELATIVE CHURN VELOCITY", output)

    # -------------------------------------------------------------------------
    # MUTATION & FIELD PARITY BREAK GATES: STRICT TEXT ALIGNMENT TRACKS
    # -------------------------------------------------------------------------
    def test_compare_snapshots_strict_text_alignment_good_match(self):
        """[POSITIVE CONTROL] Validates absolute text template alignment against frozen console baselines."""
        import difflib
        file_base = os.path.join("src", "test", "resources", "threat_landscape_2026-05-18_app.json")
        file_current = os.path.join("src", "test", "resources", "threat_landscape_2026-05-21_app.json")
        good_baseline_path = os.path.join("src", "test", "resources", "comparison_console_output.txt")

        if not os.path.exists(good_baseline_path):
            self.skipTest(f"Skipping positive control. Missing baseline asset at: {good_baseline_path}")

        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            top10ecosystems.compare_snapshots(file_base=file_base, file_current=file_current, html_output=None)
        live_output = captured_output.getvalue()

        if UPDATE_GOLDEN_MASTERS:
            # Unlike every other golden-master fixture, this one had no --update branch of its
            # own -- re-minting it meant manually capturing compare_snapshots()'s output and
            # overwriting the file by hand (encoding matters: it's UTF-16 with a BOM, not UTF-8).
            print(f"[+] --update active: Auto-minting frozen baseline asset -> {good_baseline_path}")
            with open(good_baseline_path, "w", encoding="utf-16") as f:
                f.write(live_output)
            return

        try:
            with open(good_baseline_path, "r", encoding="utf-8") as f:
                expected_output = f.read()
        except UnicodeDecodeError:
            with open(good_baseline_path, "r", encoding="utf-16") as f:
                expected_output = f.read()

        if live_output != expected_output:
            live_lines = live_output.splitlines(keepends=True)
            expected_lines = expected_output.splitlines(keepends=True)
            delta = difflib.unified_diff(expected_lines, live_lines, fromfile="BASELINE_FILE", tofile="LIVE_OUTPUT", n=3)
            diff_text = "".join(delta)
            
            self.fail(
                f"\n\n{'='*80}\n"
                f"❌ CRITICAL TEXT ALIGNMENT DRIFT DETECTED IN POSITIVE CONTROL\n"
                f"{'='*80}\n"
                f"Target Reference File: {good_baseline_path}\n\n"
                f"SURGICAL LINE-BY-LINE DELTA:\n"
                f"{diff_text}\n"
                f"{'='*80}\n"
            )

    def test_compare_snapshots_strict_text_alignment_bad_mismatch(self):
        """[NEGATIVE CONTROL] Verifies the suite successfully flags and rejects mutated templates."""
        file_base = os.path.join("src", "test", "resources", "threat_landscape_2026-05-18_app.json")
        file_current = os.path.join("src", "test", "resources", "threat_landscape_2026-05-21_app.json")
        bad_baseline_path = os.path.join("src", "test", "resources", "comparison_console_output_bad.txt")

        if not os.path.exists(bad_baseline_path):
            self.skipTest(f"Skipping negative control break-gate verification. Missing asset: {bad_baseline_path}")

        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            top10ecosystems.compare_snapshots(file_base=file_base, file_current=file_current, html_output=None)
        live_output = captured_output.getvalue()

        try:
            with open(bad_baseline_path, "r", encoding="utf-8") as f:
                expected_output = f.read()
        except UnicodeDecodeError:
            with open(bad_baseline_path, "r", encoding="utf-16") as f:
                expected_output = f.read()

        if live_output == expected_output:
            self.fail(
                f"\n\n{'='*80}\n"
                f"⚠️  NEGATIVE CONTROL BREAK-GATE SECURITY FAULT\n"
                f"{'='*80}\n"
                f"The test engine failed to detect structural inequality against a contaminated file!\n"
                f"{'='*80}\n"
            )

    # -------------------------------------------------------------------------
    # DB WAREHOUSE SYNC REGRESSIONS
    # Each of these reproduces a failure that actually happened: colon-bearing advisory IDs
    # collapsing into garbage, a truncated zip's mtime moving the sync baseline forward past three
    # days of upstream changes, and fetch failures being silently dropped.
    # -------------------------------------------------------------------------
    def test_sync_manifest_path_id_extraction_preserves_colons_in_advisory_ids(self):
        """
        [REGRESSION] Real Red Hat/SUSE/openSUSE/Rocky advisory IDs contain colons. The sync used
        to split the manifest path on ':', collapsing ~74K feed rows into ~185 garbage "IDs" like
        "Red Hat/RHSA-2026" that 404 on the API -- so no incremental sync ever refreshed any of them.
        """
        cases = {
            "Red Hat/RHSA-2026:1234": "RHSA-2026:1234",
            "openSUSE/openSUSE-SU-2026:11976-1": "openSUSE-SU-2026:11976-1",
            "SUSE/SUSE-SU-2025:3305-1": "SUSE-SU-2025:3305-1",
            "Rocky Linux/RLSA-2026:0042": "RLSA-2026:0042",
            "Debian/DEBIAN-CVE-2026-71891": "DEBIAN-CVE-2026-71891",
            "npm/GHSA-abcd-efgh-ijkl.json": "GHSA-abcd-efgh-ijkl",
            "MAL-2026-1": "MAL-2026-1",
        }
        for path, expected in cases.items():
            extracted = db_warehouse.advisory_id_from_manifest_path(path)
            self.assertEqual(extracted, expected, f"[!] Wrong advisory ID extracted from manifest path {path!r}.")
            self.assertNotIn("/", extracted, f"[!] Ecosystem prefix leaked into the advisory ID for {path!r}.")

    def _make_snapshots_conn(self, interval_tos):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute(
            "CREATE TABLE snapshots (snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT, generated_at TEXT NOT NULL, "
            "interval_from TEXT NOT NULL, interval_to TEXT NOT NULL UNIQUE, target_layer TEXT NOT NULL)"
        )
        for value in interval_tos:
            conn.execute("INSERT INTO snapshots (generated_at, interval_from, interval_to, target_layer) VALUES (?, ?, ?, ?)",
                         ("x", "1970-01-01", value, "all"))
        return conn

    def test_sync_baseline_uses_high_water_mark_not_cache_zip_mtime(self):
        """
        [REGRESSION] A truncated/re-downloaded cache zip carries a fresh mtime without the database
        gaining anything. The baseline used to take max(zip mtime, high-water), so a partial
        download on Sep 29 pushed the sync past everything modified Sep 26-29 -- those advisories
        were never ingested. The baseline must follow the database's own recorded high-water mark.
        """
        import tempfile
        utc = datetime.timezone.utc
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            zip_path = os.path.join(tmp, "osv_master_all.zip")
            with open(zip_path, "wb") as f:
                f.write(b"truncated partial download")
            later = datetime.datetime(2026, 9, 29, 20, 54, tzinfo=utc).timestamp()
            os.utime(zip_path, (later, later))

            conn = self._make_snapshots_conn(["2026-04-18", "2026-09-26T21:17:35+00:00"])
            with patch.object(db_warehouse, "LOCAL_ZIP_PATH", zip_path):
                start, source = db_warehouse.resolve_sync_baseline(conn.cursor())
            self.assertEqual(start, datetime.datetime(2026, 9, 26, 20, 17, 35, tzinfo=utc),
                             "[!] Sync baseline followed the cache zip's mtime instead of the recorded high-water mark.")
            self.assertIn("high-water", source)

            conn = self._make_snapshots_conn(["2026-09-26T21:17:35+00:00", "2026-10-03T21:15:51+00:00", "2026-04-18"])
            with patch.object(db_warehouse, "LOCAL_ZIP_PATH", zip_path):
                start, _ = db_warehouse.resolve_sync_baseline(conn.cursor())
            self.assertEqual(start, datetime.datetime(2026, 10, 3, 20, 15, 51, tzinfo=utc),
                             "[!] Sync baseline did not pick the NEWEST high-water mark across snapshot rows.")

    def test_sync_baseline_legacy_anchor_falls_back_only_to_a_valid_zip(self):
        """
        [REGRESSION] Older full builds recorded the literal interval_to "2026-04-18" regardless of
        when they ran. That placeholder is ignored; such a database falls back to its cache zip's
        mtime only if the zip is actually valid, otherwise to 24 hours -- never to a corrupt file's mtime.
        """
        import tempfile, zipfile
        utc = datetime.timezone.utc
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            zip_path = os.path.join(tmp, "osv_master_all.zip")

            with open(zip_path, "wb") as f:
                f.write(b"not a zip")
            conn = self._make_snapshots_conn(["2026-04-18"])
            with patch.object(db_warehouse, "LOCAL_ZIP_PATH", zip_path):
                start, source = db_warehouse.resolve_sync_baseline(conn.cursor())
            expected = datetime.datetime.now(utc) - datetime.timedelta(days=1)
            self.assertLess(abs((start - expected).total_seconds()), 120, "[!] Corrupt zip's mtime was trusted as a baseline.")
            self.assertIn("24-hour", source)

            os.remove(zip_path)
            with zipfile.ZipFile(zip_path, "w") as z:
                z.writestr("a.json", "{}")
            stamp = datetime.datetime(2026, 9, 20, 12, 0, tzinfo=utc).timestamp()
            os.utime(zip_path, (stamp, stamp))
            with patch.object(db_warehouse, "LOCAL_ZIP_PATH", zip_path):
                start, source = db_warehouse.resolve_sync_baseline(conn.cursor())
            self.assertEqual(start, datetime.datetime(2026, 9, 20, 11, 0, tzinfo=utc))
            self.assertIn("legacy fallback", source)

    def test_modification_feed_keeps_newest_timestamp_per_id_and_honours_since(self):
        """
        An advisory listed under several ecosystems collapses to one ID with its newest timestamp;
        `since` is inclusive; colon IDs survive; malformed rows are skipped, not fatal.
        """
        utc = datetime.timezone.utc
        rows = [
            ["2026-10-01T00:00:00Z", "npm/GHSA-aaaa"],
            ["2026-10-03T00:00:00Z", "PyPI/GHSA-aaaa"],
            ["2026-10-02T00:00:00Z", "Red Hat/RHSA-2026:1234"],
            ["not a date", "npm/GHSA-bad"],
            [],
        ]
        everything = db_warehouse.parse_modification_feed(rows)
        self.assertEqual(everything, {
            "GHSA-aaaa": datetime.datetime(2026, 10, 3, tzinfo=utc),
            "RHSA-2026:1234": datetime.datetime(2026, 10, 2, tzinfo=utc),
        })
        recent = db_warehouse.parse_modification_feed(rows, since=datetime.datetime(2026, 10, 2, tzinfo=utc))
        self.assertEqual(set(recent), {"GHSA-aaaa", "RHSA-2026:1234"})
        later = db_warehouse.parse_modification_feed(rows, since=datetime.datetime(2026, 10, 2, 0, 0, 1, tzinfo=utc))
        self.assertEqual(set(later), {"GHSA-aaaa"})

    def test_verify_flags_missing_and_stale_but_not_changes_inside_the_resync_window(self):
        """
        `db_warehouse.py --verify` must (a) report advisories the feed lists that the warehouse lacks,
        (b) report ones whose stored last_modified day is older than the feed's, and (c) NOT report
        changes inside the SYNC_OVERLAP window before the high-water mark, which the next sync
        re-fetches by design (the upstream index/API lag it). It must never write.
        """
        import contextlib
        conn = self._make_snapshots_conn(["2026-10-05T00:00:00+00:00"])
        conn.execute("CREATE TABLE vulnerabilities (advisory_id TEXT PRIMARY KEY, last_modified TEXT)")
        conn.executemany("INSERT INTO vulnerabilities VALUES (?, ?)", [
            ("GHSA-current", "2026-10-02"),
            ("GHSA-stale", "2026-10-01"),
            ("GHSA-lagging", "2026-10-04"),
            ("RHSA-2026:1234", "2026-10-02"),
            ("GHSA-gone-from-feed", "2020-01-01"),
        ])
        feed = "\n".join([
            "2026-10-02T08:00:00Z,npm/GHSA-current",
            "2026-10-03T08:00:00Z,npm/GHSA-stale",
            "2026-10-04T23:30:00Z,npm/GHSA-lagging",
            "2026-10-02T09:00:00Z,Red Hat/RHSA-2026:1234",
            "2026-10-02T10:00:00Z,npm/GHSA-missing",
        ])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ok = db_warehouse.verify_warehouse(conn, feed_text=feed)
        text = out.getvalue()
        self.assertFalse(ok)
        self.assertIn("1 advisories MISSING from warehouse; e.g. GHSA-missing", text)
        self.assertIn("1 advisories STALE in warehouse; e.g. GHSA-stale", text)
        flagged = "".join(line for line in text.splitlines() if "MISSING" in line or "STALE" in line)
        self.assertNotIn("GHSA-lagging", flagged, "[!] A change inside the re-sync window was reported as a failure.")
        self.assertIn("Pending next sync: 1", text)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0], 5, "[!] --verify wrote to the warehouse.")

        conn.execute("DELETE FROM vulnerabilities WHERE advisory_id = 'GHSA-stale'")
        conn.execute("INSERT INTO vulnerabilities VALUES ('GHSA-stale', '2026-10-03')")
        conn.execute("INSERT INTO vulnerabilities VALUES ('GHSA-missing', '2026-10-02')")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(db_warehouse.verify_warehouse(conn, feed_text=feed), "[!] A repaired warehouse should verify clean.")

    def test_feed_cache_expiry_is_not_reported_as_a_forced_refresh(self):
        """
        [REGRESSION] EPSS/KEV pipelines passed force=(force or is_too_old) down to the downloader, so a
        merely expired cache logged "[Reason: Forced]". Only an explicit force may be forced.
        """
        import contextlib, tempfile, time
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE epss_scores (cve_id TEXT PRIMARY KEY, epss_score REAL, percentile REAL, model_date TEXT)")
        conn.execute("CREATE TABLE kev_catalog (cve_id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO epss_scores VALUES ('CVE-1', 0.1, 0.1, '2026-10-01')")
        conn.execute("INSERT INTO kev_catalog VALUES ('CVE-1')")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            epss_path, kev_path = os.path.join(tmp, "epss.gz"), os.path.join(tmp, "kev.json")
            old = time.time() - 48 * 3600
            for path in (epss_path, kev_path):
                with open(path, "wb") as f:
                    f.write(b"x")
                os.utime(path, (old, old))
            seen = {}
            with patch.object(db_warehouse, "EPSS_GZ_PATH", epss_path), patch.object(db_warehouse, "KEV_JSON_PATH", kev_path), \
                 patch.object(db_warehouse, "download_epss_feed", lambda force=False: seen.__setitem__("epss", force) or False), \
                 patch.object(db_warehouse, "download_kev_feed", lambda force=False: seen.__setitem__("kev", force) or False), \
                 contextlib.redirect_stdout(io.StringIO()):
                db_warehouse.run_epss_pipeline(conn)
                db_warehouse.run_kev_pipeline(conn)
        self.assertEqual(seen, {"epss": False, "kev": False})

    def test_master_archive_download_never_leaves_a_truncated_zip_at_the_cache_path(self):
        """
        [REGRESSION] The download used to stream straight to the cache path, so an interrupted run
        left an unreadable zip there with a fresh mtime. It must now only ever rename a fully
        received, valid zip into place, and leave nothing behind on failure.
        """
        import tempfile, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.json", "{}" * 500)
        good = buf.getvalue()

        class FakeResponse:
            def __init__(self, payload, claimed_length):
                self.payload = payload
                self.headers = {"Content-Length": str(claimed_length)}
            def raise_for_status(self): pass
            def iter_content(self, chunk_size=1):
                yield self.payload

        scenarios = [
            ("truncated body", FakeResponse(good[:-20], len(good)), False),
            ("full length but not a zip", FakeResponse(b"x" * len(good), len(good)), False),
            ("complete valid zip", FakeResponse(good, len(good)), True),
        ]
        for label, response, should_succeed in scenarios:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                zip_path = os.path.join(tmp, "osv_master_all.zip")
                with patch.object(db_warehouse, "CACHE_DIR", tmp), \
                     patch.object(db_warehouse, "LOCAL_ZIP_PATH", zip_path), \
                     patch.object(db_warehouse.requests, "get", return_value=response), \
                     patch('sys.stdout', io.StringIO()):
                    db_warehouse.download_master_archive()
                self.assertEqual(os.path.exists(zip_path), should_succeed, f"[!] Wrong cache-path outcome for scenario: {label}.")
                self.assertFalse(os.path.exists(zip_path + ".part"), f"[!] Stray .part file left behind for scenario: {label}.")
                if should_succeed:
                    self.assertTrue(zipfile.is_zipfile(zip_path))

    def test_incremental_sync_requests_true_colon_ids_and_holds_high_water_for_failures(self):
        """
        [REGRESSION] End-to-end against a faked feed and API: colon-bearing IDs must be requested
        under their TRUE IDs, entries older than the baseline must not be requested, a 404 must
        not block progress, and a persistent fetch failure must hold the high-water mark just
        before it (so the next sync retries it) instead of silently advancing past it.
        """
        import tempfile
        utc = datetime.timezone.utc
        requested = []
        flaky_recovers = {"value": False}

        class FakeApiResponse:
            def __init__(self, status, vid=None):
                self.status_code = status
                self._vid = vid
            def json(self):
                return {"id": self._vid, "published": "2024-05-01T00:00:00Z", "modified": "2024-05-02T10:00:00Z",
                        "affected": [{"package": {"ecosystem": "npm", "name": "pkg"}, "versions": ["1.0.0"]}]}

        class FakeSession:
            def __enter__(self): return self
            def __exit__(self, *exc): return False
            def mount(self, *args, **kwargs): pass
            def get(self, url, timeout=None):
                vid = url[len(db_warehouse.OSV_API_URL):]
                requested.append(vid)
                if vid == "GONE-1": return FakeApiResponse(404)
                if vid == "FLAKY-1" and not flaky_recovers["value"]: return FakeApiResponse(500)
                return FakeApiResponse(200, vid)

        class FakeFeedResponse:
            text = ("2024-05-02T10:00:00Z,npm/OK-1\n"
                    "2024-05-02T11:00:00Z,Red Hat/RHSA-2026:1234\n"
                    "2024-05-02T12:00:00Z,npm/GONE-1\n"
                    "2024-05-02T13:00:00Z,npm/FLAKY-1\n"
                    "2024-04-01T00:00:00Z,npm/OLD-1\n")
            def raise_for_status(self): pass

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            tmp_db = os.path.join(tmp, "t.db")
            with patch.object(db_warehouse, "DB_DIR", tmp), \
                 patch.object(db_warehouse, "DB_PATH", tmp_db), \
                 patch.object(db_warehouse, "LOCAL_ZIP_PATH", os.path.join(tmp, "none.zip")), \
                 patch.object(db_warehouse.requests, "get", return_value=FakeFeedResponse()), \
                 patch.object(db_warehouse.requests, "Session", FakeSession), \
                 patch.object(db_warehouse.time, "sleep", lambda *_: None), \
                 patch('sys.stdout', io.StringIO()):
                self.assertNotEqual(os.path.abspath(db_warehouse.DB_PATH), os.path.abspath("database/threat_stream.db"),
                                    "[!] Test would have touched the production warehouse.")
                conn = db_warehouse.init_database()
                conn.execute("INSERT INTO snapshots (generated_at, interval_from, interval_to, target_layer) VALUES (?, ?, ?, ?)",
                             ("x", "1970-01-01", "2024-05-01T00:00:00+00:00", "incremental_sync"))
                conn.commit()

                db_warehouse.sync_incremental_window(conn)

                self.assertIn("RHSA-2026:1234", requested, "[!] Colon-bearing advisory was not requested under its true ID.")
                self.assertNotIn("Red Hat/RHSA-2026", requested, "[!] Garbage colon-split ID was requested.")
                self.assertNotIn("OLD-1", requested, "[!] An entry older than the baseline was re-fetched.")
                ingested = {r[0] for r in conn.execute("SELECT advisory_id FROM vulnerabilities")}
                self.assertEqual(ingested, {"OK-1", "RHSA-2026:1234"})

                held = conn.execute("SELECT interval_to FROM snapshots ORDER BY snapshot_id DESC LIMIT 1").fetchone()[0]
                self.assertEqual(datetime.datetime.fromisoformat(held), datetime.datetime(2024, 5, 2, 12, 59, 59, tzinfo=utc),
                                 "[!] High-water mark must be held just before the earliest failed fetch (FLAKY-1), not advanced past it.")

                flaky_recovers["value"] = True
                db_warehouse.sync_incremental_window(conn)
                advanced = conn.execute("SELECT interval_to FROM snapshots ORDER BY snapshot_id DESC LIMIT 1").fetchone()[0]
                self.assertGreater(datetime.datetime.fromisoformat(advanced), datetime.datetime(2025, 1, 1, tzinfo=utc),
                                   "[!] High-water mark did not advance once every fetch succeeded.")
                self.assertIn("FLAKY-1", {r[0] for r in conn.execute("SELECT advisory_id FROM vulnerabilities")})
                conn.close()


    # -------------------------------------------------------------------------
    # INGEST FIXTURE TESTS (db_warehouse.parse_osv_json -- the code that actually fills the DB)
    # Small hand-built OSV records with exact expected output. Every case here is a real bug that
    # got through the old aggregate-count golden masters, because those compared totals taken
    # from a live database rather than asserting what a single record should become.
    # -------------------------------------------------------------------------
    _ROW_FIELDS = ("advisory_id package_name ecosystems cvss_score blast_radius threat_profile last_modified "
                   "malware_vector vulnerable_versions dwell_days withdrawn_date published_date cve_alias aliases "
                   "cwe_ids package_names_by_ecosystem purls_by_ecosystem repo_anchor fixed_by_ecosystem").split()

    @staticmethod
    def _osv_record(**overrides):
        record = {
            "id": "GHSA-test-0001",
            "published": "2026-01-01T00:00:00Z",
            "modified": "2026-01-10T00:00:00Z",
            "summary": "A vulnerability",
            "details": "",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "pkg"},
                "versions": ["1.0.0"],
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
            }],
            "references": [],
        }
        record.update(overrides)
        return record

    def _ingest(self, **overrides):
        return dict(zip(self._ROW_FIELDS, db_warehouse.parse_osv_json(self._osv_record(**overrides))))

    def test_ecosystem_tag_bucketing_has_one_shared_memoized_implementation(self):
        """
        [INTEGRITY] db_warehouse.py (at ingest) and top10ecosystems.py (reading the live stream)
        both bucket raw OSV ecosystem tags. They used to each carry their own copy of the logic and
        of the ecosystem lists, hand-mirrored -- which is how the "pub" vs "Public" bug survived in
        one place after being fixed in the other. There is now exactly one implementation
        (osv_ecosystems.py); this fails if a second copy creeps back, or the memoization is lost
        (the bucketing runs ~4M times per dashboard window; caching it took one from 64s to 25s).
        """
        import osv_ecosystems
        for name in ("clean_ecosystem_tag", "get_artifact_layer"):
            self.assertIs(getattr(top10ecosystems, name), getattr(osv_ecosystems, name), f"[!] top10ecosystems.{name} is not the shared implementation.")
        self.assertIs(db_warehouse.clean_ecosystem_tag, osv_ecosystems.clean_ecosystem_tag, "[!] db_warehouse.clean_ecosystem_tag is not the shared implementation.")

        for path in ("top10ecosystems.py", "db_warehouse.py"):
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            self.assertNotIn('"Alpaquita Linux"', text, f"[!] {path} has its own copy of the ecosystem lists again -- import them from osv_ecosystems.")
            self.assertNotIn('"crates.io": "Crates.io"', text, f"[!] {path} has its own copy of the hard-mapping table again -- import it from osv_ecosystems.")

        self.assertTrue(hasattr(osv_ecosystems.clean_ecosystem_tag, "cache_info"),
                        "[!] clean_ecosystem_tag lost its memoization -- a dashboard window gets ~2.6x slower.")

        expected = {"npm": "npm", "PyPI": "PyPI", "maven": "Maven (Java)", "Maven": "Maven (Java)", "Go": "Go (Golang)",
                    "crates.io": "Crates.io", "GIT": "GIT", "Debian:11": "Debian", "Debian:12": "Debian", "Pub": "Pub",
                    "  NPM  ": "npm", "0001-1": "Other", "": "Other",
                    "Android": "Android", "Wolfi": "Other", "Red Hat": "Other", "SUSE": "Other", "Root": "Other", "Julia": "Other"}
        for tag, bucket in expected.items():
            self.assertEqual(osv_ecosystems.clean_ecosystem_tag(tag), bucket, f"[!] Wrong bucket for {tag!r}.")
        self.assertNotEqual(osv_ecosystems.clean_ecosystem_tag("SUSE:Linux Enterprise Module for Public Cloud 12"), "Pub")
        self.assertEqual(set(osv_ecosystems.MASTER_TRACKS),
                         set(osv_ecosystems.KNOWN_CONTAINER_ECOSYSTEMS) | set(osv_ecosystems.KNOWN_REGISTRY_ECOSYSTEMS) | {"GIT", "Android", "Untagged Commit Hash/CVE Noise"})
        self.assertNotIn("Other", osv_ecosystems.MASTER_TRACKS, "[!] The fallback bucket became a match target: raw tags containing the word 'other' would bucket into it.")
        self.assertEqual(osv_ecosystems.OUTPUT_TRACKS, osv_ecosystems.MASTER_TRACKS + ["Other"])

    def test_ingest_unrecognised_ecosystems_land_in_other_never_in_android(self):
        """
        [REGRESSION] Any ecosystem tag outside the known tracks used to bucket into "Android" -- ~20% of
        the OSV feed (Wolfi, Red Hat, SUSE, Root, ...) merged into a genuine ecosystem that is ~0.8% of
        it, inflating the container layer's #3 entry and its dwell numbers. Unknown tags go to
        "Other"; a real Android tag stays Android; an affected-less record is "Other" too.
        """
        def ecosystems_for(tag):
            return json.loads(self._ingest(affected=[{"package": {"ecosystem": tag, "name": "pkg"}, "versions": ["1"]}])["ecosystems"])
        self.assertEqual(ecosystems_for("Wolfi"), ["Other"])
        self.assertEqual(ecosystems_for("Red Hat"), ["Other"])
        self.assertEqual(ecosystems_for("Android"), ["Android"])
        self.assertEqual(json.loads(self._ingest(affected=[])["ecosystems"]), ["Other"])
        self.assertEqual(top10ecosystems.get_artifact_layer("Other"), "Global Baseline Noise",
                         "[!] The fallback bucket must not count toward the container or app layers.")

    def test_top_records_for_ecosystem_matches_the_naive_full_sort(self):
        """
        [EQUIVALENCE] Sections IV and VII pick the top 10 advisories per ecosystem. That used to
        rescan the whole ~2M-entry lookup per ecosystem and sort every match; it now uses a
        one-pass index and heapq.nsmallest. This pins identical selection AND identical tie
        resolution against the naive algorithm it replaced, on data with many deliberate ties,
        advisories spanning several ecosystems, a blank ID (excluded), and ecosystem names that
        match several index keys or none.
        """
        import random
        rng = random.Random(3)
        names = ["npm", "PyPI", "Maven (Java)", "Debian", "Android"]
        lookup = {}
        for i in range(400):
            lookup[f"ID-{i:04d}"] = {"ecosystems": rng.sample(names, rng.randint(1, 3)),
                                     "cvss_score": float(rng.choice([0, 5.0, 7.5, 9.8])), "blast_radius": rng.choice([0, 1, 3, 50]),
                                     "package_name": f"pkg{i}", "last_modified": "2026-01-01"}
        lookup["   "] = {"ecosystems": ["npm"], "cvss_score": 10.0, "blast_radius": 999, "package_name": "blank", "last_modified": "2026-01-01"}

        sort_key = lambda vid, meta: (-meta["cvss_score"], -meta["blast_radius"])
        for eco in names + ["npm PyPI", "Maven (Java) Debian", "Nonexistent"]:
            eco_lower = eco.lower()
            naive = sorted(((vid, meta) for vid, meta in lookup.items()
                            if vid.strip() and any(raw.lower() in eco_lower for raw in meta["ecosystems"])),
                           key=lambda pair: sort_key(*pair))[:10]
            actual = top10ecosystems._top_records_for_ecosystem(lookup, eco, sort_key)
            self.assertEqual([vid for vid, _ in actual], [vid for vid, _ in naive], f"[!] Top-10 selection diverged for ecosystem {eco!r}.")
            self.assertTrue(all(meta is lookup[vid] for vid, meta in actual))

    def test_lookup_loads_light_fields_up_front_and_hydrates_heavy_details_on_demand(self):
        """
        [CONTRACT] build_ghsa_from_db() used to parse five JSON columns for every one of ~2M
        advisories on every run, though only Section VIII (advisories in the current window) and
        project-manifest matching read them. The lookup now carries only the light fields, and
        hydrate_lookup_details() fills in the heavy ones for just the IDs asked for. Built from a
        throwaway warehouse through the real ingest path, so it exercises the same parser that
        fills production.
        """
        import tempfile
        records = [
            self._osv_record(id="GHSA-hyd-0001", references=[{"url": "https://github.com/netty/netty/security/advisories/GHSA-x"}],
                             affected=[{"package": {"ecosystem": "npm", "name": "pkg-a", "purl": "pkg:npm/pkg-a"}, "versions": ["1.0.0", "1.0.1"],
                                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.2"}]}]},
                                       {"package": {"ecosystem": "PyPI", "name": "pkg-a"}, "versions": ["2.0"]}]),
            self._osv_record(id="GHSA-hyd-0002"),
            self._osv_record(id="SUSE-SU-2026:9-1"),
        ]
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            tmp_db = os.path.join(tmp, "t.db")
            with patch.object(db_warehouse, "DB_DIR", tmp), patch.object(db_warehouse, "DB_PATH", tmp_db):
                self.assertNotEqual(os.path.abspath(tmp_db), os.path.abspath(top10ecosystems.DB_PATH))
                conn = db_warehouse.init_database()
                conn.executemany("""INSERT INTO vulnerabilities (advisory_id, package_name, ecosystems, cvss_score, blast_radius,
                    threat_profile, last_modified, malware_vector, vulnerable_versions, dwell_days, withdrawn_date, published_date,
                    cve_alias, aliases, cwe_ids, package_names_by_ecosystem, purls_by_ecosystem, repo_anchor, fixed_by_ecosystem)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", [db_warehouse.parse_osv_json(r) for r in records])
                conn.commit()
                conn.close()

            with patch('sys.stdout', io.StringIO()):
                lookup = top10ecosystems.build_ghsa_from_db(db_path=tmp_db)
            self.assertEqual(set(lookup), {"GHSA-hyd-0001", "GHSA-hyd-0002", "SUSE-SU-2026:9-1"})

            light = {"ecosystems", "package_name", "type", "vector", "dwell_days", "blast_radius", "cvss_score", "last_modified"}
            heavy = {"vulnerable_versions", "package_names_by_ecosystem", "purls_by_ecosystem", "repo_anchor", "fixed_by_ecosystem"}
            for entry in lookup.values():
                self.assertEqual(set(entry), light, "[!] The lookup should carry only the light fields until hydrated.")

            self.assertEqual(top10ecosystems.hydrate_lookup_details(lookup, ["GHSA-hyd-0001", "NOT-IN-LOOKUP"], tmp_db), 1)
            hydrated = lookup["GHSA-hyd-0001"]
            self.assertTrue(heavy <= set(hydrated))
            self.assertEqual(hydrated["vulnerable_versions"], {"1.0.0", "1.0.1", "2.0"})
            self.assertEqual(hydrated["package_names_by_ecosystem"], {"npm": ["pkg-a"], "PyPI": ["pkg-a"]})
            self.assertEqual(hydrated["purls_by_ecosystem"], {"npm": ["pkg:npm/pkg-a"]})
            self.assertEqual(hydrated["repo_anchor"], "netty/netty")
            self.assertEqual(hydrated["fixed_by_ecosystem"], {"npm": True, "PyPI": False})
            self.assertEqual(set(lookup["GHSA-hyd-0002"]), light, "[!] Hydrating one advisory must not touch the others.")

            self.assertEqual(top10ecosystems.hydrate_lookup_details(lookup, ["GHSA-hyd-0001"], tmp_db), 0, "[!] Hydration is not idempotent.")
            self.assertEqual(top10ecosystems.hydrate_lookup_details(lookup, ["GHSA-hyd-0002", "SUSE-SU-2026:9-1"], tmp_db), 2)
            self.assertIsNone(lookup["GHSA-hyd-0002"]["repo_anchor"])      # hydrated even when the value is NULL/None

    def test_project_alert_order_is_deterministic(self):
        """
        [REGRESSION] Project-manifest alerts were deduplicated through a set and sorted by package
        name alone, so advisories sharing a package printed in a different order on every run
        (Python randomizes string hashing per process). Ties now break on advisory ID.
        """
        base = [(f"ROOT-APP-PYPI-CVE-2026-{n:05d}", "requests", "PyPI", "Vulnerability Fix (New Entry)") for n in (99, 7, 31, 4)]
        base += [("ROOT-APP-PYPI-CVE-2020-1", "cvss", "PyPI", "Vulnerability Fix (Update)")]
        expected = [base[4]] + sorted(base[:4], key=lambda a: a[0])
        import random
        rng = random.Random(11)
        for _ in range(25):
            shuffled = base + base[:2]             # duplicates must collapse too
            rng.shuffle(shuffled)
            self.assertEqual(top10ecosystems._sorted_project_alerts(shuffled), expected)

    def test_scatter_pair_export_is_deterministic_and_capped(self):
        """
        [REGRESSION] Chart V's CVSS-vs-EPSS points are randomly down-sampled to a cap per
        ecosystem. The sampling was unseeded, so the same data exported different points every
        run. It must be reproducible regardless of pool insertion order, respect the cap, and never
        drop a KEV-listed point (the rare ones the chart exists to highlight).
        """
        cap = top10ecosystems._MAX_SCATTER_POINTS_PER_ECO
        entries = [(f"ID-{i}", (1.0 + (i % 90) / 10, (i % 997) / 1000.0, i % 400 == 0)) for i in range(cap + 400)]
        forward = {"npm": dict(entries), "PyPI": dict(entries[:50])}
        backward = {"npm": dict(reversed(entries)), "PyPI": dict(reversed(entries[:50]))}
        first = top10ecosystems._extract_cvss_epss_pairs(forward)
        self.assertEqual(first, top10ecosystems._extract_cvss_epss_pairs(forward))
        self.assertEqual(first, top10ecosystems._extract_cvss_epss_pairs(backward), "[!] Sampling depends on pool insertion order.")
        self.assertEqual(len(first["npm"]), cap)
        self.assertEqual(len(first["PyPI"]), 50)
        expected_kev = sum(1 for _, (_, _, kev) in entries if kev)
        self.assertEqual(sum(p[2] for p in first["npm"]), expected_kev, "[!] KEV-listed points must survive down-sampling.")

    def test_scatter_pair_export_skips_points_missing_cvss_or_epss(self):
        pools = {"npm": {"A": (0.0, 0.5, False), "B": (7.5, None, False), "C": (7.5, 0.5, True)}}
        self.assertEqual(top10ecosystems._extract_cvss_epss_pairs(pools), {"npm": [[7.5, 0.5, 1]]})

    def test_ranking_no_longer_uses_blast_radius(self):
        """
        [REGRESSION] Blast radius (affected-version count) correlates negatively with EPSS and carries no
        KEV signal, so it must not break ties in any ranking mode: equal-CVSS advisories order by id.
        """
        small = {"cvss_score": 7.5, "blast_radius": 1}
        huge = {"cvss_score": 7.5, "blast_radius": 5000}
        for mode in ("default", "kev", "epss"):
            self.assertLess(top10ecosystems._priority_sort_key(small, "A", mode), top10ecosystems._priority_sort_key(huge, "B", mode))
            self.assertLess(top10ecosystems._priority_sort_key(huge, "A", mode), top10ecosystems._priority_sort_key(small, "B", mode),
                            f"[!] Blast radius is still influencing the '{mode}' ranking.")
        kev_low = {"cvss_score": 4.0, "kev_date_added": "2026-09-01", "epss_score": 0.1}
        epss_high = {"cvss_score": 9.0, "epss_score": 0.9}
        self.assertLess(top10ecosystems._priority_sort_key(kev_low, "B", "kev"), top10ecosystems._priority_sort_key(epss_high, "A", "kev"))
        self.assertLess(top10ecosystems._priority_sort_key(epss_high, "B", "epss"), top10ecosystems._priority_sort_key(kev_low, "A", "epss"))

    def test_section_iv_shows_epss_and_kev_instead_of_blast_radius(self):
        import contextlib
        profile = {}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            top10ecosystems.print_section_iv_threat_metabolism(
                ["npm", "PyPI"], {}, {"npm": [10.0], "PyPI": [20.0]}, {"npm": [5, 7], "PyPI": [100]}, {},
                datetime.datetime(2026, 10, 1), profile,
                spatial_epss={"npm": [0.1, 0.3]}, spatial_kev_hits={"npm": 2})
        out = buf.getvalue()
        self.assertIn("Avg EPSS (n)", out)
        self.assertIn("KEV Hits", out)
        self.assertNotIn("Blast", out, "[!] Section IV still prints blast radius.")
        self.assertIn("20.0% (n=2)", out)
        self.assertEqual(profile["npm"]["avg_epss"], 0.2)
        self.assertEqual((profile["npm"]["epss_sample"], profile["npm"]["kev_hits"]), (2, 2))
        self.assertIsNone(profile["PyPI"]["avg_epss"])
        self.assertEqual(profile["npm"]["avg_blast_radius"], 6.0, "[!] --compare still reads avg_blast_radius from snapshots; keep exporting it.")

    def test_lookup_loader_always_enriches_with_epss_and_kev_when_present(self):
        import tempfile
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, "enrich.db")
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE vulnerabilities (advisory_id TEXT PRIMARY KEY, package_name TEXT, cvss_score REAL, blast_radius INTEGER, "
                         "threat_profile TEXT, ecosystems TEXT, last_modified TEXT, malware_vector TEXT, dwell_days REAL, cve_alias TEXT)")
            conn.execute("CREATE TABLE epss_scores (cve_id TEXT PRIMARY KEY, epss_score REAL, percentile REAL, model_date TEXT)")
            conn.execute("CREATE TABLE kev_catalog (cve_id TEXT PRIMARY KEY, date_added TEXT, due_date TEXT)")
            conn.executemany("INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?)", [
                ("GHSA-1", "a", 9.0, 1, "t", '["npm"]', "2026-09-01", "", 1.0, "CVE-1"),
                ("GHSA-2", "b", 5.0, 1, "t", '["npm"]', "2026-09-01", "", 1.0, "CVE-2"),
                ("GHSA-3", "c", 5.0, 1, "t", '["npm"]', "2026-09-01", "", 1.0, None)])
            conn.execute("INSERT INTO epss_scores VALUES ('CVE-1', 0.8, 0.99, '2026-10-01')")
            conn.execute("INSERT INTO epss_scores VALUES ('CVE-2', 0.01, 0.2, '2026-10-01')")
            conn.execute("INSERT INTO kev_catalog VALUES ('CVE-1', '2026-09-02', '2026-09-23')")
            conn.commit()
            conn.close()
            import contextlib
            with contextlib.redirect_stdout(io.StringIO()):
                lookup = top10ecosystems.build_ghsa_from_db(db_path=path)
            self.assertEqual((lookup["GHSA-1"]["epss_score"], lookup["GHSA-1"]["kev_date_added"]), (0.8, "2026-09-02"))
            self.assertEqual(lookup["GHSA-2"]["epss_score"], 0.01)
            self.assertNotIn("kev_date_added", lookup["GHSA-2"], "Entries with no KEV listing must not carry the key.")
            self.assertNotIn("epss_score", lookup["GHSA-3"], "Entries with no CVE alias must not carry enrichment keys.")

    def test_ingest_cvss_malware_override(self):
        """Explicitly malicious payloads max out at 10.0 regardless of any severity data."""
        self.assertEqual(db_warehouse.extract_production_cvss({"id": "MAL-2026-9999"}), 10.0)
        self.assertEqual(db_warehouse.extract_production_cvss({"id": "GHSA-xxxx", "summary": "This is a malware package"}), 10.0)

    def test_ingest_cvss_v3_vector_scores_via_first_library(self):
        vuln = {"id": "GHSA-xxxx", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(db_warehouse.extract_production_cvss(vuln), 9.8)

    def test_ingest_cvss_empty_severity_is_zero(self):
        self.assertEqual(db_warehouse.extract_production_cvss({"id": "CVE-2026-0000", "severity": []}), 0.0)

    def test_ingest_advisory_id_with_colon_is_preserved(self):
        """Red Hat/SUSE/Rocky IDs contain colons; ingest must keep them intact."""
        self.assertEqual(self._ingest(id="SUSE-SU-2026:1234-1")["advisory_id"], "SUSE-SU-2026:1234-1")

    def test_ingest_malware_classifier_trusts_keywords_only_when_cwes_corroborate(self):
        """
        [REGRESSION] A bug IN a malware scanner (GuardDog: CWE-116, summary mentions "malicious
        package content") and a privilege-escalation bug that merely mentions "backdoor" accounts
        were both flagged as malware by a bare keyword match. Keywords now count only when the
        advisory's own CWEs corroborate (CWE-506 present, or no CWE assigned at all).
        """
        scanner_bug = self._ingest(summary="Terminal escape injection from malicious package content",
                                   database_specific={"cwe_ids": ["CWE-116"]})
        self.assertFalse(scanner_bug["threat_profile"].startswith("Malware"), scanner_bug["threat_profile"])

        privesc = self._ingest(summary="Lets an attacker create backdoor service accounts",
                               database_specific={"cwe_ids": ["CWE-269", "CWE-284"]})
        self.assertFalse(privesc["threat_profile"].startswith("Malware"), privesc["threat_profile"])

        real_no_cwe = self._ingest(summary="Typosquat of a popular package")
        self.assertTrue(real_no_cwe["threat_profile"].startswith("Malware"), real_no_cwe["threat_profile"])

        real_cwe_506 = self._ingest(summary="Package contains a backdoor", database_specific={"cwe_ids": ["CWE-506"]})
        self.assertTrue(real_cwe_506["threat_profile"].startswith("Malware"), real_cwe_506["threat_profile"])

        self.assertTrue(self._ingest(id="MAL-2026-1")["threat_profile"].startswith("Malware"))

    def test_ingest_suse_public_cloud_does_not_become_the_pub_ecosystem(self):
        """
        [REGRESSION] "pub" is a substring of "Public", so SUSE's "...Module for Public Cloud 12"
        ecosystem tag was bucketed into the Dart/Flutter "Pub" registry, which then fed Section
        VIII false cross-registry pairs. Tags must match at token boundaries only.
        """
        affected = [{"package": {"ecosystem": "SUSE:Linux Enterprise Module for Public Cloud 12", "name": "python-pip"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]}]
        ecosystems = json.loads(self._ingest(id="SUSE-SU-2026:1-1", affected=affected)["ecosystems"])
        self.assertNotIn("Pub", ecosystems)

        real_pub = [{"package": {"ecosystem": "Pub", "name": "http"}, "versions": ["1.0.0"]}]
        self.assertIn("Pub", json.loads(self._ingest(affected=real_pub)["ecosystems"]))

    def test_ingest_cve_mirror_reference_is_not_a_repo_anchor(self):
        """
        [REGRESSION] Many advisories (Chainguard's CGA-* especially) cite the CVE Project's own
        record mirror (cveproject/cvelistv5) as a reference. It must not become the advisory's
        repo anchor -- it had become ~24% of all stored anchors, which Section VIII reads as
        "same upstream project", producing false cross-registry matches.
        """
        mirror = [{"url": "https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/1xxx/CVE-2026-1.json"}]
        self.assertIsNone(self._ingest(references=mirror)["repo_anchor"])

        mixed = mirror + [{"url": "https://github.com/netty/netty/security/advisories/GHSA-xxxx"}]
        self.assertEqual(self._ingest(references=mixed)["repo_anchor"], "netty/netty")

    def test_ingest_republished_record_is_new_entry_and_aged_record_is_update(self):
        """
        Classification and dwell follow published vs modified. A record re-issued with
        published == modified (Root.io does this) is a "New Entry" with zero dwell; one modified
        weeks after publication is an "Update" whose dwell is that gap in days.
        """
        fresh = self._ingest(published="2026-09-30T00:00:00Z", modified="2026-09-30T12:00:00Z")
        self.assertEqual(fresh["threat_profile"], "Vulnerability Fix (New Entry)")
        self.assertEqual(fresh["dwell_days"], 0)

        aged = self._ingest(published="2026-05-01T00:00:00Z", modified="2026-05-22T00:00:00Z")
        self.assertEqual(aged["threat_profile"], "Vulnerability Fix (Update)")
        self.assertEqual(aged["dwell_days"], 21)

        no_fix = self._ingest(affected=[{"package": {"ecosystem": "npm", "name": "pkg"}, "versions": ["1.0.0"]}])
        self.assertEqual(no_fix["threat_profile"], "Metadata Correction / Adjustments")

    def test_ingest_withdrawn_record_is_classified_withdrawn(self):
        row = self._ingest(withdrawn="2026-03-01T00:00:00Z")
        self.assertEqual(row["threat_profile"], "Withdrawn / Retracted Advisory")
        self.assertEqual(row["withdrawn_date"], "2026-03-01")

    def test_ingest_blast_radius_is_enumerated_version_count_and_zero_for_range_only_records(self):
        """
        blast_radius is the count of version strings an advisory enumerates. Go-style records list
        affected scope only as ranges, so they legitimately score 0 -- a known limitation of this
        metric, pinned here so nobody mistakes it for "no impact".
        """
        enumerated = [{"package": {"ecosystem": "npm", "name": "pkg"}, "versions": ["1.0.0", "1.0.1", "1.0.2"]}]
        self.assertEqual(self._ingest(affected=enumerated)["blast_radius"], 3)

        range_only = [{"package": {"ecosystem": "Go", "name": "example.com/mod"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.64.0"}]}]}]
        self.assertEqual(self._ingest(affected=range_only)["blast_radius"], 0)

    # -------------------------------------------------------------------------
    # MISSING-WAREHOUSE BEHAVIOR (the file-only/ZIP fallback was removed)
    # -------------------------------------------------------------------------
    def test_missing_warehouse_is_a_hard_error_not_a_silent_zip_fallback(self):
        """
        [REGRESSION] A missing or unreadable warehouse used to silently fall back to downloading
        and streaming a ~2.6GB ZIP, producing different data with no warning. It must now stop
        with a clear message instead.
        """
        missing = os.path.join("output", "definitely_not_a_warehouse.db")
        with self.assertRaises(FileNotFoundError) as ctx:
            top10ecosystems.build_ghsa_from_db(db_path=missing)
        self.assertIn("db_warehouse.py", str(ctx.exception))

        with patch('sys.stdout', io.StringIO()), self.assertRaises(SystemExit) as exit_ctx:
            top10ecosystems.require_warehouse(missing)
        self.assertEqual(exit_ctx.exception.code, 1)

    # -------------------------------------------------------------------------
    # DATABASE HEALTH INVARIANTS (read-only checks of the live warehouse)
    # Deliberately NOT exact values: these hold after any refresh, so they never need re-minting.
    # They would have caught the problems found in this warehouse in practice: ~74K advisories
    # whose IDs were mangled by the sync, ~24% of repo anchors polluted by the CVE mirror, bogus
    # Pub tags on SUSE advisories, and a sync high-water mark days ahead of the actual data.
    # -------------------------------------------------------------------------
    def _warehouse(self):
        if not os.path.exists(top10ecosystems.DB_PATH):
            self.fail(f"[!] Warehouse missing at {top10ecosystems.DB_PATH}. Build it with: python db_warehouse.py")
        return sqlite3.connect(f"file:{top10ecosystems.DB_PATH}?mode=ro", uri=True)

    def _scalar(self, sql, params=()):
        conn = self._warehouse()
        try:
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()

    def test_db_health_no_advisory_ids_contain_a_slash(self):
        """An ID with '/' is an ecosystem prefix that leaked into the ID (a parsing bug), never a real advisory."""
        self.assertEqual(self._scalar("SELECT COUNT(*) FROM vulnerabilities WHERE advisory_id LIKE '%/%'"), 0)

    def test_db_health_repo_anchor_is_not_polluted_by_the_cve_mirror(self):
        self.assertEqual(self._scalar("SELECT COUNT(*) FROM vulnerabilities WHERE repo_anchor = 'cveproject/cvelistv5'"), 0,
                         "[!] CVE-mirror repo anchors are back -- the warehouse was built or synced with stale parsing logic. Rebuild it.")

    def test_db_health_android_is_not_a_catch_all_bucket(self):
        total = self._scalar("SELECT COUNT(*) FROM vulnerabilities")
        android = self._scalar("SELECT COUNT(*) FROM vulnerabilities WHERE ecosystems LIKE '%\"Android\"%'")
        self.assertLess(android, total * 0.02,
                        f"[!] {android:,} of {total:,} advisories are tagged Android (genuine Android is well under 1%). "
                        "The unrecognised-ecosystem fallback is merging into it again, or the warehouse predates the 'Other' bucket. Rebuild it.")
        self.assertGreater(self._scalar("SELECT COUNT(*) FROM vulnerabilities WHERE ecosystems LIKE '%\"Other\"%'"), 0,
                           "[!] No advisory is tagged Other -- the warehouse predates the 'Other' bucket. Rebuild it.")

    def test_db_health_no_suse_advisory_is_tagged_pub(self):
        self.assertEqual(self._scalar("SELECT COUNT(*) FROM vulnerabilities WHERE advisory_id LIKE 'SUSE-%' AND ecosystems LIKE '%\"Pub\"%'"), 0,
                         "[!] SUSE advisories tagged Pub -- the 'pub' vs 'Public' substring collision is back. Rebuild the warehouse.")

    def test_db_health_classification_columns_are_well_formed(self):
        allowed = ("Malware (New Entry)", "Malware (Incremental Update)", "Vulnerability Fix (New Entry)",
                   "Vulnerability Fix (Update)", "Metadata Correction / Adjustments", "Withdrawn / Retracted Advisory")
        placeholders = ",".join("?" * len(allowed))
        checks = {
            "unknown threat_profile value": (f"SELECT COUNT(*) FROM vulnerabilities WHERE threat_profile NOT IN ({placeholders})", allowed),
            "negative dwell_days": ("SELECT COUNT(*) FROM vulnerabilities WHERE dwell_days < 0", ()),
            "negative blast_radius": ("SELECT COUNT(*) FROM vulnerabilities WHERE blast_radius < 0", ()),
            "cvss outside 0-10": ("SELECT COUNT(*) FROM vulnerabilities WHERE cvss_score < 0 OR cvss_score > 10", ()),
            "empty advisory_id": ("SELECT COUNT(*) FROM vulnerabilities WHERE advisory_id IS NULL OR advisory_id = ''", ()),
        }
        for label, (sql, params) in checks.items():
            self.assertEqual(self._scalar(sql, params), 0, f"[!] Warehouse health violation: {label}.")

    def test_db_health_no_record_is_modified_in_the_future(self):
        tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
        self.assertEqual(self._scalar("SELECT COUNT(*) FROM vulnerabilities WHERE last_modified > ?", (tomorrow,)), 0)

    def test_db_health_sync_high_water_mark_is_consistent_with_the_data(self):
        """
        The sync resumes from the recorded high-water mark. If that mark runs far AHEAD of the
        newest record actually stored, everything in between was silently skipped -- exactly how
        a truncated cache file once hid three days of upstream changes. OSV never goes several
        days without any modification, so a multi-day lead is a sign of a gap.
        """
        conn = self._warehouse()
        try:
            baseline, source = db_warehouse.resolve_sync_baseline(conn.cursor())
            newest = conn.execute("SELECT MAX(last_modified) FROM vulnerabilities").fetchone()[0]
        finally:
            conn.close()
        self.assertIn("high-water", source, "[!] Warehouse has no usable sync high-water mark. Rebuild it with: python db_warehouse.py")
        high_water = (baseline + db_warehouse.SYNC_OVERLAP).date()
        newest_day = datetime.date.fromisoformat(newest)
        self.assertLessEqual((high_water - newest_day).days, 3,
                             f"[!] Sync high-water mark ({high_water}) is {(high_water - newest_day).days} days ahead of the newest stored "
                             f"record ({newest_day}); advisories in between were likely skipped. Rebuild with: python db_warehouse.py")

    # -------------------------------------------------------------------------
    # --report LANDMARK ADVISORIES: KEV-listed headline CVEs marked on the daily timeline charts
    # -------------------------------------------------------------------------
    def _landmark_db(self, tmp):
        path = os.path.join(tmp, "landmarks.db")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE vulnerabilities (advisory_id TEXT PRIMARY KEY, cve_alias TEXT, published_date TEXT, cvss_score REAL)")
        conn.execute("CREATE TABLE kev_catalog (cve_id TEXT PRIMARY KEY, date_added TEXT, vulnerability_name TEXT, short_description TEXT, known_ransomware_use TEXT)")
        conn.execute("CREATE TABLE epss_scores (cve_id TEXT PRIMARY KEY, epss_score REAL)")
        conn.executemany("INSERT INTO vulnerabilities VALUES (?,?,?,?)", [
            ("GHSA-a1", "CVE-A", "2026-09-10", 9.8),
            ("GHSA-a2", "CVE-A", "2026-09-12", 9.8),   # second record for the same CVE
            ("GHSA-b1", "CVE-B", "2026-01-05", 7.0),   # old CVE, KEV-added inside the window
            ("GHSA-c1", "CVE-C", "2026-09-20", 5.0),
            ("GHSA-d1", "CVE-D", "2026-09-15", 9.0),   # in window but not on KEV
            ("GHSA-e1", "CVE-E", "2026-02-01", 9.0),   # on KEV but nothing falls in the window
        ])
        conn.executemany("INSERT INTO kev_catalog VALUES (?,?,?,?,?)", [
            ("CVE-A", "2026-09-11", "Alpha RCE", "Alpha desc", "Known"),
            ("CVE-B", "2026-09-22", "Beta Bypass", "Beta desc", "Unknown"),
            ("CVE-C", "2026-10-30", "Gamma Leak", "Gamma desc", "Unknown"),
            ("CVE-E", "2026-03-01", "Epsilon", "Epsilon desc", "Unknown"),
        ])
        conn.executemany("INSERT INTO epss_scores VALUES (?,?)",
                         [("CVE-A", 0.5), ("CVE-B", 0.9), ("CVE-C", 0.1), ("CVE-D", 0.99), ("CVE-E", 0.99)])
        conn.commit()
        conn.close()
        return path

    def test_landmark_advisories_are_kev_listed_in_window_ranked_by_epss(self):
        import tempfile
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = self._landmark_db(tmp)
            found = top10ecosystems.find_landmark_advisories(path, "2026-09-01", "2026-09-30", top_n=3)
            self.assertEqual([lm["cve_id"] for lm in found], ["CVE-B", "CVE-A", "CVE-C"],
                             "[!] Landmarks must be KEV-listed CVEs with activity in the window, highest EPSS first -- "
                             "CVE-D (not on KEV) and CVE-E (nothing in the window) must be excluded.")
            by_id = {lm["cve_id"]: lm for lm in found}
            self.assertEqual(by_id["CVE-B"]["event_date"], "2026-09-22", "An old CVE KEV-added in the window is placed at its KEV date.")
            self.assertEqual(by_id["CVE-A"]["event_date"], "2026-09-10", "One entry per CVE, placed at its earliest in-window publish date.")
            self.assertEqual(by_id["CVE-A"]["name"], "Alpha RCE")
            self.assertTrue(by_id["CVE-A"]["ransomware"])
            self.assertFalse(by_id["CVE-B"]["ransomware"])
            self.assertEqual(len(top10ecosystems.find_landmark_advisories(path, "2026-09-01", "2026-09-30", top_n=1)), 1)

    def test_landmark_advisories_degrade_to_empty_instead_of_failing(self):
        import tempfile
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            self.assertEqual(top10ecosystems.find_landmark_advisories(os.path.join(tmp, "missing.db"), "2026-09-01", "2026-09-30"), [])
            bare = os.path.join(tmp, "bare.db")
            conn = sqlite3.connect(bare)
            conn.execute("CREATE TABLE vulnerabilities (advisory_id TEXT PRIMARY KEY)")
            conn.close()
            self.assertEqual(top10ecosystems.find_landmark_advisories(bare, "2026-09-01", "2026-09-30"), [])
            self.assertEqual(top10ecosystems.find_landmark_advisories(self._landmark_db(tmp), "Unknown", "2026-09-30"), [])

    def test_landmark_chart_overlay_is_linked_escaped_and_positioned_on_the_image(self):
        import re
        dates = ["2026-09-01", "2026-09-02", "2026-09-03"]
        landmark = {"cve_id": "CVE-A", "name": "<script>alert(1)</script>", "description": "d", "epss": 0.5, "cvss": 9.8,
                    "published": "2026-09-02", "kev_added": "2026-09-02", "ransomware": False, "event_date": "2026-09-02"}
        fig, ax = top10ecosystems.mplplt.subplots(figsize=(6, 3))
        ax.plot(dates, [1, 5, 2])
        try:
            out = top10ecosystems._render_chart_with_landmarks(fig, ax, [landmark], dates, "alt")
        finally:
            top10ecosystems.mplplt.close(fig)
        self.assertIn('href="https://osv.dev/vulnerability/CVE-A"', out)
        self.assertNotIn("<script>", out, "[!] Advisory text must be HTML-escaped before it goes into the report.")
        self.assertIn("&lt;script&gt;", out)
        pos = re.search(r'style="left:([\d.]+)%;top:([\d.]+)%"', out)
        self.assertIsNotNone(pos, "[!] Landmark label overlay missing.")
        left, top = float(pos.group(1)), float(pos.group(2))
        self.assertTrue(30 < left < 70, f"[!] Middle-date landmark should sit near the middle of the chart image, got left={left}%.")
        self.assertTrue(0 <= top <= 100)

    def test_landmark_chart_without_landmarks_is_just_the_plain_image(self):
        fig, ax = top10ecosystems.mplplt.subplots(figsize=(6, 3))
        ax.plot(["2026-09-01", "2026-09-02"], [1, 2])
        try:
            out = top10ecosystems._render_chart_with_landmarks(fig, ax, [], ["2026-09-01", "2026-09-02"], "alt")
        finally:
            top10ecosystems.mplplt.close(fig)
        self.assertTrue(out.startswith("<img "))
        self.assertNotIn("chart-wrap", out)


if __name__ == '__main__':
    unittest.main()