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

# -----------------------------------------------------------------------------
# 1. INTERCEPT CUSTOM CLI FLAGS BEFORE PASSING CONTROL TO UNITTEST
# -----------------------------------------------------------------------------
UPDATE_GOLDEN_MASTERS = False
if "--update" in sys.argv:
    UPDATE_GOLDEN_MASTERS = True
    sys.argv.remove("--update")  # Stripped so unittest engine doesn't choke

USE_DATABASE_WAREHOUSE = False
if "--database" in sys.argv:
    USE_DATABASE_WAREHOUSE = True
    sys.argv.remove("--database")  # Stripped to protect unittest setup execution
    
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
        cls.cache_dir = "cache/"
        cls.cache_filepath = "cache/osv_master_all.zip"
        
        #   ZERO CROSS-TALK: Absolute mutual exclusivity enforcement
        if USE_DATABASE_WAREHOUSE:
            print("[*] Mode Flag Active: Forcing test execution 100% against SQLite warehouse index.")
            cls.ghsa_lookup = top10ecosystems.build_ghsa_from_db()
        else:
            print("[*] Mode Flag Idle: Executing test engine 100% against legacy master ZIP archive.")
            if not os.path.exists(cls.cache_filepath):
                raise FileNotFoundError(f"[!] Missing file: {cls.cache_filepath}")
            cls.ghsa_lookup = top10ecosystems.build_ghsa_ecosystem_map(cls.cache_dir)
        
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
        self.verify_production_target_signature("generate_html_report", expected_args_count=2)

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
            "test_extract_cvss_score_malware_override",
            "test_extract_cvss_score_v3_parsing",
            "test_extract_cvss_score_empty_severity",
            "test_get_artifact_layer_routing",
            "test_generate_leaderboard_stream_aggregation",
            "test_historical_golden_masters",
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
            "test_000_a_anti_hallucination_guard_for_repo_anchor_extractor",
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
            "test_rank_cross_registry_tables_ranks_by_ecosystem_span_then_cvss"
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
        if USE_DATABASE_WAREHOUSE:
            mock_flags.append('--database')

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
        if "0 CVEs confirmed" not in zone_c and "Requires --database" not in zone_c:
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
             patch('top10ecosystems.build_ghsa_ecosystem_map', return_value=self.ghsa_lookup), \
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
        if USE_DATABASE_WAREHOUSE:
            mock_flags.append('--database')
            
        self.addCleanup(lambda: os.remove(target_export_path) if os.path.exists(target_export_path) else None)
        exit_code, output = self.run_scanner_with_args(mock_flags)
        
        self.assertEqual(exit_code, 0, f"Export execution failed under test harness with stdout:\n{output}")
        self.assertTrue(os.path.exists(target_export_path), "[!] CRITICAL REGRESSION: JSON export payload was not persisted to disk.")
        
        with open(target_export_path, 'r', encoding='utf-8') as f:
            payload = json.load(f)
            
        required_schema_nodes = [
            "metadata", "leaderboard", "threat_profile", "layer_profile_matrix", 
            "malware_vectors", "profile_matrix", "outliers_leaderboards"
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
    def test_extract_cvss_score_malware_override(self):
        """Verifies that explicitly malicious payloads automatically max out at 10.0."""
        vuln_data_mal_id = {"id": "MAL-2026-9999"}
        vuln_data_mal_keyword = {"id": "GHSA-xxxx", "summary": "This is a malware package"}
        self.assertEqual(top10ecosystems.extract_cvss_score(vuln_data_mal_id), 10.0)
        self.assertEqual(top10ecosystems.extract_cvss_score(vuln_data_mal_keyword), 10.0)

    def test_extract_cvss_score_v3_parsing(self):
        """Verifies CVSSv3 vectors are correctly parsed by the FIRST library."""
        vuln_data = {
            "id": "GHSA-xxxx",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        }
        score = top10ecosystems.extract_cvss_score(vuln_data)
        self.assertEqual(score, 9.8)

    def test_extract_cvss_score_empty_severity(self):
        """Ensures missing severity structures safely return 0.0 without crashing."""
        vuln_data = {"id": "CVE-2026-0000", "severity": []}
        score = top10ecosystems.extract_cvss_score(vuln_data)
        self.assertEqual(score, 0.0)

    # -------------------------------------------------------------------------
    # UNIT TESTS: SECTION VIII CROSS-REGISTRY CLASSIFICATION
    # (replaces the old "HARDWARE ARCHITECTURE COMPILATION CROSS-POLLINATION MATRIX" -- see
    # rank_cross_registry_tables / classify_advisory_cross_registry / classify_cross_registry_pair
    # / extract_repo_anchor in top10ecosystems.py)
    # -------------------------------------------------------------------------
    def test_000_a_anti_hallucination_guard_for_repo_anchor_extractor(self):
        """[INTEGRITY] Guards against the deletion of the cross-registry repo-identity extractor."""
        self.verify_production_target_signature("extract_repo_anchor", expected_args_count=1)

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
            b"2026-04-20T10:00:00Z,GHSA-mock-1111:npm",
            b"2026-04-20T11:00:00Z,CVE-mock-2222:Debian",
            b"2026-04-20T11:30:00Z,CVE-mock-3333:Debian",
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

    @patch('requests.get')
    def test_historical_golden_masters(self, mock_requests_get):
        """Iterates over verified historical baseline snapshot payloads to prevent delta regressions."""
        import json
        if not self.cached_stream_lines:
            self.skipTest(f"Frozen CSV stream not found at {self.frozen_csv_path}.")

        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        mock_response.iter_lines.return_value = self.cached_stream_lines
        mock_requests_get.return_value = mock_response

        golden_files = [
            ("2026-04-18", "2026-05-18", "threat_landscape_2026-05-18_app.json"),
            ("2026-04-18", "2026-05-19", "threat_landscape_2026-05-19_app.json"),
            ("2026-04-18", "2026-05-20", "threat_landscape_2026-05-20_app.json"),
            ("2026-04-18", "2026-05-21", "threat_landscape_2026-05-21_app.json"),
        ]

        print(f"\n[*] Validating engine parity against Golden Master files using frozen state...")

        for start_str, end_str, filename in golden_files:
            with self.subTest(file=filename):
                golden_path = os.path.join("src", "test", "resources", filename)
                if not os.path.exists(golden_path):
                    self.skipTest(f"Golden master {filename} not found in {golden_path}")

                temp_export_path = f"./output/temp_{filename}"
                mock_flags = [
                    '--layer', 'app', '--from', start_str, '--to', end_str, '--export', temp_export_path
                ]
                if USE_DATABASE_WAREHOUSE:
                    mock_flags.append('--database')
                
                exit_code, _ = self.run_scanner_with_args(mock_flags)
                self.assertEqual(exit_code, 0, f"Script execution failed for window {end_str}")
                
                with open(temp_export_path, 'r', encoding='utf-8') as f_temp:
                    temp_data = json.load(f_temp)
                    
                if UPDATE_GOLDEN_MASTERS:
                    print(f"[+] --update active: Auto-minting frozen baseline asset -> {filename}")
                    with open(golden_path, 'w', encoding='utf-8') as gf:
                        json.dump(temp_data, gf, indent=4)
                    continue

                with open(golden_path, 'r', encoding='utf-8') as gf:
                    golden_data = json.load(gf)

                failure_runbook = (
                    f"\n\n{'='*80}\n"
                    f"❌ GOLDEN MASTER REGRESSION OR METADATA DRIFT DETECTED\n"
                    f"{'='*80}\n"
                    f"File: {filename}\n\n"
                    f"👉 Remediation Command: python .\\test_runner.py "
                    f"{'--database ' if USE_DATABASE_WAREHOUSE else ''}--update\n"
                    f"{'='*80}\n"
                )

                self.assertDictEqual(temp_data.get("leaderboard", {}), golden_data.get("leaderboard", {}), msg=f"Leaderboard data mismatch.{failure_runbook}")
                self.assertDictEqual(temp_data.get("threat_profile", {}), golden_data.get("threat_profile", {}), msg=f"Threat profile classification mismatch.{failure_runbook}")
                self.assertDictEqual(temp_data.get("malware_vectors", {}), golden_data.get("malware_vectors", {}), msg=f"Malware vector mismatch detected in {filename}")
                
                if os.path.exists(temp_export_path):
                    os.remove(temp_export_path)   

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

if __name__ == '__main__':
    unittest.main()