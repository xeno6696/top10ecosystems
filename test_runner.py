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
            "test_compare_snapshots_strict_text_alignment_bad_mismatch"
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

        # 6. PARITY GATE C: Validate Section VIII Cross-Compiled Hardware Matrix counts
        section_viii_header = "VIII. HARDWARE ARCHITECTURE COMPILATION"
        if section_viii_header in stdout_capture:
            section_viii_zone = stdout_capture.split(section_viii_header)[1]
        else:
            section_viii_zone = stdout_capture

        for eco_source, json_metrics in export_payload.get("intel_architecture_matrix", {}).items():
            escaped_source = re.escape(eco_source)
            intel_regex = re.compile(rf"{escaped_source}\s*\|\s*([0-9,]+)\s*\|")
            
            match = intel_regex.search(section_viii_zone)
            if match:
                console_intel_total = int(match.group(1).replace(",", ""))
                json_intel_total = json_metrics.get("total", 0)
                self.assertEqual(
                    console_intel_total, json_intel_total,
                    f"[!] TELEMETRY PARITY DRIFT: Section VIII Intel total mismatch for '{eco_source}'. "
                    f"Console reported '{console_intel_total:,}' while Export contains '{json_intel_total:,}'."
                )

    def run_scanner_with_args(self, mock_args):
        """Helper utility to simulate an authentic CLI execution and capture output."""
        base_args = ['top10ecosystems.py', '--layer', 'app', '--from', '2020-01-01']
        full_args = base_args + mock_args
        captured_output = io.StringIO()
        
        with patch.object(sys, 'argv', full_args), \
             patch('sys.stdout', captured_output), \
             patch('top10ecosystems.build_ghsa_ecosystem_map', return_value=self.ghsa_lookup), \
             patch('top10ecosystems.build_ghsa_from_db', return_value=self.ghsa_lookup):
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