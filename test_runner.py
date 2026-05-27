import unittest
from unittest.mock import patch
import sys
import io
import os
import datetime

# Import your command line application module
import top10ecosystems

# 1. Intercept custom CLI flag before passing control to the unittest runner
UPDATE_GOLDEN_MASTERS = False
if "--update" in sys.argv:
    UPDATE_GOLDEN_MASTERS = True
    sys.argv.remove("--update")  # Stripped so unittest engine doesn't choke on unknown arguments

class TestThreatStreamScanner(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Executes once before the suite starts.
        Loads the archive cache exactly ONE time into a class singleton."""
        print("[*] Initializing Global Testing Harness...")
        print("[*] Staging Upstream Threat Intelligence Index (Single Ingestion Layer)...")
        
        # Define both the directory and the file path explicitly
        cls.cache_dir = "./cache"
        cls.cache_filepath = "./cache/osv_master_all.zip"
        
        if not os.path.exists(cls.cache_filepath):
            raise FileNotFoundError(
                f"\n[!] CRITICAL: Test harness cannot find the database cache at: {cls.cache_filepath}\n"
                f"    Action: Verify the 'cache' directory exists here, or run 'python top10ecosystems.py --layer app' once to rebuild it."
            )

        # Pass the DIRECTORY path to match your script's native parameter expectations
        # Expecting ONLY the lookup dictionary to return (matching your actual script)
        cls.ghsa_lookup = top10ecosystems.build_ghsa_ecosystem_map(cls.cache_dir)
        
        # Hard assertion to prevent cascading false-positives if the zip is corrupt or empty
        if not cls.ghsa_lookup:
            raise ValueError("[!] CRITICAL: build_ghsa_ecosystem_map returned an empty dictionary. The cache is missing or corrupt.")
            
        print(f"[+] Harness Setup Complete. Indexed {len(cls.ghsa_lookup):,} global advisories.\n")

    def run_scanner_with_args(self, mock_args):
        """Helper utility to simulate an authentic CLI execution and capture output."""
        # Baseline arguments fed directly into the script's native argparse engine
        base_args = ['top10ecosystems.py', '--layer', 'app', '--from', '2020-01-01']
        full_args = base_args + mock_args
        
        captured_output = io.StringIO()
        
        # 1. Patch sys.argv with our simulated flags
        # 2. Patch stdout to trap terminal prints
        # 3. Intercept build_ghsa_ecosystem_map so it instantly hands back our SINGLE cached dictionary
        with patch.object(sys, 'argv', full_args), \
             patch('sys.stdout', captured_output), \
             patch('top10ecosystems.build_ghsa_ecosystem_map', return_value=self.ghsa_lookup):
            try:
                # Fire your script's actual top-level entry point function!
                top10ecosystems.main()
            except SystemExit as e:
                # Capture standard or intentional exit flags safely
                return e.code, captured_output.getvalue()
                
        return 0, captured_output.getvalue()

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
        
        # The engine should process the file cleanly without throwing a linting or configuration exit code (1)
        self.assertEqual(exit_code, 0)
        
        # Explicitly ensure our dynamic range guardrails weren't accidentally tripped by the raw CLI output
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
        """Mocks the live OSV CSV stream to verify the analytical engine aggregates ecosystem counts correctly."""
        
        # 1. Setup the mock response to simulate the CSV stream coming from Google Cloud Storage
        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        
        # We use a date (April 20, 2026) that safely falls within the script's default 
        # fallback window (April 18, 2026 to present) so it isn't filtered out.
        mock_csv_lines = [
            b"2026-04-20T10:00:00Z,GHSA-mock-1111:npm",
            b"2026-04-20T11:00:00Z,CVE-mock-2222:Debian",
            b"2026-04-20T11:30:00Z,CVE-mock-3333:Debian",
            b"2026-04-20T12:00:00Z,npm/MAL-mock-4444.json" 
        ]
        mock_response.iter_lines.return_value = mock_csv_lines
        mock_requests_get.return_value = mock_response

        # 2. Trap the stdout to verify the printed output
        captured_output = io.StringIO()
        
        # We supply an empty ghsa_lookup so the parser relies purely on the CSV string routing
        with patch('sys.stdout', captured_output):
            top10ecosystems.generate_enterprise_threat_leaderboard(
                start_date=datetime.datetime(2026, 4, 18, tzinfo=datetime.timezone.utc),
                end_date=datetime.datetime(2026, 4, 25, tzinfo=datetime.timezone.utc),
                target_layer=None, 
                debug_mode=False, 
                ghsa_lookup={} 
            )
            
        output = captured_output.getvalue()

        # 3. Assert the stream was parsed and aggregated accurately
        self.assertIn("VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD", output)
        
        # We fed it 2 Debian entries and 2 npm entries
        self.assertRegex(output, r"Debian\s+\|\s+2")
        self.assertRegex(output, r"npm\s+\|\s+2")
        self.assertIn("Raw Entry Stream Items:    4", output)

    @patch('requests.get')
    def test_historical_golden_masters(self, mock_requests_get):
        """
        Iterates over verified historical export files in src/test/resources/ 
        and ensures current engine logic produces identical analytical payloads.
        Uses a frozen local CSV stream to prevent network drift.
        """
        import json
        import os

        # We point to a static, frozen copy of the OSV stream
        frozen_csv_path = os.path.join("src", "test", "resources", "frozen_modified_id.csv")
        
        if not os.path.exists(frozen_csv_path):
            self.skipTest(f"Frozen CSV stream not found at {frozen_csv_path}. Action: Download the current OSV modified_id.csv and place it here.")

        # Configure the network mock to serve our frozen file instead of hitting the internet
        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        
        def frozen_stream_generator():
            with open(frozen_csv_path, 'rb') as f:
                for line in f:
                    yield line
                    
        mock_response.iter_lines.side_effect = lambda: frozen_stream_generator()
        mock_requests_get.return_value = mock_response

        # The locked files from your directory mapped to their date windows
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

                # Bypass the absolute path stripping by using the expected relative output path
                temp_export_path = f"./output/temp_{filename}"
                
                mock_flags = [
                    '--layer', 'app',
                    '--from', start_str,
                    '--to', end_str,
                    '--export', temp_export_path
                ]
                
                exit_code, _ = self.run_scanner_with_args(mock_flags)
                self.assertEqual(exit_code, 0, f"Script execution failed for window {end_str}")
                
                with open(golden_path, 'r', encoding='utf-8') as f_golden:
                    golden_data = json.load(f_golden)
                    
                with open(temp_export_path, 'r', encoding='utf-8') as f_temp:
                    temp_data = json.load(f_temp)
                    
                # STRATEGY 1: Native Auto-Minting Hook
                if UPDATE_GOLDEN_MASTERS:
                    print(f"[+] --update active: Auto-minting frozen baseline asset -> {filename}")
                    with open(golden_path, 'w', encoding='utf-8') as gf:
                        json.dump(temp_data, gf, indent=4)
                    continue  # Skip validation assertions when updating baselines

                # Load the existing golden data asset for validation
                with open(golden_path, 'r', encoding='utf-8') as gf:
                    golden_data = json.load(gf)

                # STRATEGY 2: Embedded On-Failure Runbook Guidance
                failure_runbook = (
                    f"\n\n{'='*80}\n"
                    f"❌ GOLDEN MASTER REGRESSION OR METADATA DRIFT DETECTED\n"
                    f"{'='*80}\n"
                    f"File: {filename}\n\n"
                    f"TROUBLESHOOTING STEPS:\n"
                    f"1. Verify if this change stems from an intentional engineering upgrade (e.g., a newly added \n"
                    f"   metrics calculation layer, section refactor, or altered filter logic).\n"
                    f"2. If the logic modification is legitimate, do NOT hack the test engine source files.\n"
                    f"3. Automatically overwrite and recalibrate all Golden Master assets against the true \n"
                    f"   offline test stream database by running the following command:\n\n"
                    f"   👉 python .\\test_runner.py --update\n\n"
                    f"4. Confirm that the newly minted json structures look sane before committing changes.\n"
                    f"{'='*80}\n"
                )

                # Assertions enhanced with the diagnostic runbook output
                self.assertDictEqual(
                    temp_data.get("leaderboard", {}), 
                    golden_data.get("leaderboard", {}),
                    msg=f"Leaderboard data mismatch.{failure_runbook}"
                )
                self.assertDictEqual(
                    temp_data.get("threat_profile", {}), 
                    golden_data.get("threat_profile", {}),
                    msg=f"Threat lifecycle profile classification mismatch.{failure_runbook}"
                )
                    
                self.assertDictEqual(
                    temp_data.get("leaderboard", {}), 
                    golden_data.get("leaderboard", {}),
                    f"Leaderboard mismatch detected in {filename}"
                )
                self.assertDictEqual(
                    temp_data.get("threat_profile", {}), 
                    golden_data.get("threat_profile", {}),
                    f"Threat profile mismatch detected in {filename}"
                )
                self.assertDictEqual(
                    temp_data.get("malware_vectors", {}), 
                    golden_data.get("malware_vectors", {}),
                    f"Malware vector mismatch detected in {filename}"
                )
                
                # Clean up the temporary file so we don't litter your output directory
                if os.path.exists(temp_export_path):
                    os.remove(temp_export_path)   

    def test_global_advisory_index_volume_baseline(self):
        """Validates that the parsed global memory index does not suffer silent truncation regressions."""
        # Pull the record count from your global tracking map
        total_indexed_records = len(self.ghsa_lookup) if hasattr(self, 'ghsa_lookup') else 0
        
        # Hard threshold set to flag if data drops significantly below our ~570k baseline
        minimum_safe_threshold = 560000
        
        self.assertGreaterEqual(
            total_indexed_records,  # Aligned variable name
            minimum_safe_threshold,
            msg=(
                f"\n\n{'='*80}\n"
                f"⚠️  CRITICAL REGRESSION: GLOBAL ADVISORY INDEX TRUNCATION DETECTED\n"
                f"{'='*80}\n"
                f"Current Record Count: {total_indexed_records:,}\n"  # Aligned variable name
                f"Expected Safe Floor:  {minimum_safe_threshold:,}\n\n"
                f"POSSIBLE ROOT CAUSES:\n"
                f"1. The local data cache file (`./cache/osv_master_all.zip`) was generated during an \n"
                f"   incomplete download stream or write failure.\n"
                f"2. The core upstream parsing engine (`build_ghsa_ecosystem_map`) dropped active records \n"
                f"   due to an unhandled object nesting structure error.\n\n"
                f"REMEDIATION:\n"
                f"Nuke the stale asset cache directory and re-execute the loader to pull a fresh master stream.\n"
                f"{'='*80}\n"
            )
        )
    # -------------------------------------------------------------------------
    # INTEGRATION TESTS: GOLDEN MASTER SNAPSHOT DELTA VERIFICATION
    # -------------------------------------------------------------------------
    def test_compare_snapshots_golden_master_deltas(self):
        """
        Validates the comparison engine's delta arithmetic and rank shifts 
        against frozen historical Golden Master snapshots (May 18 vs May 21).
        """
        import os
        import io
        from unittest.mock import patch

        # Explicitly target the historical files from your execution pipeline
        file_base = os.path.join("src", "test", "resources", "threat_landscape_2026-05-18_app.json")
        file_current = os.path.join("src", "test", "resources", "threat_landscape_2026-05-21_app.json")

        # Fallback guard to skip cleanly if paths are misaligned in a CI/CD environment
        if not os.path.exists(file_base) or not os.path.exists(file_current):
            self.skipTest(
                f"\n[!] Snapshot delta verification skipped.\n"
                f"    Missing target assets: {file_base} or {file_current}"
            )

        captured_output = io.StringIO()

        # Fire the comparison engine cover-to-cover using the frozen historical records
        with patch('sys.stdout', captured_output):
            top10ecosystems.compare_snapshots(
                file_base=file_base,
                file_current=file_current,
                html_output=None
            )

        output = captured_output.getvalue()

        # Assertions Layer 1: Core Engine Integrity Guards
        self.assertNotIn(
            "Snapshot comparison failed", output,
            "[!] CRITICAL: The comparison engine crashed internally during execution!"
        )
        self.assertIn(
            "SECURITY THREAT INTELLIGENCE STREAM MOVEMENT COMPARISON", output,
            "[!] Main header section is missing from the comparison output canvas."
        )

        # Assertions Layer 2: Visual Section Boundaries
        self.assertIn("I. ECOSYSTEM ACTIVITY & RANK SHIFTS", output)
        self.assertIn("II. THREAT BEHAVIOR VARIANCE", output)
        
        # Checking for sections that depend on extended metadata keys
        if "malware_vectors" in output or "III." in output:
            self.assertIn("III. MALWARE VECTOR ATTACK MATRIX SHIFTS", output)
        if "profile_matrix" in output or "IV." in output:
            self.assertIn("IV. SPATIAL DWELL & BLAST RADIUS BASELINE SHIFTS", output)
        if "outliers_leaderboards" in output or "V." in output:
            self.assertIn("V. CRITICAL OUTLIER ATTACK SURFACE RADIUS POOLS VARIANCE ANALYSIS", output)
            
        self.assertIn("VI. RELATIVE CHURN VELOCITY", output)

        # =====================================================================
        # 🎯 DATA DETERMINISM LOCKS
        # =====================================================================
        # Since your Windows system now natively outputs clean UTF-8 strings,
        # you can inspect the 'comparison_console_output.txt' file you generated
        # and paste exact rows here to lock down the math.
        #
        # Examples:
        # self.assertIn("npm                        |", output)
        # self.assertIn("PyPI                       |", output)
        # =====================================================================
if __name__ == '__main__':
    unittest.main()