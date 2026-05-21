import unittest
from unittest.mock import patch
import sys
import io
import os

# Import your command line application module
import top10ecosystems

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
if __name__ == '__main__':
    unittest.main()