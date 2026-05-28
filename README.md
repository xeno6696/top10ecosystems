# OSV Threat Stream Campaign Dashboard Indicator

A Python command-line security engineering tool for tracking software supply chain activity across the Open Source Vulnerability (OSV) database.

The script builds a local advisory index from OSV, reads the OSV modified advisory stream, and produces a terminal dashboard showing which ecosystems are experiencing the most vulnerability database churn over a selected time window. It can also export JSON snapshots, compare two snapshots, and audit a local project manifest against currently mutating advisories.

## 🚀 Quick Start & Execution Path

For an engineer cloning this repository clean, follow this sequential execution path to bootstrap the environment and wire the high-performance local database warehouse:

### 1. Clone the Repository & Install Dependencies
First, target your workspace directory and install the required core packages and high-precision parsing libraries:
```bash
git clone <your-repository-url>
cd top-10-ecosystems
pip install -r requirements.txt
```

### 2. Initialize and Seed the Relational Data Warehouse
Before launching dashboard profiles against the relational backend, deploy your local schema layout and seed the 10-column SQLite grid indexes:
```bash
python db_warehouse.py
```
*Note: If your local folder is clean, this automatically initializes your tracking tables, provisions the performance B-Tree blocks (`database/threat_stream.db`), and streams down the full ~1GB upstream bulk master snapshot archive package seamlessly in sequential 1MB chunks to safeguard your memory footprint.*

### 3. Initial Baseline Calibration
When running the suite for the first time, you will likely encounter unit test failures in the text alignment alignment gates. This is **expected behavior** as the system compares live execution output against local "Golden Master" baseline files.

1. **Run the suite:**
   ```bash
   python test_runner.py --database
   ```
3. **Investigate the failure:** The `AssertionError` output will display a surgical line-by-line delta. Review this output. If the differences represent expected system formatting (e.g., local path differences) rather than data regressions, proceed to re-mint the baseline.
4. **Calibrate:** Use the `--update` flag to force the engine to overwrite the existing baselines with the current, verified environment output:
   ```bash
   python test_runner.py --database --update
   ```

### 4. Run the Main Dashboard Engine
With your relational data asset successfully populated and synchronized, call the core application using the `--database` execution flag to isolate operations to your local index:
```bash
# Analyze application registry layers over a distinct historical interval
python top10ecosystems.py --database --layer app --from 2026-04-18 --to 2026-05-28

# Compare two distinct historical exported JSON snapshots natively
python top10ecosystems.py --database --compare snapshot_a.json snapshot_b.json
```

---

## 📊 What this tool measures

The `Activity Delta` column does **not** represent individual exploit attempts, attacks, compromises, or incidents.

It measures **upstream vulnerability database churn**: changes in the OSV advisory data over a selected time window. One activity unit may represent any of the following:

1. A new vulnerability or malware advisory entry.
2. A structural update to an existing advisory, such as changed affected-version ranges or newly fixed versions.
3. A metadata correction, such as a CVSS adjustment or advisory text update.

This distinction matters because operating-system ecosystems such as Debian and Ubuntu can generate very large update volumes due to automated backporting and maintenance across many supported releases. Application registries such as npm and PyPI are often more directly relevant to application-layer supply chain events, including malicious package campaigns.

---

## ⚙️ Requirements

- Python 3.9 or newer recommended.
- Network access to OSV-hosted data (for archive bootstrapping and incremental sync windows).
- The `requests` and `cvss` Python library frameworks.
