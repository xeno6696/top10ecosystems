# OSV Threat Stream Campaign Dashboard Indicator

A Python command-line security engineering tool for tracking software supply chain activity across the Open Source Vulnerability (OSV) database.

The script builds a local advisory index from OSV, reads the OSV modified advisory stream, and produces a terminal dashboard showing which ecosystems are experiencing the most vulnerability database churn over a selected time window. Beyond the core dashboard, it also cross-references CISA's KEV catalog and FIRST's EPSS exploitation-probability scores into a prioritized dispatch list, tracks cross-registry package relationships (native multi-registry releases vs. mechanical repackaging vs. duplicate CVE tracking across ecosystems), generates historical trend charts, audits a local project manifest/SBOM against currently mutating advisories, and hunts for suspicious retracted advisories.

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
Before launching dashboard profiles against the relational backend, deploy your local schema layout and seed the SQLite grid indexes:
```bash
python db_warehouse.py
```
*Note: If your local folder is clean, this automatically initializes your tracking tables, provisions the performance B-Tree blocks (`database/threat_stream.db`), and streams down the full ~1GB upstream bulk master snapshot archive package seamlessly in sequential 1MB chunks to safeguard your memory footprint. It also pulls the FIRST EPSS exploitation-probability feed and the CISA KEV (Known Exploited Vulnerabilities) catalog, both cached locally and auto-refreshed once they're 24h old.*

`db_warehouse.py` supports a few flags of its own:

| Flag | Effect |
|---|---|
| *(none)* | Bootstrap from the cached/downloaded ZIP if the table is empty, then run an incremental sync. This is the normal day-to-day command. |
| `--bootstrap` | Force the bulk ZIP seed step even if the table already has rows (skipped by default once populated). |
| `--sync` | Run only the incremental modified-stream sync (skip the bulk bootstrap). |
| `--rebuild` | **Full fresh rebuild.** Deletes the local database file *and* every cached artifact (the ~1GB master ZIP, the EPSS feed, the KEV catalog), so the next run downloads everything from scratch rather than silently reusing whatever happens to be sitting in `./cache`. Use this when you want a guaranteed-clean rebuild, not a quick refresh — expect it to take several minutes even with a fast connection, since it re-parses the full upstream advisory corpus. |
| `--skip-kev` | Skip the CISA KEV catalog refresh pipeline for this run. |

### 3. Initial Baseline Calibration
When running the verification suite for the first time, you will likely encounter unit test failures in the text alignment gates. This is **expected behavior** as the system compares live execution output against local "Golden Master" baseline files that may not perfectly match your local filesystem paths or the current state of the live warehouse.

1. **Run the suite:**
   ```bash
   python test_runner.py --database
   ```
2. **Investigate the failure:** The `AssertionError` output will display a surgical line-by-line delta. Review this output. If the differences represent expected system formatting or ordinary data drift (the local warehouse legitimately advances day to day) rather than data regressions, proceed to re-mint the baseline.
3. **Calibrate:** Use the `--update` flag to force the engine to overwrite the existing baselines with the current, verified environment output:
   ```bash
   python test_runner.py --database --update
   ```
   *Note: one gate — the strict text-alignment positive control against `src/test/resources/comparison_console_output.txt` — has no `--update` branch of its own (unlike the other golden-master fixtures). If it fails after everything else is green, re-mint it directly by capturing `compare_snapshots()`'s output for the base/current JSON pair it uses and overwriting that file (it's UTF-16 encoded — write it with `encoding="utf-16"` to match).*

### 4. Run the Main Dashboard Engine
With your relational data asset successfully populated, call the core application using the `--database` execution flag to isolate operations to your local index for performance:
```bash
# Analyze application registry layers over a distinct historical interval
python top10ecosystems.py --database --layer app --from 2026-04-18 --to 2026-05-28
```
Omit `--database` to fall back to streaming the OSV bulk ZIP directly (slower, no local index required, and doesn't get the KEV/EPSS enrichment described below).

### 5. High-Performance Isolation Filtering
To skip heavy scanning overhead and optimize operational speeds, pass the `--registry` option along with a comma-separated checklist array to drop unrelated database footprints instantly. Quote the whole list if any registry name contains spaces or parentheses (e.g. `Maven (Java)`):
```bash
# Isolate calculation matrix mappings strictly to target registries
python top10ecosystems.py --database --registry "npm,PyPI,Maven (Java)" --from 2026-04-18 --to 2026-05-28
```

### 6. Advanced Research Hunting & Snapshot Tooling
```bash
# Hunt for suspicious contested retractions within a context window
python top10ecosystems.py --database --layer app --from 2026-04-18 --to 2026-05-28 --hunt-retracted

# Standalone Comparison (Pure file-diffing, does not require --database)
python top10ecosystems.py --compare snapshot_a.json snapshot_b.json
```

---

## 📊 What this tool measures

The `Activity Delta` column does **not** represent individual exploit attempts, attacks, compromises, or incidents.

It measures **upstream vulnerability database churn**: changes in the OSV advisory data over a selected time window. One activity unit may represent any of the following:

1. A new vulnerability or malware advisory entry.
2. A structural update to an existing advisory, such as changed affected-version ranges or newly fixed versions.
3. A metadata correction, such as a CVSS adjustment or advisory text update.

This distinction matters because operating-system ecosystems such as Debian and Ubuntu can generate very large update volumes due to automated backporting and maintenance across many supported releases. Application registries such as npm and PyPI are often more directly relevant to application-layer supply chain events, including malicious package campaigns.

It also matters because upstream advisory sources — GHSA, PyPA, Chainguard, and others — periodically run bulk metadata-correction or re-ingestion passes that stamp thousands of unrelated advisories with the same modification timestamp on a single day. A single day with an enormous churn spike is far more often one of these bulk maintenance events than a coordinated attack; before treating a spike as a live incident, check whether it's isolated to one package/ecosystem (more likely a real event) or spread evenly across many unrelated packages (more likely bulk housekeeping).

**A caveat for historical trend analysis**: the OSV modified-advisory stream this tool reads from records each advisory's *current* latest-modified timestamp, not a full history of every time it changed. That means re-running an export for a date window well in the past will not exactly reproduce a snapshot taken of that same window closer to the time — any advisory touched again since will have "aged out" of the older window. Treat exports generated promptly (same day, or close to it) as the more historically faithful record; a from-scratch regeneration of an old window trades some of that fidelity for having the whole archive come from one consistent warehouse state and codebase version.

---

## 🖥️ Dashboard Sections (default run)

A standard `top10ecosystems.py` invocation (without `--trends`/`--crosscheck`/`--velocity`/`--compare`/`--hunt-retracted`) renders eight sections:

| # | Section | What it shows |
|---|---|---|
| I | Verified Enterprise Ecosystem Leaderboard | Top 10 ecosystems/registries by raw activity delta in the window. |
| II | Architectural Layer Threat Matrix | Same churn, broken down by App Registry vs. Container Base Image layer and mutation type. |
| III | Malware Attack Vector Analysis | Breakdown of malware-classified entries by vector (typosquatting, dependency confusion, credential stealing, backdoor/execution). |
| IV | Ecosystem Threat Metabolism & Systemic Backlog Matrix | Dwell-time (time-to-fix) and blast-radius (affected version count) averages per ecosystem. |
| V | Critical Outlier Attack Surface Radius Pools | Per-ecosystem top-10 ranking by blast radius/CVSS, regardless of malware/vulnerability classification. |
| VI | New Arrivals & Campaign Discoveries Within Timeframe | Advisories that are brand-new (not just updated) within the window. |
| VII | Systemic Risk vs. Active Exposure (The Attention Deficit) | Flags advisories with high objective severity but low community/tracking attention. |
| VIII | Is This The Same Vulnerability Showing Up More Than Once? | Three sub-tables (see below). |

**Section VIII** answers a specific supply-chain question: when the same advisory spans multiple ecosystems, is that because the same project is genuinely released natively to each registry, or because one registry is just vendoring another's code unmodified?
- **VIII-A — True Cross-Compiled**: the same upstream project independently released to multiple registries (e.g. a library shipped natively to both PyPI and Maven).
- **VIII-B — Repackaged-As-Is**: one registry mechanically vendoring another's artifact unmodified (the textbook case is Maven's `webjars` namespace wrapping an npm package verbatim), with a per-ecosystem fix-status marker (`F`/`U`/`?`) and a dependency-direction signal for which side is the plausible upstream fix origin.
- **VIII-C — Cross-Tracker CVE Correlation**: the same CVE independently tracked as separate advisory records across ecosystems (requires `--database`).

Pass `--priority-sort` to re-rank Sections I/V/VI/VII by KEV presence → EPSS score → CVSS/blast-radius instead of CVSS/blast-radius alone (default ranking is unchanged when the flag is omitted).

---

## 🎯 KEV/EPSS Prioritized Dispatch List (`--crosscheck`)

Cross-checks the CISA KEV catalog, FIRST's EPSS exploitation-probability score, and raw OSV/CVSS severity against the vulnerability catalog for a given window, producing a single prioritized "what should a developer actually work on first" list — sorted KEV (known to be actively exploited) first, then by descending EPSS probability, then by CVSS/blast-radius. Requires `--database` and an explicit `--registry` filter:
```bash
python top10ecosystems.py --database --crosscheck --registry npm,PyPI --from 2026-08-18 --to 2026-09-17
```
- `--crosscheck-limit N` caps the console table to the top N rows (default 100; `0` for uncapped).
- `--crosscheck-export [PATH]` exports the full, uncapped list as JSON regardless of the console cap.

---

## 📈 Ecosystem Trend Briefings (`--trends`)

Computes lookback trend metrics, mutation-velocity spikes, and dormancy-decay models for a specific registry over a rolling window (default 30 days, override with `--window-days N`). Requires `--database` and an explicit `--registry` target:
```bash
python top10ecosystems.py --database --trends --registry npm --window-days 30 --to 2026-09-17
```
Includes a KEV-first prioritized list plus a secondary EPSS-only watchlist for advisories that aren't in KEV but carry a meaningfully elevated exploitation probability.

---

## 🔍 Retraction Hunting (`--hunt-retracted`)

Surfaces advisories that were published, then withdrawn/retracted, with unusually long dwell times before retraction — a pattern worth a second look, since a retraction that took a long time to happen is a different risk profile than one caught and reversed quickly. Requires `--database`:
```bash
python top10ecosystems.py --database --layer app --from 2026-04-18 --to 2026-05-28 --hunt-retracted
```

---

## 📊 Historical Trend Charting (`--velocity` / `--html`)

Two related but separate tools for looking at churn over time instead of a single window:

- **`--velocity [DIR]`** stitches a directory of previously-exported JSON snapshots (default `./output`) into a single time-series CSV matrix (`velocity_matrix.csv`), with an optional inline terminal chart via `--terminal-plot`.
- **`--html OUTPUT_FILE`** builds a two-chart HTML dashboard from the same snapshot directory: ecosystem-level and threat-profile-level **day-over-day deltas** (not raw cumulative totals — a real burst shows up as an actual spike, not a subtle change in slope). Respects `--from`/`--to` to scope the date range, and `--layer` to restrict which layer's archive to aggregate (defaults to `app`, matching the daily archive convention below — mixing snapshots from different layers or scopes in one chart produces meaningless collisions, so it won't do that unless you explicitly ask for a different layer).

```bash
# Build/refresh the daily archive one day at a time (or as a comma-separated batch in one run
# for guaranteed single-warehouse-state consistency across the whole range):
python top10ecosystems.py --database --layer app --to 2026-09-18,2026-09-19,2026-09-20 --export

# Then chart it:
python top10ecosystems.py --html output/threat_landscape_report.html --from 2026-08-01 --to 2026-09-20
```
Bare `--export` (no filename) auto-names each window's file `threat_landscape_<end-date>_<layer>.json` in `./output` — this is the convention the daily-archive/trend-charting workflow above expects.

---

## 🗂️ Project Manifest / SBOM Audit (`--audit` / `--project-file`)

Cross-references a local dependency manifest against currently-mutating advisories in the window, so you can see which of *your* actual dependencies are showing up in upstream churn right now. Supported formats (auto-detected, or force with `--project-format`):

| Format | Flag value |
|---|---|
| Python `requirements.txt` | `pypi_requirements` |
| Maven dependency tree (`mvn dependency:tree` output) | `maven_tree` |
| CycloneDX SBOM (JSON) | `cyclonedx_json` |

```bash
python top10ecosystems.py --database --layer app --from 2026-04-18 --to 2026-05-28 --project-file requirements.txt
```

---

## 📤 Snapshot Export & Comparison

`--export [PATH]` writes the current run's results to a JSON snapshot (auto-named into `./output` if no path is given). `--compare BASE.json CURRENT.json [--html OUT.html]` diffs two snapshots' leaderboards, threat profiles, and outlier pools without needing `--database` at all — pure file-to-file comparison.

---

## ⚙️ Requirements

- Python 3.9 or newer recommended.
- Network access to OSV-hosted data, the FIRST EPSS feed, and the CISA KEV catalog (for archive bootstrapping, incremental sync windows, and the KEV/EPSS enrichment pipelines).
- Python libraries (see `requirements.txt`): `requests`, `cvss`, `matplotlib` (for `--html` charts), `plotext` (for `--terminal-plot`).
