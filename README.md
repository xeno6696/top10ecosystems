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
| `--verify` | **Read-only audit** against the live OSV modification feed. Reports advisories the feed lists that the warehouse is missing, and ones whose stored `last_modified` day is older than the feed's. Changes inside the last hour before the sync high-water mark are reported as *pending* rather than failures (the next sync re-fetches that window on purpose; the upstream index and API can lag a few minutes). Exits non-zero on any missing/stale advisory. Takes ~15s. |
| `--skip-kev` | Skip the CISA KEV catalog refresh pipeline for this run. |

### 3. Run the Verification Suite
```bash
python test_runner.py
```
The suite needs the warehouse from step 2 and takes a few minutes, mostly spent loading the advisory index. It checks:

- **Ingest fixtures** — small hand-built OSV records run through `db_warehouse.parse_osv_json` with exact expected output: threat classification, ecosystem bucketing, repo anchors, dwell, blast radius, advisory-ID handling. Each case is a real bug that was found in this tool, pinned so it can't return.
- **Warehouse health invariants** — read-only checks that hold after *any* refresh: no mangled advisory IDs, no polluted repo anchors, well-formed columns, and a sync high-water mark that is consistent with the data actually stored. These never need re-minting. A failure means the warehouse itself needs attention, usually `python db_warehouse.py --rebuild`.
- **Sync behavior** — faked-network tests of the incremental sync: baseline selection, failure accounting, the atomic master-archive download, and the `--verify` audit.
- **Report logic** — dashboards, exports, trend and cross-check rendering.
- **The `--compare` text baseline** — `src/test/resources/comparison_console_output.txt` pins the console formatting of `--compare` for two fixed snapshot files. It is deterministic and independent of the warehouse. If you change that output's format on purpose, re-mint it with `python test_runner.py --update` (the file is UTF-16 encoded).

There are deliberately no "golden master" comparisons against live warehouse data: they drifted on every routine refresh, which trained people to re-mint blindly, and they never caught the ingest bugs that mattered.

### 4. Run the Main Dashboard Engine
With the warehouse populated, run the core application. The warehouse built by `db_warehouse.py` is the only data source; if it hasn't been built, commands stop with a message telling you to run `python db_warehouse.py`:
```bash
# Analyze application registry layers over a distinct historical interval
python top10ecosystems.py --layer app --from 2026-04-18 --to 2026-05-28
```

### 5. High-Performance Isolation Filtering
To skip heavy scanning overhead and optimize operational speeds, pass the `--registry` option along with a comma-separated checklist array to drop unrelated database footprints instantly. Quote the whole list if any registry name contains spaces or parentheses (e.g. `Maven (Java)`):
```bash
# Isolate calculation matrix mappings strictly to target registries
python top10ecosystems.py --registry "npm,PyPI,Maven (Java)" --from 2026-04-18 --to 2026-05-28
```

### 6. Advanced Research Hunting & Snapshot Tooling
```bash
# Hunt for suspicious contested retractions within a context window
python top10ecosystems.py --layer app --from 2026-04-18 --to 2026-05-28 --hunt-retracted

# Standalone Comparison (pure file-diffing, no warehouse needed)
python top10ecosystems.py --compare snapshot_a.json snapshot_b.json
```

---

## 🔁 Daily Operation (Runbook)

1. **Sync the warehouse.** `python db_warehouse.py` resumes from the warehouse's own recorded high-water mark, so a missed day just means a bigger catch-up. EPSS and KEV refresh automatically once their caches are 24h old.
2. **Archive each new *complete* UTC day.** `python top10ecosystems.py --layer app --to YYYY-MM-DD --export`. Several days can go in one run (`--to 2026-10-05,2026-10-06`). Never snapshot the current, still-partial day. Snapshots are cumulative from the archive's start date, so each new file is its own day's totals and the charts diff consecutive days.
3. **Check the warehouse.** `python db_warehouse.py --verify` (about 15s) for a live audit against upstream, and `python test_runner.py` for the health invariants and logic tests.
4. **Build a briefing.** `python top10ecosystems.py --layer app --from X --to Y --report output/briefing.html`.

**When to rebuild:** if `--verify` keeps reporting stale or missing advisories after a `--sync`, if a warehouse health test fails, or after pulling code that changes ingest/parsing. Run `python db_warehouse.py --rebuild`. The warehouse is disposable by design and archiving it first isn't needed. A rebuild also re-fetches the master archive, so expect several minutes.

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
| IV | Ecosystem Threat Metabolism & Systemic Backlog Matrix | Dwell-time (time-to-fix) averages, backlog age, plus average EPSS and KEV-hit count per ecosystem. |
| VI | New Arrivals & Campaign Discoveries Within Timeframe | Advisories that are brand-new (not just updated) within the window, with EPSS / KEV per advisory. |
| VII | Systemic Risk vs. Active Exposure (The Attention Deficit) | Flags advisories with high objective severity but low community/tracking attention, with EPSS / KEV per advisory. |
| VIII | Is This The Same Vulnerability Showing Up More Than Once? | Three sub-tables (see below). |

**Section VIII** answers a specific supply-chain question: when the same advisory spans multiple ecosystems, is that because the same project is genuinely released natively to each registry, or because one registry is just vendoring another's code unmodified?
- **VIII-A — True Cross-Compiled**: the same upstream project independently released to multiple registries (e.g. a library shipped natively to both PyPI and Maven).
- **VIII-B — Repackaged-As-Is**: one registry mechanically vendoring another's artifact unmodified (the textbook case is Maven's `webjars` namespace wrapping an npm package verbatim), with a per-ecosystem fix-status marker (`F`/`U`/`?`) and a dependency-direction signal for which side is the plausible upstream fix origin.
- **VIII-C — Cross-Tracker CVE Correlation**: the same CVE independently tracked as separate advisory records across ecosystems.

Sections VI and VII rank by CVSS by default. Pass `--priority-sort` to also render them ranked by KEV presence → EPSS score → CVSS, and by EPSS alone → CVSS, alongside the default view.

> **Section numbering:** there is no Section V. It ranked advisories by blast radius (affected-version count), which against the real warehouse correlates negatively with EPSS (−0.16, versus +0.33 for CVSS) and has no KEV-rate trend — it tracks how many releases a project has shipped, not how dangerous a flaw is — so it was retired. The remaining sections keep their numbers. The `blast_radius` column and the snapshot fields derived from it are still stored and still feed `--compare` / `--velocity`.

---

## 🎯 KEV/EPSS Prioritized Dispatch List (`--crosscheck`)

Cross-checks the CISA KEV catalog, FIRST's EPSS exploitation-probability score, and raw OSV/CVSS severity against the vulnerability catalog for a given window. The console table always shows the "what should a developer actually work on first" ranking — KEV (known to be actively exploited) first, then by descending EPSS probability, then by CVSS/blast-radius. Requires an explicit `--registry` filter:
```bash
python top10ecosystems.py --crosscheck --registry npm,PyPI --from 2026-08-18 --to 2026-09-17
```
- `--crosscheck-limit N` caps the console table to the top N rows (default 100; `0` for uncapped).
- `--crosscheck-export [PATH]` exports the full, uncapped list as **three** JSON files — one per ranking mode, same underlying rows, different sort/rank — so a consumer picks exactly the ranking they mean instead of reconciling multiple numbers themselves:
  - `<PATH>_default.json` — CVSS/blast-radius only (the pre-KEV baseline)
  - `<PATH>_epss.json` — EPSS probability first, no KEV gate
  - `<PATH>_kev.json` — KEV → EPSS → CVSS/blast-radius (matches the console table)

  (omit `PATH` and it defaults to `output/supply_chain_crosscheck_<end-date>_<mode>.json`). Each file's `dispatch_list` rows carry an explicit `rank` field for that mode.

---

## 📈 Ecosystem Trend Briefings (`--trends`)

Computes lookback trend metrics, mutation-velocity spikes, and dormancy-decay models for a specific registry over a rolling window (default 30 days, override with `--window-days N`). Requires an explicit `--registry` target:
```bash
python top10ecosystems.py --trends --registry npm --window-days 30 --to 2026-09-17
```
Includes a KEV-first prioritized list plus a secondary EPSS-only watchlist for advisories that aren't in KEV but carry a meaningfully elevated exploitation probability.

---

## 🔍 Retraction Hunting (`--hunt-retracted`)

Surfaces advisories that were published, then withdrawn/retracted, with unusually long dwell times before retraction — a pattern worth a second look, since a retraction that took a long time to happen is a different risk profile than one caught and reversed quickly. 
```bash
python top10ecosystems.py --layer app --from 2026-04-18 --to 2026-05-28 --hunt-retracted
```

---

## 📊 Historical Trend Charting (`--velocity` / `--report`)

Two related but separate tools for looking at churn over time instead of a single window:

- **`--velocity [DIR]`** stitches a directory of previously-exported JSON snapshots (default `./output`) into a single time-series CSV matrix (`velocity_matrix.csv`), with an optional inline terminal chart via `--terminal-plot`.
- **`--report OUTPUT_FILE`** builds an HTML dashboard from the same snapshot directory. Two charts always render — ecosystem-level and threat-profile-level **day-over-day deltas** (not raw cumulative totals — a real burst shows up as an actual spike, not a subtle change in slope) — plus three more that render automatically whenever the loaded snapshots carry the data for them (older snapshots, or a window with zero overlap, just skip that section rather than rendering something empty):
  - **III. KEV Lead Time Trend** — for advisories later confirmed as actively exploited (CISA KEV), the mean days between the CVE's earliest known publish date and its KEV catalog addition, as of each snapshot. Unlike the other charts this one plots the raw value, not a delta — it's already a point-in-time distribution stat, not a running total.
  - **IV. CVE Active TTR Distribution** — a box plot of days-since-last-modified for active CVE advisories, one box per ecosystem, from the *latest* snapshot in the loaded window only (a distribution's shape isn't something that gains meaning from being diffed across days). Shows both median (box) and mean (diamond marker) together, since Section IV's console table only ever printed the mean — which can badly misrepresent the typical case under a long right skew (e.g. npm's Active TTR (CVE) has run as much as 23x higher on mean than median, driven by a handful of ancient stragglers a mean-only number hides completely).
  - **V. CVSS vs EPSS** — a scatter of every advisory this window that has both a CVSS score and EPSS data, colored by ecosystem with KEV-listed advisories picked out as red stars, from the latest snapshot only. Only advisories with a resolvable CVE ID have EPSS (about 8% of the warehouse). It shows how weakly CVSS predicts exploitation likelihood (they correlate at about +0.33 across the warehouse): look for stars low on the chart (KEV-confirmed despite modest severity) and unmarked dots high on it (likely exploited, not yet confirmed). Snapshots exported before this chart existed simply skip it.

  Respects `--from`/`--to` to scope the date range, and `--layer` to restrict which layer's archive to aggregate (defaults to `app`, matching the daily archive convention below — mixing snapshots from different layers or scopes in one chart produces meaningless collisions, so it won't do that unless you explicitly ask for a different layer).

```bash
# Build/refresh the daily archive one day at a time (or as a comma-separated batch in one run
# for guaranteed single-warehouse-state consistency across the whole range):
python top10ecosystems.py --layer app --to 2026-09-18,2026-09-19,2026-09-20 --export

# Then chart it:
python top10ecosystems.py --report output/threat_landscape_report.html --from 2026-08-01 --to 2026-09-20
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
python top10ecosystems.py --layer app --from 2026-04-18 --to 2026-05-28 --project-file requirements.txt
```

---

## 📤 Snapshot Export & Comparison

`--export [PATH]` writes the current run's results to a JSON snapshot (auto-named into `./output` if no path is given). `--compare BASE.json CURRENT.json [--report OUT.html]` diffs two snapshots' leaderboards, threat profiles, and outlier pools without needing the warehouse at all — pure file-to-file comparison.

---

## ⚙️ Requirements

- Python 3.9 or newer recommended.
- Network access to OSV-hosted data, the FIRST EPSS feed, and the CISA KEV catalog (for archive bootstrapping, incremental sync windows, and the KEV/EPSS enrichment pipelines).
- Python libraries (see `requirements.txt`): `requests`, `cvss`, `matplotlib` (for `--report` charts), `plotext` (for `--terminal-plot`).
