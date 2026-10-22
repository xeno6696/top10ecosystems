# OSV Threat Stream Campaign Dashboard Indicator

A Python command-line security engineering tool for tracking software supply chain activity across the Open Source Vulnerability (OSV) database.

The script builds a local advisory index from OSV, reads the OSV modified advisory stream, and produces a terminal dashboard showing which ecosystems are experiencing the most vulnerability database churn over a selected time window. Beyond the core dashboard, it also cross-references CISA's KEV catalog and FIRST's EPSS exploitation-probability scores into a prioritized dispatch list, tracks cross-registry package relationships (native multi-registry releases vs. mechanical repackaging vs. duplicate CVE tracking across ecosystems), generates historical trend charts, audits a local project manifest/SBOM against currently mutating advisories, and hunts for suspicious retracted advisories.

## 🚀 Quick Start & Execution Path

For an engineer cloning this repository clean, follow this sequential execution path to bootstrap the environment and wire the high-performance local database warehouse:

### 1. Clone the Repository & Set Up the Environment
The supported environment is the Python version in `.python-version` with the exact package versions in `requirements.lock`. One script builds it, using plain `venv` and `pip` (nothing else to install):
```bash
git clone <your-repository-url>
cd top-10-ecosystems
python setup_env.py
```
It creates a project-local `.venv` from whichever Python runs the script, installs the locked versions, and verifies the imports. It is safe to re-run (after pulling a changed lock file, or when an import fails): it only installs when the lock file changed. Nothing is mandatory: on a different Python it still builds a working venv and just says it is unsupported. If a pinned version doesn't exist for your Python, `pip install -r requirements.txt` into the venv is the unsupported way around it.

| Flag | What it does |
|---|---|
| *(none)* | Create `.venv` if missing, install the locked versions, verify imports. |
| `--check` | Read-only: report whether `.venv` is the supported environment (Python version, lock hash, per-package drift); exits non-zero if not. |
| `--force` | Reinstall even if the lock file is unchanged. |
| `--recreate` | Delete and rebuild `.venv` (the Python it was built from was removed or replaced). It is never deleted without this flag. |
| `--relock` | Maintainers: regenerate `requirements.lock` from `requirements.txt` by installing it into a scratch venv and freezing the result. Edit `requirements.txt`, relock, run the tests, commit both. |

Run the tools with the venv's interpreter (`.venv\Scripts\python.exe` on Windows, `.venv/bin/python` elsewhere), or activate it first (`.venv\Scripts\Activate.ps1` / `source .venv/bin/activate`). The commands below assume it is active.

**Support policy.** A bare `python` can be a different interpreter than the venv's, which used to show up as `ModuleNotFoundError: No module named 'cvss'`; the tools now stop with a one-line message pointing at `setup_env.py` instead. If they start in an environment that isn't the supported one (different Python, or packages that differ from the lock), they print `[!] Unsupported environment -- Python X (supported: Y) | lock <hash> | packages: N differ` on stderr and carry on. Paste that line into a bug report: results from any other environment aren't supported. Set `TOP10_ALLOW_UNSUPPORTED_ENV=1` to silence it for deliberate experiments.

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

Cross-checks the CISA KEV catalog, FIRST's EPSS exploitation-probability score, and raw OSV/CVSS severity against the vulnerability catalog for a given window. The console table always shows the "what should a developer actually work on first" ranking — KEV (known to be actively exploited) first, then by descending EPSS probability, then by CVSS. Requires an explicit `--registry` filter:
```bash
python top10ecosystems.py --crosscheck --registry npm,PyPI --from 2026-08-18 --to 2026-09-17
```
- `--crosscheck-limit N` caps the console table to the top N rows (default 100; `0` for uncapped).
- `--crosscheck-export [PATH]` exports the full, uncapped list as **three** JSON files — one per ranking mode, same underlying rows, different sort/rank — so a consumer picks exactly the ranking they mean instead of reconciling multiple numbers themselves:
  - `<PATH>_default.json` — CVSS only (the pre-KEV baseline)
  - `<PATH>_epss.json` — EPSS probability first, no KEV gate
  - `<PATH>_kev.json` — KEV → EPSS → CVSS (matches the console table)

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

## 🕓 Vulnerability Timeline (`--timeline`)

Pass one or more CVE or advisory IDs and get a dated history of each, fetched live, so an analyst can answer "what has happened to this, and how urgent is it" in one screen. It needs no warehouse and none of the modification-stream download the other modes do, so it returns in a few seconds:
```bash
python top10ecosystems.py --timeline CVE-2016-3081
python top10ecosystems.py --timeline GHSA-8c6j-ffmf-q6vm CVE-2023-44487   # several IDs; an advisory ID resolves to its CVE
python top10ecosystems.py --timeline CVE-2016-3081 --json                 # one JSON array, no color codes
```
It reads three live sources: `api.osv.dev` (the record and every record it links to), the CISA KEV feed, and `api.first.org` (EPSS history). Each row of the timeline is tagged with where it came from.

| Section | What it shows |
|---|---|
| Triage signals (first) | What the dated events suggest, each with its evidence, tagged `[RAISES]`, `[LOWERS]` or `[CONTEXT]` (see below). |
| Records | Every linked record: published, last modified, CVSS (computed from the vector, with a warning when trackers disagree), ecosystems, withdrawn. |
| Timeline | Dated events with a day count from the first publication: PUBLISHED (including the NVD date), REVIEWED (GitHub), MODIFIED, WITHDRAWN, EXPLOITED (KEV, with due date and ransomware use), SCORED (EPSS moves of a point or more, plus the start and latest). |
| Trackers | When each tracker (Debian, Ubuntu, Bitnami, GitHub, and so on) first published and how many days after the first publication, so distro lag is visible. |
| Fixed versions, References | Fixed versions per package, and reference counts by type with the fix-commit and evidence links listed. |
| At a glance | Exploited or not, KEV deadline status (flagged OVERDUE only within 30 days of the deadline), first publication to KEV, EPSS level and one-week trend, fix availability, withdrawn. |

**Triage signals** are printed first, because they are what gets discussed in a triage call. They state a fact, the evidence behind it, and what it usually means, for example "EPSS kept rising after KEV listing: 93.4% -> 96.1% (+2.7 pts): predicted exploitation grew after confirmation". They cover KEV listing (and how old the flaw was when listed), known ransomware use, top-percentile EPSS, EPSS jumps (including ones that preceded a KEV listing) and rises or falls after listing, public exploit/evidence links, packages with no fixed version, a fix being available, withdrawal, and context such as severity disagreement between trackers, a new or recently updated record, and how widely it is packaged. **The report prints a caution under the heading, and carries it in the JSON as `signals_caveat`: the thresholds are starting guesses that have not been checked against real incident outcomes, so treat the signals as guidelines for discussion, not calibrated findings. There is deliberately no verdict, tally or recommendation**: whether to escalate, hold or de-escalate is the analyst's or team's decision, and the tool only surfaces what bears on it. The signals can describe the relationship between dated events, never a field change such as a CVSS rescore (OSV and KEV keep no history). Thresholds (EPSS jump size, top percentile, "old flaw" age, how recent counts as recent) are constants at the top of `timeline_signals.py`, so a team can tune them; the `--json` output carries every signal as `{direction, id, text, meaning}` plus the EPSS series they were computed from.

Things it does on purpose: the ID you pass and the main CVE always get their own rows, while other records collapse to one row per tracker (at most 25 records, 3 per tracker, are fetched in full; the rest are counted, so a CVE linked to hundreds of per-image records stays readable). If several CVEs are linked, it follows one that is on the KEV list and names the others. If a source is down it prints what it has plus a note, and an ID is validated against a strict pattern before it reaches a URL. Exit code is non-zero if any ID produced nothing.

**What it cannot show.** OSV and KEV keep only the latest version of a record, so the report says *when* something was modified, never *what* changed; field-level diffs (CVSS rescoring, range edits) would need NVD history or upstream git. FIRST serves only the last 30 days of EPSS. The report states both limits at the bottom.

---

## 🔭 Situation Report (`--sitrep`)

`--timeline` starts from OSV, but a new CVE can exist for hours or days before OSV has a record under its own ID (CVE-2026-109618 existed only as Debian, Ubuntu and Bitnami records at first). `--sitrep` asks a configurable list of trusted sources about one CVE in a single pass and lays out what each one says.

```bash
python top10ecosystems.py --sitrep CVE-2026-109618
python top10ecosystems.py --sitrep CVE-2026-109618 CVE-2026-109619 --json        # one JSON array
python top10ecosystems.py --sitrep CVE-2026-109618 --sources "core,-github_repos,-github_oldest"   # skip sources
python top10ecosystems.py --sitrep CVE-2026-109618 --sources "core,extra"                          # add SUSE, Amazon Linux, Oracle Linux
```

Exit code: `0` something was found, `1` nothing was, `2` bad ID or configuration.

**Live status.** A run takes 10 to 35 seconds: requests to GitHub are paced to its public rate limit, and the network or DNS is sometimes slow. While it works, a block on **stderr** shows each source's state with a spinner and a running seconds counter (`contacting cveawg.mitre.org`, `waiting for api.github.com's rate limit`, `[ok] Debian ... 0.2 s`), plus the warehouse lookup and any linked pages as they are found. For `--sitrep` the finished block stays on screen above the report, so you can see which source took how long; `--watch` erases it after each poll (it would otherwise fill the screen) and leaves one summary line. It never touches stdout, so `--json` stays clean. A terminal that cannot redraw gets one line per finished source; redirected output gets nothing; `--no-progress` turns it off. `--json` also carries each source's elapsed seconds, and any source over 10 seconds is noted with the `--sources` expression that skips it.

**What it shows:** the CVE record's state (cve.org, NVD), every CVSS score each source gave (shown side by side, never merged: 9.2 vs 9.8 vs 8.1 is a finding), exploitation signals (CISA KEV, EPSS, CISA's SSVC assessment, and an *unvetted* GitHub repository sample), who ships a fix (Debian, Ubuntu, Red Hat, Arch Linux; SUSE, Amazon Linux and Oracle Linux as link-only leads in the opt-in `extra` profile), whether GitHub's advisory database (which aggregates most package registries) has an entry, what OSV itself has, which warehouse layers the CVE has reached (container vs app; from the warehouse if one exists), and a timeline across all of it.

**Coverage gaps.** When a warehouse is available, the report sets its records for the CVE against the sources configured, both ways: ecosystems that have warehouse records but no source of their own (Bitnami, for example, is seen only through OSV and the warehouse), and ecosystem-specific sources that answered while the warehouse holds nothing for their ecosystem (OSV has not ingested them yet, or this tool does not track those ecosystems). A source declares the ecosystems it speaks for with `ecosystems`.

**References checklist.** After the leads, a `REFERENCES` section lists every page the records point at, one row per page however many sources listed it (cve.org, NVD, GitHub Advisories and the distro trackers spell their tags differently, and the tags are merged), grouped by what the records say it is (`vendor-advisory`, `patch`, `third-party-advisory`, ...). Each row is a box: `[ ]` not read, `[x]` fetched and summarized in LEADS, `[!!]` fetch failed (Adobe's bulletin, for instance, answers 403 to anything but a browser, so it stays a link for you to open). Pages about the CVE on sources sitrep already queries (the NVD page, the KEV catalog link, the GitHub advisory) are counted on one line instead of listed. Only hosts on `follow_hosts` are ever fetched; the rest are listed, never fetched. The console shows the first 30; `--json` has them all.

**Colour.** On a terminal the report is colour-coded, with one meaning per colour: **teal** for who is speaking (`CISA-ADP SSVC:`, `Red Hat rating:`, `Debian fixed:`, `EPSS`), which is neutral and never implies good or bad; **green** for `[ok]` and `[x]`; **yellow** for a caution (sources disagree, or a time on a clock that is not the source's own); **red** for an alarm or failure (`LISTED` on KEV, exploitation `active`, `[!!]`, `[xx]`); **dim** for what should recede (rules, the source tag at the end of a line, `[--]`, the caution paragraph); **bold** for section names. Colour only adds escape codes to text that is already there. It is never used for `--json`, a pipe or a file, and `--no-color` or the `NO_COLOR` environment variable turns it off. `--watch` colours its alerts the same way.

**Clocks.** Every timeline row says what kind of time it is: `declared` (the source's own timestamp), `header` (an email or HTTP date), `ingested` (when a feed picked it up) or `approximate` (read from prose). They are not directly comparable, and no channel is assumed to hear first; the order comes from the data. A time of exactly midnight is shown as a date, never an invented hour, and a linked page gets a timeline row only if it states a date about itself (an email's `Date:` header or an article timestamp); an HTTP `Last-Modified` header or an index page's first `<time>` tag is ignored, since a wrong time is worse than none.

**It makes no verdict.** A source that is silent shows as `[--]` in the coverage list, an unreachable one as `[!!]`, a refused one as `[xx]`; none of that is evidence the CVE is quiet. Pages that records link to (for example an oss-security post) are fetched only when their host is on the follow list, and appear as leads with a title and date for you to read.

**Sources are data, not code.** `sitrep_sources.json` ships the defaults. Put personal changes in `sitrep_sources.local.json` (git-ignored); an entry with an existing id overrides only the fields it names, a new id adds a source:

```json
{"sources": [
  {"id": "github_repos", "enabled": false},
  {"id": "vendor_x", "label": "Vendor X", "kind": "link", "url": "https://vendor.example/advisories/{cve}",
   "path": "vendor", "trust": "lead", "profiles": ["core"]}],
 "follow_hosts": {"blog.example": {"label": "a blog", "path": "community"}}}
```

- `kind`: `builtin` (a parser shipped with the tool), `link` (only points at a page: title and date) or `json` (named fields read by dotted path: `fields: {"published": "meta.when", "severity": "scores.0.value"}`).
- `path` says how the fact reached us (`upstream`, `records`, `registry`, `distro`, `vendor`, `exploitation`, `community`, `osv`); `trust` says whether the source is the authority for what it states (`primary`) or a pointer to go and read (`lead`).
- `profiles` group sources: `--sources core` is the default, `--sources all` is everything enabled, profiles combine (`core,extra`), and `+id` / `-id` adjust the result.
- `ecosystems` lists the OSV ecosystems a source speaks for (`["Debian"]`), which feeds the coverage-gap report. `must_mention: true` makes a link source count as found only if the page names the CVE, so a generic page for a CVE the site has never heard of is not mistaken for a hit.
- Optional rate limits and credentials: `min_interval` seconds between requests to a host, and `token_env` naming an environment variable (for example `GITHUB_TOKEN`, `NVD_API_KEY`) whose value is sent only to that source's own host. Tokens are never stored.
- There are no executable plugins; a parser for a new structured format is a change to `sitrep.py`.

**Safety.** The config is the allow-list: HTTPS GET only, no private, loopback or internal hosts, no credentials in URLs, redirects must stay on the same host, responses are size-capped, and fetched text is only parsed, never followed as instructions. GitHub repositories mentioning a CVE are metadata only; the tool never clones or downloads them, and such repositories can be fake or malicious.

**What it cannot show.** It reports what sources publish at the moment you ask; OSV and the others keep only their latest state, so it cannot say what changed between two asks. GitHub cannot sort repositories by creation date, so the "oldest activity" row is a sample, not a proven first. A watch mode that remembers earlier runs is not built yet.

---

## 👁 Watching a CVE (`--watch`)

OSV, KEV and the other sources keep only their latest state, so a change is visible only if something remembered the last state. `--watch` polls `--sitrep` on a schedule, compares each poll with a stored baseline, and tells you what is new or different.

```bash
python top10ecosystems.py --watch CVE-2026-109618                    # poll every 10 minutes until Ctrl-C
python top10ecosystems.py --watch CVE-2026-109618 CVE-2026-109619 --every 5
python top10ecosystems.py --watch CVE-2026-109618 --once --json      # one poll, exit code 0 / 10 / 11 (scriptable)
python top10ecosystems.py --watch CVE-2026-109618 --alert exploitation,disclosure,fix
```

The first poll records a **baseline** and never alerts. After that, only changes are printed (a quiet `no change` line otherwise), with a live countdown to the next poll on a terminal. State lives in `output/watch/<CVE>.json` (the baseline and when *we* first saw each item) and `<CVE>.history.jsonl` (every poll that had changes); delete the files to start over.

**What counts as a change.** Anything worth a row on the `--sitrep` timeline is: a new event, or the same event with a new time ("CVE record last updated"). Also: the CVE record's state, severity scores, fix statements, and CISA's SSVC assessment when their text changes; a source that starts answering; a new warehouse record, and the first one in an app registry. Deliberately *not* changes: the GitHub repository count growing by the minute (it counts when the first repository appears, then each time the count at least doubles), EPSS drifting by less than a point (the baseline keeps the last *reported* value, so slow growth accumulates until it counts), KEV staying "not listed", and a source that times out (its last good values are kept, and it is noted as degraded after three failed polls in a row). Nothing is ever reported as "gone".

**Alert tiers.** Each change has a class: `exploitation` (KEV listing, SSVC, EPSS, public repositories, exploitation events), `disclosure` (the CVE record's state, upstream/records/OSV events, written-up pages with a date), `exposure` (new warehouse records or sources answering), `severity`, `fix`, and `records` (updated timestamps, undated linked pages). `exploitation` and `disclosure` are **immediate** by default: a terminal bell and an `!! IMMEDIATE` banner. The rest are listed under `digest`. `--alert` chooses the immediate classes.

**First seen by us.** Every change shows when the watcher first saw it. That is the honest "ingested" clock, so over a few days the history answers which channel told *you* first, whatever the channels' own timestamps say.

**Cost.** A poll is a full `--sitrep` (10 to 35 seconds). Slow or rate-limited sources (`github_repos`, `github_oldest`, `suse`, `amazon`, `oracle`) have `"watch_every": 3` in `sitrep_sources.json`: they are asked on every third poll and keep their last values in between. `--every` has a one-minute floor because the sources are rate limited.

**Not built yet (TODO): notifications when nobody is watching.** Alerts reach only the terminal (a bell and a banner). The planned next step is sending the diff somewhere: email first (SMTP settings and recipients in a git-ignored local file, credentials from environment variables, one message per poll with immediate changes and the digest in the body, plus a `--test-notify` that sends a harmless sample), and a generic `on_change` command hook that receives the poll record as JSON for toast, Slack or Teams. See the `TODO(notify)` note in `watch.py`.

**A source that failed at baseline** and answers later is filled into the baseline silently (with a note), because a late answer cannot be told from a new one and a flaky network must not look like news.

**Exit codes with `--once`:** `0` baseline or no change, `10` digest-only changes, `11` immediate changes, `2` bad request. `--json` prints one array of poll records.

---

## 📊 Historical Trend Charting (`--velocity` / `--report`)

Two related but separate tools for looking at churn over time instead of a single window:

- **`--velocity [DIR]`** stitches a directory of previously-exported JSON snapshots (default `./output`) into a single time-series CSV matrix (`velocity_matrix.csv`), with an optional inline terminal chart via `--terminal-plot`.
- **`--report OUTPUT_FILE`** builds an HTML dashboard from the same snapshot directory. Two charts always render — ecosystem-level and threat-profile-level **day-over-day deltas** (not raw cumulative totals — a real burst shows up as an actual spike, not a subtle change in slope) — plus four more that render automatically whenever the loaded snapshots carry the data for them (older snapshots, or a window with zero overlap, just skip that section rather than rendering something empty):
  - **III. KEV Lead Time Trend** — two views of how many days passed between a CVE's earliest known publish date and CISA adding it to the KEV catalog, read straight from the warehouse at report time (no snapshot field involved, so a change to the definition never needs the archive regenerated). It is a supply-chain view: only CVEs with an application-registry advisory count, and a CVE counts in the period CISA *listed* it whether or not its OSV record was edited since. *Our recording period* plots the median (solid), the mean (lighter, dashed, pulled up by a few very old CVEs) and how many CVEs each point holds, cumulative from the archive's first day, with a bucket bar (under 30 days / 30 days to 1 year / 1 to 3 years / over 3 years) for the latest point. *Lifetime view* groups every measurable CVE by the quarter CISA listed it (median, interquartile range, count), splits the quarter we started recording in at that day, shades the recording period, and holds CISA's 2021-2022 launch backfill apart from the later quarters. The page states how much of the catalog is measurable and that quarters hold only a handful of CVEs, so one quarter's median is noisy.
  - **IV. CVE Active TTR Distribution** — a box plot of days-since-last-modified for active CVE advisories, one box per ecosystem, from the *latest* snapshot in the loaded window only (a distribution's shape isn't something that gains meaning from being diffed across days). Shows both median (box) and mean (diamond marker) together, since Section IV's console table only ever printed the mean — which can badly misrepresent the typical case under a long right skew (e.g. npm's Active TTR (CVE) has run as much as 23x higher on mean than median, driven by a handful of ancient stragglers a mean-only number hides completely).
  - **V. CVSS vs EPSS** — a scatter of every advisory this window that has both a CVSS score and EPSS data, colored by ecosystem with KEV-listed advisories picked out as red stars, from the latest snapshot only. Only advisories with a resolvable CVE ID have EPSS (about 8% of the warehouse). It shows how weakly CVSS predicts exploitation likelihood (they correlate at about +0.33 across the warehouse): look for stars low on the chart (KEV-confirmed despite modest severity) and unmarked dots high on it (likely exploited, not yet confirmed). Snapshots exported before this chart existed simply skip it. Each registry's ordinary dots are randomly thinned to 1,500 while every KEV-listed advisory is drawn, so the stars look denser against the crowd than they really are; the page says so, with how much of each registry is drawn, and overlays a trendline (median EPSS per one-point CVSS band, with the middle half shaded) computed from all advisories rather than the dots.
  - **VI. What EPSS Adds** — the Section V scatter with EPSS taken away (CVSS alone, KEV-listed advisories as stars among everything else), next to bars pricing five simple triage rules (CVSS ≥ 9 / 7 / 4, EPSS ≥ 10% / 1%): how many advisories each rule puts in the work queue against how many KEV-listed advisories it reaches. The counts are exported with each snapshot from the full advisory pools (each advisory counted once, charted registries only), not the down-sampled scatter points; snapshots exported earlier fall back to the plotted sample and say so.

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
- Network access to OSV-hosted data, the FIRST EPSS feed, and the CISA KEV catalog (for archive bootstrapping, incremental sync windows, and the KEV/EPSS enrichment pipelines). `--timeline` also queries `api.osv.dev` and `api.first.org` live.
- Python libraries (see `requirements.txt`): `requests`, `cvss`, `matplotlib` (for `--report` charts), `plotext` (for `--terminal-plot`).
