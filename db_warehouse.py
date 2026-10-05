#!/usr/bin/env python3
# Copyright (C) 2026 xeno6696
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
OSV Relational Data Warehouse Coordinator - Version 2.0
=================================================================================
Parallel warehousing backend engineered to bulk-seed from a master snapshot cache 
(auto-downloading if missing), execute dynamic sync updates, maintain daily EPSS 
models, and index formal CWE vulnerability classifications alongside CVE alias bridges.
"""

import argparse
import concurrent.futures
from contextlib import contextmanager
import csv
import datetime
import gzip
import io
import json
import os
import re
import sqlite3
import sys
import time
import zipfile
from collections import Counter
from cvss import CVSS2, CVSS3, CVSS4
import requests

from osv_ecosystems import clean_ecosystem_tag

# Storage Routing Baselines
DB_DIR = "database"
DB_PATH = os.path.join(DB_DIR, "threat_stream.db")
CACHE_DIR = "./cache"
LOCAL_ZIP_PATH = os.path.join(CACHE_DIR, "osv_master_all.zip")
EPSS_GZ_PATH = os.path.join(CACHE_DIR, "epss_scores-current.csv.gz")
KEV_JSON_PATH = os.path.join(CACHE_DIR, "known_exploited_vulnerabilities.json")

MASTER_ZIP_URL = "https://storage.googleapis.com/osv-vulnerabilities/all.zip"
MANIFEST_URL = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
EPSS_FEED_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API_URL = "https://api.osv.dev/v1/vulns/"

# Terminal Visual Presentation Elements
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"





# Cross-registry product-identity signal: matches "github.com/OWNER/REPO" wherever it shows up,
# either in an advisory's own reference links or embedded directly in a Go-ecosystem purl
# (pkg:golang/github.com/OWNER/REPO...). Used by extract_repo_anchor() below.
GITHUB_REPO_URL_REGEX = re.compile(r'github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)', re.IGNORECASE)
# "cvelistv5" is the CVE Project's own record-mirror repo (cveproject/cvelistv5) -- many
# advisories (Chainguard's CGA-* entries especially) cite it as their only reference link instead
# of, or alongside, the actual vulnerable project's repo. Left unskipped, it silently becomes the
# single most common repo_anchor value in the warehouse (53.6% of all non-null anchors, verified
# live) and degrades every one of those advisories to the weaker name-matching heuristic tiers
# with no visible signal that the "HIGH confidence, shared-upstream-repo" signal never had a
# chance to fire.
_GITHUB_REPO_ANCHOR_SKIP = {"advisories", "security", "security-advisories", ".github", "cvelistv5"}







def extract_repo_anchor(vuln_data):
    """Derives a canonical 'owner/repo' identity string for an advisory, used downstream to tell
    a genuinely multi-ecosystem NATIVE release of the same upstream project (true
    cross-compilation -- e.g. the same project shipping both a Go module and a Rust crate) apart
    from one ecosystem mechanically vendoring/repackaging another's code as-is (e.g. Maven's
    webjars wrapping an npm package unmodified, or an OS distro repackaging an upstream lib).

    Pulled from two places, in priority order:
      1. Go-ecosystem purls, which embed the source repo path directly
         (pkg:golang/github.com/OWNER/REPO...) -- weighted higher since this is an explicit,
         structured package-identity field rather than an incidental link.
      2. The advisory's own references[] list, which almost always includes a link back to the
         canonical source repo.
    Returns None when no repo identity can be recovered."""
    candidates = Counter()

    for ref in vuln_data.get("references", []):
        url = ref.get("url", "") or ""
        m = GITHUB_REPO_URL_REGEX.search(url)
        if m:
            owner, repo = m.group(1).lower(), re.sub(r'\.git$', '', m.group(2), flags=re.IGNORECASE).lower()
            if repo in _GITHUB_REPO_ANCHOR_SKIP:
                continue
            candidates[f"{owner}/{repo}"] += 1

    for affected in vuln_data.get("affected", []):
        purl = affected.get("package", {}).get("purl", "") or ""
        m = GITHUB_REPO_URL_REGEX.search(purl)
        if m:
            owner, repo = m.group(1).lower(), re.sub(r'\.git$', '', m.group(2), flags=re.IGNORECASE).lower()
            if repo in _GITHUB_REPO_ANCHOR_SKIP:
                continue
            candidates[f"{owner}/{repo}"] += 2

    if not candidates:
        return None
    return candidates.most_common(1)[0][0]

@contextmanager
def execution_timer(label):
    start = time.perf_counter()
    yield
    elapsed = time.perf_counter() - start
    print(f"{GREEN}[⏱️  PERF] {label} completed in {elapsed:.3f} seconds{RESET}")


# ==============================================================================
# DATABASE INITIALIZATION & SCHEMA PROVISIONING
# ==============================================================================

def init_database():
    """Deploys the complete production warehouse relational schema layout."""
    os.makedirs(DB_DIR, exist_ok=True)
    db_exists = os.path.exists(DB_PATH)
    
    if db_exists and os.path.getsize(DB_PATH) <= 25000:
        os.remove(DB_PATH)
        db_exists = False

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Core Vulnerabilities Table (15 Columns)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            advisory_id TEXT PRIMARY KEY,
            package_name TEXT,
            ecosystems TEXT,
            cvss_score REAL,
            blast_radius INTEGER,
            threat_profile TEXT,
            last_modified TEXT,
            malware_vector TEXT,
            vulnerable_versions TEXT,
            dwell_days REAL,
            withdrawn_date TEXT,
            published_date TEXT,
            cve_alias TEXT,
            aliases TEXT,
            cwe_ids TEXT,
            package_names_by_ecosystem TEXT,
            purls_by_ecosystem TEXT,
            repo_anchor TEXT,
            fixed_by_ecosystem TEXT
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_eco ON vulnerabilities(ecosystems);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_alias);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_cwe ON vulnerabilities(cwe_ids);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_modified ON vulnerabilities(last_modified);")

    # MIGRATION: older warehouse files predate the three per-ecosystem columns above.
    # ALTER TABLE ADD COLUMN is a safe, additive upgrade for a DB that already has rows, so an
    # existing install doesn't need --rebuild just to gain the columns (a --rebuild re-ingestion
    # is still required to actually backfill values into already-ingested rows).
    cursor.execute("PRAGMA table_info(vulnerabilities)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    for new_col in ("package_names_by_ecosystem", "purls_by_ecosystem", "repo_anchor", "fixed_by_ecosystem"):
        if new_col not in existing_cols:
            cursor.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {new_col} TEXT")
    
    # 2. Snapshot Anchors
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS snapshots (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at TEXT NOT NULL,
            interval_from TEXT NOT NULL,
            interval_to TEXT NOT NULL UNIQUE,
            target_layer TEXT NOT NULL
        );
    """)
    
    # 3. Volumetric Metrics Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ecosystem_metrics (
            snapshot_id INTEGER,
            text_ecosystem TEXT NOT NULL,
            activity_count INTEGER NOT NULL,
            PRIMARY KEY (snapshot_id, text_ecosystem),
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(snapshot_id) ON DELETE CASCADE
        );
    """)

    # 4. EPSS Predictive Exploitation Probability Scores
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS epss_scores (
            cve_id TEXT PRIMARY KEY,
            epss_score REAL,
            percentile REAL,
            model_date TEXT
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_epss_score ON epss_scores(epss_score);")

    # 5. CISA Known Exploited Vulnerabilities (KEV) Catalog
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS kev_catalog (
            cve_id TEXT PRIMARY KEY,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added TEXT,
            short_description TEXT,
            required_action TEXT,
            due_date TEXT,
            known_ransomware_use TEXT,
            notes TEXT,
            cwes TEXT,
            catalog_version TEXT
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_catalog(date_added);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_kev_due_date ON kev_catalog(due_date);")

    conn.commit()
    print("[+] Storage grid tables and b-tree performance indexes deployed cleanly.")
    return conn


# ==============================================================================
# OSV INGESTION & EXTRACTION PARSERS
# ==============================================================================

def download_master_archive():
    """Streams down the full 1GB bulk advisory archive bundle natively if missing."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    print(f"[*] Local cache archive missing. Initializing master bulk stream download (~1GB)...")

    # Written to a .part file and only renamed into place once verified complete. Streaming
    # straight to LOCAL_ZIP_PATH meant an interrupted download (a killed process never reaches
    # the except block below) left a truncated, unreadable zip sitting at the real cache path
    # with a fresh mtime -- exactly what happened, and the old sync then trusted that mtime.
    part_path = LOCAL_ZIP_PATH + ".part"
    completed = False
    try:
        response = requests.get(MASTER_ZIP_URL, stream=True, timeout=120)
        response.raise_for_status()
        # Content-Length is only comparable to bytes written when the body isn't transparently
        # content-decoded on the way in.
        expected_bytes = 0 if response.headers.get("Content-Encoding") else int(response.headers.get("Content-Length", 0) or 0)

        written = 0
        with open(part_path, 'wb') as local_file:
            chunk_count = 0
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    local_file.write(chunk)
                    written += len(chunk)
                    chunk_count += 1
                    if chunk_count % 50 == 0:
                        print(f"    -> Transferred payload chunk: {chunk_count} MB...")

        if expected_bytes and written != expected_bytes:
            raise IOError(f"truncated download: received {written:,} of {expected_bytes:,} bytes")
        if not zipfile.is_zipfile(part_path):
            raise IOError("downloaded file is not a valid zip archive")

        os.replace(part_path, LOCAL_ZIP_PATH)
        completed = True
        print(f"{GREEN}[+] Download complete. Saved upstream archive payload to: {LOCAL_ZIP_PATH}{RESET}")
    except Exception as e:
        print(f"{RED}[- ] Critical master archive stream failure: {e}{RESET}")
    finally:
        if not completed and os.path.exists(part_path):
            os.remove(part_path)


def extract_cwe_classifications(vuln_data):
    """Extracts and normalizes all CWE identifiers across disparate upstream OSV sources."""
    cwes = set()
    
    # 1. Top-level database_specific metadata (GHSA, PyPA, RustSec)
    db_spec = vuln_data.get("database_specific", {})
    if isinstance(db_spec, dict):
        for item in db_spec.get("cwe_ids", []):
            if isinstance(item, str) and item.strip():
                match = re.search(r"CWE-\d+", item, re.IGNORECASE)
                if match:
                    cwes.add(match.group(0).upper())
                    
        for item in db_spec.get("cwes", []):
            if isinstance(item, str):
                match = re.search(r"CWE-\d+", item, re.IGNORECASE)
                if match:
                    cwes.add(match.group(0).upper())
            elif isinstance(item, dict):
                cwe_raw = item.get("cwe_id") or item.get("id") or ""
                match = re.search(r"CWE-\d+", str(cwe_raw), re.IGNORECASE)
                if match:
                    cwes.add(match.group(0).upper())

    # 2. Package-level database_specific blocks
    for affected in vuln_data.get("affected", []):
        aff_spec = affected.get("database_specific", {})
        if isinstance(aff_spec, dict):
            for item in aff_spec.get("cwe_ids", []):
                if isinstance(item, str) and item.strip():
                    match = re.search(r"CWE-\d+", item, re.IGNORECASE)
                    if match:
                        cwes.add(match.group(0).upper())

    return sorted(list(cwes))


def extract_production_cvss(vuln_data):
    """Parses OSV severity vectors using the official FIRST cvss library for complete parity."""
    vuln_id = vuln_data.get("id", "")
    if vuln_id.startswith("MAL-") or "malware" in json.dumps(vuln_data).lower():
        return 10.0
        
    severity_list = vuln_data.get("severity", [])
    if not severity_list: return 0.0
        
    for sev in severity_list:
        sev_type = sev.get("type", "")
        vector_str = sev.get("score", "")
        if not vector_str: continue
            
        try:
            if sev_type == "CVSS_V3" or "CVSS:3" in vector_str:
                return float(CVSS3(vector_str).base_score)
            elif sev_type == "CVSS_V4" or "CVSS:4" in vector_str:
                return float(CVSS4(vector_str).base_score)
            elif sev_type == "CVSS_V2" or "RUSTSEC" in vuln_id:
                return float(CVSS2(vector_str).base_score)
        except Exception: continue
            
    return 0.0


def parse_osv_json(vuln_data):
    """Translates raw nested OSV JSON structures into normalized flat relational database rows."""
    v_id = vuln_data.get("id", "")
    if not v_id:
        return (None,) * 19

    published_str = vuln_data.get("published", "1970-01-01T00:00:00Z")
    p_date_clean = published_str[:10]
    modified_str = vuln_data.get("modified", "1970-01-01T00:00:00Z")
    withdrawn_str = vuln_data.get("withdrawn", None)
    w_date = withdrawn_str[:10] if withdrawn_str else None
    
    dwell_days = 0.0
    is_new_entry = (published_str[:10] == modified_str[:10])
    try:
        p_dt = datetime.datetime.fromisoformat(published_str.replace("Z", "+00:00"))
        m_dt = datetime.datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
        dwell_days = max(0.0, (m_dt - p_dt).days)
        is_new_entry = (p_dt.date() == m_dt.date())
    except ValueError: pass

    has_fixes = False
    cwe_list = extract_cwe_classifications(vuln_data)
    is_malware = v_id.startswith("MAL-")

    summary = vuln_data.get("summary", "").lower()
    details = vuln_data.get("details", "").lower()
    # FIX: a bare "backdoor"/"typosquat"/"malicious package" substring match false-positives on
    # real vulnerabilities that merely mention this vocabulary as subject matter rather than
    # disclosing that the package itself is malicious -- e.g. GHSA-m5p4-gvpx-4mvr (CWE-116, a
    # terminal-escaping bug IN GuardDog, a malware *scanner*, whose own summary describes
    # "...injection from malicious package content") and CVE-2026-45043 (CWE-269/284, a
    # privilege-escalation bug that lets an attacker create "backdoor" service accounts -- the
    # bug enables backdoors, it isn't one). Real GHSA malicious-package disclosures are tagged
    # CWE-506 (Embedded Malicious Code) or carry no CWE at all, so only trust the keyword match
    # when the advisory's own CWEs corroborate it (CWE-506 present, or no CWE assigned) --
    # defer to the CWE classification when it points somewhere else entirely.
    keyword_hit = "backdoor" in summary or "typosquat" in summary or "malicious package" in summary
    if keyword_hit and (not cwe_list or "CWE-506" in cwe_list):
        is_malware = True

    m_vector = "Unclassified Malicious Payload"
    if is_malware:
        if "typosquat" in summary or "typosquat" in details: 
            m_vector = "Typosquatting / Brand Hijacking"
        elif "dependency confusion" in summary or "dependency confusion" in details: 
            m_vector = "Dependency Confusion Campaign"
        elif any(x in summary or x in details for x in ["exfiltrat", "token", "credential", "steal"]): 
            m_vector = "Data Exfiltration / Credential Stealer"
        elif any(x in summary or x in details for x in ["reverse shell", "backdoor", "remote code"]): 
            m_vector = "Persistent Backdoor / Execution Shell"
            
    p_name = "N/A"
    max_versions = 0
    all_versions = set()
    ecosystems_set = set()
    names_by_eco = {}
    purls_by_eco = {}
    fixed_by_eco = {}

    for affected in vuln_data.get("affected", []):
        pkg_block = affected.get("package", {})
        eco = pkg_block.get("ecosystem")
        name = pkg_block.get("name")
        purl = pkg_block.get("purl")
        if name: p_name = name.strip()

        for v in affected.get("versions", []):
            all_versions.add(str(v).strip())

        v_len = len(affected.get("versions", []))
        if v_len > max_versions: max_versions = v_len

        # entry_has_fix is scoped to just THIS affected[] block (one ecosystem/package), unlike
        # has_fixes below which ORs across the whole advisory -- that whole-advisory flag drives
        # the classification bucket (unchanged), but conflates ecosystems when one advisory lists
        # several (e.g. a GHSA record covering npm, Maven, and NuGet together): "has_fixes=True"
        # there could mean only ONE of those three has actually shipped a patch. fixed_by_eco
        # preserves the distinction Section VIII-C needs -- which SPECIFIC ecosystem is done.
        entry_has_fix = False
        for ranges in affected.get("ranges", []):
            for events in ranges.get("events", []):
                if "fixed" in events:
                    has_fixes = True
                    entry_has_fix = True

        if eco:
            eco_clean = clean_ecosystem_tag(eco)
            ecosystems_set.add(eco_clean)

            # Per-ecosystem package identity, not just the last-seen name. A single advisory's
            # affected[] can legitimately span many ecosystems (a shared library bundled
            # downstream, or a project natively released to several registries at once) -- the
            # old single `p_name` above silently overwrote itself on every iteration, so any
            # display keyed off it showed an arbitrary, possibly unrelated-looking name for
            # whichever registry was actually being reported on.
            if name:
                clean_name = name.strip()
                bucket = names_by_eco.setdefault(eco_clean, [])
                if clean_name and clean_name not in bucket:
                    bucket.append(clean_name)
            if purl:
                bucket = purls_by_eco.setdefault(eco_clean, [])
                if purl not in bucket:
                    bucket.append(purl)

            # OR across every affected[] block seen so far for this ecosystem, not overwrite --
            # an advisory can list separate version-range blocks for the same ecosystem (e.g. a
            # 1.x line and a 2.x line), and the ecosystem counts as fixed if ANY of them shipped
            # a patched version, even if a later/earlier block for that same ecosystem didn't.
            fixed_by_eco[eco_clean] = fixed_by_eco.get(eco_clean, False) or entry_has_fix

    if not ecosystems_set:
        ecosystems_set.add("Android")

    if withdrawn_str:
        classification = "Withdrawn / Retracted Advisory"
    else:
        if is_malware: classification = "Malware (New Entry)" if is_new_entry else "Malware (Incremental Update)"
        elif has_fixes: classification = "Vulnerability Fix (New Entry)" if is_new_entry else "Vulnerability Fix (Update)"
        else: classification = "Metadata Correction / Adjustments"
        
    cvss_score = extract_production_cvss(vuln_data)
    v_versions_json = json.dumps(list(all_versions))
    ecosystems_json = json.dumps(list(ecosystems_set))
    package_names_by_ecosystem_json = json.dumps(names_by_eco)
    purls_by_ecosystem_json = json.dumps(purls_by_eco)
    fixed_by_ecosystem_json = json.dumps(fixed_by_eco)
    repo_anchor = extract_repo_anchor(vuln_data)

    # Canonical CVE alias extraction
    raw_aliases = vuln_data.get("aliases", [])
    cve_alias = v_id if v_id.startswith("CVE-") else next(
        (a.strip().upper() for a in raw_aliases if a.strip().upper().startswith("CVE-")), 
        None
    )
    aliases_json = json.dumps(raw_aliases)
    
    # Formal CWE Classifications (extracted earlier, alongside the malware keyword gate above)
    cwe_json = json.dumps(cwe_list)
    
    return (
        v_id, p_name, ecosystems_json, cvss_score, max_versions, classification,
        modified_str[:10], m_vector, v_versions_json, dwell_days, w_date,
        p_date_clean, cve_alias, aliases_json, cwe_json,
        package_names_by_ecosystem_json, purls_by_ecosystem_json, repo_anchor,
        fixed_by_ecosystem_json
    )


def bootstrap_warehouse_from_zip(conn):
    """Parses local master archive data and bulk-loads the database using transactional blocks."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    if cursor.fetchone()[0] > 0:
        print("[+] Relational catalog already populated. Skipping bootstrap seed stage.")
        return

    if os.path.exists(LOCAL_ZIP_PATH) and not zipfile.is_zipfile(LOCAL_ZIP_PATH):
        print(f"{YELLOW}[!] Cached master archive is not a valid zip (truncated download?). Discarding it and re-downloading.{RESET}")
        os.remove(LOCAL_ZIP_PATH)

    if not os.path.exists(LOCAL_ZIP_PATH):
        download_master_archive()

    if not os.path.exists(LOCAL_ZIP_PATH):
        print(f"{RED}[- ] Missing local cache zip archive package at: {LOCAL_ZIP_PATH}{RESET}")
        return

    print(f"[*] Seeding storage grid: Unpacking master archive targets out of {LOCAL_ZIP_PATH}...")
    
    vulnerabilities_batch = []
    global_leaderboard = Counter()
    total_scanned = 0
    
    try:
        with zipfile.ZipFile(LOCAL_ZIP_PATH) as z:
            file_list = [f for f in z.namelist() if f.endswith('.json')]
            total_files = len(file_list)
            
            for idx, file_name in enumerate(file_list, start=1):
                if idx % 50000 == 0 or idx == total_files:
                    print(f"    -> Parsing archive streams: {idx:,} / {total_files:,} files...")
                    
                with z.open(file_name) as f:
                    try:
                        vuln_data = json.load(f)
                        parsed_row = parse_osv_json(vuln_data)
                        if parsed_row[0]:
                            vulnerabilities_batch.append(parsed_row)
                            global_leaderboard[parsed_row[2]] += 1
                            total_scanned += 1
                    except Exception: continue
                    
        print(f"[*] Committing {len(vulnerabilities_batch):,} entries down to SQLite storage blocks...")
        cursor.executemany("""
            INSERT OR REPLACE INTO vulnerabilities (
                advisory_id, package_name, ecosystems, cvss_score, blast_radius,
                threat_profile, last_modified, malware_vector, vulnerable_versions,
                dwell_days, withdrawn_date, published_date, cve_alias, aliases, cwe_ids,
                package_names_by_ecosystem, purls_by_ecosystem, repo_anchor, fixed_by_ecosystem
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, vulnerabilities_batch)
        
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # Anchored to the freshness of the data actually loaded -- the start of the newest
        # last_modified day in it -- not wall-clock time and not a constant. This used to record
        # the literal "2026-04-18" no matter when the build ran, which left the sync with no
        # usable high-water mark. Start-of-day (rather than the exact timestamp, which the table
        # doesn't keep) deliberately over-covers: the first sync re-fetches that day, and upserts
        # are idempotent, so the only cost is some extra API calls.
        cursor.execute("SELECT MAX(last_modified) FROM vulnerabilities")
        newest_day = cursor.fetchone()[0]
        build_anchor = f"{newest_day}T00:00:00+00:00" if newest_day else now_str
        cursor.execute("""
            INSERT OR IGNORE INTO snapshots (generated_at, interval_from, interval_to, target_layer)
            VALUES (?, ?, ?, ?)
        """, (now_str, "1970-01-01", build_anchor, "all"))
        
        snapshot_id = cursor.lastrowid
        metric_rows = [(snapshot_id, eco, count) for eco, count in global_leaderboard.items()]
        
        cursor.executemany("""
            INSERT OR REPLACE INTO ecosystem_metrics (snapshot_id, text_ecosystem, activity_count)
            VALUES (?, ?, ?)
        """, metric_rows)
        
        conn.commit()
        print(f"{GREEN}[+] Bulk load complete. Ingested {total_scanned:,} catalog components natively.{RESET}")
        
    except Exception as e:
        print(f"{RED}[- ] Critical failure loading structural database frames: {e}{RESET}")


_LEGACY_BUILD_ANCHOR = "2026-04-18"
SYNC_OVERLAP = datetime.timedelta(hours=1)


def advisory_id_from_manifest_path(path: str) -> str:
    """Extracts the advisory ID from a modified_id.csv `Ecosystem/ID` path.

    Splits on the FIRST slash only and never on ':' -- real advisory IDs from Red Hat, SUSE,
    openSUSE, Rocky, etc. contain colons themselves (RHSA-2026:1234, openSUSE-SU-2026:11976-1).
    This used to split on the colon, which collapsed ~74K of the feed's ~2.4M rows into ~185
    garbage "IDs" like "Red Hat/RHSA-2026" that 404 on the API and were silently dropped, so no
    incremental sync ever refreshed any of those advisories."""
    path = path.strip()
    advisory_id = path.split("/", 1)[1] if "/" in path else path
    if advisory_id.endswith(".json"):
        advisory_id = advisory_id[:-5]
    return advisory_id.strip()


def resolve_sync_baseline(cursor):
    """Returns (start_datetime_utc, source_description): where incremental sync should resume.

    Anchored to the warehouse's OWN recorded high-water mark (snapshots.interval_to), never to
    the cache zip's file mtime. A zip's mtime says when a file was last written to disk, not how
    fresh the database built from it is: a re-downloaded or interrupted/truncated zip moves its
    mtime forward without the database gaining anything, which silently skipped three days of
    upstream changes (everything between the last real build and a partial download) before
    this was changed. Overlaps by SYNC_OVERLAP so boundary rows are re-fetched, not missed --
    upserts are idempotent, so overlap only costs a few extra API calls.

    Rows whose interval_to is the legacy hardcoded placeholder (_LEGACY_BUILD_ANCHOR, written by
    older full builds regardless of when they ran) carry no information and are ignored; a
    database with only that row falls back to the zip's mtime (if the zip is actually valid),
    then to 24 hours."""
    high_water = None
    try:
        cursor.execute("SELECT interval_to FROM snapshots")
        for (raw,) in cursor.fetchall():
            if not raw or raw == _LEGACY_BUILD_ANCHOR:
                continue
            try:
                parsed = datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            if high_water is None or parsed > high_water:
                high_water = parsed
    except sqlite3.Error:
        pass

    if high_water is not None:
        return high_water - SYNC_OVERLAP, "relational high-water mark"

    if os.path.exists(LOCAL_ZIP_PATH) and zipfile.is_zipfile(LOCAL_ZIP_PATH):
        cache_dt = datetime.datetime.fromtimestamp(os.path.getmtime(LOCAL_ZIP_PATH), datetime.timezone.utc)
        return cache_dt - SYNC_OVERLAP, "legacy fallback: cache zip write time (no usable high-water mark)"

    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1), "24-hour fallback (no usable high-water mark or valid cache zip)"


def parse_modification_feed(rows, since=None):
    """Collapses modified_id.csv rows (`timestamp, Ecosystem/ID`) into {advisory_id: latest
    modification time}, optionally keeping only rows at or after `since`. An ID listed under
    several ecosystems keeps its newest timestamp."""
    latest = {}
    for row in rows:
        if not row: continue
        mod_time_str, path = row[0], row[1]
        try:
            mod_time = datetime.datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
        except ValueError: continue

        if since is None or mod_time >= since:
            v_id = advisory_id_from_manifest_path(path)
            if v_id and v_id != "N/A":
                previous = latest.get(v_id)
                if previous is None or mod_time > previous:
                    latest[v_id] = mod_time
    return latest


def verify_warehouse(conn, feed_text=None) -> bool:
    """Audits the warehouse against the live upstream modification feed without changing anything.
    Returns True when nothing is missing or stale.

    - MISSING: the feed lists an advisory the warehouse has no row for.
    - STALE: the feed's modification DAY is later than the stored last_modified day, for a change
      that the sync high-water mark says should already have been ingested. (last_modified is
      stored at day granularity, so a second edit on the same day as the stored one is
      undetectable here.)
    - PENDING: changed within SYNC_OVERLAP of the high-water mark or later. The next sync re-fetches
      this window by design (the upstream index and API can lag a few minutes behind real
      modification times), so these are not failures. Anything OLDER that is still missing or
      stale was genuinely lost.
    Warehouse rows absent from the feed are only counted: the feed lists latest state, so
    withdrawn/aged records can legitimately be missing from it."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*), MAX(last_modified) FROM vulnerabilities")
    db_count, db_newest = cursor.fetchone()
    start, baseline_source = resolve_sync_baseline(cursor)
    high_water = start + SYNC_OVERLAP

    print(f"\n[*] Verifying warehouse against the live OSV modification feed.")
    print(f"    -> Warehouse: {db_count:,} advisories, newest last_modified {db_newest}")
    print(f"    -> High-water mark: {high_water.strftime('%Y-%m-%d %H:%M:%S')} UTC ({baseline_source})")

    try:
        if feed_text is None:
            response = requests.get(MANIFEST_URL, timeout=120)
            response.raise_for_status()
            feed_text = response.text
    except Exception as e:
        print(f"{RED}[- ] Failed to fetch the modification feed: {e}{RESET}")
        return False

    feed = parse_modification_feed(csv.reader(io.StringIO(feed_text)))
    stored = dict(cursor.execute("SELECT advisory_id, last_modified FROM vulnerabilities"))

    missing, stale, pending = [], [], []
    for advisory_id, mod_time in feed.items():
        if mod_time >= start:
            pending.append(advisory_id)
        elif advisory_id not in stored:
            missing.append(advisory_id)
        elif (stored[advisory_id] or "") < mod_time.date().isoformat():
            stale.append(advisory_id)
    not_in_feed = sum(1 for advisory_id in stored if advisory_id not in feed)

    print(f"    -> Feed lists {len(feed):,} distinct advisories; {not_in_feed:,} warehouse rows are not in the feed (informational)")
    print(f"    -> Pending next sync: {len(pending):,}")
    ok = not missing and not stale
    for label, ids in (("MISSING from warehouse", missing), ("STALE in warehouse", stale)):
        if ids:
            print(f"{RED}[- ] {len(ids):,} advisories {label}; e.g. {', '.join(sorted(ids)[:5])}{RESET}")
    if ok:
        print(f"{GREEN}[+] Warehouse verified: no missing or stale advisories.{RESET}")
    else:
        print(f"{YELLOW}[!] Run `python db_warehouse.py --sync` to repair; if it persists, `--rebuild`.{RESET}")
    return ok


def sync_incremental_window(conn):
    """Pulls every advisory the upstream modification feed lists as changed since the warehouse's
    recorded high-water mark and upserts it, with retries and explicit failure accounting."""
    cursor = conn.cursor()

    start_date, baseline_source = resolve_sync_baseline(cursor)
    print(f"\n[*] Dynamic Sync Engine Active.")
    print(f"    -> Baseline source: {baseline_source}")
    print(f"    -> Ingestion Boundary Gate: {start_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")

    # Captured BEFORE the feed is fetched: anything modified after this instant is not covered by
    # this run's feed snapshot, so it is the furthest the high-water mark can safely advance.
    sync_started_at = datetime.datetime.now(datetime.timezone.utc)

    try:
        response = requests.get(MANIFEST_URL, timeout=120)
        response.raise_for_status()
        reader = csv.reader(io.StringIO(response.text))
    except Exception as e:
        print(f"{RED}[- ] Failed to fetch streaming modification index: {e}{RESET}")
        return

    target_mod_times = parse_modification_feed(reader, since=start_date)

    if not target_mod_times:
        print(f"{GREEN}[+] Zero late mutations detected upstream since last compilation. Warehouse completely current.{RESET}")
        return

    print(f"[+] Identified {len(target_mod_times):,} modern stream modifications to update.")

    updates_batch = []
    unavailable_ids = []
    failed_ids = []

    def fetch_vulnerability_payload(http_session, advisory_id):
        reason = "unknown"
        for attempt in range(4):
            try:
                res = http_session.get(f"{OSV_API_URL}{advisory_id}", timeout=20)
                if res.status_code == 200:
                    parsed_row = parse_osv_json(res.json())
                    if parsed_row[0]:
                        return ("ok", advisory_id, parsed_row)
                    return ("unavailable", advisory_id, None)
                if res.status_code == 404:
                    return ("unavailable", advisory_id, None)
                reason = f"HTTP {res.status_code}"
            except Exception as e:
                reason = type(e).__name__
            time.sleep(0.5 * (3 ** attempt))
        return ("failed", advisory_id, reason)

    with requests.Session() as session:
        session.mount("https://", requests.adapters.HTTPAdapter(pool_connections=40, pool_maxsize=40))
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(fetch_vulnerability_payload, session, v_id) for v_id in sorted(target_mod_times)]

            for idx, future in enumerate(concurrent.futures.as_completed(futures), start=1):
                if idx % 1000 == 0 or idx == len(futures):
                    print(f"    -> Syncing stream entries: {idx:,} / {len(futures):,}")

                status, advisory_id, payload = future.result()
                if status == "ok":
                    updates_batch.append(payload)
                elif status == "unavailable":
                    unavailable_ids.append(advisory_id)
                else:
                    failed_ids.append((advisory_id, payload))

    if updates_batch:
        print(f"[*] Executing transactional upsert for {len(updates_batch):,} localized stream elements...")
        cursor.executemany("""
            INSERT OR REPLACE INTO vulnerabilities (
                advisory_id, package_name, ecosystems, cvss_score, blast_radius,
                threat_profile, last_modified, malware_vector, vulnerable_versions,
                dwell_days, withdrawn_date, published_date, cve_alias, aliases, cwe_ids,
                package_names_by_ecosystem, purls_by_ecosystem, repo_anchor, fixed_by_ecosystem
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, updates_batch)

    if unavailable_ids:
        print(f"{YELLOW}[!] {len(unavailable_ids):,} listed advisories were unavailable from the API (404 or unparseable; e.g. "
              f"{', '.join(unavailable_ids[:3])}). Reported but not counted as failures: these are permanent conditions, "
              f"and holding the high-water mark for them would force every future sync to re-fetch the same window.{RESET}")

    # The high-water mark must never advance past an advisory that failed to fetch, or it would
    # never be retried: hold it just before the earliest failure so the next sync picks it up.
    new_high_water = sync_started_at
    if failed_ids:
        earliest_failed = min(target_mod_times[v_id] for v_id, _ in failed_ids)
        new_high_water = min(sync_started_at, earliest_failed - datetime.timedelta(seconds=1))
        print(f"{RED}[- ] {len(failed_ids):,} advisories failed to fetch after retries (e.g. "
              f"{failed_ids[0][0]}: {failed_ids[0][1]}). High-water mark held at "
              f"{new_high_water.strftime('%Y-%m-%d %H:%M:%S')} UTC so the next sync retries them.{RESET}")

    try:
        cursor.execute("""
            INSERT OR REPLACE INTO snapshots (generated_at, interval_from, interval_to, target_layer)
            VALUES (?, ?, ?, 'incremental_sync')
        """, (datetime.datetime.now(datetime.timezone.utc).isoformat(), start_date.isoformat(), new_high_water.isoformat()))
        conn.commit()
        if failed_ids:
            print(f"{YELLOW}[!] Warehouse partially synchronized: {len(updates_batch):,} upserted, {len(failed_ids):,} pending retry.{RESET}")
        else:
            print(f"{GREEN}[+] Relational warehouse delta stream successfully synchronized and anchored.{RESET}")
    except Exception as e:
        print(f"{RED}[- ] Failed to record execution snapshot context: {e}{RESET}")


# ==============================================================================
# EPSS (EXPLOIT PREDICTION SCORING SYSTEM) ENRICHMENT ENGINE
# ==============================================================================

def download_epss_feed(force: bool = False) -> bool:
    """Streams the official daily EPSS CSV gzip archive if missing, forced, or older than 24h."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    
    file_exists = os.path.exists(EPSS_GZ_PATH)
    file_age_hours = (time.time() - os.path.getmtime(EPSS_GZ_PATH)) / 3600 if file_exists else 999.0
    is_too_old = file_age_hours >= 24.0

    if file_exists and not is_too_old and not force:
        print(f"[+] Found fresh local EPSS feed (Age: {file_age_hours:.1f}h < 24h). Skipping download.")
        return True

    reason = "Forced" if force else ("Missing archive" if not file_exists else f"Expired archive ({file_age_hours:.1f}h old)")
    print(f"[*] Downloading latest EPSS score model from {EPSS_FEED_URL} [Reason: {reason}]...")
    
    try:
        response = requests.get(EPSS_FEED_URL, stream=True, timeout=60)
        response.raise_for_status()
        with open(EPSS_GZ_PATH, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
        print(f"{GREEN}[+] EPSS feed archive staged to: {EPSS_GZ_PATH}{RESET}")
        return True
    except Exception as e:
        print(f"{RED}[-] Failed to stream EPSS payload: {e}{RESET}")
        return False


def run_epss_pipeline(conn, force: bool = False):
    """Rebuilds or refreshes EPSS scores if cache >= 24h, table empty, or forced."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM epss_scores")
    existing_count = cursor.fetchone()[0]

    file_missing = not os.path.exists(EPSS_GZ_PATH)
    file_age_hours = (time.time() - os.path.getmtime(EPSS_GZ_PATH)) / 3600 if not file_missing else 999.0
    is_too_old = file_age_hours >= 24.0
    table_empty = (existing_count == 0)

    needs_refresh = force or table_empty or file_missing or is_too_old

    if not needs_refresh:
        print(f"[+] EPSS database records verified current ({existing_count:,} records, Cache Age: {file_age_hours:.1f}h). Skipping reload.")
        return

    if not download_epss_feed(force=force):
        print(f"{RED}[-] EPSS pipeline aborted: Unable to obtain valid feed archive.{RESET}")
        return

    print("[*] Dropping previous EPSS table state and rebuilding fresh dataset...")
    cursor.execute("DELETE FROM epss_scores;")
    conn.commit()

    epss_batch = []
    total_ingested = 0
    model_date = datetime.date.today().isoformat()

    try:
        with gzip.open(EPSS_GZ_PATH, 'rt', encoding='utf-8') as gz_file:
            first_line = gz_file.readline()
            if first_line.startswith("#model_date:"):
                model_date = first_line.strip().split(":")[1].split("T")[0]

            reader = csv.DictReader(gz_file)
            for row in reader:
                cve = row.get("cve")
                epss = row.get("epss")
                pct = row.get("percentile")
                if cve and epss:
                    try:
                        epss_batch.append((
                            cve.strip().upper(),
                            float(epss),
                            float(pct) if pct else 0.0,
                            model_date
                        ))
                    except ValueError:
                        continue

                if len(epss_batch) >= 50000:
                    cursor.executemany("""
                        INSERT OR REPLACE INTO epss_scores (cve_id, epss_score, percentile, model_date)
                        VALUES (?, ?, ?, ?)
                    """, epss_batch)
                    total_ingested += len(epss_batch)
                    epss_batch.clear()

            if epss_batch:
                cursor.executemany("""
                    INSERT OR REPLACE INTO epss_scores (cve_id, epss_score, percentile, model_date)
                    VALUES (?, ?, ?, ?)
                """, epss_batch)
                total_ingested += len(epss_batch)

        conn.commit()
        print(f"{GREEN}[+] Successfully ingested {total_ingested:,} EPSS records (Model Date: {model_date}).{RESET}")

    except Exception as e:
        print(f"{RED}[-] Failed parsing EPSS gzip stream: {e}{RESET}")


# ==============================================================================
# KEV (CISA KNOWN EXPLOITED VULNERABILITIES) ENRICHMENT ENGINE
# ==============================================================================

def download_kev_feed(force: bool = False) -> bool:
    """
    Streams the official CISA KEV JSON catalog if:
    1. Forced via parameter (force=True)
    2. The catalog is completely missing from local cache
    3. The cached catalog's last write time is >= 24.0 hours old
    """
    os.makedirs(CACHE_DIR, exist_ok=True)
    file_exists = os.path.exists(KEV_JSON_PATH)
    file_age_hours = (time.time() - os.path.getmtime(KEV_JSON_PATH)) / 3600 if file_exists else 999.0
    is_too_old = file_age_hours >= 24.0

    if file_exists and not is_too_old and not force:
        print(f"[+] Found fresh local KEV catalog (Age: {file_age_hours:.1f}h < 24h). Skipping download.")
        return True

    reason = "Forced" if force else ("Missing catalog" if not file_exists else f"Expired catalog ({file_age_hours:.1f}h old)")
    print(f"[*] Downloading CISA KEV catalog from {KEV_FEED_URL} [Reason: {reason}]...")

    try:
        response = requests.get(KEV_FEED_URL, timeout=60)
        response.raise_for_status()
        with open(KEV_JSON_PATH, 'wb') as f:
            f.write(response.content)
        print(f"{GREEN}[+] KEV catalog staged to: {KEV_JSON_PATH}{RESET}")
        return True
    except Exception as e:
        print(f"{RED}[-] Failed to stream KEV catalog payload: {e}{RESET}")
        return False


def run_kev_pipeline(conn, force: bool = False):
    """
    Rebuilds or refreshes the KEV catalog if:
    - force=True
    - kev_catalog table is empty
    - known_exploited_vulnerabilities.json is missing
    - known_exploited_vulnerabilities.json is >= 24 hours old
    """
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM kev_catalog")
    existing_count = cursor.fetchone()[0]

    file_missing = not os.path.exists(KEV_JSON_PATH)
    file_age_hours = (time.time() - os.path.getmtime(KEV_JSON_PATH)) / 3600 if not file_missing else 999.0
    is_too_old = file_age_hours >= 24.0
    table_empty = (existing_count == 0)

    needs_refresh = force or table_empty or file_missing or is_too_old
    if not needs_refresh:
        print(f"[+] KEV catalog records verified current ({existing_count:,} records, Cache Age: {file_age_hours:.1f}h). Skipping reload.")
        return

    if not download_kev_feed(force=force):
        print(f"{RED}[-] KEV pipeline aborted: Unable to obtain valid catalog file.{RESET}")
        return

    print("[*] Dropping previous KEV table state and rebuilding fresh dataset...")
    cursor.execute("DELETE FROM kev_catalog;")
    conn.commit()

    kev_batch = []
    total_ingested = 0
    catalog_version = None

    try:
        with open(KEV_JSON_PATH, 'r', encoding='utf-8') as f:
            catalog = json.load(f)

        catalog_version = catalog.get("catalogVersion")
        entries = catalog.get("vulnerabilities", [])

        for entry in entries:
            cve_id = entry.get("cveID", "").strip().upper()
            if not cve_id:
                continue

            cwes_json = json.dumps(entry.get("cwes", []))

            kev_batch.append((
                cve_id,
                entry.get("vendorProject"),
                entry.get("product"),
                entry.get("vulnerabilityName"),
                entry.get("dateAdded"),
                entry.get("shortDescription"),
                entry.get("requiredAction"),
                entry.get("dueDate"),
                entry.get("knownRansomwareCampaignUse"),
                entry.get("notes"),
                cwes_json,
                catalog_version
            ))

        if kev_batch:
            cursor.executemany("""
                INSERT OR REPLACE INTO kev_catalog (
                    cve_id, vendor_project, product, vulnerability_name, date_added,
                    short_description, required_action, due_date, known_ransomware_use,
                    notes, cwes, catalog_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, kev_batch)
            total_ingested = len(kev_batch)

        conn.commit()
        print(f"{GREEN}[+] Successfully ingested {total_ingested:,} KEV records (Catalog Version: {catalog_version}).{RESET}")
    except Exception as e:
        print(f"{RED}[-] Failed parsing KEV catalog JSON: {e}{RESET}")


# ==============================================================================
# CLI DISPATCHER
# ==============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSV Relational Data Warehouse Coordinator.")
    parser.add_argument("--bootstrap", action="store_true", help="Force bulk bootstrap seed from OSV ZIP.")
    parser.add_argument("--sync", action="store_true", help="Execute incremental API modification sync.")
    parser.add_argument("--rebuild", action="store_true", help="Drop and completely rebuild warehouse database from scratch.")
    parser.add_argument("--verify", action="store_true", help="Audit the warehouse against the live OSV feed (read-only); exits non-zero if advisories are missing or stale.")
    parser.add_argument("--skip-kev", action="store_true", help="Skip the CISA KEV catalog refresh pipeline for this run.")
    args = parser.parse_args()

    if args.verify:
        if not os.path.exists(DB_PATH):
            sys.exit(f"No warehouse at {DB_PATH}; run `python db_warehouse.py` first.")
        verify_conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        try:
            sys.exit(0 if verify_warehouse(verify_conn) else 1)
        finally:
            verify_conn.close()

    if args.rebuild:
        # --rebuild means "download the whole thing fresh": wipe every cached artifact up
        # front so that's true just by reading this block, rather than relying on each
        # downstream pipeline's own force-refresh plumbing to invalidate its cache correctly.
        # Before this, --rebuild only deleted the DB -- bootstrap_warehouse_from_zip() only
        # re-downloads the master archive when LOCAL_ZIP_PATH is missing, so a --rebuild would
        # silently re-seed from whatever stale ZIP happened to still be sitting in ./cache
        # (EPSS/KEV were already correctly forced via force=args.rebuild below; the master
        # archive was the one gap).
        if os.path.exists(DB_PATH):
            print(f"{YELLOW}[!] --rebuild flag passed. Removing existing database at: {DB_PATH}{RESET}")
            os.remove(DB_PATH)
        for cached_path in (LOCAL_ZIP_PATH, EPSS_GZ_PATH, KEV_JSON_PATH):
            if os.path.exists(cached_path):
                print(f"{YELLOW}[!] --rebuild flag passed. Removing cached artifact: {cached_path}{RESET}")
                os.remove(cached_path)

    print("=== OSV RELATIONAL DATA WAREHOUSE ===")
    connection = init_database()

    run_default = not (args.bootstrap or args.sync)

    if args.bootstrap or run_default:
        with execution_timer("Bootstrap (Bulk Archive Load)"):
            bootstrap_warehouse_from_zip(connection)

    if args.sync or run_default:
        with execution_timer("Incremental Sync (API Stream)"):
            sync_incremental_window(connection)

    with execution_timer("EPSS Score Pipeline"):
        run_epss_pipeline(connection, force=args.rebuild)

    if not args.skip_kev:
        with execution_timer("KEV Catalog Pipeline"):
            run_kev_pipeline(connection, force=args.rebuild)
    else:
        print(f"{YELLOW}[!] --skip-kev active: KEV catalog refresh skipped for this run.{RESET}")

    connection.close()