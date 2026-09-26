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

KNOWN_CONTAINERS = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
KNOWN_REGISTRIES = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]
MASTER_TRACKS = KNOWN_CONTAINERS + KNOWN_REGISTRIES + ["GIT", "Untagged Commit Hash/CVE Noise", "Android"]

# Cross-registry product-identity signal: matches "github.com/OWNER/REPO" wherever it shows up,
# either in an advisory's own reference links or embedded directly in a Go-ecosystem purl
# (pkg:golang/github.com/OWNER/REPO...). Used by extract_repo_anchor() below.
GITHUB_REPO_URL_REGEX = re.compile(r'github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)', re.IGNORECASE)
_GITHUB_REPO_ANCHOR_SKIP = {"advisories", "security", "security-advisories", ".github"}


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
    
    try:
        response = requests.get(MASTER_ZIP_URL, stream=True, timeout=120)
        response.raise_for_status()
        
        with open(LOCAL_ZIP_PATH, 'wb') as local_file:
            chunk_count = 0
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    local_file.write(chunk)
                    chunk_count += 1
                    if chunk_count % 50 == 0:
                        print(f"    -> Transferred payload chunk: {chunk_count} MB...")
                        
        print(f"{GREEN}[+] Download complete. Saved upstream archive payload to: {LOCAL_ZIP_PATH}{RESET}")
    except Exception as e:
        print(f"{RED}[- ] Critical master archive stream failure: {e}{RESET}")
        if os.path.exists(LOCAL_ZIP_PATH):
            os.remove(LOCAL_ZIP_PATH)


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
            eco_lower = eco.strip().lower()
            hard_mappings = {"maven": "Maven (Java)", "go": "Go (Golang)", "packagist": "Packagist (PHP)", "git": "GIT", "crates.io": "Crates.io"}
            eco_clean = hard_mappings.get(eco_lower, None)
            if not eco_clean:
                for track in MASTER_TRACKS:
                    if eco_lower in track.lower() or track.lower() in eco_lower:
                        eco_clean = track
                        break
            if not eco_clean: eco_clean = "Android"
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
        cursor.execute("""
            INSERT OR IGNORE INTO snapshots (generated_at, interval_from, interval_to, target_layer)
            VALUES (?, ?, ?, ?)
        """, (now_str, "1970-01-01", "2026-04-18", "all"))
        
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


def sync_incremental_window(conn):
    """Dynamically calculates lookback windows based on relational snapshots and runs parallel syncs."""
    cursor = conn.cursor()
    
    # 1. Establish the baseline interval from local zip archive state
    if os.path.exists(LOCAL_ZIP_PATH):
        cache_mtime = os.path.getmtime(LOCAL_ZIP_PATH)
        cache_dt = datetime.datetime.fromtimestamp(cache_mtime, datetime.timezone.utc)
        start_date = cache_dt - datetime.timedelta(hours=1)
        print(f"\n[*] Dynamic Sync Engine Active.")
        print(f"    -> Local Cache Write Time: {cache_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    else:
        start_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        print(f"\n{YELLOW}[!] Cache zip missing. Falling back to static 24-hour delta gate.{RESET}")
    
    # 2. STATE INTEGRATION: Check relational snapshots for high-water mark
    try:
        cursor.execute("SELECT MAX(interval_to) FROM snapshots")
        max_snapshot_row = cursor.fetchone()
        if max_snapshot_row and max_snapshot_row[0]:
            raw_val = max_snapshot_row[0]
            snapshot_dt = datetime.datetime.fromisoformat(raw_val.replace("Z", "+00:00"))
            
            if snapshot_dt.tzinfo is None:
                snapshot_dt = snapshot_dt.replace(tzinfo=datetime.timezone.utc)
            
            if snapshot_dt > start_date:
                start_date = snapshot_dt
                print(f"    -> Relational High-Water Mark Found: {start_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    except Exception as e:
        print(f"{YELLOW}[!] Notice: Could not process snapshot matrix tracking: {e}{RESET}")

    print(f"    -> Ingestion Boundary Gate: {start_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")

    try:
        response = requests.get(MANIFEST_URL, timeout=30)
        response.raise_for_status()
        reader = csv.reader(io.StringIO(response.text))
    except Exception as e:
        print(f"{RED}[- ] Failed to fetch streaming modification index: {e}{RESET}")
        return

    target_ids = set()
    for row in reader:
        if not row: continue
        mod_time_str, path = row[0], row[1]
        try:
            mod_time = datetime.datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
        except ValueError: continue
        
        if mod_time >= start_date:
            v_id = path.split(":")[0].strip() if ":" in path else path.split("/")[-1].replace(".json", "")
            if v_id and v_id != "N/A":
                target_ids.add(v_id)
                
    if not target_ids:
        print(f"{GREEN}[+] Zero late mutations detected upstream since last compilation. Warehouse completely current.{RESET}")
        return
        
    print(f"[+] Identified {len(target_ids):,} modern stream modifications to update.")
    
    updates_batch = []
    
    def fetch_vulnerability_payload(http_session, advisory_id):
        try:
            res = http_session.get(f"{OSV_API_URL}{advisory_id}", timeout=10)
            if res.status_code == 200:
                vuln_payload = res.json()
                parsed_row = parse_osv_json(vuln_payload)
                if parsed_row[0]:
                    return parsed_row
        except Exception: pass
        return None

    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_id = {
                executor.submit(fetch_vulnerability_payload, session, v_id): v_id 
                for v_id in sorted(target_ids)
            }
            
            for idx, future in enumerate(concurrent.futures.as_completed(future_to_id), start=1):
                if idx % 100 == 0 or idx == len(target_ids):
                    print(f"    -> Syncing stream entries: {idx:,} / {len(target_ids):,}")
                
                result = future.result()
                if result:
                    updates_batch.append(result)
        
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
        
    try:
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cursor.execute("""
            INSERT OR REPLACE INTO snapshots (generated_at, interval_from, interval_to, target_layer)
            VALUES (?, ?, ?, 'incremental_sync')
        """, (now_str, start_date.isoformat(), now_str))
        conn.commit()
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

    if not download_epss_feed(force=force or is_too_old):
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

    if not download_kev_feed(force=force or is_too_old):
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
    parser.add_argument("--skip-kev", action="store_true", help="Skip the CISA KEV catalog refresh pipeline for this run.")
    args = parser.parse_args()

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