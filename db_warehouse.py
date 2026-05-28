#!/usr/bin/env python3
"""
OSV Relational Data Warehouse Coordinator - Version 1.5 (Repaired)
=================================================================================
Parallel warehousing backend engineered to bulk-seed from a master snapshot cache 
(auto-downloading if missing) and execute chronological dynamic sync updates.
"""

import sqlite3
import os
import csv
import json
import zipfile
import datetime
import requests
import io
from collections import Counter

# Storage Routing Baselines
DB_DIR = "database"
DB_PATH = os.path.join(DB_DIR, "threat_stream.db")
CACHE_DIR = "./cache"
LOCAL_ZIP_PATH = os.path.join(CACHE_DIR, "osv_master_all.zip")

MASTER_ZIP_URL = "https://storage.googleapis.com/osv-vulnerabilities/all.zip"
MANIFEST_URL = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
OSV_API_URL = "https://api.osv.dev/v1/vulns/"

# Terminal Visual Presentation Elements
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

KNOWN_CONTAINERS = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
KNOWN_REGISTRIES = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]
MASTER_TRACKS = KNOWN_CONTAINERS + KNOWN_REGISTRIES + ["GIT", "Untagged Commit Hash/CVE Noise", "Android"]

def init_database():
    """Deploys the complete production warehouse relational schema layout."""
    os.makedirs(DB_DIR, exist_ok=True)
    db_exists = os.path.exists(DB_PATH)
    
    if db_exists and os.path.getsize(DB_PATH) <= 25000:
        os.remove(DB_PATH)
        db_exists = False

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if not db_exists:
        print(f"[*] Deploying fresh global relational catalog tables at: {DB_PATH}")
        
        # 1. Core Global Index: Houses all individual advisory elements
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                advisory_id TEXT PRIMARY KEY,
                package_name TEXT,
                ecosystem TEXT,
                cvss_score REAL,
                blast_radius INTEGER,
                threat_profile TEXT,
                last_modified TEXT,
                malware_vector TEXT,
                vulnerable_versions TEXT --
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_eco ON vulnerabilities(ecosystem);")
        
        # 2. Snapshot Anchors: Log chronological lookback window states
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
                ecosystem TEXT NOT NULL,
                activity_count INTEGER NOT NULL,
                PRIMARY KEY (snapshot_id, ecosystem),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(snapshot_id) ON DELETE CASCADE
            );
        """)
        conn.commit()
        print("[+] Storage grid tables and b-tree performance indexes deployed cleanly.")
    
    return conn

def download_master_archive():
    """Streams down the full 1GB bulk advisory archive bundle natively if missing."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    print(f"[*] Local cache archive missing. Initializing master bulk stream download (~1GB)...")
    
    try:
        response = requests.get(MASTER_ZIP_URL, stream=True, timeout=120)
        response.raise_for_status()
        
        # Stream chunks sequentially to preserve active working memory space
        with open(LOCAL_ZIP_PATH, 'wb') as local_file:
            chunk_count = 0
            for chunk in response.iter_content(chunk_size=1024 * 1024):  # 1MB blocks
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

def extract_basic_score(vuln_data):
    """Fallback scoring extraction loop matching master mapping behaviors."""
    v_id = vuln_data.get("id", "")
    if v_id.startswith("MAL-") or "malware" in json.dumps(vuln_data).lower():
        return 10.0
    for sev in vuln_data.get("severity", []):
        score_str = sev.get("score", "")
        if "CVSS:" in score_str:
            try:
                parts = score_str.split("/")
                for p in parts:
                    if p.startswith("BASE:") or p.startswith("B:"):
                        return float(p.split(":")[-1])
            except Exception: pass
    return 0.0

def parse_osv_json(vuln_data):
    """Translates raw nested OSV JSON structures into normalized flat relational database rows."""
    v_id = vuln_data.get("id", "")
    if not v_id: return (None, None, None, 0.0, 0, None, None, None)

    modified_str = vuln_data.get("modified", "1970-01-01")[:10]
    has_fixes = False
    is_malware = v_id.startswith("MAL-")
    
    summary = vuln_data.get("summary", "").lower()
    details = vuln_data.get("details", "").lower()
    text_pool = summary + " " + details
    if "backdoor" in summary or "typosquat" in summary: is_malware = True
    
    m_vector = "Unclassified Malicious Payload"
    if "typosquat" in text_pool or "brand hijacking" in text_pool:
        m_vector = "Typosquatting / Brand Hijacking"
    elif "dependency confusion" in text_pool:
        m_vector = "Dependency Confusion Campaign"
    elif "exfiltrat" in text_pool or "credential stealer" in text_pool or "token stealer" in text_pool:
        m_vector = "Data Exfiltration / Credential Stealer"
    elif "backdoor" in text_pool or "execution shell" in text_pool or "reverse shell" in text_pool:
        m_vector = "Persistent Backdoor / Execution Shell"

    p_name = "N/A"
    eco_clean = "Android"
    max_versions = 0
    all_versions = set() # 💡 Track full unique explicit version set
    
    for affected in vuln_data.get("affected", []):
        eco = affected.get("package", {}).get("ecosystem")
        name = affected.get("package", {}).get("name")
        if name: p_name = name.strip()
        
        # Pull explicitly listed strings if present
        for v in affected.get("versions", []):
            all_versions.add(str(v))
            
        v_len = len(affected.get("versions", []))
        if v_len > max_versions: max_versions = v_len
        
        for ranges in affected.get("ranges", []):
            for events in ranges.get("events", []):
                if "fixed" in events: has_fixes = True
                
        if eco:
            eco_lower = eco.strip().lower()
            hard_mappings = {"maven": "Maven (Java)", "go": "Go (Golang)", "packagist": "Packagist (PHP)", "git": "GIT", "crates.io": "Crates.io"}
            eco_clean = hard_mappings.get(eco_lower, None)
            pass
            if not eco_clean:
                for track in MASTER_TRACKS:
                    if eco_lower in track.lower() or track.lower() in eco_lower:
                        eco_clean = track
                        break
            if not eco_clean: eco_clean = "Android"
            
    if is_malware: t_profile = "Malware (New Entry)"
    elif has_fixes: t_profile = "Vulnerability Fix (Update)"
    else: t_profile = "Metadata Correction / Adjustments"
    
    cvss_score = extract_basic_score(vuln_data)
    # Serialize the set into a clean flat string array payload
    v_versions_json = json.dumps(list(all_versions))
    return (v_id, p_name, eco_clean, cvss_score, max_versions, t_profile, modified_str, m_vector, v_versions_json)

def bootstrap_warehouse_from_zip(conn):
    """Parses local master archive data and bulk-loads the database using transactional blocks."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    if cursor.fetchone()[0] > 0:
        print("[+] Relational catalog already populated. Skipping bootstrap seed stage.")
        return

    # Trigger chunked download fallback gate if file isn't present in execution scope
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
                        if "withdrawn" in vuln_data: continue
                        
                        parsed_row = parse_osv_json(vuln_data)
                        if parsed_row[0]:
                            vulnerabilities_batch.append(parsed_row)
                            global_leaderboard[parsed_row[2]] += 1
                            total_scanned += 1
                    except Exception: continue
                    
        # 💡 FIXED HERE: Changed {len(...):?} to {len(...):,}
        print(f"[*] Committing {len(vulnerabilities_batch):,} entries down to SQLite storage blocks...")
        cursor.executemany("""
            INSERT OR REPLACE INTO vulnerabilities (advisory_id, package_name, ecosystem, cvss_score, blast_radius, threat_profile, last_modified, malware_vector, vulnerable_versions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, vulnerabilities_batch) 
        
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cursor.execute("""
            INSERT OR IGNORE INTO snapshots (generated_at, interval_from, interval_to, target_layer)
            VALUES (?, ?, ?, ?)
        """, (now_str, "1970-01-01", "2026-04-18", "all"))
        
        snapshot_id = cursor.lastrowid
        metric_rows = [(snapshot_id, eco, count) for eco, count in global_leaderboard.items()]
        
        cursor.executemany("""
            INSERT OR REPLACE INTO ecosystem_metrics (snapshot_id, ecosystem, activity_count)
            VALUES (?, ?, ?)
        """, metric_rows)
        
        conn.commit()
        print(f"{GREEN}[+] Bulk load complete. Ingested {total_scanned:,} catalog components natively.{RESET}")
        
    except Exception as e:
        print(f"{RED}[- ] Critical failure loading structural database frames: {e}{RESET}")

def sync_incremental_window(conn):
    """Dynamically calculates lookback windows based on file properties to sync the database."""
    cursor = conn.cursor()
    
    if os.path.exists(LOCAL_ZIP_PATH):
        cache_mtime = os.path.getmtime(LOCAL_ZIP_PATH)
        cache_dt = datetime.datetime.fromtimestamp(cache_mtime, datetime.timezone.utc)
        start_date = cache_dt - datetime.timedelta(hours=1)
        print(f"\n[*] Dynamic Sync Engine Active.")
        print(f"    -> Local Cache Write Time: {cache_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"    -> Ingestion Boundary Gate: {start_date.strftime('%Y-%m-%d %H:%M:%S')} UTC (Includes 1hr padding)")
    else:
        start_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        print(f"\n{YELLOW}[!] Cache zip missing. Falling back to static 24-hour delta gate.{RESET}")
    
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
        print(f"{GREEN}[+] Zero late mutations detected upstream since cache compilation. Warehouse completely current.{RESET}")
        return
        
    print(f"[+] Identified {len(target_ids):,} modern stream modifications to update.")
    
    updates_batch = []
    for idx, v_id in enumerate(sorted(target_ids), start=1):
        if idx % 100 == 0 or idx == len(target_ids):
            print(f"    -> Syncing stream entries: {idx:,} / {len(target_ids):,}")
            
        try:
            res = requests.get(f"{OSV_API_URL}{v_id}", timeout=10)
            if res.status_code == 200:
                vuln_payload = res.json()
                parsed_row = parse_osv_json(vuln_payload)
                if parsed_row[0]:
                    updates_batch.append(parsed_row)
        except Exception: continue
        
    if updates_batch:
        print(f"[*] Executing transactional upsert for {len(updates_batch):,} localized stream elements...")
        cursor.executemany("""
            INSERT OR REPLACE INTO vulnerabilities (advisory_id, package_name, ecosystem, cvss_score, blast_radius, threat_profile, last_modified, malware_vector, vulnerable_versions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, updates_batch) # 💡 FIXED: Changed from vulnerabilities_batch to updates_batch
        conn.commit()
        print(f"{GREEN}[+] Relational warehouse delta stream successfully synchronized.{RESET}")

if __name__ == "__main__":
    print("=== OSV RELATIONAL DATA WAREHOUSE PROTOTYPE ===")
    connection = init_database()
    
    # Phase 1: Seed base mapping logs from offline media (downloading zip chunked if missing)
    bootstrap_warehouse_from_zip(connection)
    
    # Phase 2: Pull localized dynamic deltas since file package timestamp modification age
    sync_incremental_window(connection)
    
    connection.close()