#!/usr/bin/env python3

"""
OSV Threat Stream Campaign Dashboard Indicator
=================================================================================
A security engineering tool designed to track software supply chain fluctuations 
by aggregating upstream vulnerability mutations from the Open Source Vulnerability 
(OSV) database.

CRITICAL ARCHITECTURAL NOTE ON METRICS:
---------------------------------------------------------------------------------
The "Activity Delta" column DOES NOT measure individual, real-world exploit attacks.
Instead, it measures upstream VULNERABILITY DATABASE CHURN (mutations) over a 
user-defined day window. 

A single unit added to the Activity Delta column indicates one of three events:
  1. A Brand New Vulnerability Entry: Creation of a new CVE, GHSA, or malware 
     advisory (e.g., active typosquatting campaigns in npm/PyPI).
  2. A Structural Patch/Version Update: An existing advisory was modified to 
     expand/contract affected version ranges, or to inject newly patched versions.
  3. Metadata Correction: Minor back-end adjustments, such as updating CVSS 
     severity ratings or updating vendor description logs.
     
     

Why Operating Systems (Debian/Ubuntu) volume dwarfs Application Registries (npm):
---------------------------------------------------------------------------------
Linux distributions run massive automated tracking systems. When a core utility 
(like glibc or openssl) receives a security patch, the maintainers backport and 
update thousands of historical records across multiple supported OS releases and 
architectures simultaneously. This causes massive, automated, non-malicious 
database spikes. 

Conversely, Application Registry spikes (like npm) are heavily driven by active, 
targeted software supply chain injections, malicious packages, or distinct library 
vulnerabilities impacting application runtime code.

WARNING ON LAYER FILTERING & MALWARE METRICS BEHAVIOR:
---------------------------------------------------------------------------------
Virtually 100% of cataloged open-source malware payloads live natively within 
Application Layer registries (npm/PyPI). Operating system distributions track 
vulnerabilities strictly as system CVEs (Vulnerability Fixes/Updates). 

As a result:
  - Running the script with '--layer app' yields malware vector counts that are 
    IDENTICAL to a default run, because no malware data is omitted by removing 
    containers. However, the Layer Threat Profile percentages will correctly scale
    upward to reflect malware's true dominance over application-only churn.
  - Running the script with '--layear container' suppresses the "MALWARE ATTACK 
    VECTOR ANALYSIS" panel entirely, as the targeted malware metrics drop to zero.
=================================================================================
"""
#!/usr/bin/env python3
"""
OSV Threat Stream Campaign Dashboard Indicator
=================================================================================
A security engineering tool designed to track software supply chain fluctuations 
by aggregating upstream vulnerability mutations from the Open Source Vulnerability 
(OSV) database.

CRITICAL ARCHITECTURAL NOTE ON METRICS:
---------------------------------------------------------------------------------
The "Activity Delta" column DOES NOT measure individual, real-world exploit attacks.
Instead, it measures upstream VULNERABILITY DATABASE CHURN (mutations) over a 
user-defined day window. 
=================================================================================
"""

import csv
import datetime
import io
import json
import os
import time
import zipfile
import argparse
from collections import Counter
import requests

# ANSI Color Codes for Scannable Shell Output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

def build_ghsa_ecosystem_map(cache_dir: str = "./cache", cache_expiry_hours: int = 24):
    """
    Downloads the master database zip from OSV if missing or stale,
    and enriches the local lookup index by classifying the threat type, 
    lifecycle status, explicit malware attack mechanics, and blast radius profiles.
    """
    master_zip_url = "https://storage.googleapis.com/osv-vulnerabilities/all.zip"
    os.makedirs(cache_dir, exist_ok=True)
    local_zip_path = os.path.join(cache_dir, "osv_master_all.zip")
    
    should_download = True
    
    if os.path.exists(local_zip_path):
        file_age_seconds = time.time() - os.path.getmtime(local_zip_path)
        file_age_hours = file_age_seconds / 3600
        
        if file_age_hours < cache_expiry_hours:
            print(f"[+] Found fresh local cache: {local_zip_path} (Age: {file_age_hours:.1f} hours). Skipping download.")
            should_download = False
        else:
            print(f"[*] Local cache found but it is stale (Age: {file_age_hours:.1f} hours).")

    if should_download:
        print(f"[*] Downloading master database archive from OSV (~1GB)...")
        try:
            response = requests.get(master_zip_url, stream=True, timeout=120)
            response.raise_for_status()
            
            with open(local_zip_path, 'wb') as local_file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        local_file.write(chunk)
            print(f"[+] Download complete. Saved to: {local_zip_path}")
        except Exception as e:
            print(f"[-] Download failed: {e}")
            if os.path.exists(local_zip_path):
                print("[!] Warning: Falling back to stale local cache to continue execution.")
            else:
                return {}

    print("[*] Building global advisory memory index & profiling threat lifecycle states...")
    id_to_meta = {}
    
    try:
        with zipfile.ZipFile(local_zip_path) as z:
            for file_name in z.namelist():
                if file_name.endswith('.json'):
                    with z.open(file_name) as f:
                        try:
                            vuln_data = json.load(f)
                            vuln_id = vuln_data.get("id", "")
                            
                            ecosystems = set()
                            has_fixes = False
                            is_malware = False
                            
                            if vuln_id.startswith("MAL-") or "malicious" in file_name.lower():
                                is_malware = True
                                
                            summary = vuln_data.get("summary", "").lower()
                            details = vuln_data.get("details", "").lower()
                            
                            if "backdoor" in summary or "typosquat" in summary or "malicious package" in summary:
                                is_malware = True

                            max_versions_found = 0
                            for affected in vuln_data.get("affected", []):
                                eco = affected.get("package", {}).get("ecosystem")
                                if eco:
                                    ecosystems.add(eco)
                                
                                v_len = len(affected.get("versions", []))
                                if v_len > max_versions_found:
                                    max_versions_found = v_len

                                for ranges in affected.get("ranges", []):
                                    for events in ranges.get("events", []):
                                        if "fixed" in events:
                                            has_fixes = True
                            
                            published_str = vuln_data.get("published", "1970-01-01T00:00:00Z")
                            modified_str = vuln_data.get("modified", "1970-01-01T00:00:00Z")
                            
                            dwell_days = 0.0
                            try:
                                p_dt = datetime.datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                                m_dt = datetime.datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                                dwell_days = max(0.0, (m_dt - p_dt).days)
                            except ValueError:
                                pass

                            is_new_entry = (published_str == modified_str)

                            # MALWARE TYPE ANALYSIS ENGINE
                            malware_vector = "Unclassified Malicious Payload"
                            if is_malware:
                                if "typosquat" in summary or "typosquat" in details:
                                    malware_vector = "Typosquatting / Brand Hijacking"
                                elif "dependency confusion" in summary or "dependency confusion" in details:
                                    malware_vector = "Dependency Confusion Campaign"
                                elif any(x in summary or x in details for x in ["exfiltrat", "token", "credential", "steal"]):
                                    malware_vector = "Data Exfiltration / Credential Stealer"
                                elif any(x in summary or x in details for x in ["reverse shell", "backdoor", "remote code"]):
                                    malware_vector = "Persistent Backdoor / Execution Shell"

                            if is_malware:
                                classification = "Malware (New Entry)" if is_new_entry else "Malware (Incremental Update)"
                            elif has_fixes:
                                classification = "Vulnerability Fix (New Entry)" if is_new_entry else "Vulnerability Fix (Update)"
                            else:
                                classification = "Metadata Correction / Adjustments"

                            if vuln_id and ecosystems:
                                id_to_meta[vuln_id] = {
                                    "ecosystems": list(ecosystems),
                                    "type": classification,
                                    "vector": malware_vector,
                                    "dwell_days": dwell_days,
                                    "blast_radius": max_versions_found
                                }
                        except json.JSONDecodeError:
                            continue 
                            
        print(f"[+] Successfully indexed {len(id_to_meta):,} global advisory mappings.")
    except Exception as e:
        print(f"[-] Failed to read and parse local zip file: {e}")
        
    return id_to_meta

def get_artifact_layer(eco_name):
    """Maps ecosystem tags to clear enterprise infrastructure layers."""
    container_images = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    app_registries = [
        "npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", 
        "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"
    ]
    
    if eco_name in container_images:
        return "Container Base Image"
    elif eco_name in app_registries:
        return "App Software Registry"
    elif eco_name == "GIT":
        return "Source Control (SCM)"
    else:
        return "Global Baseline Noise"

def compare_snapshots(file_base: str, file_current: str):
    """Parses two snapshots to generate dynamic colored delta trend reports across all sections."""
    try:
        with open(file_base, 'r', encoding='utf-8') as f1, open(file_current, 'r', encoding='utf-8') as f2:
            base = json.load(f1)
            current = json.load(f2)
    except Exception as e:
        print(f"[-] Snapshot comparison failed. Error loading files: {e}")
        return

    print("\n" + "="*85)
    print(f"  {BOLD}SECURITY THREAT INTELLIGENCE STREAM MOVEMENT COMPARISON{RESET}")
    print("="*85)
    print(f"Base Document:    {file_base} (Generated: {base['metadata']['generated_at'][:10]})")
    print(f"Current Document: {file_current} (Generated: {current['metadata']['generated_at'][:10]})")
    print("="*85)

    known_clean_keys = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", 
                        "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL", "Debian", "Ubuntu", "MinimOS", 
                        "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "GIT",
                        "Android", "Untagged Commit Hash/CVE Noise"]

    sanitized_base_leaderboard = Counter()
    for eco, count in base["leaderboard"].items():
        clean_name = "Android" if eco not in known_clean_keys else eco
        sanitized_base_leaderboard[clean_name] += count

    sanitized_curr_leaderboard = Counter()
    for eco, count in current["leaderboard"].items():
        clean_name = "Android" if eco not in known_clean_keys else eco
        sanitized_curr_leaderboard[clean_name] += count

    base_sorted = sorted(sanitized_base_leaderboard.items(), key=lambda x: x[1], reverse=True)
    curr_sorted = sorted(sanitized_curr_leaderboard.items(), key=lambda x: x[1], reverse=True)

    base_rank_map = {item[0]: rank for rank, item in enumerate(base_sorted, 1) if item[1] > 0}
    curr_rank_map = {item[0]: rank for rank, item in enumerate(curr_sorted, 1) if item[1] > 0}

    print(f"\n{BOLD}I. ECOSYSTEM ACTIVITY & RANK SHIFTS:{RESET}")
    print("-"*85)
    print(f"{'Ecosystem / Registry':<28} | {'Base Vol':<10} | {'Current Vol':<12} | {'Volume Delta':<14} | {'Rank Shift'}")
    print("-"*85)

    all_ecosystems = sorted(list(set(sanitized_base_leaderboard.keys()).union(set(sanitized_curr_leaderboard.keys()))))
    
    for eco in all_ecosystems:
        v1 = sanitized_base_leaderboard.get(eco, 0)
        v2 = sanitized_curr_leaderboard.get(eco, 0)
        v_diff = v2 - v1
        
        raw_v_str = f"{v_diff:+,}" if v_diff != 0 else "0"
        padded_v_str = f"{raw_v_str:>14}"
        
        if v_diff > 0:
            v_str = f"{GREEN}{padded_v_str}{RESET}"
        elif v_diff < 0:
            v_str = f"{RED}{padded_v_str}{RESET}"
        else:
            v_str = padded_v_str

        r1 = base_rank_map.get(eco, None)
        r2 = curr_rank_map.get(eco, None)
        
        if r1 and r2:
            r_diff = r1 - r2
            if r_diff > 0:
                r_str = f"{GREEN}Moved up {r_diff} spots ({r1} -> {r2}){RESET}"
            elif r_diff < 0:
                r_str = f"{RED}Moved down {abs(r_diff)} spots ({r1} -> {r2}){RESET}"
            else:
                r_str = f"No Change ({r2})"
        elif not r1 and r2:
            r_str = f"{GREEN}New Entry To Rank ({r2}){RESET}"
        elif r1 and not r2:
            r_str = f"{RED}Dropped Out of Active Rankings (Was {r1}){RESET}"
        else:
            r_str = "Inactive / Zero Activity Trace"

        print(f"{eco:<28} | {v1:<10,} | {v2:<12,} | {v_str} | {r_str}")

    print(f"\n{BOLD}II. THREAT BEHAVIOR VARIANCE:{RESET}")
    print("-"*85)
    for category in base["threat_profile"].keys():
        b_count = base["threat_profile"].get(category, 0)
        c_count = current["threat_profile"].get(category, 0)
        diff = c_count - b_count
        
        raw_diff_str = f"{diff:+,}" if diff != 0 else "0"
        padded_diff_str = f"{raw_diff_str:>10}"
        
        if diff > 0:
            diff_str = f"{GREEN}{padded_diff_str}{RESET}"
        elif diff < 0:
            diff_str = f"{RED}{padded_diff_str}{RESET}"
        else:
            diff_str = padded_diff_str
            
        print(f"-> {category:<35} | Base: {b_count:<7,} | Current: {c_count:<7,} | Delta: {diff_str}")

    if base.get("malware_vectors") or current.get("malware_vectors"):
        print(f"\n{BOLD}III. MALWARE VECTOR ATTACK MATRIX SHIFTS:{RESET}")
        print("-"*85)
        all_vectors = sorted(list(set(base.get("malware_vectors", {}).keys()).union(set(current.get("malware_vectors", {}).keys()))))
        for vec in all_vectors:
            b_v = base.get("malware_vectors", {}).get(vec, 0)
            c_v = current.get("malware_vectors", {}).get(vec, 0)
            v_diff = c_v - b_v
            
            raw_v_diff_str = f"{v_diff:+,}" if v_diff != 0 else "0"
            padded_v_diff_str = f"{raw_v_diff_str:>10}"
            
            if v_diff > 0:
                v_diff_str = f"{GREEN}{padded_v_diff_str}{RESET}"
            elif v_diff < 0:
                v_diff_str = f"{RED}{padded_v_diff_str}{RESET}"
            else:
                v_diff_str = padded_v_diff_str
                
            print(f"-> {vec:<38} | Base: {b_v:<6,} | Current: {c_v:<6,} | Delta: {v_diff_str}")

    if "profile_matrix" in base and "profile_matrix" in current:
        print(f"\n{BOLD}IV. SPATIAL DWELL & BLAST RADIUS BASELINE SHIFTS:{RESET}")
        print("-"*95)
        print(f"{'Ecosystem / Registry':<22} | {'Avg Dwell MAL Delta':<20} | {'Avg Dwell CVE Delta':<20} | {'Avg Blast Radius Delta'}")
        print("-"*95)
        
        for eco in sorted(list(set(base["profile_matrix"].keys()).union(set(current["profile_matrix"].keys())))):
            b_mat = base["profile_matrix"].get(eco, {"avg_dwell_mal": 0.0, "avg_dwell_cve": 0.0, "avg_blast_radius": 0.0})
            c_mat = current["profile_matrix"].get(eco, {"avg_dwell_mal": 0.0, "avg_dwell_cve": 0.0, "avg_blast_radius": 0.0})
            
            dm_diff = c_mat["avg_dwell_mal"] - b_mat["avg_dwell_mal"]
            dc_diff = c_mat["avg_dwell_cve"] - b_mat["avg_dwell_cve"]
            br_diff = c_mat["avg_blast_radius"] - b_mat["avg_blast_radius"]
            
            def format_delta_str(diff, suffix=""):
                if diff > 0: return f"{GREEN}+{diff:.1f}{suffix}{RESET}"
                elif diff < 0: return f"{RED}{diff:.1f}{suffix}{RESET}"
                return f"{diff:.1f}{suffix}"

            print(f"{eco:<22} | {format_delta_str(dm_diff, ' Days'):<29} | {format_delta_str(dc_diff, ' Days'):<29} | {format_delta_str(br_diff, ' Vers')}")
        print("-"*95)

        print(f"\n{BOLD}V. NEW CRITICAL OUTLIER ADVISORY ARRIVALS (NOT DETECTED IN BASE TIMELINE):{RESET}")
        print("-"*95)
        print(f"{'Ecosystem':<15} | {'Advisory ID':<20} | {'Impacted Versions':<20} | {'Threat Profile Type'}")
        print("-"*95)
        
        new_arrivals_found = False
        for eco, pool in current.get("outliers_leaderboards", {}).items():
            base_pool = base.get("outliers_leaderboards", {}).get(eco, {})
            for r_id, (radius, u_type) in pool.items():
                if r_id not in base_pool:
                    new_arrivals_found = True
                    print(f"{eco:<15} | {r_id:<20} | {radius:<20,} | {u_type}")
                    
        if not new_arrivals_found:
            print(f" -> No new maximum blast radius outliers added inside this comparison delta frame.")
        print("-"*95)
        
    print("="*85 + "\n")

# ==============================================================================
# OPTIMIZED SPEEDWAY TIMELINE ENGINE (BOUNDED INTERVAL VERSION)
# ==============================================================================
def render_speedway_timeline(start_date, end_date, target_layer, debug_mode):
    """Isolated Speedway tracking engine utilizing dual chronological box boundaries."""
    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    hourly_buckets = Counter()
    total_processed = 0

    print("[*] Streaming timeline modifications from live ledger stream...")
    try:
        response = requests.get(manifest_url, stream=True, timeout=30)
        response.raise_for_status()
        
        lines = (line.decode('utf-8') for line in response.iter_lines())
        reader = csv.reader(lines)
        
        for row in reader:
            if not row: continue
            
            mod_time_str, path = row[0], row[1]
            mod_time = datetime.datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
            
            # Bound 1: If entry is newer than our cap, skip past it to reach the target interval
            if mod_time > end_date:
                continue
                
            # Bound 2: If entry is older than our floor, stop stream parsing entirely
            if mod_time < start_date:
                break

            eco_clean = "Untagged Commit Hash/CVE Noise"
            if ":" in path:
                parts = path.split(":")
                if len(parts) > 1: eco_clean = parts[1].strip()
            else:
                path_parts = path.split('/')
                if len(path_parts) > 1 and path_parts[0].lower() not in ['root', '']:
                    eco_clean = path_parts[0].strip()

            if eco_clean == "Untagged Commit Hash/CVE Noise" and not debug_mode:
                continue

            layer = get_artifact_layer(eco_clean)
            if target_layer == "container" and layer != "Container Base Image": continue
            elif target_layer == "app" and layer != "App Software Registry": continue

            hourly_buckets[mod_time.hour] += 1
            total_processed += 1

    except Exception as e:
        print(f"[-] Speedway stream visualization tracking disrupted: {e}")
        return

    if total_processed == 0:
        print("\n[!] Zero records tracked matching layer constraints inside timeline window.")
        return

    max_count = max(hourly_buckets.values()) if hourly_buckets else 1
    scale_factor = max(1, max_count // 50)

    print("\n" + "="*85)
    print(f"  GLOBAL OSV STREAM: 24-HOUR TRAFFIC ACCELERATION (UTC)")
    print(f"  Window Frame: {start_date.date()} -> {end_date.date()}")
    print(f"  Target Filter Scope Layer: {target_layer if target_layer else 'all'}")
    print(f"  Total Processed Window Events: {total_processed:,}")
    print("="*85)
    
    for hour in range(24):
        count = hourly_buckets[hour]
        bar = "█" * (count // scale_factor) if count > 0 else ""
        alert_tag = f" {RED}[!] ACCELERATION SPIKE{RESET}" if count > 10 and count >= (max_count * 0.8) else ""
        print(f"{hour:02d}:00 | {count:5d} entries {bar}{alert_tag}")
    print("="*85 + "\n")


def generate_enterprise_threat_leaderboard(start_date, end_date, target_layer: str = None, debug_mode: bool = False, custom_export_arg=None, run_speedway: bool = False):
    now = datetime.datetime.now(datetime.timezone.utc)
    if run_speedway:
        render_speedway_timeline(start_date, end_date, target_layer, debug_mode)
        return

    print(f"[*] Analyzing live threat stream logs within window: {start_date.date()} to {end_date.date()}...")

    ghsa_lookup = build_ghsa_ecosystem_map()
    
    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    final_leaderboard = Counter()
    total_raw_rows = 0

    known_containers = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    known_registries = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]

    if target_layer == "app":
        final_leaderboard.update({k: 0 for k in known_registries})
    elif target_layer == "container":
        final_leaderboard.update({k: 0 for k in known_containers})

    bucket_counts = Counter({
        "Malware (New Entry)": 0, "Malware (Incremental Update)": 0,
        "Vulnerability Fix (New Entry)": 0, "Vulnerability Fix (Update)": 0,
        "Metadata Correction / Adjustments": 0
    })
    
    malware_vector_counts = Counter({
        "Typosquatting / Brand Hijacking": 0,
        "Dependency Confusion Campaign": 0,
        "Data Exfiltration / Credential Stealer": 0,
        "Persistent Backdoor / Execution Shell": 0,
        "Unclassified Malicious Payload": 0
    })

    spatial_dwell_malware = {k: [] for k in (known_containers + known_registries + ["Android"])}
    spatial_dwell_cve = {k: [] for k in (known_containers + known_registries + ["Android"])}
    spatial_blast_radius = {k: [] for k in (known_containers + known_registries + ["Android"])}
    ecosystem_outlier_pools = {k: {} for k in (known_containers + known_registries + ["Android"])}

    try:
        response = requests.get(manifest_url, stream=True, timeout=30)
        response.raise_for_status()
        
        lines = (line.decode('utf-8') for line in response.iter_lines())
        reader = csv.reader(lines)
        
        for row in reader:
            if not row:
                continue
            
            mod_time_str, path = row[0], row[1]
            mod_time = datetime.datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
            
            # Bounded Interval Execution Gateways
            if mod_time > end_date:
                continue
            if mod_time < start_date:
                break
            
            total_raw_rows += 1
            raw_ecosystems = []
            update_type = "Metadata Correction / Adjustments"
            current_vector = None
            current_id = "N/A"

            if ":" in path:
                parts = path.split(":")
                if len(parts) > 1:
                    current_id = parts[0].strip()
                    raw_ecosystems.append(parts[1].strip())
                    update_type = "Vulnerability Fix (Update)"
                else:
                    raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
            else:
                path_parts = path.split('/')
                if len(path_parts) == 1 or path_parts[0].lower() in ['root', '']:
                    osv_id = path_parts[-1].replace(".json", "")
                    current_id = osv_id
                    if osv_id in ghsa_lookup:
                        raw_ecosystems.extend(ghsa_lookup[osv_id]["ecosystems"])
                        update_type = ghsa_lookup[osv_id]["type"]
                        if "Malware" in update_type:
                            current_vector = ghsa_lookup[osv_id]["vector"]
                    else:
                        raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
                else:
                    raw_ecosystems.append(path_parts[0])
                    osv_id = path_parts[-1].replace(".json", "")
                    current_id = osv_id
                    if path_parts[0].lower() in ['npm', 'pypi'] and "mal-" in path_parts[-1].lower():
                        update_type = "Malware (New Entry)"
                        current_vector = ghsa_lookup.get(osv_id, {}).get("vector", "Unclassified Malicious Payload")
                    else:
                        update_type = "Vulnerability Fix (Update)"

            for eco in raw_ecosystems:
                eco_clean = eco.strip()
                eco_lower = eco_clean.lower()
                
                if eco_lower == "crates.io": eco_clean = "Crates.io"
                elif eco_lower == "hex": eco_clean = "Hex"
                elif eco_lower == "pub": eco_clean = "Pub"
                elif "conan" in eco_lower: eco_clean = "ConanCenter"
                elif "swift" in eco_lower: eco_clean = "SwiftURL"

                is_explicit_match = any(eco_clean == k or eco_lower in k.lower() for k in (known_containers + known_registries + ["GIT", "Untagged Commit Hash/CVE Noise"]))
                if not is_explicit_match:
                    eco_clean = "Android"
                    eco_lower = "android"

                if eco_clean in ["OSV Global Meta-Records", "[EMPTY]", ""]:
                    eco_clean = "Untagged Commit Hash/CVE Noise"

                if eco_clean == "Untagged Commit Hash/CVE Noise" and not debug_mode:
                    continue

                layer = get_artifact_layer(eco_clean)
                if target_layer == "container" and layer != "Container Base Image":
                    continue
                elif target_layer == "app" and layer != "App Software Registry":
                    continue

                bucket_counts[update_type] += 1
                if "Malware" in update_type and current_vector:
                    malware_vector_counts[current_vector] += 1

                if current_id in ghsa_lookup:
                    meta_entry = ghsa_lookup[current_id]
                    if "Malware" in update_type:
                        spatial_dwell_malware[eco_clean].append(meta_entry["dwell_days"])
                    else:
                        spatial_dwell_cve[eco_clean].append(meta_entry["dwell_days"])
                    
                    spatial_blast_radius[eco_clean].append(meta_entry["blast_radius"])
                    
                    if meta_entry["blast_radius"] > 0:
                        pool = ecosystem_outlier_pools[eco_clean]
                        if current_id not in pool or meta_entry["blast_radius"] > pool[current_id][0]:
                            pool[current_id] = (meta_entry["blast_radius"], update_type)

                if "ubuntu" in eco_lower: final_leaderboard["Ubuntu"] += 1
                elif "debian" in eco_lower: final_leaderboard["Debian"] += 1
                elif "alpine" in eco_lower: final_leaderboard["Alpine Linux"] += 1
                elif "alpaquita" in eco_lower: final_leaderboard["Alpaquita Linux"] += 1
                elif "azure linux" in eco_lower or "cbl-mariner" in eco_lower: final_leaderboard["Azure Linux"] += 1
                elif "minimos" in eco_lower: final_leaderboard["MinimOS"] += 1
                elif "android" in eco_lower: final_leaderboard["Android"] += 1
                elif "maven" in eco_lower: final_leaderboard["Maven (Java)"] += 1
                elif "packagist" in eco_lower: final_leaderboard["Packagist (PHP)"] += 1
                elif eco_lower == "go" or "golang" in eco_lower: final_leaderboard["Go (Golang)"] += 1
                elif "npm" in eco_lower: final_leaderboard["npm"] += 1
                elif "pypi" in eco_lower: final_leaderboard["PyPI"] += 1
                elif "bitnami" in eco_lower: final_leaderboard["Bitnami"] += 1
                elif "chainguard" in eco_lower: final_leaderboard["Chainguard"] += 1
                elif "echo" in eco_lower: final_leaderboard["Echo"] += 1
                elif eco_lower == "git": final_leaderboard["GIT"] += 1
                elif eco_lower == "crates.io": final_leaderboard["Crates.io"] += 1
                elif eco_lower == "hex": final_leaderboard["Hex"] += 1
                elif eco_lower == "pub": final_leaderboard["Pub"] += 1
                elif "conan" in eco_lower: final_leaderboard["ConanCenter"] += 1
                elif "swift" in eco_lower: final_leaderboard["SwiftURL"] += 1
                elif eco_clean == "Untagged Commit Hash/CVE Noise":
                    final_leaderboard["Untagged Commit Hash/CVE Noise"] += 1
                else:
                    final_leaderboard[eco_clean] += 1

    except Exception as e:
        print(f"[-] Threat ledger stream disrupted: {e}")
        return

    filtered_results = []
    for eco, count in final_leaderboard.items():
        layer = get_artifact_layer(eco)
        filtered_results.append((eco, count, layer))
        
    filtered_results.sort(key=lambda x: x[1], reverse=True)

    if not filtered_results:
        print("[-] No valid delta records compiled for the selected filter.")
        return

    title = "VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD"
    if target_layer == "container": title += " (CONTAINER BASE IMAGES ONLY)"
    elif target_layer == "app": title += " (APP SOFTWARE REGISTRIES ONLY)"

    print("\n" + "="*85)
    print(f"  {title}")
    print(f"  Chronological Box: {start_date.date()} to {end_date.date()}")
    print("="*85)
    print(f"{'Rank':<5} | {'Ecosystem/Registry':<32} | {'Activity Delta':<14} | {'Artifact Layer'}")
    print("-"*85)
    
    for rank, (eco, count, layer) in enumerate(filtered_results[:10], 1):
        print(f"#{rank:<3} | {eco:<32} | {count:<14,} | {layer}")
        
    print("="*85)
    print(f"Raw Entry Stream Items:    {total_raw_rows:,}")
    print(f"Ecosystem Attributions:    {sum(count for _, count, _ in filtered_results):,}")

    total_buckets = sum(bucket_counts.values())
    
    print("\n" + "="*50)
    print("  DATA ENRICHMENT: LAYER THREAT PROFILE")
    print("="*50)
    for b_type in ["Malware (New Entry)", "Malware (Incremental Update)", "Vulnerability Fix (New Entry)", "Vulnerability Fix (Update)", "Metadata Correction / Adjustments"]:
        b_count = bucket_counts[b_type]
        percentage = (b_count / total_buckets) * 100 if total_buckets > 0 else 0.0
        print(f"-> {b_type:<32} | {b_count:<6,} ({percentage:.1f}%)")
    print("="*50)

    total_malware_signals = sum(malware_vector_counts.values())
    if total_malware_signals > 0:
        print("\n" + "="*50)
        print("  DEEP DIVE: MALWARE ATTACK VECTOR ANALYSIS")
        print("="*50)
        for vector_name, vector_count in malware_vector_counts.most_common():
            v_p = (vector_count / total_malware_signals) * 100 if total_malware_signals > 0 else 0.0
            print(f"-> {vector_name:<38} | {vector_count:<4,} ({v_p:.1f}%)")
        print("="*50)

    export_profile_matrix = {}
    export_outliers_leaderboards = {}

    active_matrix_ecosystems = [eco for eco, count, _ in filtered_results[:10] if eco != "Untagged Commit Hash/CVE Noise" and count > 0]
    if active_matrix_ecosystems:
        print("\n" + "="*95)
        print("  IV. ECOSYSTEM THREAT DWELL TIME & BLAST RADIUS PROFILE MATRIX")
        print("="*95)
        print(f"{'Ecosystem/Registry':<22} | {'Avg Dwell (Malware)':<20} | {'Avg Dwell (CVE)':<16} | {'Avg Blast Radius'}")
        print("-"*95)
        
        for eco in active_matrix_ecosystems:
            m_list = spatial_dwell_malware.get(eco, [])
            c_list = spatial_dwell_cve.get(eco, [])
            r_list = spatial_blast_radius.get(eco, [])
            
            raw_avg_m = sum(m_list)/len(m_list) if m_list else 0.0
            raw_avg_c = sum(c_list)/len(c_list) if c_list else 0.0
            raw_avg_r = sum(r_list)/len(r_list) if r_list else 0.0

            export_profile_matrix[eco] = {
                "avg_dwell_mal": raw_avg_m,
                "avg_dwell_cve": raw_avg_c,
                "avg_blast_radius": raw_avg_r
            }

            avg_m = f"{raw_avg_m:.1f} Days" if m_list else "0.0 Days"
            avg_c = f"{raw_avg_c:.1f} Days" if c_list else "0.0 Days"
            avg_r = f"{raw_avg_r:.1f} Versions Affected" if r_list else "0.0 Versions Affected"
            
            print(f"{eco:<22} | {avg_m:<20} | {avg_c:<16} | {avg_r}")
        print("="*95)

        print("\n" + "="*95)
        print(f"  {BOLD}CRITICAL ANOMALY BREAKOUT: TOP 10 BLAST RADIUS OUTLIERS PER ACTIVE REGISTRY{RESET}")
        print("="*95)
        
        for eco in active_matrix_ecosystems:
            pool = ecosystem_outlier_pools.get(eco, {})
            sorted_pool = sorted(pool.items(), key=lambda x: x[1][0], reverse=True)
            
            if not sorted_pool:
                continue
                
            export_outliers_leaderboards[eco] = {r_id: list(data) for r_id, data in sorted_pool[:10]}

            print(f"\n[+] Active Telemetry Focus: {BOLD}{eco}{RESET}")
            print("-"*95)
            print(f"{'Rank':<5} | {'Advisory ID':<20} | {'Versions Impacted':<22} | {'Threat Classification'}")
            print("-"*95)
            
            for idx, (r_id, (radius, u_type)) in enumerate(sorted_pool[:10], 1):
                clean_type = u_type.split("(")[0].strip() if "(" in u_type else u_type
                print(f"#{idx:<3} | {r_id:<20} | {radius:<22,} | {clean_type}")
            print("-"*95)
    print()

    # ==============================================================================
    # INTERVAL SNAPSHOT EXPORT WRAPPER
    # ==============================================================================
    if custom_export_arg:
        if isinstance(custom_export_arg, str):
            export_path = custom_export_arg
        else:
            # Automatic filename signature now matches the dual boundaries perfectly
            from_str = start_date.strftime("%d-%m-%y")
            to_str = end_date.strftime("%d-%m-%y")
            layer_str = target_layer if target_layer else "all"
            export_path = f"{from_str}_to_{to_str}_{layer_str}.json"

        export_payload = {
            "metadata": {
                "generated_at": now.isoformat(),
                "interval_from": start_date.date().isoformat(),
                "interval_to": end_date.date().isoformat(),
                "target_layer_filter": target_layer if target_layer else "all",
                "total_raw_rows_processed": total_raw_rows
            },
            "leaderboard": {eco: count for eco, count, _ in filtered_results},
            "threat_profile": dict(bucket_counts),
            "malware_vectors": dict(malware_vector_counts) if total_malware_signals > 0 else {},
            "profile_matrix": export_profile_matrix,
            "outliers_leaderboards": export_outliers_leaderboards
        }
        try:
            with open(export_path, 'w', encoding='utf-8') as ef:
                json.dump(export_payload, ef, indent=4)
            print(f"[Static Snapshot Saved]: {export_path}")
        except Exception as e:
            print(f"[-] Snapshot export failed to write to file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSV Threat Stream Campaign Dashboard Indicator.")
    parser.add_argument("--layer", choices=["container", "app"], help="Isolate the dashboard layout by layer type.")
    parser.add_argument("--days", type=int, help="Relative lookback day window shortcut from today.")
    parser.add_argument("--from", metavar="YYYY-MM-DD", help="Explicit chronological interval starting boundary.")
    parser.add_argument("--to", metavar="YYYY-MM-DD", help="Explicit chronological interval ending boundary.")
    parser.add_argument("--debug", action="store_true", help="Surface raw, untagged noise.")
    
    parser.add_argument(
        "--export", 
        nargs='?', 
        const=True, 
        default=False, 
        help="Pass a custom filename string, or leave empty to auto-generate a boxed interval snapshot."
    )
    
    parser.add_argument(
        "--compare", 
        nargs=2, 
        metavar=('BASE_JSON', 'CURRENT_JSON'),
        help="Provide exactly two exported snapshot files to run an internal trends comparison delta report."
    )
    parser.add_argument("--speedway", action="store_true", help="Analyze unified stream timeline velocity distribution.")
    
    args = getattr(parser, 'parse_args')()
    
    if args.compare:
        compare_snapshots(file_base=args.compare[0], file_current=args.compare[1])
    else:
        # Chronological Engine Core Alignment
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        if args.__dict__["from"]:
            try:
                p_from = datetime.date.fromisoformat(args.__dict__["from"])
                calculated_start = datetime.datetime.combine(p_from, datetime.time.min, tzinfo=datetime.timezone.utc)
            except ValueError:
                print("[-] Format error: `--from` must use YYYY-MM-DD template.")
                exit(1)
        elif args.days:
            calculated_start = now_utc - datetime.timedelta(days=args.days)
        else:
            calculated_start = now_utc - datetime.timedelta(days=30) # Default baseline fallback

        if args.to:
            try:
                p_to = datetime.date.fromisoformat(args.to)
                calculated_end = datetime.datetime.combine(p_to, datetime.time.max, tzinfo=datetime.timezone.utc)
            except ValueError:
                print("[-] Format error: `--to` must use YYYY-MM-DD template.")
                exit(1)
        else:
            calculated_end = now_utc # Default to this exact second

        if calculated_start > calculated_end:
            print("[-] Interval Constraint Error: Logical clash. Start parameter cannot exist ahead of End parameter.")
            exit(1)

        generate_enterprise_threat_leaderboard(
            start_date=calculated_start,
            end_date=calculated_end,
            target_layer=args.layer, 
            debug_mode=args.debug,
            custom_export_arg=args.export,
            run_speedway=args.speedway
        )