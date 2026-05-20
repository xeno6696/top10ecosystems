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
OSV Threat Stream Campaign Dashboard Indicator - Version 1.2
=================================================================================
A security engineering tool designed to track software supply chain fluctuations 
by aggregating upstream vulnerability mutations from the Open Source Vulnerability 
(OSV) database and cross-referencing strict local project manifest pins.

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
import re
from collections import Counter
import requests

# ANSI Color Codes for Scannable Shell Output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ==============================================================================
# MODULAR PLUG-AND-PLAY DECOUPLED MANIFEST PARSERS (STRATEGY PATTERN)
# ==============================================================================

def parse_maven_dependency_tree(file_path: str) -> dict:
    """Extracts unique groupId:artifactId pairs mapped to pinned versions, barfing on dynamic ranges."""
    discovered_packages = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.replace("+-", "").replace("\\-", "").replace("|", "").strip()
                if not clean_line or ":" not in clean_line:
                    continue
                
                # Check for fancy dynamic range tokens or open resolution symbols
                illegal_maven_indicators = ["[", "]", "(", ")", "LATEST", "RELEASE", "SNAPSHOT"]
                if any(indicator in clean_line for indicator in illegal_maven_indicators):
                    print(f"\n{BOLD}{RED}[!] MAVEN TREE LINTING FAILURE (Line {line_num}):{RESET}")
                    print(f"    -> Offending Line: '{line.strip()}'")
                    print(f"    -> Reason: Dynamic ranges, SNAPSHOTs, or LATEST keywords are forbidden to ensure build determinism.")
                    print(f"    -> Action: Please run dependency:tree against a fully resolved, locked release build.\n")
                    exit(1)
                
                parts = clean_line.split(":")
                if len(parts) >= 4:
                    group_id = parts[0].strip()
                    artifact_id = parts[1].strip()
                    version_pin = parts[3].strip()
                    
                    package_key = f"{group_id}:{artifact_id}".lower().strip()
                    if package_key:
                        discovered_packages[package_key] = version_pin
    except Exception as e:
        print(f"[-] Error executing strict Maven tree parser strategy: {e}")
        exit(1)
    return discovered_packages

def parse_cyclonedx_sbom(file_path: str) -> dict:
    """Extracts package names mapped to versions from a standard CycloneDX JSON SBOM."""
    discovered_packages = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
            for component in sbom_data.get("components", []):
                name = component.get("name")
                group = component.get("group")
                version = component.get("version", "0.0.0").strip()
                if name:
                    full_name = f"{group}:{name}" if group else name
                    discovered_packages[full_name.strip().lower()] = version
    except Exception as e:
        print(f"[-] Error executing CycloneDX JSON strategy: {e}")
    return discovered_packages

def parse_pypi_requirements(file_path: str) -> dict:
    """Extracts exact package names mapped to pinned versions, rejecting dynamic operators."""
    discovered_packages = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("-r"):
                    continue
                
                # Check for dynamic range symbols before parsing
                illegal_operators = [">=", "<=", ">", "<", "~=", "!="]
                if any(op in clean_line for op in illegal_operators):
                    print(f"\n{BOLD}{RED}[!] MANIFEST LINTING FAILURE (Line {line_num}):{RESET}")
                    print(f"    -> Offending Line: '{clean_line}'")
                    print(f"    -> Reason: Dynamic range operators are forbidden to ensure build determinism.")
                    print(f"    -> Action: Please compile your lockfile or freeze the library to a strict pin ('==').\n")
                    exit(1) # Immediate hard halt
                
                parts = clean_line.split("==")
                package_name = parts[0].strip().lower().replace('_', '-')
                
                version_pin = "0.0.0"
                if len(parts) > 1:
                    # Strip out downstream comments or environment markers if present
                    version_pin = parts[1].split(";")[0].split("#")[0].strip()
                        
                if package_name:
                    discovered_packages[package_name] = version_pin
    except Exception as e:
        print(f"[-] Error executing strict PyPI parser strategy: {e}")
        exit(1)
    return discovered_packages

# Central Registry Routing Interface Mapping
MANIFEST_PARSER_REGISTRY = {
    "maven_tree": parse_maven_dependency_tree,
    "cyclonedx_json": parse_cyclonedx_sbom,
    "pypi_requirements": parse_pypi_requirements
}

def auto_sniff_manifest_strategy(file_path: str) -> str:
    """Inspects file characteristics to assign the correct parsing algorithm."""
    if not os.path.exists(file_path):
        return None
    
    if file_path.endswith(".json"):
        return "cyclonedx_json"
        
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            sample = [f.readline() for _ in range(15)]
            for line in sample:
                if any(x in line for x in ["+-", "\\-", "|"]) and len(line.split(":")) >= 3:
                    return "maven_tree"
    except Exception:
        pass
        
    return "pypi_requirements"

# ==============================================================================
# CORE ANALYTICAL ENGINES
# ==============================================================================

def build_ghsa_ecosystem_map(cache_dir: str = "./cache", cache_expiry_hours: int = 24):
    master_zip_url = "https://storage.googleapis.com/osv-vulnerabilities/all.zip"
    os.makedirs(cache_dir, exist_ok=True)
    local_zip_path = os.path.join(cache_dir, "osv_master_all.zip")
    should_download = True
    
    if os.path.exists(local_zip_path):
        file_age_hours = (time.time() - os.path.getmtime(local_zip_path)) / 3600
        if file_age_hours < cache_expiry_hours:
            print(f"[+] Found fresh local cache: {local_zip_path} (Age: {file_age_hours:.1f} hours). Skipping download.")
            should_download = False

    if should_download:
        print(f"[*] Downloading master database archive from OSV (~1GB)...")
        try:
            response = requests.get(master_zip_url, stream=True, timeout=120)
            response.raise_for_status()
            with open(local_zip_path, 'wb') as local_file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk: local_file.write(chunk)
            print(f"[+] Download complete. Saved to: {local_zip_path}")
        except Exception as e:
            print(f"[-] Download failed: {e}")
            if not os.path.exists(local_zip_path): return {}

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
                            p_name = "N/A"
                            vuln_versions = set() # Track explicit vulnerable literal versions
                            
                            if vuln_id.startswith("MAL-") or "malicious" in file_name.lower():
                                is_malware = True
                                
                            summary = vuln_data.get("summary", "").lower()
                            details = vuln_data.get("details", "").lower()
                            if "backdoor" in summary or "typosquat" in summary or "malicious package" in summary:
                                is_malware = True

                            max_versions_found = 0
                            for affected in vuln_data.get("affected", []):
                                eco = affected.get("package", {}).get("ecosystem")
                                name = affected.get("package", {}).get("name")
                                if eco: ecosystems.add(eco)
                                if name: p_name = name.strip()
                                
                                # Index literal vulnerable version values directly from the record
                                for v in affected.get("versions", []):
                                    vuln_versions.add(str(v).strip())
                                
                                v_len = len(affected.get("versions", []))
                                if v_len > max_versions_found: max_versions_found = v_len

                                for ranges in affected.get("ranges", []):
                                    for events in ranges.get("events", []):
                                        if "fixed" in events: has_fixes = True
                            
                            published_str = vuln_data.get("published", "1970-01-01T00:00:00Z")
                            modified_str = vuln_data.get("modified", "1970-01-01T00:00:00Z")
                            dwell_days = 0.0
                            try:
                                p_dt = datetime.datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                                m_dt = datetime.datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                                dwell_days = max(0.0, (m_dt - p_dt).days)
                            except ValueError: pass

                            is_new_entry = (published_str == modified_str)

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
                                    "package_name": p_name,
                                    "type": classification,
                                    "vector": malware_vector,
                                    "dwell_days": dwell_days,
                                    "blast_radius": max_versions_found,
                                    "vulnerable_versions": vuln_versions # Stored for validation checking
                                }
                        except json.JSONDecodeError: continue 
        print(f"[+] Successfully indexed {len(id_to_meta):,} global advisory mappings.")
    except Exception as e:
        print(f"[-] Failed to read master archive: {e}")
    return id_to_meta

def get_artifact_layer(eco_name):
    container_images = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    app_registries = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]
    if eco_name in container_images: return "Container Base Image"
    elif eco_name in app_registries: return "App Software Registry"
    elif eco_name == "GIT": return "Source Control (SCM)"
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
        
        if v_diff > 0: v_str = f"{GREEN}{padded_v_str}{RESET}"
        elif v_diff < 0: v_str = f"{RED}{padded_v_str}{RESET}"
        else: v_str = padded_v_str

        r1 = base_rank_map.get(eco, None)
        r2 = curr_rank_map.get(eco, None)
        
        if r1 and r2:
            r_diff = r1 - r2
            if r_diff > 0: r_str = f"{GREEN}Moved up {r_diff} spots ({r1} -> {r2}){RESET}"
            elif r_diff < 0: r_str = f"{RED}Moved down {abs(r_diff)} spots ({r1} -> {r2}){RESET}"
            else: r_str = f"No Change ({r2})"
        elif not r1 and r2: r_str = f"{GREEN}New Entry To Rank ({r2}){RESET}"
        elif r1 and not r2: r_str = f"{RED}Dropped Out of Active Rankings (Was {r1}){RESET}"
        else: r_str = "Inactive / Zero Activity Trace"

        print(f"{eco:<28} | {v1:<10,} | {v2:<12,} | {v_str} | {r_str}")

    print(f"\n{BOLD}II. THREAT BEHAVIOR VARIANCE:{RESET}")
    print("-"*85)
    for category in base["threat_profile"].keys():
        b_count = base["threat_profile"].get(category, 0)
        c_count = current["threat_profile"].get(category, 0)
        diff = c_count - b_count
        
        raw_diff_str = f"{diff:+,}" if diff != 0 else "0"
        padded_diff_str = f"{raw_diff_str:>10}"
        
        if diff > 0: diff_str = f"{GREEN}{padded_diff_str}{RESET}"
        elif diff < 0: diff_str = f"{RED}{padded_diff_str}{RESET}"
        else: diff_str = padded_diff_str
            
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
            
            if v_diff > 0: v_diff_str = f"{GREEN}{padded_v_diff_str}{RESET}"
            elif v_diff < 0: v_diff_str = f"{RED}{padded_v_diff_str}{RESET}"
            else: v_diff_str = padded_v_diff_str
                
            print(f"-> {vec:<38} | Base: {b_v:<6,} | Current: {c_v:<6,} | Delta: {v_diff_str}")

    if "profile_matrix" in base and "profile_matrix" in current:
        print(f"\n{BOLD}IV. SPATIAL DWELL & BLAST RADIUS BASELINE SHIFTS:{RESET}")
        print("="*115)
        print(f"{'Ecosystem / Registry':<22} | {'Avg Dwell MAL Delta':<26} | {'Avg Dwell CVE Delta':<26} | {'Avg Blast Radius Delta'}")
        print("-"*115)
        
        for eco in sorted(list(set(base["profile_matrix"].keys()).union(set(current["profile_matrix"].keys())))):
            b_mat = base["profile_matrix"].get(eco, {"avg_dwell_mal": 0.0, "avg_dwell_cve": 0.0, "avg_blast_radius": 0.0})
            c_mat = current["profile_matrix"].get(eco, {"avg_dwell_mal": 0.0, "avg_dwell_cve": 0.0, "avg_blast_radius": 0.0})
            
            dm_base = b_mat.get("avg_dwell_mal", 0.0)
            dc_base = b_mat.get("avg_dwell_cve", 0.0)
            br_base = b_mat.get("avg_blast_radius", 0.0)
            
            dm_diff = c_mat["avg_dwell_mal"] - dm_base
            dc_diff = c_mat["avg_dwell_cve"] - dc_base
            br_diff = c_mat["avg_blast_radius"] - br_base
            
            def color_metric_string(diff, base_val, suffix, width_size):
                diff_str = f"{diff:+.1f}{suffix}" if diff != 0 else f"0.0{suffix}"
                raw_str = f"{diff_str:<12} (from {base_val:.1f})"
                padded_raw = f"{raw_str:<{width_size}}"
                
                if diff > 0: return f"{GREEN}{padded_raw}{RESET}"
                elif diff < 0: return f"{RED}{padded_raw}{RESET}"
                return padded_raw

            dm_str = color_metric_string(dm_diff, dm_base, " Days", 26)
            dc_str = color_metric_string(dc_diff, dc_base, " Days", 26)
            br_str = color_metric_string(br_diff, br_base, " Vers", 26)

            print(f"{eco:<22} | {dm_str} | {dc_str} | {br_str}")
        print("="*115)
        
    if "outliers_leaderboards" in base and "outliers_leaderboards" in current:
        print(f"\n{BOLD}V. CRITICAL OUTLIER ATTACK SURFACE RADIUS POOLS VARIANCE ANALYSIS:{RESET}")
        print("="*95)
        
        for eco in sorted(list(current["outliers_leaderboards"].keys())):
            base_pool = base["outliers_leaderboards"].get(eco, {})
            curr_pool = current["outliers_leaderboards"].get(eco, {})
            
            if not base_pool and not curr_pool: continue
                
            print(f"\n{BOLD}[+] {eco} Outlier Tracking Shifts:{RESET}")
            print(f"    {'Advisory ID':<20} | {'Base Impact':<16} | {'Current Impact':<16} | {'Impact Delta'}")
            print(f"    {'-'*76}")
            
            all_advisories = set(base_pool.keys()).union(set(curr_pool.keys()))
            has_shifts = False
            
            for r_id in all_advisories:
                b_radius = base_pool.get(r_id, [0, ""])[0]
                c_radius = curr_pool.get(r_id, [0, ""])[0]
                
                radius_diff = c_radius - b_radius
                if radius_diff == 0: continue
                
                has_shifts = True
                b_str = f"{b_radius:,} Vers" if b_radius > 0 else "N/A"
                c_str = f"{c_radius:,} Vers" if c_radius > 0 else "N/A"
                
                if radius_diff > 0:
                    if b_radius == 0: diff_str = f"{GREEN}+ {radius_diff:,} Vers (NEW ARRIVAL){RESET}"
                    else: diff_str = f"{GREEN}+ {radius_diff:,} Vers (EXPANDED){RESET}"
                else:
                    if c_radius == 0: diff_str = f"{RED}- {abs(radius_diff):,} Vers (DROPPED OUT){RESET}"
                    else: diff_str = f"{RED}- {abs(radius_diff):,} Vers (REDUCED){RESET}"
                        
                print(f"    {r_id:<20} | {b_str:<16} | {c_str:<16} | {diff_str}")
                
            if not has_shifts:
                print(f"    -> All tracked critical outlier thresholds remained static between snapshots.")
        print("="*95)
        
    print("="*85 + "\n")

# ==============================================================================
# MAIN ENGINE EXECUTION
# ==============================================================================

def generate_enterprise_threat_leaderboard(start_date, end_date, target_layer: str = None, debug_mode: bool = False, custom_export_arg=None, run_speedway: bool = False, project_file_path: str = None, forced_format: str = None, audit_mode: bool = False):
    now = datetime.datetime.now(datetime.timezone.utc)
    
    final_leaderboard = Counter()
    target_inventory_map = {} # Shifted to dictionary to record exact Name -> Version mappings
    is_project_mode = False
    allowed_project_ecosystems = []
    
    known_containers = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    known_registries = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]

    master_tracks = known_containers + known_registries + ["GIT", "Untagged Commit Hash/CVE Noise", "Android"]
    
    if target_layer == "app":
        final_leaderboard.update({k: 0 for k in known_registries})
    elif target_layer == "container":
        final_leaderboard.update({k: 0 for k in known_containers})
    else:
        final_leaderboard.update({k: 0 for k in master_tracks if k not in ["GIT", "Untagged Commit Hash/CVE Noise"]})

    manifest_target = project_file_path if project_file_path else (audit_mode if isinstance(audit_mode, str) else None)
    
    if manifest_target:
        strategy = forced_format if forced_format else auto_sniff_manifest_strategy(manifest_target)
        if strategy and strategy in MANIFEST_PARSER_REGISTRY:
            print(f"[*] Ingesting project manifest file using strategy profile: {strategy}...")
            target_inventory_map = MANIFEST_PARSER_REGISTRY[strategy](manifest_target)
            is_project_mode = True
            print(f"[+] Loaded {len(target_inventory_map)} project unique package tracking keys.")
            
            # Decoupled Language Context Whitelists mapping parser types straight to registry targets
            # AFTER
            STRATEGY_ECOSYSTEM_WHITELIST = {
                "pypi_requirements": ["PyPI"],
                "maven_tree": ["Maven (Java)", "Maven"], # Allows both the raw and translated tokens
                "cyclonedx_json": ["npm", "PyPI", "Maven (Java)", "Maven", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems"]
            }
            allowed_project_ecosystems = STRATEGY_ECOSYSTEM_WHITELIST.get(strategy, [])
        else:
            print(f"[-] Configuration Error: Unable to accurately parse layout structure for: {manifest_target}")
            exit(1)

    ghsa_lookup = build_ghsa_ecosystem_map()
    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    
    total_raw_rows = 0
    project_intercept_alerts = []

    bucket_counts = Counter({"Malware (New Entry)": 0, "Malware (Incremental Update)": 0, "Vulnerability Fix (New Entry)": 0, "Vulnerability Fix (Update)": 0, "Metadata Correction / Adjustments": 0})
    malware_vector_counts = Counter({"Typosquatting / Brand Hijacking": 0, "Dependency Confusion Campaign": 0, "Data Exfiltration / Credential Stealer": 0, "Persistent Backdoor / Execution Shell": 0, "Unclassified Malicious Payload": 0})

    spatial_dwell_malware = {k: [] for k in master_tracks}
    spatial_dwell_cve = {k: [] for k in master_tracks}
    spatial_blast_radius = {k: [] for k in master_tracks}
    ecosystem_outlier_pools = {k: {} for k in master_tracks}

    try:
        response = requests.get(manifest_url, stream=True, timeout=30)
        response.raise_for_status()
        lines = (line.decode('utf-8') for line in response.iter_lines())
        reader = csv.reader(lines)
        
        for row in reader:
            if not row: continue
            mod_time_str, path = row[0], row[1]
            mod_time = datetime.datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
            
            if mod_time > end_date: continue
            if mod_time < start_date: break
            
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
                else: raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
            else:
                path_parts = path.split('/')
                if len(path_parts) == 1 or path_parts[0].lower() in ['root', '']:
                    osv_id = path_parts[-1].replace(".json", "")
                    current_id = osv_id
                    if osv_id in ghsa_lookup:
                        raw_ecosystems.extend(ghsa_lookup[osv_id]["ecosystems"])
                        update_type = ghsa_lookup[osv_id]["type"]
                        if "Malware" in update_type: current_vector = ghsa_lookup[osv_id]["vector"]
                    else: raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
                else:
                    raw_ecosystems.append(path_parts[0])
                    osv_id = path_parts[-1].replace(".json", "")
                    current_id = osv_id
                    if path_parts[0].lower() in ['npm', 'pypi'] and "mal-" in path_parts[-1].lower():
                        update_type = "Malware (New Entry)"
                        current_vector = ghsa_lookup.get(osv_id, {}).get("vector", "Unclassified Malicious Payload")
                    else: update_type = "Vulnerability Fix (Update)"

            for eco in raw_ecosystems:
                eco_raw = eco.strip()
                eco_lower = eco_raw.lower()
                
                hard_mappings = {
                    "maven": "Maven (Java)",
                    "go": "Go (Golang)",
                    "packagist": "Packagist (PHP)",
                    "git": "GIT",
                    "crates.io": "Crates.io"
                }
                
                eco_clean = None
                if eco_lower in hard_mappings:
                    eco_clean = hard_mappings[eco_lower]
                else:
                    for track in master_tracks:
                        if eco_lower in track.lower() or track.lower() in eco_lower:
                            eco_clean = track
                            break
                
                if not eco_clean:
                    eco_clean = "Android" if eco_lower not in ["git", "untagged commit hash/cve noise"] else "Untagged Commit Hash/CVE Noise"

                if eco_clean == "Untagged Commit Hash/CVE Noise" and not debug_mode: continue

                layer = get_artifact_layer(eco_clean)
                if target_layer == "container" and layer != "Container Base Image": continue
                if target_layer == "app" and layer != "App Software Registry": continue

                # Strict Exact Key and Pinned Version Boundary Validation Interception
                if is_project_mode and current_id in ghsa_lookup:
                    m_name = ghsa_lookup[current_id]["package_name"].lower().strip()
                    
                    if m_name in target_inventory_map:
                        if allowed_project_ecosystems and eco_clean not in allowed_project_ecosystems:
                            continue
                            
                        local_version = target_inventory_map[m_name]
                        vulnerable_versions_pool = ghsa_lookup[current_id].get("vulnerable_versions", set())
                        
                        # Fix: If running version is found OR if the upstream record omits a literal 
                        # version list (common in Maven ranges), flag it for analyst triage.
                        if local_version == "0.0.0" or local_version in vulnerable_versions_pool or not vulnerable_versions_pool:
                            project_intercept_alerts.append((current_id, ghsa_lookup[current_id]["package_name"], eco_clean, update_type))

                bucket_counts[update_type] += 1
                if "Malware" in update_type and current_vector: malware_vector_counts[current_vector] += 1

                if current_id in ghsa_lookup:
                    meta_entry = ghsa_lookup[current_id]
                    if "Malware" in update_type: spatial_dwell_malware[eco_clean].append(meta_entry["dwell_days"])
                    else: spatial_dwell_cve[eco_clean].append(meta_entry["dwell_days"])
                    spatial_blast_radius[eco_clean].append(meta_entry["blast_radius"])
                    
                    if meta_entry["blast_radius"] > 0:
                        pool = ecosystem_outlier_pools[eco_clean]
                        if current_id not in pool or meta_entry["blast_radius"] > pool[current_id][0]:
                            pool[current_id] = (meta_entry["blast_radius"], update_type)

                final_leaderboard[eco_clean] += 1

    except Exception as e:
        print(f"[-] Threat ledger stream disrupted: {e}")
        return

    filtered_results = sorted([(e, c, get_artifact_layer(e)) for e, c in final_leaderboard.items() if e not in ["Untagged Commit Hash/CVE Noise", "GIT"]], key=lambda x: x[1], reverse=True)
    
    if is_project_mode:
        print("\n" + "="*95)
        title_source = project_file_path if project_file_path else audit_mode
        print(f"  {BOLD}LOCAL REPOSITORY INTERSECTION REPORT: {os.path.basename(title_source)}{RESET}")
        print("="*95)
        if project_intercept_alerts:
            print(f"{BOLD}{RED}[!] LOCAL BLAST RADIUS BREACH ALERT:{RESET}")
            print("-"*95)
            print(f"{'Advisory ID':<22} | {'Package Name':<20} | {'Ecosystem/Registry':<22} | {'Threat Profile'}")
            print("-"*95)
            for r_id, p_name, eco, u_type in sorted(list(set(project_intercept_alerts)), key=lambda x: x[1]):
                print(f"{r_id:<22} | {p_name:<20} | {eco:<22} | {u_type}")
        else:
            print(f" {GREEN}[+] Clean Bill of Health: Zero active package mutations match your local manifest elements within this timeframe.{RESET}")
        print("="*95 + "\n")
        return

    # ==============================================================================
    # ONSCREEN RENDER OUTPUT GENERATION
    # ==============================================================================

    print("\n" + "="*85)
    print(f"  {BOLD}VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD{RESET}")
    print(f"  Chronological Box Window: {start_date.date()} to {end_date.date()}")
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
    print(f"  {BOLD}II. DATA ENRICHMENT: LAYER THREAT PROFILE{RESET}")
    print("="*50)
    for b_type in ["Malware (New Entry)", "Malware (Incremental Update)", "Vulnerability Fix (New Entry)", "Vulnerability Fix (Update)", "Metadata Correction / Adjustments"]:
        b_count = bucket_counts[b_type]
        percentage = (b_count / total_buckets) * 100 if total_buckets > 0 else 0.0
        print(f"-> {b_type:<32} | {b_count:<6,} ({percentage:.1f}%)")
    print("="*50)

    total_malware_signals = sum(malware_vector_counts.values())
    if total_malware_signals > 0:
        print("\n" + "="*50)
        print(f"  {BOLD}III. DEEP DIVE: MALWARE ATTACK VECTOR ANALYSIS{RESET}")
        print("="*50)
        for vector_name, vector_count in malware_vector_counts.most_common():
            v_p = (vector_count / total_malware_signals) * 100 if total_malware_signals > 0 else 0.0
            print(f"-> {vector_name:<38} | {vector_count:<4,} ({v_p:.1f}%)")
        print("="*50)

    print("\n" + "="*95)
    print(f"  {BOLD}IV. ECOSYSTEM THREAT DWELL TIME & BLAST RADIUS PROFILE MATRIX{RESET}")
    print("="*95)
    print(f"{'Ecosystem/Registry':<22} | {'Avg Dwell (Malware)':<20} | {'Avg Dwell (CVE)':<16} | {'Avg Blast Radius'}")
    print("-"*95)
    
    export_profile_matrix = {}
    active_matrix_ecosystems = [eco for eco, _, _ in filtered_results[:10]]
    
    for eco in active_matrix_ecosystems:
        m_list, c_list, r_list = spatial_dwell_malware.get(eco, []), spatial_dwell_cve.get(eco, []), spatial_blast_radius.get(eco, [])
        raw_avg_m = sum(m_list)/len(m_list) if m_list else 0.0
        raw_avg_c = sum(c_list)/len(c_list) if c_list else 0.0
        raw_avg_r = sum(r_list)/len(r_list) if r_list else 0.0
        
        export_profile_matrix[eco] = {"avg_dwell_mal": raw_avg_m, "avg_dwell_cve": raw_avg_c, "avg_blast_radius": raw_avg_r}
        print(f"{eco:<22} | {f'{raw_avg_m:.1f} Days':<20} | {f'{raw_avg_c:.1f} Days':<16} | {raw_avg_r:.1f} Versions")
    print("="*95)

    print("\n" + "="*95)
    print(f"  {BOLD}V. CRITICAL OUTLIER ATTACK SURFACE RADIUS POOLS (TOP 10 PER ECOSYSTEM){RESET}")
    print("="*95)
    
    export_outlier_manifests = {}
    for eco in active_matrix_ecosystems:
        pool = ecosystem_outlier_pools.get(eco, {})
        if pool:
            print(f"\n{BOLD}[+] {eco} Top Impact Outliers:{RESET}")
            print(f"    {'Rank':<5} | {'Advisory ID':<20} | {'Impact Blast Radius':<20} | {'Threat Profile'}")
            print(f"    {'-'*79}")
            
            sorted_pool = sorted(pool.items(), key=lambda x: x[1][0], reverse=True)[:10]
            export_outlier_manifests[eco] = {r_id: [radius, u_type] for r_id, (radius, u_type) in sorted_pool}
            
            for rank, (r_id, (radius, u_type)) in enumerate(sorted_pool, 1):
                print(f"    #{rank:<3} | {r_id:<20} | {f'{radius:,} Versions':<20} | {u_type}")
        else:
            export_outlier_manifests[eco] = {}
            print(f"\n[+] {eco}: No critical outliers tracked in this window.")
    print("\n" + "="*95)

    if custom_export_arg:
        output_dir = "./output"
        os.makedirs(output_dir, exist_ok=True)
        
        if isinstance(custom_export_arg, str):
            if not custom_export_arg.startswith(output_dir):
                export_filename = os.path.basename(custom_export_arg)
                export_path = os.path.join(output_dir, export_filename)
            else:
                export_path = custom_export_arg
        else:
            filename = f"{start_date.strftime('%d-%m-%y')}_to_{end_date.strftime('%d-%m-%y')}_{target_layer if target_layer else 'all'}.json"
            export_path = os.path.join(output_dir, filename)
        
        export_payload = {
            "metadata": {"generated_at": now.isoformat(), "interval_from": start_date.date().isoformat(), "interval_to": end_date.date().isoformat(), "target_layer_filter": target_layer if target_layer else "all"},
            "leaderboard": {eco: count for eco, count, _ in filtered_results},
            "threat_profile": dict(bucket_counts),
            "malware_vectors": dict(malware_vector_counts) if sum(malware_vector_counts.values()) > 0 else {},
            "profile_matrix": export_profile_matrix,
            "outliers_leaderboards": export_outlier_manifests
        }
        try:
            with open(export_path, 'w', encoding='utf-8') as ef: json.dump(export_payload, ef, indent=4)
            print(f"[Static Snapshot Saved]: {export_path}")
        except Exception as e: print(f"[-] Snapshot export write error: {e}")

# ==============================================================================
# ENTRY ENGINE EXECUTIVE PARSER ROUTINES
# ==============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSV Threat Stream Campaign Dashboard Indicator.")
    parser.add_argument("--layer", choices=["container", "app"], help="Isolate the dashboard layout by layer type.")
    parser.add_argument("--days", type=int, help="Relative lookback day window shortcut from today.")
    parser.add_argument("--from", metavar="YYYY-MM-DD", dest="from_date", help="Explicit chronological interval starting boundary.")
    parser.add_argument("--to", metavar="YYYY-MM-DD", help="Explicit chronological interval ending boundary.")
    parser.add_argument("--debug", action="store_true", help="Surface raw, untagged noise.")
    
    # Core Snapshot Pipeline Arguments
    parser.add_argument("--export", nargs='?', const=True, default=False, help="Auto-generate or name a static JSON snapshot payload.")
    parser.add_argument("--compare", nargs=2, metavar=('BASE_JSON', 'CURRENT_JSON'), help="Compare two snapshots to output dynamic variance metrics.")
    parser.add_argument("--speedway", action="store_true", help="Analyze live timeline log velocity distribution metrics.")
    
    # Modular Project Manifest Ingest Parameters
    parser.add_argument("--project-file", metavar="PATH", help="Path to project dependency tree output or standard SBOM.")
    parser.add_argument("--project-format", choices=list(MANIFEST_PARSER_REGISTRY.keys()), help="Force a manual schema parser profile selection.")
    
    # Target Intersection Sprint Addition
    parser.add_argument("--audit", metavar="MANIFEST_PATH", help="Ingest a local lockfile/requirements format directly to track active blast radius breaches.")
    
    args = parser.parse_args()
    
    if args.compare:
        compare_snapshots(file_base=args.compare[0], file_current=args.compare[1])
    else:
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        if args.days:
            calculated_start = now_utc - datetime.timedelta(days=args.days)
        elif args.from_date:
            calculated_start = datetime.datetime.combine(datetime.date.fromisoformat(args.from_date), datetime.time.min, tzinfo=datetime.timezone.utc)
        else:
            calculated_start = datetime.datetime(2026, 4, 18, 0, 0, 0, tzinfo=datetime.timezone.utc)
            
        if args.to:
            parsed_date = None
            for fmt in ("%Y-%m-%d", "%m-%d-%Y", "%d-%m-%Y"):
                try:
                    parsed_date = datetime.datetime.strptime(args.to, fmt).date()
                    break
                except ValueError: continue
            if not parsed_date:
                print(f"[-] Configuration Error: Unable to parse date '{args.to}'. Please use YYYY-MM-DD or MM-DD-YYYY formatting.")
                exit(1)
            calculated_end = datetime.datetime.combine(parsed_date, datetime.time.max, tzinfo=datetime.timezone.utc)
        else:
            calculated_end = now_utc

        generate_enterprise_threat_leaderboard(
            start_date=calculated_start, end_date=calculated_end,
            target_layer=args.layer, debug_mode=args.debug,
            custom_export_arg=args.export, run_speedway=args.speedway,
            project_file_path=args.project_file, forced_format=args.project_format,
            audit_mode=args.audit
        )