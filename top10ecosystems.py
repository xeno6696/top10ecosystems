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
    lifecycle status, and explicit malware attack mechanics.
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

                            for affected in vuln_data.get("affected", []):
                                eco = affected.get("package", {}).get("ecosystem")
                                if eco:
                                    ecosystems.add(eco)
                                for ranges in affected.get("ranges", []):
                                    for events in ranges.get("events", []):
                                        if "fixed" in events:
                                            has_fixes = True
                            
                            published_str = vuln_data.get("published", "1970-01-01T00:00:00Z").replace("Z", "+00:00")
                            modified_str = vuln_data.get("modified", "1970-01-01T00:00:00Z").replace("Z", "+00:00")
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
                                    "vector": malware_vector
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
    """
    Parses two local snapshot files, aggregates dynamic subfolder leakage on the fly,
    generates trend metrics, and prints an ANSI-colored delta report.
    """
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

    # DYNAMIC ON-THE-FLY ROLLUP SANITIZATION: Intercept legacy snapshot data fields
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
        
        if v_diff > 0:
            v_str = f"{GREEN}+{v_diff:,}{RESET}"
        elif v_diff < 0:
            v_str = f"{RED}{v_diff:,}{RESET}"
        else:
            v_str = "0"

        r1 = base_rank_map.get(eco, None)
        r2 = curr_rank_map.get(eco, None)
        
        if r1 and r2:
            r_diff = r1 - r2
            if r_diff > 0:
                r_str = f"{GREEN}Moved up {r_diff} spots (#{r1} -> #{r2}){RESET}"
            elif r_diff < 0:
                r_str = f"{RED}Moved down {abs(r_diff)} spots (#{r1} -> #{r2}){RESET}"
            else:
                r_str = f"No Change (#{r2})"
        elif not r1 and r2:
            r_str = f"{GREEN}New Entry To Rank (#{r2}){RESET}"
        elif r1 and not r2:
            r_str = f"{RED}Dropped Out of Active Rankings (Was #{r1}){RESET}"
        else:
            r_str = "Inactive / Zero Activity Trace"

        print(f"{eco:<28} | {v1:<10,} | {v2:<12,} | {v_str:<23} | {r_str}")

    print(f"\n{BOLD}II. THREAT BEHAVIOR VARIANCE:{RESET}")
    print("-"*85)
    for category in base["threat_profile"].keys():
        b_count = base["threat_profile"].get(category, 0)
        c_count = current["threat_profile"].get(category, 0)
        diff = c_count - b_count
        
        if diff > 0:
            diff_str = f"{GREEN}+{diff:,}{RESET}"
        elif diff < 0:
            diff_str = f"{RED}{diff:,}{RESET}"
        else:
            diff_str = "0"
            
        print(f"-> {category:<35} | Base: {b_count:<6,} | Current: {c_count:<6,} | Delta: {diff_str}")

    if base.get("malware_vectors") or current.get("malware_vectors"):
        print(f"\n{BOLD}III. MALWARE VECTOR ATTACK MATRIX SHIFTS:{RESET}")
        print("-"*85)
        all_vectors = sorted(list(set(base.get("malware_vectors", {}).keys()).union(set(current.get("malware_vectors", {}).keys()))))
        for vec in all_vectors:
            b_v = base.get("malware_vectors", {}).get(vec, 0)
            c_v = current.get("malware_vectors", {}).get(vec, 0)
            v_diff = c_v - b_v
            
            if v_diff > 0:
                v_diff_str = f"{GREEN}+{v_diff:,}{RESET}"
            elif v_diff < 0:
                v_diff_str = f"{RED}{v_diff:,}{RESET}"
            else:
                v_diff_str = "0"
                
            print(f"-> {vec:<38} | Base: {b_v:<5,} | Current: {c_v:<5,} | Delta: {v_diff_str}")
    print("="*85 + "\n")

def generate_enterprise_threat_leaderboard(time_boundary_str: str, target_layer: str = None, debug_mode: bool = False, export_path: str = None):
    now = datetime.datetime.now(datetime.timezone.utc)
    
    if time_boundary_str.isdigit():
        days_delta = int(time_boundary_str)
        cutoff_date = now - datetime.timedelta(days=days_delta)
        time_label = f"LAST {days_delta} DAYS"
    else:
        try:
            parsed_date = datetime.date.fromisoformat(time_boundary_str)
            cutoff_date = datetime.datetime.combine(parsed_date, datetime.time.min, tzinfo=datetime.timezone.utc)
            days_delta = (now.date() - parsed_date).days
            time_label = f"SINCE {time_boundary_str} ({days_delta} DAYS AGO)"
        except ValueError:
            print(f"[-] Format error: '{time_boundary_str}' must be an integer or a valid YYYY-MM-DD date string.")
            return

    print(f"[*] Analyzing live threat stream logs since: {cutoff_date.date()}...")

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
            
            if mod_time < cutoff_date:
                break
            
            total_raw_rows += 1
            raw_ecosystems = []
            update_type = "Metadata Correction / Adjustments"
            current_vector = None

            if ":" in path:
                parts = path.split(":")
                if len(parts) > 1:
                    raw_ecosystems.append(parts[1])
                    update_type = "Vulnerability Fix (Update)"
                else:
                    raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
            else:
                path_parts = path.split('/')
                if len(path_parts) == 1 or path_parts[0].lower() in ['root', '']:
                    osv_id = path_parts[-1].replace(".json", "")
                    if osv_id in ghsa_lookup:
                        raw_ecosystems.extend(ghsa_lookup[osv_id]["ecosystems"])
                        update_type = ghsa_lookup[osv_id]["type"]
                        if "Malware" in update_type:
                            current_vector = ghsa_lookup[osv_id]["vector"]
                    else:
                        raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
                else:
                    raw_ecosystems.append(path_parts[0])
                    if path_parts[0].lower() in ['npm', 'pypi'] and "mal-" in path_parts[-1].lower():
                        update_type = "Malware (New Entry)"
                        osv_id = path_parts[-1].replace(".json", "")
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
    print(f"  {title} ({time_label})")
    print("="*85)
    print(f"{'Rank':<5} | {'Ecosystem/Registry':<32} | {'Activity Delta':<14} | {'Artifact Layer'}")
    print("-"*85)
    
    for rank, (eco, count, layer) in enumerate(filtered_results[:10], 1):
        print(f"#{rank:<3} | {eco:<32} | {count:<14,} | {layer}")
        
    print("="*85)
    print(f"Raw Entry Stream Items:    {total_raw_rows:,}")
    print(f"Ecosystem Attributions:    {sum(count for _, count, _ in filtered_results):,}")
    
    if debug_mode:
        print("\n[*] DEBUG NOTE: 'Untagged Commit Hash/CVE Noise' is visible.")

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
    print()

    if export_path:
        export_payload = {
            "metadata": {
                "generated_at": now.isoformat(),
                "time_boundary": time_boundary_str,
                "cutoff_date": cutoff_date.date().isoformat(),
                "target_layer_filter": target_layer if target_layer else "all",
                "total_raw_rows_processed": total_raw_rows
            },
            "leaderboard": {eco: count for eco, count, _ in filtered_results},
            "threat_profile": dict(bucket_counts),
            "malware_vectors": dict(malware_vector_counts) if total_malware_signals > 0 else {}
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
    parser.add_argument("--days", type=str, default="30", help="The lookback window string parameters.")
    parser.add_argument("--debug", action="store_true", help="Surface raw, untagged noise.")
    parser.add_argument("--export", type=str, help="Specify a filename to export a static JSON data snapshot.")
    parser.add_argument(
        "--compare", 
        nargs=2, 
        metavar=('BASE_JSON', 'CURRENT_JSON'),
        help="Provide exactly two exported snapshot files to run an internal trends comparison delta report."
    )
    
    args = parser.parse_args()
    
    if args.compare:
        compare_snapshots(file_base=args.compare[0], file_current=args.compare[1])
    else:
        generate_enterprise_threat_leaderboard(
            time_boundary_str=args.days, 
            target_layer=args.layer, 
            debug_mode=args.debug,
            export_path=args.export
        )