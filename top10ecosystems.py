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

def build_ghsa_ecosystem_map(cache_dir: str = "./cache", cache_expiry_hours: int = 24):
    """
    Downloads the master database zip from OSV if missing or stale,
    and enriches the local lookup index by classifying the threat type and 
    detecting whether it is a brand-new entry or an older update.
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

                            if is_malware:
                                classification = "Malware (New Entry)" if is_new_entry else "Malware (Incremental Update)"
                            elif has_fixes:
                                classification = "Vulnerability Fix (New Entry)" if is_new_entry else "Vulnerability Fix (Update)"
                            else:
                                classification = "Metadata Correction / Adjustments"

                            if vuln_id and ecosystems:
                                id_to_meta[vuln_id] = {
                                    "ecosystems": list(ecosystems),
                                    "type": classification
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

def generate_enterprise_threat_leaderboard(time_boundary_str: str, target_layer: str = None, debug_mode: bool = False):
    """
    Parses dynamic lookback parameters (either an integer or a YYYY-MM-DD date)
    and processes streamed log entries matching that timeframe.
    """
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

    if target_layer == "app":
        final_leaderboard.update({
            "npm": 0, "PyPI": 0, "Maven (Java)": 0, "Go (Golang)": 0, "NuGet": 0, 
            "Packagist (PHP)": 0, "RubyGems": 0, "Crates.io": 0, "Hex": 0, "Pub": 0,
            "ConanCenter": 0, "SwiftURL": 0
        })
    elif target_layer == "container":
        final_leaderboard.update({
            "Debian": 0, "Ubuntu": 0, "Alpine Linux": 0, "Alpaquita Linux": 0,
            "Azure Linux": 0, "MinimOS": 0, "Chainguard": 0, "Bitnami": 0
        })

    bucket_counts = Counter({
        "Malware (New Entry)": 0,
        "Malware (Incremental Update)": 0,
        "Vulnerability Fix (New Entry)": 0,
        "Vulnerability Fix (Update)": 0,
        "Metadata Correction / Adjustments": 0
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
                    else:
                        raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
                else:
                    raw_ecosystems.append(path_parts[0])
                    if path_parts[0].lower() in ['npm', 'pypi'] and "mal-" in path_parts[-1].lower():
                        update_type = "Malware (New Entry)"
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

                # Normalize unmappable variants up front
                if eco_clean in ["OSV Global Meta-Records", "[EMPTY]", ""]:
                    eco_clean = "Untagged Commit Hash/CVE Noise"

                # FIXED LOGIC GATE: Intercept noise entries completely if --debug isn't supplied
                if eco_clean == "Untagged Commit Hash/CVE Noise" and not debug_mode:
                    continue

                layer = get_artifact_layer(eco_clean)
                if target_layer == "container" and layer != "Container Base Image":
                    continue
                elif target_layer == "app" and layer != "App Software Registry":
                    continue

                bucket_counts[update_type] += 1

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
    print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSV Threat Stream Campaign Dashboard Indicator.")
    parser.add_argument("--layer", choices=["container", "app"], help="Isolate the dashboard layout by layer type.")
    parser.add_argument("--days", type=str, default="30", help="The lookback window string parameters.")
    parser.add_argument("--debug", action="store_true", help="Surface raw, untagged noise.")
    
    args = parser.parse_args()
    generate_enterprise_threat_leaderboard(time_boundary_str=args.days, target_layer=args.layer, debug_mode=args.debug)