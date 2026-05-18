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
    building a comprehensive local lookup index for root-level advisories.
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

    print("[*] Building global advisory memory index from local archive...")
    id_to_ecosystems = {}
    
    try:
        with zipfile.ZipFile(local_zip_path) as z:
            for file_name in z.namelist():
                if file_name.endswith('.json'):
                    with z.open(file_name) as f:
                        try:
                            vuln_data = json.load(f)
                            vuln_id = vuln_data.get("id")
                            
                            ecosystems = set()
                            for affected in vuln_data.get("affected", []):
                                eco = affected.get("package", {}).get("ecosystem")
                                if eco:
                                    ecosystems.add(eco)
                            
                            if vuln_id and ecosystems:
                                id_to_ecosystems[vuln_id] = list(ecosystems)
                        except json.JSONDecodeError:
                            continue 
                            
        print(f"[+] Successfully indexed {len(id_to_ecosystems):,} global advisory mappings.")
    except Exception as e:
        print(f"[-] Failed to read and parse local zip file: {e}")
        
    return id_to_ecosystems

def get_artifact_layer(eco_name):
    """Maps ecosystem tags to clear enterprise infrastructure layers."""
    container_images = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    app_registries = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems"]
    
    if eco_name in container_images:
        return "Container Base Image"
    elif eco_name in app_registries:
        return "App Software Registry"
    elif eco_name == "GIT":
        return "Source Control (SCM)"
    else:
        return "Global Baseline Noise"

def generate_enterprise_threat_leaderboard(days_delta: int = 30, target_layer: str = None):
    """
    Combines streamed log updates with local memory mapping to map
    both folder-prefixed and root-level records to their clean parent ecosystems.
    Can be filtered by an isolated structural artifact layer.
    """
    cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_delta)
    print(f"[*] Analyzing live threat stream logs since: {cutoff_date.date()}...")

    # Load master mapping translation schema
    ghsa_lookup = build_ghsa_ecosystem_map()
    
    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    final_leaderboard = Counter()
    
    total_raw_rows = 0

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

            # Step 1: Catch explicit colon-delimited paths (e.g. "Root:Ubuntu:22.04")
            if ":" in path:
                parts = path.split(":")
                if len(parts) > 1:
                    raw_ecosystems.append(parts[1])
                else:
                    raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
            else:
                path_parts = path.split('/')
                
                # Step 2: Handle Root/Global files lacking clean directory prefixes (e.g. "GHSA-xxxx.json")
                if len(path_parts) == 1 or path_parts[0].lower() in ['root', '']:
                    osv_id = path_parts[-1].replace(".json", "")
                    if osv_id in ghsa_lookup:
                        raw_ecosystems.extend(ghsa_lookup[osv_id])
                    else:
                        raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
                # Step 3: Handle native directory folder prefixes (e.g. "npm/MAL-xxxx.json")
                else:
                    raw_ecosystems.append(path_parts[0])

            # Step 4: Robust Enterprise Normalization & Map Aggregation
            # Each increment here represents a localized database mutation (Activity Delta)
            for eco in raw_ecosystems:
                eco_clean = eco.strip()
                eco_lower = eco_clean.lower()
                
                if "ubuntu" in eco_lower:
                    final_leaderboard["Ubuntu"] += 1
                elif "debian" in eco_lower:
                    final_leaderboard["Debian"] += 1
                elif "alpine" in eco_lower:
                    final_leaderboard["Alpine Linux"] += 1
                elif "alpaquita" in eco_lower:
                    final_leaderboard["Alpaquita Linux"] += 1
                elif "azure linux" in eco_lower or "cbl-mariner" in eco_lower:
                    final_leaderboard["Azure Linux"] += 1
                elif "minimos" in eco_lower:
                    final_leaderboard["MinimOS"] += 1
                elif "android" in eco_lower:
                    final_leaderboard["Android"] += 1
                elif "maven" in eco_lower:
                    final_leaderboard["Maven (Java)"] += 1
                elif "packagist" in eco_lower:
                    final_leaderboard["Packagist (PHP)"] += 1
                elif eco_lower == "go" or "golang" in eco_lower:
                    final_leaderboard["Go (Golang)"] += 1
                elif "npm" in eco_lower:
                    final_leaderboard["npm"] += 1
                elif "pypi" in eco_lower:
                    final_leaderboard["PyPI"] += 1
                elif "bitnami" in eco_lower:
                    final_leaderboard["Bitnami"] += 1
                elif "chainguard" in eco_lower:
                    final_leaderboard["Chainguard"] += 1
                elif "echo" in eco_lower:
                    final_leaderboard["Echo"] += 1
                elif eco_lower == "git":
                    final_leaderboard["GIT"] += 1
                elif eco_clean in ["Untagged Commit Hash/CVE Noise", "OSV Global Meta-Records", "[EMPTY]", ""]:
                    final_leaderboard["Untagged Commit Hash/CVE Noise"] += 1
                else:
                    final_leaderboard[eco_clean] += 1

    except Exception as e:
        print(f"[-] Threat ledger stream disrupted: {e}")
        return

    # Build the final filtered list if arguments are supplied
    filtered_results = []
    for eco, count in final_leaderboard.items():
        layer = get_artifact_layer(eco)
        
        # Apply layer target formatting criteria
        if target_layer == "container" and layer != "Container Base Image":
            continue
        elif target_layer == "app" and layer != "App Software Registry":
            continue
            
        filtered_results.append((eco, count, layer))
        
    # Sort results by threat delta count descending
    filtered_results.sort(key=lambda x: x[1], reverse=True)

    if not filtered_results:
        print("[-] No valid delta records compiled for the selected filter.")
        return

    # Setup Dynamic Title
    title = "VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD"
    if target_layer == "container":
        title += " (CONTAINER BASE IMAGES ONLY)"
    elif target_layer == "app":
        title += " (APP SOFTWARE REGISTRIES ONLY)"

    print("\n" + "="*85)
    print(f"  {title} (LAST {days_delta} DAYS)")
    print("="*85)
    print(f"{'Rank':<5} | {'Ecosystem/Registry':<32} | {'Activity Delta':<14} | {'Artifact Layer'}")
    print("-"*85)
    
    # Render Top 10 rows cleanly
    for rank, (eco, count, layer) in enumerate(filtered_results[:10], 1):
        print(f"#{rank:<3} | {eco:<32} | {count:<14,} | {layer}")
        
    print("="*85)
    print(f"Raw Entry Stream Items:    {total_raw_rows:,}")
    print(f"Ecosystem Attributions:    {sum(count for _, count, _ in filtered_results):,}")
    print("[*] Dashboard Interpretation Guide: Activity Delta = Upstream Registry Churn / Patch Volume.")
    print("    This does NOT measure raw external intrusion attempts against company infrastructure.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSV Threat Stream Campaign Dashboard Indicator.")
    parser.add_argument(
        "--layer", 
        choices=["container", "app"], 
        help="Isolate the dashboard layout by specific infrastructure layer types ('container' or 'app')."
    )
    parser.add_argument(
        "--days", 
        type=int, 
        default=30, 
        help="Lookback delta threshold window size in days (default: 30)."
    )
    
    args = parser.parse_args()
    generate_enterprise_threat_leaderboard(days_delta=args.days, target_layer=args.layer)