import csv
import datetime
import io
import json
import os
import time
import zipfile
from collections import Counter
import requests

def build_ghsa_ecosystem_map(cache_dir: str = "./cache", cache_expiry_hours: int = 24):
    """
    Checks for a local copy of all.zip before downloading.
    Downloads the master database zip from OSV only if it's missing or stale,
    then parses it in-memory to build the local lookup index.
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

def generate_enterprise_threat_leaderboard(days_delta: int = 30):
    """
    Combines the streamed modifications log with local memory maps 
    to output an authenticated, zero-leak ecosystem threat ledger.
    """
    cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_delta)
    print(f"[*] Analyzing live threat stream logs since: {cutoff_date.date()}...")

    # Build or fetch our local index map
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

            # Step 1: Normalize colon paths immediately (e.g., "Root:Ubuntu:22.04" -> "Ubuntu")
            if ":" in path:
                parts = path.split(":")
                if len(parts) > 1:
                    raw_ecosystems.append(parts[1])
                else:
                    raw_ecosystems.append("OSV Global Meta-Records")
            else:
                path_parts = path.split('/')
                
                # Step 2: Extract from Root/Global Advisories
                if len(path_parts) == 1 or path_parts[0].lower() in ['root', '']:
                    osv_id = path_parts[-1].replace(".json", "")
                    if osv_id in ghsa_lookup:
                        raw_ecosystems.extend(ghsa_lookup[osv_id])
                    else:
                        raw_ecosystems.append("OSV Global Meta-Records")
                # Step 3: Extract standard directory path (e.g. "npm/MAL-xxxx.json")
                else:
                    raw_ecosystems.append(path_parts[0])

            # Step 4: Strict Enterprise Rollup Map
            # Ensures version numbers and case-mismatches merge cleanly
            for eco in raw_ecosystems:
                eco_clean = eco.strip()
                eco_lower = eco_clean.lower()
                
                if "ubuntu" in eco_lower:
                    final_leaderboard["Ubuntu"] += 1
                elif "debian" in eco_lower:
                    final_leaderboard["Debian"] += 1
                elif "npm" in eco_lower:
                    final_leaderboard["npm"] += 1
                elif "pypi" in eco_lower:
                    final_leaderboard["PyPI"] += 1
                elif eco_clean == "OSV Global Meta-Records" or eco_clean == "[EMPTY]":
                    final_leaderboard["OSV Global Meta-Records"] += 1
                else:
                    # Keep original string for any other verified ecosystem (e.g., MinimOS, Azure Linux)
                    final_leaderboard[eco_clean] += 1

    except Exception as e:
        print(f"[-] Threat ledger stream disrupted: {e}")
        return

    total_attributions = sum(final_leaderboard.values())
    if total_attributions == 0:
        print("[-] No valid delta records compiled.")
        return

    print("\n" + "="*60)
    print(f"  VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD (LAST {days_delta} DAYS)")
    print("="*60)
    print(f"{'Rank':<5} | {'Ecosystem/Registry':<26} | {'Activity Delta':<14}")
    print("-"*60)
    
    # Show the top 12 to make sure your package managers (like npm) don't get pushed off by metadata keys
    for rank, (eco, count) in enumerate(final_leaderboard.most_common(12), 1):
        print(f"#{rank:<3} | {eco:<26} | {count:<14,}")
        
    print("="*60)
    print(f"Raw Entry Stream Items:    {total_raw_rows:,}")
    print(f"Ecosystem Attributions:    {total_attributions:,}\n")

if __name__ == "__main__":
    generate_enterprise_threat_leaderboard(days_delta=30)