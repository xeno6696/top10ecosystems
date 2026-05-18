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
            with open(local_zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk: f.write(chunk)
            print(f"[+] Download complete. Saved to: {local_zip_path}")
        except Exception as e:
            print(f"[-] Download failed: {e}")
            if not os.path.exists(local_zip_path): return {}

    print("[*] Building global advisory memory index from local archive...")
    id_to_ecosystems = {}
    try:
        with zipfile.ZipFile(local_zip_path) as z:
            for name in z.namelist():
                if name.endswith('.json'):
                    with z.open(name) as f:
                        try:
                            data = json.load(f)
                            v_id = data.get("id")
                            ecos = {a.get("package", {}).get("ecosystem") for a in data.get("affected", []) if a.get("package", {}).get("ecosystem")}
                            if v_id and ecos: id_to_ecosystems[v_id] = list(ecos)
                        except: continue
        print(f"[+] Successfully indexed {len(id_to_ecosystems):,} global advisory mappings.")
    except Exception as e:
        print(f"[-] Failed to parse zip: {e}")
    return id_to_ecosystems

def generate_enterprise_threat_leaderboard(days_delta: int = 30):
    cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_delta)
    print(f"[*] Analyzing live threat stream logs since: {cutoff_date.date()}...")
    ghsa_lookup = build_ghsa_ecosystem_map()
    
    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    final_leaderboard = Counter()
    total_raw_rows = 0

    try:
        res = requests.get(manifest_url, stream=True, timeout=30)
        res.raise_for_status()
        lines = (line.decode('utf-8') for line in res.iter_lines())
        reader = csv.reader(lines)
        
        for row in reader:
            if not row: continue
            mod_time = datetime.datetime.fromisoformat(row[0].replace("Z", "+00:00"))
            if mod_time < cutoff_date: break
            
            total_raw_rows += 1
            path = row[1]
            raw_ecosystems = []

            if ":" in path:
                parts = path.split(":")
                raw_ecosystems.append(parts[1] if len(parts) > 1 else "Untagged Commit Hash/CVE Noise")
            else:
                path_parts = path.split('/')
                if len(path_parts) == 1 or path_parts[0].lower() in ['root', '']:
                    osv_id = path_parts[-1].replace(".json", "")
                    if osv_id in ghsa_lookup: raw_ecosystems.extend(ghsa_lookup[osv_id])
                    else: raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
                else:
                    raw_ecosystems.append(path_parts[0])

            for eco in raw_ecosystems:
                eco_clean = eco.strip()
                eco_lower = eco_clean.lower()
                
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
                elif eco_clean in ["Untagged Commit Hash/CVE Noise", "OSV Global Meta-Records", "[EMPTY]", ""]:
                    final_leaderboard["Untagged Commit Hash/CVE Noise"] += 1
                else:
                    final_leaderboard[eco_clean] += 1

    except Exception as e:
        print(f"[-] Stream disrupted: {e}")
        return

    print("\n" + "="*60)
    print(f"  VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD (LAST {days_delta} DAYS)")
    print("="*60)
    print(f"{'Rank':<5} | {'Ecosystem/Registry':<26} | {'Activity Delta':<14}")
    print("-"*60)
    for rank, (eco, count) in enumerate(final_leaderboard.most_common(12), 1):
        print(f"#{rank:<3} | {eco:<26} | {count:<14,}")
    print("="*60)
    print(f"Raw Entry Stream Items:    {total_raw_rows:,}")
    print(f"Ecosystem Attributions:    {sum(final_leaderboard.values()):,}\n")

if __name__ == "__main__":
    generate_enterprise_threat_leaderboard(days_delta=30)
