import csv
import json
import os
import datetime
import top10ecosystems

def shrink_database():
    csv_path = os.path.join("src", "test", "resources", "frozen_modified_id.csv")
    out_path = os.path.join("src", "test", "resources", "frozen_lookup.json")
    
    if not os.path.exists(csv_path):
        print(f"[-] Missing {csv_path}. Please create the frozen CSV first.")
        return

    start_date = datetime.datetime(2026, 4, 18, tzinfo=datetime.timezone.utc)
    end_date = datetime.datetime(2026, 5, 22, tzinfo=datetime.timezone.utc)

    print("[*] 1. Scanning CSV for active time-window IDs...")
    needed_ids = set()
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row: continue
            try:
                mod_time = datetime.datetime.fromisoformat(row[0].replace("Z", "+00:00"))
                if mod_time < start_date or mod_time > end_date:
                    continue
            except ValueError: continue

            path = row[1]
            if ":" in path: needed_ids.add(path.split(":")[0].strip())
            else: needed_ids.add(path.split('/')[-1].replace(".json", ""))
                
    print(f"[+] Found {len(needed_ids)} advisories in the time window.")
    
    print("[*] 2. Parsing the live OSV archive cache...")
    full_lookup = top10ecosystems.build_ghsa_ecosystem_map()
    
    print("[*] 3. Executing deep purge of non-essential test data...")
    frozen_lookup = {}
    
    for k, v in full_lookup.items():
        if k not in needed_ids:
            continue
            
        # FILTER 1: Purge OS Noise. If it's not an App Registry, drop it.
        # (The main script's fallback parser will safely ignore these in the CSV anyway)
        is_app_layer = False
        for eco in v.get("ecosystems", []):
            if top10ecosystems.get_artifact_layer(eco) == "App Software Registry":
                is_app_layer = True
                break
                
        if not is_app_layer:
            continue
            
        # FILTER 2: Nuke the massive version string arrays to save disk space.
        if "vulnerable_versions" in v:
            v["vulnerable_versions"] = [] 
            
        frozen_lookup[k] = v
            
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(frozen_lookup, f, indent=2)
        
    print(f"[+] DONE. Stripped down to {len(frozen_lookup)} App-Layer records.")
    
    # Quick sanity check printout
    final_size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(f"[!] Final File Size: {final_size_mb:.2f} MB")

if __name__ == "__main__":
    shrink_database()