import csv
import datetime
import requests
from collections import Counter

def fetch_ecosystems_for_root_ids(osv_ids: list, batch_size: int = 1000) -> Counter:
    """
    Takes a massive list of root OSV IDs (like GHSAs) and uses the high-performance
    batch endpoint to resolve their true internal target ecosystems.
    """
    ecosystem_counts = Counter()
    total_ids = len(osv_ids)
    
    if not osv_ids:
        return ecosystem_counts

    print(f"[*] Resolving ecosystems for {total_ids:,} global/root advisories in batches of {batch_size}...")
    
    # Process IDs in chunks to avoid HTTP payload limits
    for i in range(0, total_ids, batch_size):
        chunk = osv_ids[i:i + batch_size]
        
        # Format the query according to the OSV querybatch spec
        # We query by ID to grab the structural details
        payload = {"queries": [{"id": uid} for uid in chunk]}
        
        try:
            # Using HTTP/2 or a persistent session is recommended for speed
            url = "https://api.osv.dev/v1/querybatch"
            res = requests.post(url, json=payload, timeout=30)
            res.raise_for_status()
            
            batch_data = res.json()
            results = batch_data.get("results", [])
            
            for entry in results:
                vulns = entry.get("vulnerabilities", [])
                for v in vulns:
                    # Look deep inside the affected object array for the ecosystem
                    for affected in v.get("affected", []):
                        package_info = affected.get("package", {})
                        eco = package_info.get("ecosystem")
                        if eco:
                            ecosystem_counts[eco] += 1
                            
        except Exception as e:
            print(f"[-] Batch query failure at chunk {i}-{i+batch_size}: {e}")
            continue
            
    return ecosystem_counts

def generate_accurate_leaderboard(days_delta: int = 30):
    """
    Streams OSV metrics and accurately attributes both folder-mapped and 
    root-mapped vulnerabilities to their real ecosystems.
    """
    cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_delta)
    print(f"[*] Gathering raw OSV update logs since: {cutoff_date.date()}...")

    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    
    final_ecosystems = Counter()
    root_ids_to_resolve = []
    total_raw_rows = 0

    # 1. Stream index and catalog targets
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
            path_parts = path.split('/')
            
            if len(path_parts) == 1:
                # It's a root file (e.g., "GHSA-xxxx-xxxx-xxxx.json")
                # Strip file extensions to isolate the raw ID string
                osv_id = path_parts[0].replace(".json", "")
                root_ids_to_resolve.append(osv_id)
            else:
                # Standard folder layout path (e.g., "npm/MAL-2024-123.json")
                final_ecosystems[path_parts[0]] += 1

    except Exception as e:
        print(f"[-] Manifest collection stream broke: {e}")
        return

    # 2. Extract real ecosystems from the root-level files
    if root_ids_to_resolve:
        root_mapping = fetch_ecosystems_for_root_ids(root_ids_to_resolve)
        final_ecosystems.update(root_mapping)

    # 3. Print the True Leaderboard
    total_attributions = sum(final_ecosystems.values())
    if total_attributions == 0:
        print("[-] Zero attributions compiled.")
        return

    print("\n" + "="*55)
    print(f"  ACCURATE ECOSYSTEM THREAT LEADERBOARD (LAST {days_delta} DAYS)")
    print("="*55)
    print(f"{'Rank':<5} | {'Ecosystem':<22} | {'Activity Delta':<14}")
    print("-"*55)
    
    for rank, (eco, count) in enumerate(final_ecosystems.most_common(10), 1):
        print(f"#{rank:<3} | {eco:<22} | {count:<14,}")
    print("="*55)
    print(f"Processed Raw Records: {total_raw_rows:,}")
    print(f"Total Unique Ecosystem Attributions: {total_attributions:,}\n")

if __name__ == "__main__":
    # Pulling metrics based on your 30-day window
    generate_accurate_leaderboard(days_delta=30)