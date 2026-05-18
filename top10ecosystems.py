import csv
import datetime
from collections import Counter
import requests

def generate_top_ecosystems_leaderboard(days_delta: int = 30):
    """
    Streams the OSV modified index, filters records within the delta window,
    and aggregates them to rank the top 10 most active software ecosystems.
    """
    # Calculate cutoff time based on delta days
    cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_delta)
    print(f"[*] Analyzing OSV data for the last {days_delta} days (Since: {cutoff_date.date()})...")

    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    
    # Track vulnerability mutations per ecosystem
    ecosystem_counts = Counter()
    total_processed = 0

    try:
        response = requests.get(manifest_url, stream=True, timeout=30)
        response.raise_for_status()
        
        # Stream lines to prevent massive memory overhead
        lines = (line.decode('utf-8') for line in response.iter_lines())
        reader = csv.reader(lines)
        
        for row in reader:
            if not row:
                continue
            
            mod_time_str, path = row[0], row[1]
            mod_time = datetime.datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
            
            # Since the file is reverse-chronological, stop when we pass the delta cutoff
            if mod_time < cutoff_date:
                break
            
            # The CSV path looks like: "npm/MAL-2024-123.json" or "PyPI/GHSA-xxx.json"
            # Extract the root folder, which represents the ecosystem name
            ecosystem = path.split('/')[0]
            ecosystem_counts[ecosystem] += 1
            total_processed += 1

    except Exception as e:
        print(f"[-] Error streaming manifest data: {e}")
        return

    if total_processed == 0:
        print("[-] No advisory records found within the specified time delta.")
        return

    # Print out the formatted Top 10 leaderboard
    print("\n" + "="*50)
    print(f"  TOP 10 MOST ACTIVE ECOSYSTEMS (LAST {days_delta} DAYS)")
    print("="*50)
    print(f"{'Rank':<5} | {'Ecosystem':<18} | {'Delta Mutations':<15} | {'Share'}")
    print("-"*50)
    
    for rank, (eco, count) in enumerate(ecosystem_counts.most_common(10), 1):
        percentage = (count / total_processed) * 100
        print(f"#{rank:<3} | {eco:<18} | {count:<15,} | {percentage:.2f}%")
    print("="*50 + f"\nTotal mutated entries analyzed: {total_processed:,}\n")

if __name__ == "__main__":
    # Adjust the lookback window here (e.g., 7 days, 30 days, 90 days)
    generate_top_ecosystems_leaderboard(days_delta=30)