import zipfile
import json
from collections import Counter

def inspect_unmapped_meta_records(local_zip_path="./cache/osv_master_all.zip"):
    print("[*] Shaking down the Global Meta-Records bucket to see what we missed...")
    unmapped_ecosystems = Counter()
    
    with zipfile.ZipFile(local_zip_path) as z:
        for file_name in z.namelist():
            if file_name.endswith('.json'):
                with z.open(file_name) as f:
                    try:
                        vuln_data = json.load(f)
                        
                        # We only care about what's inside the global/root advisories
                        # (The files that lack a clean folder layout in the stream)
                        if "GHSA-" in file_name or "CVE-" in file_name:
                            ecosystems = set()
                            for affected in vuln_data.get("affected", []):
                                eco = affected.get("package", {}).get("ecosystem")
                                if eco:
                                    ecosystems.add(eco)
                            
                            if not ecosystems:
                                unmapped_ecosystems["Pure Untagged Git/CVEs (No Ecosystem)"] += 1
                            else:
                                for eco in ecosystems:
                                    # Let's filter out what we ALREADY handle properly
                                    if not any(x in eco.lower() for x in ["ubuntu", "debian", "npm", "pypi"]):
                                        unmapped_ecosystems[eco] += 1
                    except Exception:
                        continue

    print("\n" + "="*50)
    print("  TOP HIDDEN ECOSYSTEMS INSIDE META-RECORDS")
    print("="*50)
    for eco, count in unmapped_ecosystems.most_common(15):
        print(f"{eco:<35} | {count:<10,}")
    print("="*50 + "\n")

if __name__ == "__main__":
    inspect_unmapped_meta_records()