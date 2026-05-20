import zipfile
import json
from collections import Counter

def inspect_unmapped_meta_records(local_zip_path="./cache/osv_master_all.zip"):
    print("[*] Shaking down the Global Meta-Records bucket...")
    unmapped_ecosystems = Counter()
    
    # NEW TRACKING METRICS FOR MAVEN ASSESSMENT
    total_maven_records = 0
    maven_naming_formats = Counter()
    sample_maven_keys = []
    
    with zipfile.ZipFile(local_zip_path) as z:
        for file_name in z.namelist():
            if file_name.endswith('.json'):
                with z.open(file_name) as f:
                    try:
                        vuln_data = json.load(f)
                        
                        # Process all advisory records in the file
                        for affected in vuln_data.get("affected", []):
                            eco = affected.get("package", {}).get("ecosystem")
                            name = affected.get("package", {}).get("name")
                            
                            if eco == "Maven":
                                total_maven_records += 1
                                if name:
                                    # Profile if it uses a colon delimiter or is flat
                                    if ":" in name:
                                        maven_naming_formats["Unified Coordinate Format (group:artifact)"] += 1
                                        if len(sample_maven_keys) < 10:
                                            sample_maven_keys.append((vuln_data.get("id"), name))
                                    else:
                                        maven_naming_formats["Anomalous Flat Format (artifact only)"] += 1
                                        if len(sample_maven_keys) < 10:
                                            sample_maven_keys.append((vuln_data.get("id"), f"!!! {name}"))
                            
                            # Standard global ecosystem categorization tracking
                            if "GHSA-" in file_name or "CVE-" in file_name:
                                ecosystems = set()
                                for aff in vuln_data.get("affected", []):
                                    e = aff.get("package", {}).get("ecosystem")
                                    if e: ecosystems.add(e)
                                
                                if not ecosystems:
                                    unmapped_ecosystems["Pure Untagged Git/CVEs (No Ecosystem)"] += 1
                                else:
                                    for e in ecosystems:
                                        if not any(x in e.lower() for x in ["ubuntu", "debian", "npm", "pypi"]):
                                            unmapped_ecosystems[e] += 1
                    except Exception:
                        continue

    print("\n" + "="*65)
    print("  MAVEN UPSTREAM DATA ARCHITECTURE PROFILE")
    print("="*65)
    print(f"Total Evaluated Java Records: {total_maven_records:,}")
    print("-"*65)
    for fmt, count in maven_naming_formats.items():
        print(f"-> {fmt:<45} | {count:<10,}")
    
    print("\n[+] Direct Examples of Upstream String Formats (ID | Package Name):")
    print("-"*65)
    for v_id, p_name in sample_maven_keys:
        print(f"    {v_id:<20} | {p_name}")
    print("="*65)

    print("\n" + "="*50)
    print("  TOP HIDDEN ECOSYSTEMS INSIDE META-RECORDS")
    print("="*50)
    for eco, count in unmapped_ecosystems.most_common(15):
        print(f"{eco:<35} | {count:<10,}")
    print("="*50 + "\n")

if __name__ == "__main__":
    inspect_unmapped_meta_records()