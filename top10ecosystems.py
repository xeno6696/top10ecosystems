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

def generate_enterprise_threat_leaderboard(days_delta: int = 30):
    """
    Combines streamed log updates with local memory mapping to map
    both folder-prefixed and root-level