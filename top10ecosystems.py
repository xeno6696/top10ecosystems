#!/usr/bin/env python3
# Copyright (C) 2026 xeno6696
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
OSV Threat Stream Campaign Dashboard Indicator - Version 1.2
=================================================================================
A security engineering tool designed to track software supply chain fluctuations 
by aggregating upstream vulnerability mutations from the Open Source Vulnerability 
(OSV) database and cross-referencing strict local project manifest pins.
"""

import csv
import datetime
import json
import os
import sys
import time
import zipfile
import argparse
import re
from collections import Counter
import requests
from cvss import CVSS2, CVSS3, CVSS4
import plotext as pltx
import matplotlib
matplotlib.use('Agg') # CRITICAL for headless servers
import matplotlib.pyplot as mplplt
import numpy as np
import io
import base64

# ANSI Color Codes for Scannable Shell Output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ==============================================================================
# GLOBAL METADATA & ARTIFACT ROUTING LAYER
# ==============================================================================

def get_artifact_layer(eco_name):
    """Buckets ecosystems into their proper architectural tracking layers."""
    container_images = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    app_registries = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]
    if eco_name in container_images: return "Container Base Image"
    elif eco_name in app_registries: return "App Software Registry"
    elif eco_name == "GIT": return "Source Control (SCM)"
    return "Global Baseline Noise"

def extract_cvss_score(vuln_data):
    """Parses OSV severity vectors using the official FIRST cvss library."""
    vuln_id = vuln_data.get("id", "")
    if vuln_id.startswith("MAL-") or "malware" in json.dumps(vuln_data).lower():
        return 10.0
        
    severity_list = vuln_data.get("severity", [])
    if not severity_list: return 0.0
        
    for sev in severity_list:
        sev_type = sev.get("type", "")
        vector_str = sev.get("score", "")
        if not vector_str: continue
            
        try:
            if sev_type == "CVSS_V3" or "CVSS:3" in vector_str:
                return float(CVSS3(vector_str).base_score)
            elif sev_type == "CVSS_V4" or "CVSS:4" in vector_str:
                return float(CVSS4(vector_str).base_score)
            elif sev_type == "CVSS_V2" or "RUSTSEC" in vuln_id:
                return float(CVSS2(vector_str).base_score)
        except Exception: continue
            
    return 0.0

def run_data_health_check(id_to_meta):
    """Audits the GHSA lookup index for structural integrity."""
    malformed_count = 0
    health_log = []
    
    for vuln_id, data in id_to_meta.items():
        if not vuln_id or vuln_id == "N/A":
            malformed_count += 1
            health_log.append(f"Missing/Malformed ID: {data}")
            continue
            
        if not data.get("ecosystems"):
            health_log.append(f"Missing Ecosystem tag: {vuln_id}")
            malformed_count += 1
            
    if malformed_count > 0:
        print(f"\n{RED}[!] DATA HEALTH WARNING: {malformed_count} malformed records detected in the OSV index.{RESET}")
        for entry in health_log[:5]:
            print(f"    -> {entry}")
    else:
        print(f"[+] Data Health Check Passed: {len(id_to_meta):,} records verified.")

# ==============================================================================
# MODULAR PLUG-AND-PLAY DECOUPLED MANIFEST PARSERS (STRATEGY PATTERN)
# ==============================================================================

def parse_maven_dependency_tree(file_path: str) -> dict:
    """Extracts unique groupId:artifactId pairs mapped to pinned versions."""
    discovered_packages = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                clean_line = re.sub(r'^\[(?:INFO|WARNING|ERROR)\]\s*', '', clean_line)
                if not clean_line or ":" not in clean_line or clean_line.startswith("-"): continue
                if any(x in clean_line for x in ["Total time:", "Finished at:", "BUILD SUCCESS", "BUILD FAILURE"]): continue
                clean_line = clean_line.replace(" (optional)", "")
                if re.match(r'^[a-zA-Z0-9]', clean_line) and line_num < 10: continue

                illegal_maven_indicators = ["[", "]", "(", ")", "LATEST", "RELEASE", "SNAPSHOT"]
                if any(indicator in clean_line for indicator in illegal_maven_indicators):
                    print(f"\n{BOLD}{RED}[!] MAVEN TREE LINTING FAILURE (Line {line_num}):{RESET}")
                    print(f"    -> Offending Line: '{line.strip()}'")
                    sys.exit(1)
                
                parts = clean_line.split(":")
                if len(parts) >= 4:
                    raw_group = parts[0]
                    group_id = re.sub(r'^[\\|\s\+\-]+', '', raw_group).strip()
                    package_key = f"{group_id}:{parts[1].strip()}".lower().strip()
                    if package_key:
                        discovered_packages[package_key] = parts[3].strip()
                        
    except SystemExit: raise
    except Exception as e:
        print(f"[-] Error executing strict Maven tree parser strategy: {e}")
        sys.exit(1)
        
    return discovered_packages

def parse_cyclonedx_sbom(file_path: str) -> dict:
    """Extracts package names mapped to versions from a CycloneDX JSON SBOM."""
    discovered_packages = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
            for component in sbom_data.get("components", []):
                name = component.get("name")
                group = component.get("group")
                version = component.get("version", "").strip()
                if name:
                    full_name = f"{group}:{name}" if group else name
                    full_name_clean = full_name.strip().lower()
                    if not version or version in ["0.0.0", "latest", "snapshot"]:
                        print(f"\n{BOLD}{RED}[!] SBOM LINTING FAILURE:{RESET}")
                        sys.exit(1)
                    discovered_packages[full_name_clean] = version
    except SystemExit: raise
    except Exception as e:
        print(f"[-] Error executing strict CycloneDX JSON strategy: {e}")
        sys.exit(1)
    return discovered_packages

def parse_pypi_requirements(file_path: str) -> dict:
    """Extracts exact package names mapped to pinned versions, rejecting dynamic operators."""
    discovered_packages = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("-r"): continue
                
                illegal_operators = [">=", "<=", ">", "<", "~=", "!="]
                if any(op in clean_line for op in illegal_operators):
                    print(f"\n{BOLD}{RED}[!] Configuration Error{RESET}")
                    sys.exit(1)
                
                parts = clean_line.split("==")
                package_name = parts[0].strip().lower().replace('_', '-')
                version_pin = "0.0.0"
                if len(parts) > 1:
                    version_pin = parts[1].split(";")[0].split("#")[0].strip()
                if package_name:
                    discovered_packages[package_name] = version_pin
    except SystemExit: raise
    except Exception as e:
        print(f"[-] Error executing strict PyPI parser strategy: {e}")
        sys.exit(1)
    return discovered_packages

MANIFEST_PARSER_REGISTRY = {
    "maven_tree": parse_maven_dependency_tree,
    "cyclonedx_json": parse_cyclonedx_sbom,
    "pypi_requirements": parse_pypi_requirements
}

def auto_sniff_manifest_strategy(file_path: str) -> str:
    if not os.path.exists(file_path): return None
    if file_path.endswith(".json"): return "cyclonedx_json"
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            sample = [f.readline() for _ in range(15)]
            for line in sample:
                if any(x in line for x in ["+-", "\\-", "|"]) and len(line.split(":")) >= 3:
                    return "maven_tree"
    except Exception: pass
    return "pypi_requirements"

# ==============================================================================
# DATABASE COMPILATION ENGINE
# ==============================================================================

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
            with open(local_zip_path, 'wb') as local_file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk: local_file.write(chunk)
            print(f"[+] Download complete. Saved to: {local_zip_path}")
        except Exception as e:
            print(f"[-] Download failed: {e}")
            if not os.path.exists(local_zip_path): return {}

    print("[*] Building global advisory memory index & profiling threat lifecycle states...")
    id_to_meta = {}
    try:
        with zipfile.ZipFile(local_zip_path) as z:
            for file_name in z.namelist():
                if file_name.endswith('.json'):
                    with z.open(file_name) as f:
                        try:
                            vuln_data = json.load(f)
                            if "withdrawn" in vuln_data: continue
                            vuln_id = vuln_data.get("id", "")
                            ecosystems = set()
                            has_fixes = False
                            is_malware = False
                            p_name = "N/A"
                            vuln_versions = set() 
                            
                            if vuln_id.startswith("MAL-") or "malicious" in file_name.lower(): is_malware = True
                            summary = vuln_data.get("summary", "").lower()
                            details = vuln_data.get("details", "").lower()
                            if "backdoor" in summary or "typosquat" in summary or "malicious package" in summary: is_malware = True

                            max_versions_found = 0
                            for affected in vuln_data.get("affected", []):
                                eco = affected.get("package", {}).get("ecosystem")
                                name = affected.get("package", {}).get("name")
                                if eco: ecosystems.add(eco)
                                if name: p_name = name.strip()
                                for v in affected.get("versions", []): vuln_versions.add(str(v).strip())
                                v_len = len(affected.get("versions", []))
                                if v_len > max_versions_found: max_versions_found = v_len
                                for ranges in affected.get("ranges", []):
                                    for events in ranges.get("events", []):
                                        if "fixed" in events: has_fixes = True
                            
                            published_str = vuln_data.get("published", "1970-01-01T00:00:00Z")
                            modified_str = vuln_data.get("modified", "1970-01-01T00:00:00Z")
                            dwell_days = 0.0
                            try:
                                p_dt = datetime.datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                                m_dt = datetime.datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                                dwell_days = max(0.0, (m_dt - p_dt).days)
                            except ValueError: pass

                            is_new_entry = (published_str == modified_str)
                            malware_vector = "Unclassified Malicious Payload"
                            if is_malware:
                                if "typosquat" in summary or "typosquat" in details: malware_vector = "Typosquatting / Brand Hijacking"
                                elif "dependency confusion" in summary or "dependency confusion" in details: malware_vector = "Dependency Confusion Campaign"
                                elif any(x in summary or x in details for x in ["exfiltrat", "token", "credential", "steal"]): malware_vector = "Data Exfiltration / Credential Stealer"
                                elif any(x in summary or x in details for x in ["reverse shell", "backdoor", "remote code"]): malware_vector = "Persistent Backdoor / Execution Shell"

                            if is_malware: classification = "Malware (New Entry)" if is_new_entry else "Malware (Incremental Update)"
                            elif has_fixes: classification = "Vulnerability Fix (New Entry)" if is_new_entry else "Vulnerability Fix (Update)"
                            else: classification = "Metadata Correction / Adjustments"

                            if vuln_id and ecosystems:
                                id_to_meta[vuln_id] = {
                                    "ecosystems": list(ecosystems),
                                    "package_name": p_name,
                                    "type": classification,
                                    "vector": malware_vector,
                                    "dwell_days": dwell_days,
                                    "blast_radius": max_versions_found,
                                    "vulnerable_versions": vuln_versions,
                                    "cvss_score": extract_cvss_score(vuln_data),
                                    "last_modified": modified_str[:10]
                                }
                        except json.JSONDecodeError: continue 
        print(f"[+] Successfully indexed {len(id_to_meta):,} global advisory mappings.")
    except Exception as e:
        print(f"[-] Failed to read master archive: {e}")
    return id_to_meta

# ==============================================================================
# CORE STREAM PROCESSING ENGINE
# ==============================================================================

def generate_enterprise_threat_leaderboard(
    start_date, end_date, target_layer: str = None, debug_mode: bool = False, 
    custom_export_arg=None, run_speedway: bool = False, project_file_path: str = None, 
    forced_format: str = None, audit_mode: bool = False, ghsa_lookup: dict = None
    ):
    now = datetime.datetime.now(datetime.timezone.utc)
    final_leaderboard = Counter()
    target_inventory_map = {} 
    is_project_mode = False
    allowed_project_ecosystems = []
    
    known_containers = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    known_registries = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]
    master_tracks = known_containers + known_registries + ["GIT", "Untagged Commit Hash/CVE Noise", "Android"]
    
    if target_layer == "app": final_leaderboard.update({k: 0 for k in known_registries})
    elif target_layer == "container": final_leaderboard.update({k: 0 for k in known_containers})
    else: final_leaderboard.update({k: 0 for k in master_tracks if k not in ["GIT", "Untagged Commit Hash/CVE Noise"]})

    manifest_target = project_file_path if project_file_path else (audit_mode if isinstance(audit_mode, str) else None)
    if manifest_target:
        strategy = forced_format if forced_format else auto_sniff_manifest_strategy(manifest_target)
        if strategy and strategy in MANIFEST_PARSER_REGISTRY:
            print(f"[*] Ingesting project manifest file using strategy profile: {strategy}...")
            target_inventory_map = MANIFEST_PARSER_REGISTRY[strategy](manifest_target)
            is_project_mode = True
            print(f"[+] Loaded {len(target_inventory_map)} project unique package tracking keys.")
            allowed_project_ecosystems = {"pypi_requirements": ["PyPI"], "maven_tree": ["Maven (Java)", "Maven"], "cyclonedx_json": ["npm", "PyPI", "Maven (Java)", "Maven", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems"]}.get(strategy, [])
        else:
            print(f"[-] Configuration Error: Unable to accurately parse layout structure for: {manifest_target}")
            sys.exit(1)

    if ghsa_lookup is None: ghsa_lookup = build_ghsa_ecosystem_map()
    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"   
    total_raw_rows = 0
    project_intercept_alerts = []

    bucket_counts = Counter({"Malware (New Entry)": 0, "Malware (Incremental Update)": 0, "Vulnerability Fix (New Entry)": 0, "Vulnerability Fix (Update)": 0, "Metadata Correction / Adjustments": 0})
    malware_vector_counts = Counter({"Typosquatting / Brand Hijacking": 0, "Dependency Confusion Campaign": 0, "Data Exfiltration / Credential Stealer": 0, "Persistent Backdoor / Execution Shell": 0, "Unclassified Malicious Payload": 0})
    speedway_counts = Counter() 

    spatial_dwell_malware = {k: [] for k in master_tracks}
    spatial_dwell_cve = {k: [] for k in master_tracks}
    spatial_blast_radius = {k: [] for k in master_tracks}
    ecosystem_outlier_pools = {k: {} for k in master_tracks}

    try:
        response = requests.get(manifest_url, stream=True, timeout=30)
        response.raise_for_status()
        lines = (line.decode('utf-8') for line in response.iter_lines())
        reader = csv.reader(lines)
        
        for row in reader:
            if not row: continue
            mod_time_str, path = row[0], row[1]
            mod_time = datetime.datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
            if mod_time > end_date: continue
            if mod_time < start_date: break # Critical path reverse-chronological loop break optimization
            
            speedway_counts[mod_time.hour] += 1 
            total_raw_rows += 1
            raw_ecosystems = []
            update_type = "Metadata Correction / Adjustments"
            current_vector = None
            current_id = "N/A"

            if ":" in path:
                parts = path.split(":")
                if len(parts) > 1:
                    current_id = parts[0].strip()
                    raw_ecosystems.append(parts[1].strip())
                    update_type = "Vulnerability Fix (Update)"
                else: raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
            else:
                path_parts = path.split('/')
                if len(path_parts) == 1 or path_parts[0].lower() in ['root', '']:
                    osv_id = path_parts[-1].replace(".json", "")
                    current_id = osv_id
                    if osv_id in ghsa_lookup:
                        raw_ecosystems.extend(ghsa_lookup[osv_id]["ecosystems"])
                        update_type = ghsa_lookup[osv_id]["type"]
                        if "Malware" in update_type: current_vector = ghsa_lookup[osv_id]["vector"]
                    else: raw_ecosystems.append("Untagged Commit Hash/CVE Noise")
                else:
                    raw_ecosystems.append(path_parts[0])
                    osv_id = path_parts[-1].replace(".json", "")
                    current_id = osv_id
                    if path_parts[0].lower() in ['npm', 'pypi'] and "mal-" in path_parts[-1].lower():
                        update_type = "Malware (New Entry)"
                        current_vector = ghsa_lookup.get(osv_id, {}).get("vector", "Unclassified Malicious Payload")
                    else: update_type = "Vulnerability Fix (Update)"

            for eco in raw_ecosystems:
                eco_raw = eco.strip()
                eco_lower = eco_raw.lower()
                hard_mappings = {"maven": "Maven (Java)", "go": "Go (Golang)", "packagist": "Packagist (PHP)", "git": "GIT", "crates.io": "Crates.io"}
                eco_clean = hard_mappings.get(eco_lower, None)
                if not eco_clean:
                    for track in master_tracks:
                        if eco_lower in track.lower() or track.lower() in eco_lower:
                            eco_clean = track
                            break
                if not eco_clean: eco_clean = "Android"

                if eco_clean == "Untagged Commit Hash/CVE Noise" and not debug_mode: continue

                layer = get_artifact_layer(eco_clean)
                if target_layer == "container" and layer != "Container Base Image": continue
                if target_layer == "app" and layer != "App Software Registry": continue

                if is_project_mode and current_id in ghsa_lookup:
                    m_name = ghsa_lookup[current_id]["package_name"].lower().strip()
                    if m_name in target_inventory_map:
                        if not allowed_project_ecosystems or eco_clean in allowed_project_ecosystems:
                            local_version = target_inventory_map[m_name]
                            vulnerable_versions_pool = ghsa_lookup[current_id].get("vulnerable_versions", set())
                            if local_version == "0.0.0" or local_version in vulnerable_versions_pool or not vulnerable_versions_pool:
                                project_intercept_alerts.append((current_id, ghsa_lookup[current_id]["package_name"], eco_clean, update_type))

                bucket_counts[update_type] += 1
                if "Malware" in update_type and current_vector: malware_vector_counts[current_vector] += 1
                if current_id in ghsa_lookup:
                    meta_entry = ghsa_lookup[current_id]
                    if "Malware" in update_type: spatial_dwell_malware[eco_clean].append(meta_entry["dwell_days"])
                    else: spatial_dwell_cve[eco_clean].append(meta_entry["dwell_days"])
                    spatial_blast_radius[eco_clean].append(meta_entry["blast_radius"])
                    if meta_entry["blast_radius"] > 0:
                        pool = ecosystem_outlier_pools[eco_clean]
                        if current_id not in pool or meta_entry["blast_radius"] > pool[current_id][0]:
                            pool[current_id] = (meta_entry["blast_radius"], update_type, meta_entry["package_name"], meta_entry.get("cvss_score", 0.0))
                final_leaderboard[eco_clean] += 1
    except Exception as e:
        print(f"[-] Threat ledger stream disrupted: {e}")
        return

    filtered_results = sorted([(e, c, get_artifact_layer(e)) for e, c in final_leaderboard.items() if e not in ["Untagged Commit Hash/CVE Noise", "GIT"]], key=lambda x: x[1], reverse=True)
    if is_project_mode:
        print("\n" + "="*95 + f"\n  {BOLD}LOCAL REPOSITORY INTERSECTION REPORT{RESET}\n" + "="*95)
        if project_intercept_alerts:
            print(f"{BOLD}{RED}[!] BREACH ALERT{RESET}\n" + "-"*95)
            print(f"{'Advisory ID':<22} | {'Package Name':<20} | {'Ecosystem/Registry':<22} | {'Threat Profile'}")
            print("-"*95)
            for r_id, p_name, eco, u_type in sorted(list(set(project_intercept_alerts)), key=lambda x: x[1]):
                print(f"{r_id:<22} | {p_name:<20} | {eco:<22} | {u_type}")
        else: print(f" {GREEN}[+] Clean Bill of Health: Zero active package mutations match your local manifest elements within this timeframe.{RESET}")
        print("="*95 + "\n")
        return

    print("\n" + "="*85 + f"\n  {BOLD}VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD{RESET}\n" + "="*85)
    print(f"{'Rank':<5} | {'Ecosystem/Registry':<32} | {'Activity Delta':<14} | {'Artifact Layer'}")
    print("-"*85)
    for rank, (eco, count, layer) in enumerate(filtered_results[:10], start=1):
        print(f"#{rank:<3} | {eco:<32} | {count:<14,} | {layer}")
    print("="*85)
    print(f"Raw Entry Stream Items:    {total_raw_rows:,}")
    print(f"Ecosystem Attributions:    {sum(count for _, count, _ in filtered_results):,}")

    print("\n" + "="*50 + f"\n  {BOLD}II. DATA ENRICHMENT: LAYER THREAT PROFILE{RESET}\n" + "="*50)
    for b_type in ["Malware (New Entry)", "Malware (Incremental Update)", "Vulnerability Fix (New Entry)", "Vulnerability Fix (Update)", "Metadata Correction / Adjustments"]:
        print(f"-> {b_type:<32} | {bucket_counts[b_type]:<6,} ({bucket_counts[b_type]/sum(bucket_counts.values())*100 if sum(bucket_counts.values())>0 else 0:.1f}%)")

    if sum(malware_vector_counts.values()) > 0:
        print("\n" + "="*50 + f"\n  {BOLD}III. DEEP DIVE: MALWARE ATTACK VECTOR ANALYSIS{RESET}\n" + "="*50)
        for vector_name, vector_count in malware_vector_counts.most_common():
            print(f"-> {vector_name:<38} | {vector_count:<4,} ({vector_count/sum(malware_vector_counts.values())*100:.1f}%)")

    # ---------------------------------------------------------
    # IV. ECOSYSTEM THREAT METABOLISM & SYSTEMIC BACKLOG MATRIX
    # ---------------------------------------------------------
    print("\n" + "="*115)
    print(f"  {BOLD}IV. ECOSYSTEM THREAT METABOLISM & SYSTEMIC BACKLOG MATRIX{RESET}")
    print("  * SLA Legend: Green <= 30d | Yellow 31-60d | Red > 60d")
    print("="*115)
    print(f"{'Ecosystem/Registry':<22} | {'Active TTR (Malware)':<20} | {'Active TTR (CVE)':<16} | {'Backlog Age (Top 10)':<22} | {'Avg Blast Radius'}")
    print("-" * 115)
    
    export_profile_matrix = {}
    active_matrix_ecosystems = [eco for eco, _, _ in filtered_results[:10]]
    for eco in active_matrix_ecosystems:
        m_list, c_list, r_list = spatial_dwell_malware.get(eco, []), spatial_dwell_cve.get(eco, []), spatial_blast_radius.get(eco, [])
        raw_avg_m = sum(m_list)/len(m_list) if m_list else 0.0
        raw_avg_c = sum(c_list)/len(c_list) if c_list else 0.0
        raw_avg_r = sum(r_list)/len(r_list) if r_list else 0.0
        
        valid_eco_records = []
        for vuln_id, meta in ghsa_lookup.items():
            if eco in meta.get('ecosystems', []) and isinstance(vuln_id, str) and vuln_id.strip():
                meta_with_id = meta.copy()
                meta_with_id['injected_id'] = vuln_id
                valid_eco_records.append(meta_with_id)

        static_top_10 = sorted(valid_eco_records, key=lambda x: (-x['cvss_score'], -x['blast_radius']))[:10]
        backlog_ages = []
        for vuln in static_top_10:
            last_mod_str = vuln.get('last_modified', '1970-01-01')
            try:
                mod_date = datetime.datetime.strptime(last_mod_str, "%Y-%m-%d").date()
                backlog_ages.append(max(0, (end_date.date() - mod_date).days))
            except ValueError: pass
                
        avg_backlog_age = sum(backlog_ages) / len(backlog_ages) if backlog_ages else 0.0
        export_profile_matrix[eco] = {"avg_dwell_mal": raw_avg_m, "avg_dwell_cve": raw_avg_c, "avg_blast_radius": raw_avg_r, "avg_backlog_age": avg_backlog_age}
        
        def color_sla(days):
            if days <= 30: return f"{GREEN}{days:.1f} Days{RESET}"
            elif days <= 60: return f"{YELLOW}{days:.1f} Days{RESET}"
            return f"{RED}{days:.1f} Days{RESET}"
            
        m_raw = f"{raw_avg_m:.1f} Days" if m_list else "0.0 Days*"
        c_raw = f"{raw_avg_c:.1f} Days"
        b_raw = f"{avg_backlog_age:.1f} Days"
        m_padded = m_raw.ljust(20).replace(m_raw, color_sla(raw_avg_m) if m_list else f"{YELLOW}0.0 Days*{RESET}")
        c_padded = c_raw.ljust(16).replace(c_raw, color_sla(raw_avg_c))
        b_padded = b_raw.ljust(22).replace(b_raw, color_sla(avg_backlog_age) if backlog_ages else f"{GREEN}0.0 Days{RESET}")
        print(f"{eco:<22} | {m_padded} | {c_padded} | {b_padded} | {raw_avg_r:.1f} Versions")
        
    print("="*115)
    print(f"{YELLOW}* Note: 0.0 Days* indicates that zero advisory modifications occurred within the chronological lookback window.{RESET}")
    print("="*115 + "\n")

    print("\n" + "="*95 + f"\n  {BOLD}V. CRITICAL OUTLIER ATTACK SURFACE RADIUS POOLS{RESET}\n" + "="*95)
    export_outlier_manifests = {}
    for eco in active_matrix_ecosystems:
        pool = ecosystem_outlier_pools.get(eco, {})
        if pool:
            print(f"\n{BOLD}[+] {eco} Top Impact Outliers:{RESET}")
            print(f"    {'Rank':<5} | {'Advisory ID':<20} | {'Artifact Name':<28} | {'CVSS':<6} | {'Impact Blast Radius':<22} | {'Threat Profile'}")
            print(f"    {'-'*116}")
            flat_pool = [{"id": r_id, "radius": item[0], "type": item[1], "name": item[2], "cvss": item[3] if len(item) > 3 else 0.0} for r_id, item in pool.items()]
            full_sorted_pool = sorted(flat_pool, key=lambda x: (-x["cvss"], -x["radius"], x["id"]))
            export_outlier_manifests[eco] = {item["id"]: [item["radius"], item["type"], item["name"], item["cvss"]] for item in full_sorted_pool[:50]}
            for rank, item in enumerate(full_sorted_pool[:10], start=1):
                print(f"    #{rank:<2} | {item['id']:<20} | {item['name'][:25]:<28} | {item['cvss']:.1f} | {item['radius']:,} Vers | {item['type']}")
        else: export_outlier_manifests[eco] = {}

    if run_speedway and speedway_counts:
        print("\n" + "="*85 + f"\n  {BOLD}VI. SPEEDWAY THREAT STREAM VELOCITY (24-HOUR TRAFFIC DISTRIBUTION){RESET}\n" + "="*85)
        print(f" {'Hour (UTC)':<10} | {'Volume':<8} | {'Traffic Intensity'}")
        print("-" * 85)
        for hour in range(24):
            hits = speedway_counts.get(hour, 0)
            bar = "█" * int((hits / max(speedway_counts.values())) * 40) if hits > 0 else "|"
            print(f" {hour:02d}:00      | {hits:<8,} | {bar}")

    # ---------------------------------------------------------
    # VII. SYSTEMIC RISK VS. ACTIVE EXPOSURE (THE ATTENTION DEFICIT)
    # ---------------------------------------------------------
    print(f"\n{BOLD}VII. SYSTEMIC RISK VS. ACTIVE EXPOSURE (THE ATTENTION DEFICIT){RESET}")
    print("="*105)
    print(f"{'Ecosystem':<16} | {'Static Risk (Top 10 Global)':<32} | {'Artifact Name':<30} | {'Last Active'}")
    print("-" * 105)
    
    for eco in active_matrix_ecosystems:
        valid_eco_records = []
        for vuln_id, meta in ghsa_lookup.items():
            if eco in meta.get('ecosystems', []) and isinstance(vuln_id, str) and vuln_id.strip():
                meta_with_id = meta.copy()
                meta_with_id['injected_id'] = vuln_id
                valid_eco_records.append(meta_with_id)

        static_top_10 = sorted(valid_eco_records, key=lambda x: (-x['cvss_score'], -x['blast_radius']))[:10]
        for rank, vuln in enumerate(static_top_10, start=1):
            v_id = vuln['injected_id']
            p_name = vuln.get('package_name', 'Unknown')
            last_mod_str = vuln.get('last_modified', '1970-01-01')
            try:
                mod_date = datetime.datetime.strptime(last_mod_str, "%Y-%m-%d").date()
                days_dormant = max(0, (end_date.date() - mod_date).days)
                if days_dormant <= 30: status_display = f"{GREEN}{last_mod_str} ({days_dormant}d ago){RESET}"
                elif days_dormant <= 60: status_display = f"{YELLOW}{last_mod_str} ({days_dormant}d ago){RESET}"
                else: status_display = f"{RED}{last_mod_str} ({days_dormant}d ago){RESET}"
            except ValueError: status_display = f"{RED}Invalid Date{RESET}"
            print(f"{eco:<16} | {f'#{rank:<2} {v_id}':<32} | {p_name[:27]:<30} | {status_display}")

    if custom_export_arg:
        output_dir = "./output"
        os.makedirs(output_dir, exist_ok=True)
        if isinstance(custom_export_arg, str): export_path = custom_export_arg
        else: export_path = os.path.join(output_dir, f"threat_landscape_{end_date.strftime('%Y-%m-%d')}_{target_layer if target_layer else 'all'}.json")

        os.makedirs(os.path.dirname(export_path) or ".", exist_ok=True)
        try:
            with open(export_path, 'w', encoding='utf-8') as ef:
                json.dump({
                    "metadata": {"generated_at": now.isoformat(), "interval_from": start_date.date().isoformat(), "interval_to": end_date.date().isoformat(), "target_layer_filter": target_layer if target_layer else "all"},
                    "leaderboard": {eco: count for eco, count, _ in filtered_results},
                    "threat_profile": dict(bucket_counts),
                    "malware_vectors": dict(malware_vector_counts) if sum(malware_vector_counts.values()) > 0 else {},
                    "profile_matrix": export_profile_matrix,
                    "outliers_leaderboards": export_outlier_manifests
                }, ef, indent=4)
            print(f"[Static Snapshot Saved]: {export_path}")
        except Exception as e: print(f"[-] Snapshot export write error: {e}")

def load_snapshots_from_dir(target_dir: str):
    snapshots = []
    if not os.path.isdir(target_dir): return snapshots
    for filename in os.listdir(target_dir):
        if not filename.endswith(".json"): continue
        try:
            with open(os.path.join(target_dir, filename), 'r', encoding='utf-8') as f:
                data = json.load(f)
                if "metadata" in data and "interval_to" in data["metadata"]: snapshots.append(data)
        except Exception: pass
    snapshots.sort(key=lambda x: x["metadata"]["interval_to"])
    return snapshots

def calculate_report_windows(args, now_utc):
    target_to_dates = " ".join(args.to).replace(",", " ").split() if args.to else [None]
    windows = []
    for date_str in target_to_dates:
        if date_str:
            parsed_date = None
            for fmt in ("%Y-%m-%d", "%m-%d-%Y", "%d-%m-%Y"):
                try:
                    parsed_date = datetime.datetime.strptime(date_str, fmt).date()
                    break
                except ValueError: continue
            if not parsed_date: continue
            calculated_end = datetime.datetime.combine(parsed_date, datetime.time.max, tzinfo=datetime.timezone.utc)
        else: calculated_end = now_utc

        if args.days: calculated_start = calculated_end - datetime.timedelta(days=args.days)
        elif args.from_date: calculated_start = datetime.datetime.combine(datetime.date.fromisoformat(args.from_date), datetime.time.min, tzinfo=datetime.timezone.utc)
        else: calculated_start = datetime.datetime(2026, 4, 18, 0, 0, 0, tzinfo=datetime.timezone.utc)
        windows.append((calculated_start, calculated_end))
    return windows

def build_snapshot_filename(start_date, end_date, target_layer=None):
    return f"{start_date.strftime('%d-%m-%y')}_to_{end_date.strftime('%d-%m-%y')}_{target_layer if target_layer else 'all'}.json"

def run_velocity_update(args):
    snapshot_dir = args.velocity or "./output"
    os.makedirs(snapshot_dir, exist_ok=True)
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    windows = calculate_report_windows(args, now_utc)
    global_ghsa_lookup = build_ghsa_ecosystem_map()
    
    for calculated_start, calculated_end in windows:
        snapshot_path = os.path.join(snapshot_dir, build_snapshot_filename(calculated_start, calculated_end, args.layer))
        generate_enterprise_threat_leaderboard(start_date=calculated_start, end_date=calculated_end, target_layer=args.layer, debug_mode=args.debug, custom_export_arg=snapshot_path, run_speedway=args.speedway, project_file_path=args.project_file, forced_format=args.project_format, audit_mode=args.audit, ghsa_lookup=global_ghsa_lookup)

    generate_velocity_matrix(target_dir=snapshot_dir, output_path=os.path.join(snapshot_dir, "velocity_matrix.csv"), render_terminal_plot=args.terminal_plot)
    snapshots = load_snapshots_from_dir(snapshot_dir)
    if snapshots: generate_html_report(snapshots, args.html if args.html else os.path.join(snapshot_dir, "briefing.html"))

def main(): 
    parser = argparse.ArgumentParser(description="OSV Threat Stream Campaign Dashboard Indicator.")
    parser.add_argument("--layer", choices=["container", "app"], help="Isolate by layer type.")
    parser.add_argument("--days", type=int, help="Lookback day window shortcut.")
    parser.add_argument("--from", metavar="YYYY-MM-DD", dest="from_date", help="Explicit chronological interval starting boundary.")
    parser.add_argument("--to", nargs='+', metavar="YYYY-MM-DD", help="Explicit chronological interval ending boundary.")
    parser.add_argument("--debug", action="store_true", help="Surface raw noise.")
    parser.add_argument("--export", nargs='?', const=True, default=False, help="Name or auto-generate JSON snapshot payload.")
    parser.add_argument("--compare", nargs=2, metavar=('BASE_JSON', 'CURRENT_JSON'), help="Compare two snapshots.")
    parser.add_argument("--speedway", action="store_true", help="Analyze traffic velocity distributions.")
    parser.add_argument("--project-file", metavar="PATH", help="Path to manifest or standard SBOM.")
    parser.add_argument("--project-format", choices=list(MANIFEST_PARSER_REGISTRY.keys()), help="Force manual schema parser selection.")
    parser.add_argument("--audit", metavar="MANIFEST_PATH", help="Direct lockfile ingestion.")
    parser.add_argument("--velocity", nargs="?", const="./output", metavar="DIR_PATH", help="Stitch snapshots into historical matrix.")
    parser.add_argument("--html", metavar="OUTPUT_FILE", help="Override briefing report output path.")
    parser.add_argument("--terminal-plot", action="store_true", help="Render velocity tracking inline layout.")
    args = parser.parse_args()

    if args.velocity:
        run_velocity_update(args)
        return
    if args.compare:
        compare_snapshots(file_base=args.compare[0], file_current=args.compare[1], html_output=args.html)
        return
    if args.html and not args.velocity and not args.compare:
        snapshots = load_snapshots_from_dir("./output")
        generate_html_report(snapshots, args.html)
        return

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    global_ghsa_lookup = build_ghsa_ecosystem_map()
    for calculated_start, calculated_end in calculate_report_windows(args, now_utc):
        generate_enterprise_threat_leaderboard(start_date=calculated_start, end_date=calculated_end, target_layer=args.layer, debug_mode=args.debug, custom_export_arg=args.export, run_speedway=args.speedway, project_file_path=args.project_file, forced_format=args.project_format, audit_mode=args.audit, ghsa_lookup=global_ghsa_lookup)

if __name__ == "__main__":
    main()