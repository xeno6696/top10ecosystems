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
OSV Threat Stream Campaign Dashboard Indicator - Version 1.3
=================================================================================
A security engineering tool designed to track software supply chain fluctuations 
by aggregating upstream vulnerability mutations from the Open Source Vulnerability 
(OSV) database and cross-referencing strict local project manifest pins.
"""

# Standard Library Imports
import argparse
import base64
import csv
import datetime
import io
import json
import os
import re
import sqlite3
import sys
import time
import zipfile
from collections import Counter, defaultdict

# Third-Party Framework Imports
from cvss import CVSS2, CVSS3, CVSS4
import matplotlib
matplotlib.use('Agg')  # CRITICAL for headless servers
import matplotlib.pyplot as mplplt
import numpy as np
import plotext as pltx
import requests

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
                clean_line = re.sub(r'^\[(INFO|WARNING|ERROR)\]\s*', '', clean_line)
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


def build_ghsa_from_db(db_path: str = "database/threat_stream.db", target_registries: list = None) -> dict:
    """Queries the local SQLite warehouse to build a legacy-compatible memory lookup map."""
    id_to_meta = {}
    if not os.path.exists(db_path):
        return build_ghsa_ecosystem_map()
        
    filter_set = {r.strip().lower() for r in target_registries} if target_registries else None
    print(f"[*] Extracting global context from SQLite warehouse: {db_path}...")
    if filter_set:
        print(f"    -> Applying localized registry isolation filter: {list(filter_set)}")
        
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT advisory_id, package_name, cvss_score, blast_radius, threat_profile, ecosystems, last_modified, malware_vector, vulnerable_versions, dwell_days 
            FROM vulnerabilities
        """)
        
        for row in cursor.fetchall():
            v_id, p_name, cvss, radius, t_profile, ecos_json, last_mod, m_vector, v_versions_json, dwell_days = row
            ecosystems_list = json.loads(ecos_json) if ecos_json else ["Android"]
            
            # PERFORMANCE WIN: Early rejection exit prior to heavy allocations
            if filter_set:
                if not any(e.lower() in filter_set for e in ecosystems_list):
                    continue
            
            version_set = set(json.loads(v_versions_json)) if v_versions_json else set()
            id_to_meta[v_id] = {
                "ecosystems": ecosystems_list,
                "package_name": p_name,
                "type": t_profile,
                "vector": m_vector,
                "dwell_days": dwell_days,
                "blast_radius": radius,
                "vulnerable_versions": version_set,
                "cvss_score": cvss,
                "last_modified": last_mod
            }
        conn.close()
        print(f"[+] Successfully loaded {len(id_to_meta):,} records out of the SQLite warehouse index.")
    except Exception as e:
        print(f"[- ] Relational warehouse extraction failure: {e}. Falling back to ZIP.")
        return build_ghsa_ecosystem_map()
        
    return id_to_meta


# ==============================================================================
# CORE STREAM PROCESSING ENGINE
# ==============================================================================

def generate_enterprise_threat_leaderboard(
    start_date, end_date, target_layer: str = None, debug_mode: bool = False, 
    custom_export_arg=None, run_speedway: bool = False, project_file_path: str = None, 
    forced_format: str = None, audit_mode: bool = False, ghsa_lookup: dict = None,
    manifest_rows: list = None  
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

    # CRADLE: Build Ecosystem-Specific Absolute Rank Map
    ecosystem_archive_buckets = defaultdict(list)
    for advisory_id, advisory_data in ghsa_lookup.items():
        for raw_eco in advisory_data.get("ecosystems", []):
            eco_lower = raw_eco.lower().strip()
            hard_mappings = {"maven": "Maven (Java)", "go": "Go (Golang)", "packagist": "Packagist (PHP)", "git": "GIT", "crates.io": "Crates.io"}
            eco_clean = hard_mappings.get(eco_lower, None)
            if not eco_clean:
                for track in master_tracks:
                    if eco_lower in track.lower() or track.lower() in eco_lower:
                        eco_clean = track
                        break
            if not eco_clean: eco_clean = "Android"
            ecosystem_archive_buckets[eco_clean].append((advisory_id, advisory_data))

    eco_absolute_ranks = {}
    for eco_name, advisories in ecosystem_archive_buckets.items():
        sorted_bucket = sorted(
            advisories,
            key=lambda x: (
                -x[1].get("cvss_score", 0.0),
                -int(x[1].get("blast_radius", 0)),
                x[0]
            )
        )
        eco_absolute_ranks[eco_name] = {
            advisory_id: rank 
            for rank, (advisory_id, _) in enumerate(sorted_bucket, start=1)
        }

    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"   
    total_raw_rows = 0
    project_intercept_alerts = []

    bucket_counts = Counter({"Malware (New Entry)": 0, "Malware (Incremental Update)": 0, "Vulnerability Fix (New Entry)": 0, "Vulnerability Fix (Update)": 0, "Metadata Correction / Adjustments": 0})
    malware_vector_counts = Counter({"Typosquatting / Brand Hijacking": 0, "Dependency Confusion Campaign": 0, "Data Exfiltration / Credential Stealer": 0, "Persistent Backdoor / Execution Shell": 0, "Unclassified Malicious Payload": 0})

    spatial_dwell_malware = {k: [] for k in master_tracks}
    spatial_dwell_cve = {k: [] for k in master_tracks}
    spatial_blast_radius = {k: [] for k in master_tracks}
    ecosystem_outlier_pools = {k: {} for k in master_tracks}

    if manifest_rows is not None:
        reader = manifest_rows
    else:
        try:
            response = requests.get(manifest_url, stream=True, timeout=30)
            response.raise_for_status()
            lines = (line.decode('utf-8') for line in response.iter_lines())
            reader = list(csv.reader(lines))
        except Exception as e:
            print(f"[-] Threat ledger stream connection error: {e}")
            reader = []

    try:
        for row in reader:
            if not row: continue
            mod_time_str, path = row[0], row[1]
            mod_time = datetime.datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
            
            if mod_time > end_date or mod_time < start_date: 
                continue
            
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
        print(f"[-] Threat ledger stream disrupted during processing: {e}")
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
        eco_lower_matrix = eco.lower()
        for vuln_id, meta in ghsa_lookup.items():
            if any(raw_eco.lower() in eco_lower_matrix for raw_eco in meta.get('ecosystems', [])) and isinstance(vuln_id, str) and vuln_id.strip():
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
            w_rank, w_id, w_name, w_cvss, w_radius = 6, 36, 30, 6, 22
            print(f"    {'Rank':<{w_rank}} | {'Advisory ID / Rank':<{w_id}} | {'Artifact Name':<{w_name}} | {'CVSS':<{w_cvss}} | {'Impact Blast Radius':<{w_radius}} | {'Threat Profile'}")
            print(f"    {'-' * (w_rank + w_id + w_name + w_cvss + w_radius + 16)}")
            
            flat_pool = [{"id": r_id, "radius": item[0], "type": item[1], "name": item[2], "cvss": item[3] if len(item) > 3 else 0.0} for r_id, item in pool.items()]
            full_sorted_pool = sorted(flat_pool, key=lambda x: (-x["cvss"], -x["radius"], x["id"]))
            export_outlier_manifests[eco] = {item["id"]: [item["radius"], item["type"], item["name"], item["cvss"]] for item in full_sorted_pool[:50]}
            
            for rank, item in enumerate(full_sorted_pool[:10], start=1):
                local_eco_map = eco_absolute_ranks.get(eco, {})
                abs_eco_rank = local_eco_map.get(item['id'], "N/A")
                rank_val_str = f"{abs_eco_rank:,}" if isinstance(abs_eco_rank, int) else str(abs_eco_rank)
                overall_token = f"(#{rank_val_str} overall)"
                
                rank_str = f"#{rank}"
                id_column_display = f"{item['id']} {overall_token}"
                artifact_str = item['name'][:27]  
                cvss_str = f"{item['cvss']:.1f}"
                radius_str = f"{item['radius']:,} Vers"
                print(f"    {rank_str:<{w_rank}} | {id_column_display:<{w_id}} | {artifact_str:<{w_name}} | {cvss_str:<{w_cvss}} | {radius_str:<{w_radius}} | {item['type']}")
        else: export_outlier_manifests[eco] = {}

    print(f"\n{BOLD}VII. SYSTEMIC RISK VS. ACTIVE EXPOSURE (THE ATTENTION DEFICIT){RESET}")
    print("="*95)
    for eco in active_matrix_ecosystems:
        print(f"\n{BOLD}[+] Ecosystem/Registry Hierarchy: {eco}{RESET}")
        print("-" * 95)
        print(f"{'Static Risk (Top 10 Global)':<32} | {'Artifact Name':<30} | {'Last Active'}")
        print("-" * 95)
        
        valid_eco_records = []
        eco_lower_def = eco.lower()
        for vuln_id, meta in ghsa_lookup.items():
            if any(raw_eco.lower() in eco_lower_def for raw_eco in meta.get('ecosystems', [])) and isinstance(vuln_id, str) and vuln_id.strip():
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
            
            print(f"{f'#{rank:<2} {v_id}':<32} | {p_name[:27]:<30} | {status_display}")
        print("-" * 95)

    if custom_export_arg:
        output_dir = "./output"
        os.makedirs(output_dir, exist_ok=True)
        if isinstance(custom_export_arg, str): 
            export_path = custom_export_arg
        else: 
            export_path = os.path.join(output_dir, f"threat_landscape_{end_date.strftime('%Y-%m-%d')}_{target_layer if target_layer else 'all'}.json")

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
        except Exception as e: 
            print(f"{RED}[-] CRITICAL FILE EXPORT FAIL: {e}{RESET}")


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


def compare_snapshots(file_base: str, file_current: str, html_output: str = None):
    try:
        with open(file_base, 'r', encoding='utf-8') as f1, open(file_current, 'r', encoding='utf-8') as f2:
            base = json.load(f1)
            current = json.load(f2)
    except Exception as e:
        print(f"[-] Snapshot comparison failed. Error loading files: {e}")
        return

    print("\n" + "="*85)
    print(f"  {BOLD}SECURITY THREAT INTELLIGENCE STREAM MOVEMENT COMPARISON{RESET}")
    print("="*85)
    print(f"Base Document:    {file_base} (Generated: {base['metadata']['generated_at'][:10]})")
    print(f"Current Document: {file_current} (Generated: {current['metadata']['generated_at'][:10]})")
    print("="*85)

    known_clean_keys = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", 
                        "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL", "Debian", "Ubuntu", "MinimOS", 
                        "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "GIT",
                        "Android", "Untagged Commit Hash/CVE Noise"]

    sanitized_base_leaderboard = Counter()
    for eco, count in base["leaderboard"].items():
        clean_name = "Android" if eco not in known_clean_keys else eco
        sanitized_base_leaderboard[clean_name] += count

    sanitized_curr_leaderboard = Counter()
    for eco, count in current["leaderboard"].items():
        clean_name = "Android" if eco not in known_clean_keys else eco
        sanitized_curr_leaderboard[clean_name] += count

    base_sorted = sorted(sanitized_base_leaderboard.items(), key=lambda x: (x[1], x[0]), reverse=True)
    curr_sorted = sorted(sanitized_curr_leaderboard.items(), key=lambda x: (x[1], x[0]), reverse=True)

    base_rank_map = {item[0]: rank for rank, item in enumerate(base_sorted, 1) if item[1] > 0}
    curr_rank_map = {item[0]: rank for rank, item in enumerate(curr_sorted, 1) if item[1] > 0}

    print(f"\n{BOLD}I. ECOSYSTEM ACTIVITY & RANK SHIFTS (TOP 10):{RESET}")
    print("-"*95)
    print(f"{'Rank':<4} | {'Ecosystem / Registry':<26} | {'Base Vol':<10} | {'Current Vol':<12} | {'Volume Delta':<14} | {'Rank Shift'}")
    print("-"*95)

    all_ecosystems = sorted(
        list(set(sanitized_base_leaderboard.keys()).union(set(sanitized_curr_leaderboard.keys()))),
        key=lambda x: (sanitized_curr_leaderboard.get(x, 0), sanitized_base_leaderboard.get(x, 0)),
        reverse=True
    )
    
    top_10_ecos = all_ecosystems[:10]
    for current_rank, eco in enumerate(top_10_ecos, start=1):
        v1 = sanitized_base_leaderboard.get(eco, 0)
        v2 = sanitized_curr_leaderboard.get(eco, 0)
        v_diff = v2 - v1
        
        raw_v_str = f"{v_diff:+,}" if v_diff != 0 else "0"
        padded_v_str = f"{raw_v_str:>14}"
        
        if v_diff > 0: v_str = f"{GREEN}{padded_v_str}{RESET}"
        elif v_diff < 0: v_str = f"{RED}{padded_v_str}{RESET}"
        else: v_str = padded_v_str

        r1 = base_rank_map.get(eco, None)
        r2 = curr_rank_map.get(eco, None)
        
        if r1 and r2:
            r_diff = r1 - r2
            if r_diff > 0: r_str = f"{GREEN}Moved up {r_diff} spots ({r1} -> {r2}){RESET}"
            elif r_diff < 0: r_str = f"{RED}Moved down {abs(r_diff)} spots ({r1} -> {r2}){RESET}"
            else: r_str = f"No Change ({r2})"
        elif not r1 and r2: r_str = f"{GREEN}New Entry To Rank ({r2}){RESET}"
        elif r1 and not r2: r_str = f"{RED}Dropped Out of Active Rankings (Was {r1}){RESET}"
        else: r_str = "Inactive / Zero Activity Trace"

        print(f"#{current_rank:<3} | {eco:<26} | {v1:<10,} | {v2:<12,} | {v_str} | {r_str}")

    print(f"\n{BOLD}II. THREAT BEHAVIOR VARIANCE:{RESET}")
    print("-"*85)
    for category in base["threat_profile"].keys():
        b_count = base["threat_profile"].get(category, 0)
        c_count = current["threat_profile"].get(category, 0)
        diff = c_count - b_count
        
        raw_diff_str = f"{diff:+,}" if diff != 0 else "0"
        padded_diff_str = f"{raw_diff_str:>10}"
        
        if diff > 0: diff_str = f"{GREEN}{padded_diff_str}{RESET}"
        elif diff < 0: diff_str = f"{RED}{padded_diff_str}{RESET}"
        else: diff_str = padded_diff_str
            
        print(f"-> {category:<35} | Base: {b_count:<7,} | Current: {c_count:<7,} | Delta: {diff_str}")

    if base.get("malware_vectors") or current.get("malware_vectors"):
        print(f"\n{BOLD}III. MALWARE VECTOR ATTACK MATRIX SHIFTS:{RESET}")
        print("-"*85)
        all_vectors = sorted(list(set(base.get("malware_vectors", {}).keys()).union(set(current.get("malware_vectors", {}).keys()))))
        for vec in all_vectors:
            b_v = base.get("malware_vectors", {}).get(vec, 0)
            c_v = current.get("malware_vectors", {}).get(vec, 0)
            v_diff = c_v - b_v
            
            raw_v_diff_str = f"{v_diff:+,}" if v_diff != 0 else "0"
            padded_v_diff_str = f"{raw_v_diff_str:>10}"
            
            if v_diff > 0: v_diff_str = f"{GREEN}{padded_v_diff_str}{RESET}"
            elif v_diff < 0: v_diff_str = f"{RED}{padded_v_diff_str}{RESET}"
            else: v_diff_str = padded_v_diff_str
                
            print(f"-> {vec:<38} | Base: {b_v:<6,} | Current: {c_v:<6,} | Delta: {v_diff_str}")

    if "profile_matrix" in base and "profile_matrix" in current:
        print(f"\n{BOLD}IV. SPATIAL DWELL & BLAST RADIUS BASELINE SHIFTS:{RESET}")
        print("="*115)
        print(f"{'Ecosystem / Registry':<22} | {'Avg Dwell MAL Delta':<26} | {'Avg Dwell CVE Delta':<26} | {'Avg Blast Radius Delta'}")
        print("-"*115)
        
        for eco in sorted(list(set(base["profile_matrix"].keys()).union(set(current["profile_matrix"].keys())))):
            b_mat = base["profile_matrix"].get(eco, {"avg_dwell_mal": 0.0, "avg_dwell_cve": 0.0, "avg_blast_radius": 0.0})
            c_mat = current["profile_matrix"].get(eco, {"avg_dwell_mal": 0.0, "avg_dwell_cve": 0.0, "avg_blast_radius": 0.0})
            
            dm_base = b_mat.get("avg_dwell_mal", 0.0)
            dc_base = b_mat.get("avg_dwell_cve", 0.0)
            br_base = b_mat.get("avg_blast_radius", 0.0)
            
            dm_diff = c_mat["avg_dwell_mal"] - dm_base
            dc_diff = c_mat["avg_dwell_cve"] - dc_base
            br_diff = c_mat["avg_blast_radius"] - br_base
            
            def color_metric_string(diff, base_val, suffix, width_size):
                if ...: pass
                if abs(diff) < 0.05: diff = 0.0
                diff_str = f"{diff:+.1f}{suffix}" if diff != 0 else f"0.0{suffix}"
                raw_str = f"{diff_str:<12} (from {base_val:.1f})"
                padded_raw = f"{raw_str:<{width_size}}"
                if diff == 0.0: return padded_raw
                return f"{RED}{padded_raw}{RESET}" if diff > 0 else f"{GREEN}{padded_raw}{RESET}"

            dm_str = color_metric_string(dm_diff, dm_base, " Days", 26)
            dc_str = color_metric_string(dc_diff, dc_base, " Days", 26)
            br_str = color_metric_string(br_diff, br_base, " Vers", 26)
            print(f"{eco:<22} | {dm_str} | {dc_str} | {br_str}")
        print("="*115)
        
    if "outliers_leaderboards" in base and "outliers_leaderboards" in current:
        print(f"\n{BOLD}V. CRITICAL OUTLIER ATTACK SURFACE RADIUS POOLS VARIANCE ANALYSIS:{RESET}")
        print("="*156)
        
        for eco in sorted(list(current["outliers_leaderboards"].keys())):
            base_pool = base["outliers_leaderboards"].get(eco, {})
            curr_pool = current["outliers_leaderboards"].get(eco, {})
            if not base_pool and not curr_pool: continue
                
            print(f"\n{BOLD}[+] {eco} Outlier Tracking Shifts (Top 10):{RESET}")
            w_rank, w_id, w_name, w_cvss, w_impact, w_delta = 5, 28, 28, 6, 16, 18
            print(f"    {'Rank':<{w_rank}} | {'Advisory ID':<{w_id}} | {'Artifact Name':<{w_name}} | {'CVSS':<{w_cvss}} | {'Current Impact':<{w_impact}} | {'Impact Delta':<{w_delta}} | {'Rank Shift'}")
            print(f"    {'-'*150}")
            
            base_mapped = []
            for r_id, item in base_pool.items():
                score = item[3] if len(item) > 3 else 0.0
                base_mapped.append({"id": r_id, "radius": item[0], "type": item[1], "name": item[2], "cvss": score})
                
            curr_mapped = []
            for r_id, item in curr_pool.items():
                score = item[3] if len(item) > 3 else 0.0
                curr_mapped.append({"id": r_id, "radius": item[0], "type": item[1], "name": item[2], "cvss": score})
            
            base_sorted_pool = sorted(base_mapped, key=lambda x: (-x["cvss"], -x["radius"], x["id"]))
            curr_sorted_pool = sorted(curr_mapped, key=lambda x: (-x["cvss"], -x["radius"], x["id"]))
            
            base_ranks = {item["id"]: rank for rank, item in enumerate(base_sorted_pool, 1) if item["radius"] > 0}
            curr_ranks = {item["id"]: rank for rank, item in enumerate(curr_sorted_pool, 1) if item["radius"] > 0}
            
            sortable_pool = []
            all_advisories = set(base_pool.keys()).union(set(curr_pool.keys()))
            
            for r_id in all_advisories:
                b_item = next((x for x in base_sorted_pool if x["id"] == r_id), {"radius": 0, "name": "N/A", "cvss": 0.0})
                c_item = next((x for x in curr_sorted_pool if x["id"] == r_id), {"radius": 0, "name": "N/A", "cvss": 0.0})
                p_name = c_item["name"] if c_item["name"] != "N/A" else b_item["name"]
                c_score = c_item["cvss"] if c_item["cvss"] > 0.0 else b_item["cvss"]
                sortable_pool.append({"id": r_id, "name": p_name, "b_radius": b_item["radius"], "c_radius": c_item["radius"], "cvss": c_score})
                
            sorted_advisories = sorted(sortable_pool, key=lambda x: (-x["cvss"], -x["c_radius"], x["id"]))
            current_top_10 = sorted_advisories[:10]
            
            base_top_10_ids = {item["id"] for item in base_sorted_pool[:10]}
            curr_top_10_ids = {item["id"] for item in current_top_10}
            dropped_out_ids = base_top_10_ids - curr_top_10_ids
            dropped_out = [item for item in sorted_advisories if item["id"] in dropped_out_ids]
            
            has_shifts = False
            for rank, item in enumerate(current_top_10, 1):
                r_id = item["id"]
                p_name = item["name"]
                b_radius = item["b_radius"]
                c_radius = item["c_radius"]
                radius_diff = c_radius - b_radius
                
                if radius_diff > 0: raw_diff_str = f"+{radius_diff:,} Vers"
                elif radius_diff < 0: raw_diff_str = f"{radius_diff:,} Vers"
                else: raw_diff_str = "No Change"
                    
                b_rank = base_ranks.get(r_id)
                c_rank = curr_ranks.get(r_id)
                
                if b_rank and c_rank:
                    r_diff = b_rank - c_rank
                    if r_diff > 0: raw_r_str = f"Up {r_diff} ({b_rank}->{c_rank})"
                    elif r_diff < 0: raw_r_str = f"Down {abs(r_diff)} ({b_rank}->{c_rank})"
                    else: raw_r_str = "No Change"
                elif not b_rank and c_rank: raw_r_str = "New to Radar"
                else: raw_r_str = "-"
                    
                if radius_diff != 0 or (b_rank and c_rank and b_rank != c_rank) or (not b_rank and c_rank): has_shifts = True
                if radius_diff > 0: diff_display = f"{GREEN}{raw_diff_str:<{w_delta}}{RESET}"
                elif radius_diff < 0: diff_display = f"{RED}{raw_diff_str:<{w_delta}}{RESET}"
                else: diff_display = f"{raw_diff_str:<{w_delta}}"
                    
                if "Up" in raw_r_str or "New" in raw_r_str: r_display = f"{GREEN}{raw_r_str}{RESET}"
                elif "Down" in raw_r_str: r_display = f"{RED}{raw_r_str}{RESET}"
                else: r_display = raw_r_str
                    
                c_str = f"{c_radius:,} Vers"
                p_name_display = p_name[:25] + "..." if len(p_name) > 28 else p_name
                cvss_display = f"{item['cvss']:.1f}"
                print(f"    #{rank:<{w_rank-1}} | {r_id:<{w_id}} | {p_name_display:<{w_name}} | {cvss_display:<{w_cvss}} | {c_str:<{w_impact}} | {diff_display} | {r_display}")
                
            if dropped_out:
                print(f"    {'-'*150}")
                print(f"    {YELLOW}* The following advisories mitigated or dropped out of the {eco} Top 10:{RESET}")
                for item in dropped_out:
                    r_id = item['id']
                    b_rank = base_ranks.get(r_id, "N/A")
                    c_rank = curr_ranks.get(r_id, ">50") if item['c_radius'] > 0 else "Mitigated (0)"
                    p_name_display = item["name"][:25] + "..." if len(item["name"]) > 28 else item["name"]
                    print(f"      - {r_id:<20} | {p_name_display:<28} | Base Rank: #{b_rank:<3} -> Current Rank: {c_rank}")
                
            if not has_shifts and not dropped_out:
                print(f"    -> All tracked critical outlier thresholds remained static between snapshots.")
        print("="*156 + "\n")

    print(f"\n{BOLD}VI. RELATIVE CHURN VELOCITY (TERMINAL GRAPH){RESET}")
    print("="*85)
    print(f"{'Ecosystem / Registry':<26} | {'Delta':<10} | {'Visual Sparkline'}")
    print("-" * 85)
    
    max_abs_diff = max([abs(sanitized_curr_leaderboard.get(e, 0) - sanitized_base_leaderboard.get(e, 0)) for e in top_10_ecos] + [1])
    max_bar_width = 30
    
    for eco in top_10_ecos:
        v1 = sanitized_base_leaderboard.get(eco, 0)
        v2 = sanitized_curr_leaderboard.get(eco, 0)
        v_diff = v2 - v1
        
        bar_len = int((abs(v_diff) / max_abs_diff) * max_bar_width)
        bar_char = "█" * max(bar_len, 1) if v_diff != 0 else "|"
        
        if v_diff > 0: color, sign = GREEN, "+"
        elif v_diff < 0: color, sign = RED, ""
        else: color, sign = RESET, " "
            
        delta_str = f"{sign}{v_diff:,}"
        print(f"{eco:<26} | {delta_str:<10} | {color}{bar_char}{RESET}")

    if html_output:
        print(f"\n[*] Generating base64-embedded HTML comparison visualization...")
        try:
            b_vals = [sanitized_base_leaderboard.get(e, 0) for e in top_10_ecos]
            c_vals = [sanitized_curr_leaderboard.get(e, 0) for e in top_10_ecos]
            x = np.arange(len(top_10_ecos))
            width = 0.35
            
            fig1, ax1 = mplplt.subplots(figsize=(12, 5))
            ax1.bar(x - width/2, b_vals, width, label='Base Snapshot', color='#6c757d')
            ax1.bar(x + width/2, c_vals, width, label='Current Snapshot', color='#007bff')
            ax1.set_ylabel('Vulnerability Count')
            ax1.set_title('Ecosystem Vulnerability Delta (Base vs. Current)')
            ax1.set_xticks(x)
            ax1.set_xticklabels(top_10_ecos, rotation=45, ha='right')
            ax1.legend()
            mplplt.tight_layout()
            
            buf1 = io.BytesIO()
            fig1.savefig(buf1, format='png', bbox_inches='tight')
            buf1.seek(0)
            img_str_vol = base64.b64encode(buf1.read()).decode('utf-8')
            mplplt.close(fig1)

            dm_deltas, dc_deltas, br_deltas = [], [], []
            for eco in top_10_ecos:
                b_mat = base.get("profile_matrix", {}).get(eco, {"avg_dwell_mal": 0.0, "avg_dwell_cve": 0.0, "avg_blast_radius": 0.0})
                c_mat = current.get("profile_matrix", {}).get(eco, {"avg_dwell_mal": 0.0, "avg_dwell_cve": 0.0, "avg_blast_radius": 0.0})
                dm_deltas.append(c_mat.get("avg_dwell_mal", 0.0) - b_mat.get("avg_dwell_mal", 0.0))
                dc_deltas.append(c_mat.get("avg_dwell_cve", 0.0) - b_mat.get("avg_dwell_cve", 0.0))
                br_deltas.append(c_mat.get("avg_blast_radius", 0.0) - b_mat.get("avg_blast_radius", 0.0))

            fig2, axes = mplplt.subplots(1, 3, figsize=(15, 5), sharey=True)
            y_pos = np.arange(len(top_10_ecos))

            def plot_diverging(ax, data, title, xlabel):
                colors = ['#dc3545' if val > 0 else '#28a745' for val in data]
                ax.barh(y_pos, data, color=colors)
                ax.set_title(title)
                ax.set_xlabel(xlabel)
                ax.axvline(0, color='black', linewidth=1)
                ax.grid(axis='x', linestyle='--', alpha=0.7)

            plot_diverging(axes[0], dm_deltas, "Malware Dwell Delta", "Days")
            plot_diverging(axes[1], dc_deltas, "CVE Dwell Delta", "Days")
            plot_diverging(axes[2], br_deltas, "Blast Radius Delta", "Versions")
            axes[0].set_yticks(y_pos)
            axes[0].set_yticklabels(top_10_ecos)
            axes[0].invert_yaxis() 

            mplplt.tight_layout()
            buf2 = io.BytesIO()
            fig2.savefig(buf2, format='png', bbox_inches='tight')
            buf2.seek(0)
            img_str_div = base64.b64encode(buf2.read()).decode('utf-8')
            mplplt.close(fig2)
            
            html_report = f"""<!DOCTYPE html>
            <html>
            <head>
                <title>AppSec Threat Delta Report</title>
                <style>
                    body {{ background-color: #121212; color: #e0e0e0; font-family: sans-serif; padding: 40px; }}
                    .container {{ max-width: 1400px; margin: auto; background: #1e1e1e; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                    h1 {{ color: #ffffff; border-bottom: 1px solid #333; padding-bottom: 10px; }}
                    h2 {{ color: #bbbbbb; margin-top: 30px; font-weight: 300; }}
                    .chart {{ text-align: center; margin-top: 20px; background: #ffffff; padding: 15px; border-radius: 4px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>AppSec Threat Delta Report</h1>
                    <p><strong>Base Snapshot:</strong> {file_base} <br><strong>Current Snapshot:</strong> {file_current}</p>
                    <h2>I. Volume Shifts</h2>
                    <div class="chart">
                        <img src="data:image/png;base64,{img_str_vol}" alt="Volume Chart" style="max-width: 100%;" />
                    </div>
                    <h2>II. Spatial Dwell & Blast Radius Variance</h2>
                    <div class="chart">
                        <img src="data:image/png;base64,{img_str_div}" alt="Diverging Chart" style="max-width: 100%;" />
                    </div>
                </div>
            </body>
            </html>"""
            
            with open(html_output, "w", encoding="utf-8") as f: f.write(html_report)
            print(f"[+] HTML Comparison Report generated: {html_output}")
        except Exception as e:
            print(f"\n{RED}[!] Failed to generate HTML output: {e}{RESET}")

    print("="*85 + "\n")


# =====================================================================
# ADVANCED RESEARCH METRICS & RETRACTION AUDITING 
# =====================================================================

def display_all_time_retraction_stats(db_path="database/threat_stream.db"):
    """
    Computes global macro-distribution metrics and age brackets for all 
    withdrawn advisories relative to today's date.
    """
    if not os.path.exists(db_path):
        print(f"\n[!] Analytics Skipped: Target database missing at {db_path}")
        return

    # Establish explicit chronological boundary reference for today
    today = datetime.date(2026, 5, 28)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Extract raw structural metrics for all populated retractions
    cursor.execute("""
        SELECT advisory_id, withdrawn_date, dwell_days 
        FROM vulnerabilities 
        WHERE withdrawn_date IS NOT NULL
    """)
    rows = cursor.fetchall()
    conn.close()
    
    total_retracted = len(rows)
    if total_retracted == 0:
        print("\n[!] Zero retracted entries found in the relational schema index.")
        return

    # Define standard analytical age spreads (in days)
    brackets = [
        {"label": "< 1 Year",      "min_d": 0,          "max_d": 365},
        {"label": "1 - 3 Years",   "min_d": 365,        "max_d": 365 * 3},
        {"label": "3 - 5 Years",   "min_d": 365 * 3,    "max_d": 365 * 5},
        {"label": "5 - 10 Years",  "min_d": 365 * 5,    "max_d": 365 * 10},
        {"label": "10 - 15 Years", "min_d": 365 * 10,   "max_d": 365 * 15},
        {"label": "15+ Years",     "min_d": 365 * 15,   "max_d": 999999}
    ]
    
    # Initialize allocation grids
    retraction_counts = {b["label"]: 0 for b in brackets}
    vintage_counts = {b["label"]: 0 for b in brackets}
    
    # Compute chronological metrics across the raw rows
    for r_id, w_date_str, dwell_days in rows:
        try:
            w_date = datetime.datetime.strptime(w_date_str, "%Y-%m-%d").date()
        except ValueError:
            continue
            
        # Metric 1: Retraction Age (Time elapsed since withdrawal)
        days_since_retraction = (today - w_date).days
        
        # Metric 2: Historical Vintage (Time elapsed since original publication)
        pub_date = w_date - datetime.timedelta(days=int(dwell_days))
        total_advisory_age = (today - pub_date).days
        
        # Assign to matching retraction interval bracket
        for b in brackets:
            if b["min_d"] <= days_since_retraction < b["max_d"]:
                retraction_counts[b["label"]] += 1
                break
                
        # Assign to matching vintage interval bracket
        for b in brackets:
            if b["min_d"] <= total_advisory_age < b["max_d"]:
                vintage_counts[b["label"]] += 1
                break

    # Render Macro Consolidated Dashboard Report
    print(f"\n📊 GLOBAL ARCHIVE SUMMARY: ALL-TIME WITHDRAWN ADVISORY SPREAD")
    print(f"Total Relational Retraction Base: {total_retracted:,} Advisories")
    print("=" * 110)
    print(f"{'Age Bracket (From Today)':<25} | {'Retraction Volume':<20} | {'Retraction %':<14} | {'Vintage Volume':<16} | {'Vintage %'}")
    print("-" * 110)
    
    for b in brackets:
        label = b["label"]
        r_count = retraction_counts[label]
        v_count = vintage_counts[label]
        
        r_pct = (r_count / total_retracted) * 100
        v_pct = (v_count / total_retracted) * 100
        
        print(f"{label:<25} | {r_count:<20,} | {r_pct:<14.2f}% | {v_count:<16,} | {v_pct:.2f}%")
        
    print("=" * 110)

# =====================================================================
# ADVANCED RESEARCH METRICS & RETRACTION AUDITING 
# =====================================================================
def extract_suspicious_retractions(db_path="database/threat_stream.db", from_date=None, to_date=None, layer="all"):
    """
    Advanced context-aware research hunt engine for tracking contested 
    upstream advisory retractions with deep database schema telemetry.
    """
    if not os.path.exists(db_path):
        print(f"\n[!] Research Hunt Skipped: Warehouse database missing at {db_path}")
        return
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 🔬 INTERNALS AUTOPSY: Look past string labels straight to the column data
    print(f"\n[🔬 DEEP DIAGNOSTIC] Relational Warehouse Core Autopsy:")
    print("-" * 90)
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    print(f"    -> Total Ingested Dataset Rows:          {cursor.fetchone()[0]:,}")
    
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE withdrawn_date IS NOT NULL")
    withdrawn_col_count = cursor.fetchone()[0]
    print(f"    -> Rows with 'withdrawn_date' Populated: {withdrawn_col_count:,}")
    
    print(f"    -> Active Threat Profile String Distribution:")
    cursor.execute("SELECT threat_profile, COUNT(*) FROM vulnerabilities GROUP BY threat_profile")
    for profile, count in cursor.fetchall():
        print(f"       * '{profile}': {count:,} rows")
        
    if withdrawn_col_count > 0:
        cursor.execute("SELECT advisory_id, threat_profile, withdrawn_date FROM vulnerabilities WHERE withdrawn_date IS NOT NULL LIMIT 2")
        print(f"    -> Raw Column Sample Mapping:")
        for aid, prof, wdate in cursor.fetchall():
            print(f"       * ID: {aid} | Current Profile Field: '{prof}' | Withdrawn Date: {wdate}")
    print("-" * 90)
    
    KNOWN_CONTAINERS = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    KNOWN_REGISTRIES = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]
    
    # 💡 INSERTION 1: Added 'published_date' directly into the core SELECT template string
    query = """
        SELECT advisory_id, package_name, ecosystems, cvss_score, blast_radius, dwell_days, last_modified, published_date
        FROM vulnerabilities
        WHERE (threat_profile = 'Withdrawn / Retracted Advisory' OR withdrawn_date IS NOT NULL)
    """
    params = []
    
    if from_date and to_date:
        query += " AND last_modified BETWEEN ? AND ?"
        params.extend([from_date, to_date])
    elif from_date:
        query += " AND last_modified >= ?"
        params.append(from_date)
        
    print(f"\n🕵️‍♂️  OSV RETRACTION HUNT ACTIVE | Scope: Layer={layer.upper()}")
    print("=" * 145)
    # 💡 INSERTION 2: Re-aligned the console header line to accommodate 'First Seen' column bounds
    print(f"{'Advisory ID':<20} | {'Package Name':<25} | {'Ecosystems':<18} | {'CVSS':<5} | {'First Seen':<12} | {'Dwell (Days)':<12} | {'Last Mod'}")
    print("-"*145)
    
    cursor.execute(query + " ORDER BY dwell_days DESC, cvss_score DESC", params)
    
    hit_count = 0
    for row in cursor.fetchall():
        # 💡 INSERTION 3: Unpack the 8th 'pub_date' element out of the database fetch execution array
        v_id, p_name, ecos_json, cvss, radius, dwell, last_mod, pub_date = row
        ecos_list = json.loads(ecos_json) if ecos_json else []
        
        if layer == "app" and not any(e in KNOWN_REGISTRIES for e in ecos_list) and len(ecos_list) > 0:
            continue
        elif layer == "os" and not any(e in KNOWN_CONTAINERS for e in ecos_list) and len(ecos_list) > 0:
            continue
            
        ecos = ", ".join(ecos_list) if ecos_list else "⚠️ SCRUBBED BY UPSTREAM"
        p_name_display = p_name if p_name else "⚠️ Redacted Artifact"
        
        # 💡 INSERTION 4: Flag historical items with greater than 5 years (1,825 days) of shelf life
        flag = "🔥 DEEP HISTORICAL IMPORT" if dwell > 1825 else "ℹ️ Standard Dispute"
        cvss_display = f"{cvss:.1f}" if cvss and cvss > 0 else "N/A"
        
        # 💡 INSERTION 5: Updated print wrapper incorporating spatial formatting matching the layout headers
        print(f"{v_id:<20} | {p_name_display[:25]:<25} | {ecos[:18]:<18} | {cvss_display:<5} | {pub_date:<12} | {dwell:<12.1f} | {last_mod} [{flag}]")
        hit_count += 1
        if hit_count >= 10:
            break
            
    if hit_count == 0:
        print("    [+] Zero high-exposure retractions detected matching this specific scope query.")
        
    conn.close()
    print("=" * 145)
    """
    Advanced context-aware research hunt engine for tracking contested 
    upstream advisory retractions with deep database schema telemetry.
    """
    if not os.path.exists(db_path):
        print(f"\n[!] Research Hunt Skipped: Warehouse database missing at {db_path}")
        return
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # INTERNALS AUTOPSY: Look past string labels straight to the column data
    print(f"\n[🔬 DEEP DIAGNOSTIC] Relational Warehouse Core Autopsy:")
    print("-" * 90)
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    print(f"    -> Total Ingested Dataset Rows:          {cursor.fetchone()[0]:,}")
    
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE withdrawn_date IS NOT NULL")
    withdrawn_col_count = cursor.fetchone()[0]
    print(f"    -> Rows with 'withdrawn_date' Populated: {withdrawn_col_count:,}")
    
    print(f"    -> Active Threat Profile String Distribution:")
    cursor.execute("SELECT threat_profile, COUNT(*) FROM vulnerabilities GROUP BY threat_profile")
    for profile, count in cursor.fetchall():
        print(f"       * '{profile}': {count:,} rows")
        
    if withdrawn_col_count > 0:
        cursor.execute("SELECT advisory_id, threat_profile, withdrawn_date FROM vulnerabilities WHERE withdrawn_date IS NOT NULL LIMIT 2")
        print(f"    -> Raw Column Sample Mapping:")
        for aid, prof, wdate in cursor.fetchall():
            print(f"       * ID: {aid} | Current Profile Field: '{prof}' | Withdrawn Date: {wdate}")
    print("-" * 90)
    
    KNOWN_CONTAINERS = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    KNOWN_REGISTRIES = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]
    
    query = """
        SELECT advisory_id, package_name, ecosystems, cvss_score, blast_radius, dwell_days, last_modified
        FROM vulnerabilities
        WHERE (threat_profile = 'Withdrawn / Retracted Advisory' OR withdrawn_date IS NOT NULL)
    """
    params = []
    
    if from_date and to_date:
        query += " AND last_modified BETWEEN ? AND ?"
        params.extend([from_date, to_date])
    elif from_date:
        query += " AND last_modified >= ?"
        params.append(from_date)
        
    print(f"\n🕵️‍♂️  OSV RETRACTION HUNT ACTIVE | Scope: Layer={layer.upper()} | Window: {from_date or 'ANY'} -> {to_date or 'ANY'}")
    print("=" * 130)
    print(f"{'Advisory ID':<20} | {'Package Name':<35} | {'Ecosystems':<20} | {'CVSS':<5} | {'Dwell (Days)':<12} | {'Last Mod'}")
    print("-"*130)
    
    cursor.execute(query + " ORDER BY dwell_days DESC, cvss_score DESC", params)
    
    hit_count = 0
    for row in cursor.fetchall():
        v_id, p_name, ecos_json, cvss, radius, dwell, last_mod = row
        ecos_list = json.loads(ecos_json) if ecos_json else []
        
        if layer == "app" and not any(e in KNOWN_REGISTRIES for e in ecos_list) and len(ecos_list) > 0:
            continue
        elif layer == "os" and not any(e in KNOWN_CONTAINERS for e in ecos_list) and len(ecos_list) > 0:
            continue
            
        ecos = ", ".join(ecos_list) if ecos_list else "⚠️ SCRUBBED BY UPSTREAM"
        p_name_display = p_name if p_name else "⚠️ Redacted Artifact"
        flag = "🔥 SUSPICIOUS (CONTESTED)" if dwell >= 30 else "ℹ️ Disputed/Duplicate"
        cvss_display = f"{cvss:.1f}" if cvss and cvss > 0 else "N/A"
        
        print(f"{v_id:<20} | {p_name_display[:35]:<35} | {ecos[:20]:<20} | {cvss_display:<5} | {dwell:<12.1f} | {last_mod} [{flag}]")
        hit_count += 1
        if hit_count >= 10:
            break
            
    if hit_count == 0:
        print("    [+] Zero high-exposure retractions detected matching this specific scope query.")
        
    conn.close()
    print("=" * 130)


# =====================================================================
# CORE ENGINE COMMAND ORCHESTRATION LAYER
# =====================================================================

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
    parser.add_argument("--database", action="store_true", help="Query global advisory context from local SQLite3 warehouse instead of master ZIP archive.")
    parser.add_argument("--registry", type=str, help="Isolate evaluation strictly to a comma-separated registry array subset (e.g., --registry npm,PyPI,Maven (Java)).")
    parser.add_argument("--hunt-retracted", action="store_true", help="Execute an advanced research hunt for suspicious retracted advisories.")
    args = parser.parse_args()
    
    if args.hunt_retracted:
        if not args.database:
            parser.error("[!] The --hunt-retracted mechanism requires the --database relational engine active.")
        
        display_all_time_retraction_stats(db_path="database/threat_stream.db")
        extract_suspicious_retractions(
            db_path="database/threat_stream.db",
            from_date=args.from_date if hasattr(args, 'from_date') else None,
            to_date=args.to_date if hasattr(args, 'to_date') else None,
            layer=args.layer
        )
        return

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
    target_registries = [r.strip() for r in args.registry.split(",")] if args.registry else None
    if args.database:
        global_ghsa_lookup = build_ghsa_from_db(db_path="database/threat_stream.db", target_registries=target_registries)
    else:
        global_ghsa_lookup = build_ghsa_ecosystem_map()
    
    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
    print("[*] Staging upstream modification stream index into memory...")
    try:
        response = requests.get(manifest_url, timeout=30)
        response.raise_for_status()
        cached_manifest_rows = list(csv.reader(io.StringIO(response.text)))
        print(f"[+] Cached {len(cached_manifest_rows):,} mutation rows cleanly. Commencing generation pipeline.")
    except Exception as e:
        print(f"{YELLOW}[!] Failed to pre-fetch stream index: {e}. Falling back to individual live connections.{RESET}")
        cached_manifest_rows = None

    for calculated_start, calculated_end in calculate_report_windows(args, now_utc):
        print(f"\n[*] Executing Generation Profile for window ending: {calculated_end.date()}")
        generate_enterprise_threat_leaderboard(
            start_date=calculated_start, 
            end_date=calculated_end,
            target_layer=args.layer, 
            debug_mode=args.debug,
            custom_export_arg=args.export, 
            run_speedway=args.speedway,
            project_file_path=args.project_file, 
            forced_format=args.project_format,
            audit_mode=args.audit,
            ghsa_lookup=global_ghsa_lookup,
            manifest_rows=cached_manifest_rows  
        )


if __name__ == "__main__":
    main()