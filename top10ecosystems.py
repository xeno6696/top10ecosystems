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

                            # ARCHITECTURAL FIX: Use native datetime object date matching
                            is_new_entry = (p_dt.date() == m_dt.date())
                            
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


def print_section_i_leaderboard(filtered_results, total_raw_rows):
    """Renders Section I: The Verified Enterprise Ecosystem Leaderboard."""
    print("\n" + "="*85 + f"\n  {BOLD}VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD{RESET}\n" + "="*85)
    print(f"{'Rank':<5} | {'Ecosystem/Registry':<32} | {'Activity Delta':<14} | {'Artifact Layer'}")
    print("-"*85)
    for rank, (eco, count, layer) in enumerate(filtered_results[:10], start=1):
        print(f"#{rank:<3} | {eco:<32} | {count:<14,} | {layer}")
    print("=" * 85)
    print(f"Raw Entry Stream Items:    {total_raw_rows:,}")
    print(f"Ecosystem Attributions:    {sum(count for _, count, _ in filtered_results):,}")


def print_section_ii_layer_matrix(layer_bucket_counts):
    """Renders Section II: Architectural Layer Threat Matrix."""
    print("\n" + "="*65 + f"\n  {BOLD}II. DATA ENRICHMENT: ARCHITECTURAL LAYER THREAT MATRIX{RESET}\n" + "="*65)
    
    for layer_name, counts in sorted(layer_bucket_counts.items()):
        layer_total = sum(counts.values())
        if layer_total == 0: continue
        
        print(f"\n[+] Layer Perspective: {BOLD}{layer_name}{RESET} ({layer_total:,} attributions)")
        print("-" * 65)
        for b_type in ["Malware (New Entry)", "Malware (Incremental Update)", "Vulnerability Fix (New Entry)", "Vulnerability Fix (Update)", "Metadata Correction / Adjustments"]:
            c_val = counts.get(b_type, 0)
            pct = (c_val / layer_total * 100) if layer_total > 0 else 0.0
            print(f"  -> {b_type:<35} | {c_val:<6,} ({pct:.1f}%)")
    print("=" * 65 + "\n")


def print_section_iii_malware_vectors(malware_vector_counts):
    """Renders Section III: Malware Attack Vector Analysis."""
    if sum(malware_vector_counts.values()) > 0:
        print("\n" + "="*50 + f"\n  {BOLD}III. DEEP DIVE: MALWARE ATTACK VECTOR ANALYSIS{RESET}\n" + "="*50)
        for vector_name, vector_count in malware_vector_counts.most_common():
            print(f"-> {vector_name:<38} | {vector_count:<4,} ({vector_count/sum(malware_vector_counts.values())*100:.1f}%)")


def print_section_iv_threat_metabolism(active_matrix_ecosystems, spatial_dwell_malware, spatial_dwell_cve, spatial_blast_radius, ghsa_lookup, end_date, export_profile_matrix):
    """Renders Section IV: Ecosystem Threat Metabolism & Systemic Backlog Matrix."""
    print("\n" + "="*115)
    print(f"  {BOLD}IV. ECOSYSTEM THREAT METABOLISM & SYSTEMIC BACKLOG MATRIX{RESET}")
    print("  * SLA Legend: Green <= 30d | Yellow 31-60d | Red > 60d")
    print("="*115)
    print(f"{'Ecosystem/Registry':<22} | {'Active TTR (Malware)':<20} | {'Active TTR (CVE)':<16} | {'Backlog Age (Top 10)':<22} | {'Avg Blast Radius'}")
    print("-" * 115)
    
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


def print_section_v_outlier_pools(active_matrix_ecosystems, ecosystem_outlier_pools, eco_absolute_ranks, global_absolute_ranks, export_outlier_manifests):
    """Renders Section V: Critical Outlier Attack Surface Radius Pools."""
    print("\n" + "="*115)
    print(f"  {BOLD}V. CRITICAL OUTLIER ATTACK SURFACE RADIUS POOLS{RESET}")
    print("="*115)
    
    for eco in active_matrix_ecosystems:
        pool = ecosystem_outlier_pools.get(eco, {})
        if pool:
            print(f"\n{BOLD}[+] {eco} Top Impact Outliers:{RESET}")
            w_rank, w_id, w_name, w_cvss, w_radius = 6, 56, 22, 6, 22
            total_line_len = w_rank + w_id + w_name + w_cvss + w_radius + 16
            
            print(f"    {'Rank':<{w_rank}} | {'Advisory ID / Rank Tracking Matrix':<{w_id}} | {'Artifact Name':<{w_name}} | {'CVSS':<{w_cvss}} | {'Impact Blast Radius':<{w_radius}} | {'Threat Profile'}")
            print(f"    {'-' * total_line_len}")
            
            flat_pool = [{"id": r_id, "radius": item[0], "type": item[1], "name": item[2], "cvss": item[3] if len(item) > 3 else 0.0} for r_id, item in pool.items()]
            full_sorted_pool = sorted(flat_pool, key=lambda x: (-x["cvss"], -x["radius"], x["id"]))
            export_outlier_manifests[eco] = {item["id"]: [item["radius"], item["type"], item["name"], item["cvss"]] for item in full_sorted_pool[:50]}
            
            for rank, item in enumerate(full_sorted_pool[:10], start=1):
                local_eco_map = eco_absolute_ranks.get(eco, {})
                abs_eco_rank = local_eco_map.get(item['id'], "N/A")
                rank_val_str = f"{abs_eco_rank:,}" if isinstance(abs_eco_rank, int) else str(abs_eco_rank)
                
                true_global_rank = global_absolute_ranks.get(item['id'], "N/A")
                global_rank_str = f"{true_global_rank:,}" if isinstance(true_global_rank, int) else str(true_global_rank)
                
                overall_token = f"(#{rank_val_str} local / #{global_rank_str} overall)"
                
                rank_str = f"#{rank}"
                id_column_display = f"{item['id']} {overall_token}"
                artifact_str = item['name'][:19] + "..." if len(item['name']) > 22 else item['name']
                cvss_str = f"{item['cvss']:.1f}"
                radius_str = f"{item['radius']:,} Vers"
                print(f"    {rank_str:<{w_rank}} | {id_column_display:<{w_id}} | {artifact_str:<{w_name}} | {cvss_str:<{w_cvss}} | {radius_str:<{w_radius}} | {item['type']}")
        else: export_outlier_manifests[eco] = {}


def print_section_vi_new_arrivals(active_matrix_ecosystems, live_window_new_arrivals, ghsa_lookup, global_absolute_ranks):
    """Renders Section VI: New Arrivals & Campaign Discoveries Within Timeframe."""
    print(f"\n{BOLD}VI. NEW ARRIVALS & CAMPAIGN DISCOVERIES WITHIN TIMEFRAME{RESET}")
    print("=" * 115)
    
    for eco in active_matrix_ecosystems:
        print(f"\n{BOLD}[+] Ecosystem/Registry New Entries: {eco}{RESET}")
        print("-" * 115)
        print(f"{'New Threat Arrival Matrix':<52} | {'Artifact Name':<30} | {'Discovery Impact'}")
        print("-" * 115)
        
        new_window_records = []
        active_new_ids = live_window_new_arrivals.get(eco, set())
        
        for v_id in active_new_ids:
            if v_id in ghsa_lookup:
                meta = ghsa_lookup[v_id]
                meta_with_id = meta.copy()
                meta_with_id['injected_id'] = v_id
                new_window_records.append(meta_with_id)
            else:
                new_window_records.append({
                    'injected_id': v_id,
                    'package_name': 'Pending Catalog Compilation Index',
                    'cvss_score': 10.0 if v_id.startswith('MAL-') else 0.0,
                    'blast_radius': 0
                })

        top_new_arrivals = sorted(
            new_window_records, 
            key=lambda x: (-x['cvss_score'], -x['blast_radius'], x['injected_id'])
        )[:10]
        
        if top_new_arrivals:
            for rank, vuln in enumerate(top_new_arrivals, start=1):
                v_id = vuln['injected_id']
                p_name = vuln.get('package_name', 'Unknown')
                cvss = vuln.get('cvss_score', 0.0)
                
                abs_global_rank = global_absolute_ranks.get(v_id, "N/A")
                global_rank_str = f"{abs_global_rank:,}" if isinstance(abs_global_rank, int) else str(abs_global_rank)
                
                overall_token = f"({global_rank_str} overall)"
                id_column_display = f"#{rank:<2} {v_id} {overall_token}"
                
                severity_display = f"{RED}CRITICAL (CVSS {cvss:.1f}){RESET}" if cvss >= 9.0 else f"HIGH (CVSS {cvss:.1f})"
                print(f"{id_column_display:<52} | {p_name[:27]:<30} | {severity_display}")
        else:
            print("    [-] Zero newly published threat profiles or malicious entry drops recorded in this lookback window.")
        print("-" * 115)


def print_section_vii_attention_deficit(active_matrix_ecosystems, ghsa_lookup, global_absolute_ranks, end_date):
    """Renders Section VII: Systemic Risk Vs. Active Exposure (The Attention Deficit)."""
    print(f"\n{BOLD}VII. SYSTEMIC RISK VS. ACTIVE EXPOSURE (THE ATTENTION DEFICIT){RESET}")
    print("=" * 115)
    for eco in active_matrix_ecosystems:
        print(f"\n{BOLD}[+] Ecosystem/Registry Hierarchy: {eco}{RESET}")
        print("-" * 115)
        print(f"{'Static Risk Position Matrix':<52} | {'Artifact Name':<30} | {'Last Active'}")
        print("-" * 115)
        
        valid_eco_records = []
        eco_lower_def = eco.lower()
        for vuln_id, meta in ghsa_lookup.items():
            if any(raw_eco.lower() in eco_lower_def for raw_eco in meta.get('ecosystems', [])) and isinstance(vuln_id, str) and vuln_id.strip():
                meta_with_id = meta.copy()
                meta_with_id['injected_id'] = vuln_id
                valid_eco_records.append(meta_with_id)

        static_top_10 = sorted(
            valid_eco_records, 
            key=lambda x: (-x['cvss_score'], -x['blast_radius'], x['injected_id'])
        )[:10]
        
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
            
            abs_global_rank = global_absolute_ranks.get(v_id, "N/A")
            global_rank_str = f"{abs_global_rank:,}" if isinstance(abs_global_rank, int) else str(abs_global_rank)
            
            overall_token = f"({global_rank_str} overall)"
            id_column_display = f"#{rank:<2} {v_id} {overall_token}"
            print(f"{id_column_display:<52} | {p_name[:27]:<30} | {status_display}")
        print("-" * 115)


def print_section_viii_hardware_matrix(intel_feed_matrix):
    """Renders Section VIII: Hardware Architecture Compilation Cross-Pollination Matrix."""
    print("\n" + "="*115)
    print(f"  {BOLD}VIII. HARDWARE ARCHITECTURE COMPILATION CROSS-POLLINATION MATRIX (INTEL x86_64){RESET}")
    print("="*115)
    if not intel_feed_matrix:
        print("  [+] Zero explicit Intel/x86_64 architecture compile-target hooks detected in this execution frame.")
    else:
        print(f"{'Ecosystem / Registry Source':<30} | {'Total Intel Pulls':<18} | {'Malware Payloads':<18} | {'CVE Vulnerabilities':<20} | {'Max Blast Radius'}")
        print("-" * 115)
        for eco_source, counts in sorted(intel_feed_matrix.items(), key=lambda x: x[1]["total"], reverse=True):
            print(f"{eco_source:<30} | {counts['total']:<18,} | {counts['malware']:<18,} | {counts['cve']:<20,} | {counts['max_radius']:,} Versions")
    print("="*115 + "\n")


def serialize_snapshot_payload(custom_export_arg, now, start_date, end_date, target_layer, filtered_results, bucket_counts, layer_bucket_counts, intel_feed_matrix, malware_vector_counts, export_profile_matrix, export_outlier_manifests):
    """Handles snapshot backup serialization routines to disk schema layout."""
    if not custom_export_arg:
        return
        
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
                "metadata": {
                    "generated_at": now.isoformat(), 
                    "interval_from": start_date.date().isoformat(), 
                    "interval_to": end_date.date().isoformat(), 
                    "target_layer_filter": target_layer if target_layer else "all"
                },
                "leaderboard": {eco: count for eco, count, _ in filtered_results},
                "threat_profile": dict(bucket_counts),
                "layer_profile_matrix": {l: dict(c) for l, c in layer_bucket_counts.items()},
                "intel_architecture_matrix": {e: dict(c) for e, c in intel_feed_matrix.items()},
                "malware_vectors": dict(malware_vector_counts) if sum(malware_vector_counts.values()) > 0 else {},
                "profile_matrix": export_profile_matrix,
                "outliers_leaderboards": export_outlier_manifests
            }, ef, indent=4)
        print(f"[Static Snapshot Saved]: {export_path}")
    except Exception as e: 
        print(f"{RED}[-] CRITICAL FILE EXPORT FAIL: {e}{RESET}")

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

    # Build True Global Master Rank Map (Across All Rows)
    sorted_global_heap = sorted(
        ghsa_lookup.items(),
        key=lambda x: (-x[1].get("cvss_score", 0.0), -int(x[1].get("blast_radius", 0)), x[0])
    )
    global_absolute_ranks = {advisory_id: rank for rank, (advisory_id, _) in enumerate(sorted_global_heap, start=1)}

    # Build Ecosystem-Specific Absolute Rank Map
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
        sorted_bucket = sorted(advisories, key=lambda x: (-x[1].get("cvss_score", 0.0), -int(x[1].get("blast_radius", 0)), x[0]))
        eco_absolute_ranks[eco_name] = {advisory_id: rank for rank, (advisory_id, _) in enumerate(sorted_bucket, start=1)}

    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"   
    total_raw_rows = 0
    project_intercept_alerts = []

    bucket_counts = Counter({"Malware (New Entry)": 0, "Malware (Incremental Update)": 0, "Vulnerability Fix (New Entry)": 0, "Vulnerability Fix (Update)": 0, "Metadata Correction / Adjustments": 0})
    layer_bucket_counts = defaultdict(Counter)
    
    intel_feed_matrix = defaultdict(lambda: {"total": 0, "malware": 0, "cve": 0, "max_radius": 0})
    intel_sig_regex = re.compile(r'(x86|amd64|x64|intel|elf64|pe32|win-64|linux-64)', re.IGNORECASE)
    malware_vector_counts = Counter({"Typosquatting / Brand Hijacking": 0, "Dependency Confusion Campaign": 0, "Data Exfiltration / Credential Stealer": 0, "Persistent Backdoor / Execution Shell": 0, "Unclassified Malicious Payload": 0})

    spatial_dwell_malware = {k: [] for k in master_tracks}
    spatial_dwell_cve = {k: [] for k in master_tracks}
    spatial_blast_radius = {k: [] for k in master_tracks}
    ecosystem_outlier_pools = {k: {} for k in master_tracks}
    live_window_new_arrivals = defaultdict(set)

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
                    
                    # FIX #2: Consult the relational database to see if this is an all-new CVE discovery
                    if current_id in ghsa_lookup:
                        update_type = ghsa_lookup[current_id]["type"]
                    else:
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
                    else: 
                        # FIX #1 (Retained): Context lookup for standard slash-split entries
                        if osv_id in ghsa_lookup:
                            update_type = ghsa_lookup[osv_id]["type"]
                        else:
                            update_type = "Vulnerability Fix (Update)"

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
                layer_bucket_counts[layer][update_type] += 1
                
                if "New Entry" in update_type:
                    live_window_new_arrivals[eco_clean].add(current_id)

                is_intel_target = False
                p_name_check = ""
                blast_radius_val = 0
                
                if current_id in ghsa_lookup:
                    meta_ref = ghsa_lookup[current_id]
                    p_name_check = meta_ref.get("package_name", "")
                    blast_radius_val = meta_ref.get("blast_radius", 0)
                    if intel_sig_regex.search(p_name_check) or intel_sig_regex.search(meta_ref.get("vector", "")):
                        is_intel_target = True
                
                if not is_intel_target and intel_sig_regex.search(path):
                    is_intel_target = True
                    
                if is_intel_target:
                    metrics = intel_feed_matrix[eco_clean]
                    metrics["total"] += 1
                    metrics["max_radius"] = max(metrics["max_radius"], blast_radius_val)
                    if "Malware" in update_type: metrics["malware"] += 1
                    else: metrics["cve"] += 1
                
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

    # =========================================================================
    # SERIAL SEQUENTIAL EXECUTION LAYER (CONSOLIDATED ROUTER CALLS)
    # =========================================================================
    export_profile_matrix = {}
    export_outlier_manifests = {}
    active_matrix_ecosystems = [eco for eco, _, _ in filtered_results[:10]]

    # Run Dashboard Output Generations Serially
    print_section_i_leaderboard(filtered_results, total_raw_rows)
    print_section_ii_layer_matrix(layer_bucket_counts)
    print_section_iii_malware_vectors(malware_vector_counts)
    
    print_section_iv_threat_metabolism(
        active_matrix_ecosystems, spatial_dwell_malware, spatial_dwell_cve, 
        spatial_blast_radius, ghsa_lookup, end_date, export_profile_matrix
    )
    
    print_section_v_outlier_pools(
        active_matrix_ecosystems, ecosystem_outlier_pools, 
        eco_absolute_ranks, global_absolute_ranks, export_outlier_manifests
    )
    
    print_section_vi_new_arrivals(
        active_matrix_ecosystems, live_window_new_arrivals, 
        ghsa_lookup, global_absolute_ranks
    )
    
    print_section_vii_attention_deficit(
        active_matrix_ecosystems, ghsa_lookup, global_absolute_ranks, end_date
    )
    
    print_section_viii_hardware_matrix(intel_feed_matrix)
    
    # Save Snapshot Disk Serialization Routine
    serialize_snapshot_payload(
        custom_export_arg, now, start_date, end_date, target_layer, 
        filtered_results, bucket_counts, layer_bucket_counts, intel_feed_matrix, 
        malware_vector_counts, export_profile_matrix, export_outlier_manifests
    )

def generate_html_report(snapshots: list, html_output: str):
    """Generates a historical time-series AppSec trend dashboard from accumulated snapshot logs."""
    if not snapshots:
        print(f"{RED}[-] Report Generation Aborted: No valid snapshot data assets found in output directory.{RESET}")
        return

    print(f"[*] Compiling historical intelligence map from {len(snapshots)} chronological snapshot intervals...")

    # Extract dates and metrics across the historical track
    dates = []
    ecosystem_trends = defaultdict(list)
    threat_profile_trends = defaultdict(list)

    # Track structural target coordinates over time
    target_ecos = ["npm", "PyPI", "Go (Golang)", "Maven (Java)", "Packagist (PHP)", "Crates.io", "NuGet"]
    threat_categories = ["Malware (New Entry)", "Vulnerability Fix (Update)", "Metadata Correction / Adjustments"]

    for snap in snapshots:
        end_date = snap.get("metadata", {}).get("interval_to", "Unknown")
        dates.append(end_date)
        
        # Map leaderboard stats
        lboard = snap.get("leaderboard", {})
        for eco in target_ecos:
            ecosystem_trends[eco].append(lboard.get(eco, 0))
            
        # Map threat profile stats
        tprof = snap.get("threat_profile", {})
        for cat in threat_categories:
            threat_profile_trends[cat].append(tprof.get(cat, 0))

    try:
        # Chart 1: Ecosystem Volume Trajectory Over Time
        fig1, ax1 = mplplt.subplots(figsize=(12, 6))
        fig1.patch.set_facecolor('#1e1e1e')
        ax1.set_facecolor('#1e1e1e')
        
        for eco in target_ecos:
            if sum(ecosystem_trends[eco]) > 0:  
                ax1.plot(dates, ecosystem_trends[eco], marker='o', linewidth=2, label=eco)
        
        ax1.set_title("Ecosystem Cumulative Vulnerability Velocity Over Time", color='#ffffff', fontsize=14, pad=15)
        ax1.set_ylabel("Accumulated Stream Volume", color='#bbbbbb')
        ax1.set_xlabel("Snapshot Boundary Timeline", color='#bbbbbb')
        ax1.tick_params(colors='#bbbbbb', labelsize=10)
        ax1.grid(True, linestyle='--', alpha=0.15, color='#ffffff')
        ax1.legend(facecolor='#1e1e1e', edgecolor='#333333', labelcolor='#ffffff') # Fixed line
        mplplt.xticks(rotation=30, ha='right')
        mplplt.tight_layout()

        buf1 = io.BytesIO()
        fig1.savefig(buf1, format='png', bbox_inches='tight', facecolor=fig1.get_facecolor())
        buf1.seek(0)
        img_str_ecos = base64.b64encode(buf1.read()).decode('utf-8')
        mplplt.close(fig1)

        # Chart 2: Threat Profile Evolutionary Breakdown
        fig2, ax2 = mplplt.subplots(figsize=(12, 5))
        fig2.patch.set_facecolor('#1e1e1e')
        ax2.set_facecolor('#1e1e1e')
        
        for cat in threat_categories:
            if sum(threat_profile_trends[cat]) > 0:
                ax2.plot(dates, threat_profile_trends[cat], linestyle='--', marker='s', linewidth=2, label=cat)

        ax2.set_title("Threat Behavior Profile Structural Evolution", color='#ffffff', fontsize=14, pad=15)
        ax2.set_ylabel("Mutation Volume", color='#bbbbbb')
        ax2.set_xlabel("Snapshot Boundary Timeline", color='#bbbbbb')
        ax2.tick_params(colors='#bbbbbb', labelsize=10)
        ax2.grid(True, linestyle='--', alpha=0.15, color='#ffffff')
        ax2.legend(facecolor='#1e1e1e', edgecolor='#333333', labelcolor='#ffffff') # Fixed line
        mplplt.xticks(rotation=30, ha='right')
        mplplt.tight_layout()

        buf2 = io.BytesIO()
        fig2.savefig(buf2, format='png', bbox_inches='tight', facecolor=fig2.get_facecolor())
        buf2.seek(0)
        img_str_threats = base64.b64encode(buf2.read()).decode('utf-8')
        mplplt.close(fig2)

        # Construct Unified Dashboard Payload Doc
        html_report = f"""<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Supply Chain Threat Map Timeline</title>
    <style>
        body {{ background-color: #121212; color: #e0e0e0; font-family: sans-serif; padding: 40px; margin: 0; }}
        .container {{ max-width: 1400px; margin: auto; background: #1e1e1e; padding: 40px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); border: 1px solid #2d2d2d; }}
        h1 {{ color: #ffffff; border-bottom: 2px solid #333; padding-bottom: 15px; font-size: 28px; margin-top: 0; }}
        h2 {{ color: #007bff; margin-top: 40px; font-weight: 400; font-size: 20px; border-left: 4px solid #007bff; padding-left: 10px; }}
        p {{ color: #aaaaaa; font-size: 14px; line-height: 1.6; }}
        .meta-box {{ background: #151515; padding: 15px 20px; border-radius: 6px; border: 1px solid #252525; margin-bottom: 30px; }}
        .chart {{ text-align: center; margin-top: 25px; background: #1e1e1e; padding: 20px; border-radius: 8px; border: 1px solid #333; }}
        .chart img {{ max-width: 100%; height: auto; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Enterprise Supply Chain Threat Map Timeline</h1>
        <div class="meta-box">
            <p><strong>Timeline Scale Depth:</strong> {len(snapshots)} serialized intervals compiled</p>
            <p><strong>Historical Horizon Range:</strong> {dates[0]} &xrarr; {dates[-1]}</p>
            <p><strong>Dashboard Engine:</strong> AppSec Center of Excellence (COE) Analytics Warehouse v1.7</p>
        </div>
        
        <h2>I. Ecosystem Volume Trajectory over Time</h2>
        <p>Tracks the cumulative volume trajectory and discovery velocity across major software registry targets.</p>
        <div class="chart">
            <img src="data:image/png;base64,{img_str_ecos}" alt="Ecosystem Time Series Chart" />
        </div>
        
        <h2>II. Threat Behavior Profile Structural Evolution</h2>
        <p>Monitors how the composition of inbound mutations fluctuates over time between active malware injections, standard software security patches, and database metadata adjustments.</p>
        <div class="chart">
            <img src="data:image/png;base64,{img_str_threats}" alt="Threat Mutation Breakdown Chart" />
        </div>
    </div>
</body>
</html>"""

        with open(html_output, "w", encoding="utf-8") as f:
            f.write(html_report)
        print(f"{GREEN}[+] Historical Threat Map HTML Dashboard generated successfully: {html_output}{RESET}")

    except Exception as e:
        print(f"\n{RED}[!] Critical Failure generating timeline HTML asset: {e}{RESET}")

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

    # =========================================================================
    # 🎯 III. CHRONOLOGICAL ATTACK VECTOR DOMINANCE VELOCITY SHIFTS
    # =========================================================================
    if base.get("malware_vectors") or current.get("malware_vectors"):
        print(f"\n{BOLD}III. CHRONOLOGICAL ATTACK VECTOR DOMINANCE VELOCITY SHIFTS:{RESET}")
        print("-"*106)
        print(f"{'Attack Vector Mechanical Profile':<40} | {'Base Snapshot':<18} | {'Current Snapshot':<18} | {'Raw Delta':<12} | {'Dominance Shift'}")
        print("-"*106)
        
        b_mal_dict = base.get("malware_vectors", {})
        c_mal_dict = current.get("malware_vectors", {})
        
        b_total_mal = sum(b_mal_dict.values())
        c_total_mal = sum(c_mal_dict.values())
        
        all_vectors = sorted(list(set(b_mal_dict.keys()).union(set(c_mal_dict.keys()))))
        for vec in all_vectors:
            b_v = b_mal_dict.get(vec, 0)
            c_v = c_mal_dict.get(vec, 0)
            v_diff = c_v - b_v
            
            b_share = (b_v / b_total_mal * 100) if b_total_mal > 0 else 0.0
            c_share = (c_v / c_total_mal * 100) if c_total_mal > 0 else 0.0
            share_diff = c_share - b_share
            
            raw_diff_str = f"{v_diff:+,}" if v_diff != 0 else "0"
            padded_diff_str = f"{raw_diff_str:>10}"
            if v_diff > 0: v_diff_str = f"{GREEN}{padded_diff_str}{RESET}"
            elif v_diff < 0: v_diff_str = f"{RED}{padded_diff_str}{RESET}"
            else: v_diff_str = padded_diff_str
            
            share_diff_str = f"{share_diff:+.1f}%" if share_diff != 0.0 else "0.0%"
            padded_share_str = f"{share_diff_str:>14}"
            if share_diff > 0.05: share_str = f"{GREEN}{padded_share_str}{RESET}"
            elif share_diff < -0.05: share_str = f"{RED}{padded_share_str}{RESET}"
            else: share_str = padded_share_str
            
            base_display = f"{b_v:,} ({b_share:.1f}%)"
            curr_display = f"{c_v:,} ({c_share:.1f}%)"
            
            print(f"-> {vec:<37} | {base_display:<18} | {curr_display:<18} | {v_diff_str} | {share_str}")
        print("-"*106)

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
                print(f"    --> All tracked critical outlier thresholds remained static between snapshots.")
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
    print("="*85)

    # =========================================================================
    # 📊 VII. ARCHITECTURAL LAYER MUTATION VARIANCE BREAKOUT
    # =========================================================================
    if base.get("layer_profile_matrix") or current.get("layer_profile_matrix"):
        print(f"\n{BOLD}VII. ARCHITECTURAL LAYER MUTATION VARIANCE BREAKOUT:{RESET}")
        print("-" * 105)
        
        b_layers = base.get("layer_profile_matrix", {})
        c_layers = current.get("layer_profile_matrix", {})
        all_layers = sorted(list(set(b_layers.keys()).union(set(c_layers.keys()))))
        
        for layer_name in all_layers:
            b_counts = b_layers.get(layer_name, {})
            c_counts = c_layers.get(layer_name, {})
            
            if not b_counts and not c_counts: continue
            
            print(f"\n[+] Layer Mutation Group: {BOLD}{layer_name}{RESET}")
            print("-" * 105)
            print(f"  {'Threat Profile Classification Category':<37} | {'Base Vol':<10} | {'Current Vol':<12} | {'Volume Delta'}")
            print("  " + "-" * 103)
            
            for b_type in ["Malware (New Entry)", "Malware (Incremental Update)", "Vulnerability Fix (New Entry)", "Vulnerability Fix (Update)", "Metadata Correction / Adjustments"]:
                b_c = b_counts.get(b_type, 0)
                c_c = c_counts.get(b_type, 0)
                diff = c_c - b_c
                if b_c == 0 and c_c == 0: continue
                
                raw_diff_str = f"{diff:+,}" if diff != 0 else "0"
                padded_diff_str = f"{raw_diff_str:>12}"
                
                if diff > 0: diff_str = f"{GREEN}{padded_diff_str}{RESET}"
                elif diff < 0: diff_str = f"{RED}{padded_diff_str}{RESET}"
                else: diff_str = padded_diff_str
                
                print(f"  -> {b_type:<35} | {b_c:<10,} | {c_c:<12,} | {diff_str}")
        print("-" * 105 + "\n")

    # =========================================================================
    # 📊 VIII. HARDWARE ARCHITECTURE COMPILATION MATRIX VARIANCE ANALYSIS
    # =========================================================================
    if base.get("intel_architecture_matrix") or current.get("intel_architecture_matrix"):
        print(f"\n{BOLD}VIII. HARDWARE ARCHITECTURE COMPILATION MATRIX VARIANCE ANALYSIS:{RESET}")
        print("-" * 125)
        print(f"{'Ecosystem / Registry Source':<26} | {'Intel Pulls (Base->Curr)':<28} | {'Malware (Base->Curr)':<24} | {'CVEs (Base->Curr)':<24} | {'Max Blast Radius Shift'}")
        print("-" * 125)
        
        b_intel = base.get("intel_architecture_matrix", {})
        c_intel = current.get("intel_architecture_matrix", {})
        all_intel_ecos = sorted(list(set(b_intel.keys()).union(set(c_intel.keys()))))
        
        for eco in all_intel_ecos:
            b_m = b_intel.get(eco, {"total": 0, "malware": 0, "cve": 0, "max_radius": 0})
            c_m = c_intel.get(eco, {"total": 0, "malware": 0, "cve": 0, "max_radius": 0})
            
            t_diff = c_m.get("total", 0) - b_m.get("total", 0)
            m_diff = c_m.get("malware", 0) - b_m.get("malware", 0)
            v_diff = c_m.get("cve", 0) - b_m.get("cve", 0)
            r_diff = c_m.get("max_radius", 0) - b_m.get("max_radius", 0)
            
            t_delta = f"{t_diff:+,}" if t_diff != 0 else "0"
            t_padded = f"{b_m.get('total',0):,} -> {c_m.get('total',0):,} ({t_delta})".ljust(28)
            if t_diff > 0: t_padded = t_padded.replace(t_delta, f"{GREEN}{t_delta}{RESET}")
            elif t_diff < 0: t_padded = t_padded.replace(t_delta, f"{RED}{t_delta}{RESET}")
            
            m_delta = f"{m_diff:+,}" if m_diff != 0 else "0"
            m_padded = f"{b_m.get('malware',0):,} -> {c_m.get('malware',0):,} ({m_delta})".ljust(24)
            if m_diff > 0: m_padded = m_padded.replace(m_delta, f"{GREEN}{m_delta}{RESET}")
            elif m_diff < 0: m_padded = m_padded.replace(m_delta, f"{RED}{m_delta}{RESET}")
            
            v_delta = f"{v_diff:+,}" if v_diff != 0 else "0"
            v_padded = f"{b_m.get('cve',0):,} -> {c_m.get('cve',0):,} ({v_delta})".ljust(24)
            if v_diff > 0: v_padded = v_padded.replace(v_delta, f"{GREEN}{v_delta}{RESET}")
            elif v_diff < 0: v_padded = v_padded.replace(v_delta, f"{RED}{v_delta}{RESET}")
            
            r_raw = f"{r_diff:+,} Vers" if r_diff != 0 else "No Change"
            if r_diff > 0: r_str = f"{GREEN}{r_raw}{RESET} (from {b_m.get('max_radius', 0)})"
            elif r_diff < 0: r_str = f"{RED}{r_raw}{RESET} (from {b_m.get('max_radius', 0)})"
            else: r_str = f"{r_raw} (from {b_m.get('max_radius', 0)})"
            
            print(f"{eco:<26} | {t_padded} | {m_padded} | {v_padded} | {r_str}")
        print("-" * 125 + "\n")

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
            ax1.legend(facecolor='#1e1e1e', edgecolor='#333333', labelcolor='#ffffff')
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
    
    KNOWN_CONTAINERS = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    KNOWN_REGISTRIES = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]
    
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
        
    print(f"\n️‍♂️  OSV RETRACTION HUNT ACTIVE | Scope: Layer={layer.upper()}")
    print("=" * 145)
    print(f"{'Advisory ID':<20} | {'Package Name':<25} | {'Ecosystems':<18} | {'CVSS':<5} | {'First Seen':<12} | {'Dwell (Days)':<12} | {'Last Mod'}")
    print("-"*145)
    
    cursor.execute(query + " ORDER BY dwell_days DESC, cvss_score DESC", params)
    
    hit_count = 0
    for row in cursor.fetchall():
        v_id, p_name, ecos_json, cvss, radius, dwell, last_mod, pub_date = row
        ecos_list = json.loads(ecos_json) if ecos_json else []
        
        if layer == "app" and not any(e in KNOWN_REGISTRIES for e in ecos_list) and len(ecos_list) > 0:
            continue
        elif layer == "os" and not any(e in KNOWN_CONTAINERS for e in ecos_list) and len(ecos_list) > 0:
            continue
            
        ecos = ", ".join(ecos_list) if ecos_list else " SCRUBBED BY UPSTREAM"
        p_name_display = p_name if p_name else " Redacted Artifact"
        
        flag = " DEEP HISTORICAL IMPORT" if dwell > 1825 else "ℹ️ Standard Dispute"
        cvss_display = f"{cvss:.1f}" if cvss and cvss > 0 else "N/A"
        
        print(f"{v_id:<20} | {p_name_display[:25]:<25} | {ecos[:18]:<18} | {cvss_display:<5} | {pub_date:<12} | {dwell:<12.1f} | {last_mod} [{flag}]")
        hit_count += 1
        if hit_count >= 10:
            break
            
    if hit_count == 0:
        print("    [+] Zero high-exposure retractions detected matching this specific scope query.")
        
    conn.close()
    print("=" * 145)

def generate_ecosystem_trend_briefing(db_path: str, start_date, end_date, registry_target: str, manifest_rows: list):
    """
    Computes lookback trend metrics, mutation velocity spikes from live streams,
    and dormancy decay models using a standardized 115-character wide grid.
    """
    if not os.path.exists(db_path):
        print(f"{RED}[-] Trend Engine Aborted: Relational warehouse missing at {db_path}{RESET}")
        return

    if manifest_rows is None:
        print(f"{RED}[-] Trend Engine Aborted: Live stream modification rows missing.{RESET}")
        return

    # Phase 1: Aggregate stream mutation velocity out of the live log rows
    stream_mutation_counter = Counter()
    for row in manifest_rows:
        if not row: continue
        mod_time_str, path = row[0], row[1]
        try:
            mod_time = datetime.datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
            if start_date <= mod_time <= end_date:
                if ":" in path:
                    advisory_id = path.split(":")[0].strip()
                else:
                    advisory_id = path.split("/")[-1].replace(".json", "").strip()
                
                if advisory_id and advisory_id != "N/A":
                    stream_mutation_counter[advisory_id] += 1
        except ValueError: continue

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    start_str = start_date.strftime("%Y-%m-%d")
    relaxed_like_pattern = f"%{registry_target}%"
    
    print("\n" + "="*115)
    print(f"   IX. CHRONOLOGICAL LOOKBACK TREND ANALYTICS: {registry_target.upper()} REGISTRY")
    print("="*115)
    
    # -------------------------------------------------------------------------
    # 1. HIGH CHATTER ADVISORIES (TRUE STREAM VELOCITY)
    # -------------------------------------------------------------------------
    print(f"\n[+] High-Chatter Advisories (Top Mutation Velocity Spikes inside {registry_target}):")
    print("-" * 115)
    print(f"{'Advisory ID':<20} | {'Artifact Name':<25} | {'CVSS':<5} | {'Age':<8} | {'Modifications inside Window'}")
    print("-" * 115)
    
    resolved_chatter_hits = 0
    for adv_id, true_updates_count in stream_mutation_counter.most_common():
        if resolved_chatter_hits >= 10:
            break
            
        cursor.execute("""
            SELECT package_name, cvss_score, published_date 
            FROM vulnerabilities 
            WHERE advisory_id = ? AND ecosystems LIKE ?
        """, (adv_id, relaxed_like_pattern))
        
        db_match = cursor.fetchone()
        if db_match:
            p_name, cvss, pub_date_str = db_match
            
            age_str = "N/A"
            if pub_date_str:
                try:
                    pub_date = datetime.datetime.strptime(pub_date_str[:10], "%Y-%m-%d").date()
                    age_days = (end_date.date() - pub_date).days
                    age_str = f"{age_days}d"
                except ValueError:
                    pass

            print(f"{adv_id:<20} | {p_name[:25]:<25} | {cvss:<5.1f} | {age_str:<8} | {true_updates_count} updates")
            resolved_chatter_hits += 1
            
    if resolved_chatter_hits == 0:
        print("    [-] Zero active advisory mutations tracked within this lookback window boundary.")
    print("-" * 115)

    # -------------------------------------------------------------------------
    # 2. INTERNAL REGISTRY SEVERITY RANK SHIFTS (HARDCORE LEADERBOARD MOVEMENT)
    # -------------------------------------------------------------------------
    print(f"\n[+] Internal Registry Severity Rank Shifts (Leaderboard Velocity inside {registry_target}):")
    print("-" * 115)
    print(f"{'Catalog Rank':<14} | {'Advisory ID':<22} | {'Artifact Name':<28} | {'CVSS':<6} | {'Historical Movement'}")
    print("-" * 115)

    cursor.execute("""
        SELECT advisory_id, package_name, cvss_score, blast_radius, published_date
        FROM vulnerabilities
        WHERE ecosystems LIKE ? AND threat_profile NOT LIKE '%Withdrawn%'
    """, (relaxed_like_pattern,))
    all_repo_records = cursor.fetchall()

    # 1. Canonical deduplication for twin advisories (collapse GHSA / PYSEC pairs)
    vuln_clusters = {}
    for row in all_repo_records:
        adv_id, p_name, cvss, radius, pub_date = row
        cluster_key = (p_name.lower().strip(), cvss, radius)
        
        if cluster_key not in vuln_clusters:
            vuln_clusters[cluster_key] = row
        else:
            existing = vuln_clusters[cluster_key]
            earlier_pub = min(filter(None, [existing[4], pub_date]), default=existing[4])
            canonical_id = adv_id if adv_id.startswith("GHSA-") else existing[0]
            vuln_clusters[cluster_key] = (canonical_id, p_name, cvss, radius, earlier_pub)

    deduped_catalog = list(vuln_clusters.values())

    # 2. Current catalog ranking (All known items in registry)
    current_sorted = sorted(deduped_catalog, key=lambda x: (-x[2], -x[3], x[1].lower(), x[0]))
    current_rank_map = {row[0]: idx for idx, row in enumerate(current_sorted, start=1)}

    # 3. Historical catalog ranking (Items published strictly prior to start_date)
    historical_snapshot = [
        r for r in deduped_catalog 
        if r[4] and r[4][:10] < start_str
    ]
    historical_sorted = sorted(historical_snapshot, key=lambda x: (-x[2], -x[3], x[1].lower(), x[0]))
    historical_rank_map = {row[0]: idx for idx, row in enumerate(historical_sorted, start=1)}

    # 4. Evaluate the true Top 5 leaderboard positions (#1 through #5)
    top_5_leaderboard = current_sorted[:5]

    for c_rank, db_row in enumerate(top_5_leaderboard, start=1):
        adv_id, p_name, cvss, radius, pub_date = db_row
        
        # Check if this disclosure was first published within the active window
        is_new_arrival = (pub_date is not None and pub_date[:10] >= start_str)
        b_rank = historical_rank_map.get(adv_id, None)
        
        if is_new_arrival or b_rank is None:
            shift_display = f"{YELLOW}New Arrival (Entered at #{c_rank}){RESET}"
        elif b_rank == c_rank:
            shift_display = "No Movement (Static)"
        elif b_rank > c_rank:
            shift_display = f"{GREEN}Ascended +{b_rank - c_rank} spots (Was #{b_rank}){RESET}"
        else:
            shift_display = f"{RED}Dropped -{c_rank - b_rank} spots (Was #{b_rank}){RESET}"
            
        rank_label = f"#{c_rank}"
        print(f"{rank_label:<14} | {adv_id:<22} | {p_name[:28]:<28} | {cvss:<6.1f} | {shift_display}")

    if not top_5_leaderboard:
        print("    [-] No catalog vulnerabilities found matching this registry.")
    print("-" * 115)
        
    # -------------------------------------------------------------------------
    # 3. HIGH RISK TECHNICAL DEBT CALCIFICATION (DORMANCY TRACKING)
    # -------------------------------------------------------------------------
    print(f"\n[+] High-Severity Technical Debt Calcification (Dormant inside {registry_target} > {start_date.date()}):")
    
    cursor.execute("""
        SELECT COUNT(DISTINCT advisory_id)
        FROM vulnerabilities
        WHERE cvss_score >= 8.5 AND last_modified < ? AND ecosystems LIKE ?
    """, (start_str, relaxed_like_pattern))
    total_stagnant_debt = cursor.fetchone()[0]
    
    print(f"    [*] Identified {total_stagnant_debt:,} total critical technical debt entries calcified prior to this window.")
    print("-" * 115)
    print(f"{'Advisory ID':<20} | {'Artifact Name':<25} | {'CVSS':<5} | {'Days Since Last Active'}")
    print("-" * 115)
    
    cursor.execute("""
        SELECT advisory_id, package_name, cvss_score, last_modified
        FROM vulnerabilities
        WHERE cvss_score >= 8.5 AND last_modified < ? AND ecosystems LIKE ?
        GROUP BY advisory_id
        ORDER BY cvss_score DESC, last_modified ASC
        LIMIT 5
    """, (start_str, relaxed_like_pattern))
    
    rows_dormant = cursor.fetchall()
    if rows_dormant:
        for row in rows_dormant:
            aid, p_name, cvss, last_mod_str = row
            mod_date = datetime.datetime.strptime(last_mod_str, "%Y-%m-%d").date()
            days_dormant = (end_date.date() - mod_date).days
            print(f"{aid:<20} | {p_name[:25]:<25} | {cvss:<5.1f} | {days_dormant}d stagnant")
    else:
        print("    [-] Zero high-risk technical debt structures remain stagnant outside the window boundary.")
    print("-" * 115)

    # -------------------------------------------------------------------------
    # 4. TOP 10 CRITICAL THREAT ARRIVALS & CAMPAIGNS (DEDUPLICATED)
    # -------------------------------------------------------------------------
    print(f"\n[+] Top 10 Critical Threat Arrivals & Campaigns (Published Since {start_str}):")
    print("-" * 115)
    print(f"{'Advisory ID':<20} | {'Artifact Name':<25} | {'CVSS':<5} | {'Blast Radius':<14} | {'Age':<6} | {'Threat Profile'}")
    print("-" * 115)
    
    cursor.execute("""
        SELECT advisory_id, package_name, cvss_score, blast_radius, threat_profile, published_date
        FROM vulnerabilities
        WHERE last_modified >= ? 
          AND ecosystems LIKE ? 
          AND published_date >= ?
          AND threat_profile NOT LIKE '%Withdrawn%'
        ORDER BY cvss_score DESC, blast_radius DESC, advisory_id ASC
        LIMIT 50
    """, (start_str, relaxed_like_pattern, start_str))
    
    raw_worst = cursor.fetchall()
    seen_worst_pkgs = set()
    deduped_worst = []
    for row in raw_worst:
        pkg_key = row[1].lower().strip()
        if pkg_key in seen_worst_pkgs:
            continue
        seen_worst_pkgs.add(pkg_key)
        deduped_worst.append(row)
        if len(deduped_worst) == 10:
            break

    if deduped_worst:
        for row in deduped_worst:
            aid, p_name, cvss, radius, t_profile, pub_date_str = row
            radius_str = f"{radius:,} Vers"
            
            age_str = "N/A"
            if pub_date_str:
                try:
                    pub_date = datetime.datetime.strptime(pub_date_str[:10], "%Y-%m-%d").date()
                    age_days = (end_date.date() - pub_date).days
                    age_str = f"{age_days}d"
                except ValueError:
                    pass
                    
            print(f"{aid:<20} | {p_name[:25]:<25} | {cvss:<5.1f} | {radius_str:<14} | {age_str:<6} | {t_profile}")
    else:
        print("    [-] No severe new threat arrivals or malware campaigns recorded in this window.")
    print("-" * 115)
        
    # -------------------------------------------------------------------------
    # 5. WHICH THINGS ACTUALLY GOT FIXED? (DEDUPLICATED)
    # -------------------------------------------------------------------------
    print(f"\n[+] Top 5 Critical Vulnerabilities Code-Fixed (Remediated Since {start_str}):")
    print("-" * 115)
    print(f"{'Advisory ID':<28} | {'Artifact Name':<22} | {'CVSS':<5} | {'Fixed':<6} | {'Days Alive':<10} | {'Resolution State'}")
    print("-" * 115)
    
    cursor.execute("""
        SELECT advisory_id, package_name, cvss_score, last_modified, threat_profile, dwell_days
        FROM vulnerabilities
        WHERE last_modified >= ? AND ecosystems LIKE ? 
          AND threat_profile LIKE '%Fix%'
          AND threat_profile NOT LIKE '%Withdrawn%'
        ORDER BY cvss_score DESC, last_modified DESC
        LIMIT 25
    """, (start_str, relaxed_like_pattern))
    
    raw_fixed = cursor.fetchall()
    seen_fixed_pkgs = set()
    deduped_fixed = []
    for row in raw_fixed:
        pkg_key = row[1].lower().strip()
        if pkg_key in seen_fixed_pkgs:
            continue
        seen_fixed_pkgs.add(pkg_key)
        deduped_fixed.append(row)
        if len(deduped_fixed) == 5:
            break

    if deduped_fixed:
        for row in deduped_fixed:
            aid, p_name, cvss, last_mod_str, t_profile, dwell = row
            date_short = last_mod_str[5:] if len(last_mod_str) >= 10 else last_mod_str
            dwell_str = f"{int(dwell)}d" if dwell is not None else "N/A"
            print(f"{aid:<28} | {p_name[:22]:<22} | {cvss:<5.1f} | {date_short:<6} | {dwell_str:<10} | {t_profile}")
    else:
        print("    [-] No vulnerability mitigations or upstream fixes published in this window.")
    print("-" * 115)

    # -------------------------------------------------------------------------
    # 6. WHICH THINGS WERE WITHDRAWN / RETRACTED? (Intel Noise Filter)
    # -------------------------------------------------------------------------
    print(f"\n[+] Upstream Advisory Retractions & Disputed Noise (Withdrawn Since {start_str}):")
    print("-" * 115)
    print(f"{'Advisory ID':<20} | {'Artifact Name':<25} | {'CVSS':<5} | {'Withdrn':<7} | {'Days Alive':<10} | {'Reason / State'}")
    print("-" * 115)
    
    cursor.execute("""
        SELECT advisory_id, package_name, cvss_score, last_modified, threat_profile, dwell_days
        FROM vulnerabilities
        WHERE last_modified >= ? AND ecosystems LIKE ? 
          AND (threat_profile LIKE '%Withdrawn%' OR threat_profile = 'Withdrawn / Retracted Advisory')
        ORDER BY last_modified DESC
        LIMIT 3
    """, (start_str, relaxed_like_pattern))
    
    rows_withdrawn = cursor.fetchall()
    if rows_withdrawn:
        for row in rows_withdrawn:
            aid, p_name, cvss, last_mod_str, t_profile, dwell = row
            date_short = last_mod_str[5:] if len(last_mod_str) >= 10 else last_mod_str
            cvss_str = f"{cvss:.1f}" if cvss > 0 else "N/A"
            dwell_str = f"{int(dwell)}d" if dwell is not None else "N/A"
            print(f"{aid:<20} | {p_name[:25]:<25} | {cvss_str:<5} | {date_short:<7} | {dwell_str:<10} | {t_profile}")
    else:
        print("    [-] Zero historical entries retracted or disputed by maintainers in this window.")
    print("-" * 115)

    # -------------------------------------------------------------------------
    # 7. THREE-BUCKET EXECUTIVE BRIEFING VELOCITY GRAPH
    # -------------------------------------------------------------------------
    cursor.execute("""
        SELECT COUNT(*) FROM vulnerabilities 
        WHERE last_modified >= ? AND ecosystems LIKE ? 
          AND (threat_profile LIKE '%New Entry%' OR threat_profile LIKE '%Malware%')
          AND threat_profile NOT LIKE '%Withdrawn%'
    """, (start_str, relaxed_like_pattern))
    total_new_hotness = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM vulnerabilities 
        WHERE last_modified >= ? AND ecosystems LIKE ? 
          AND threat_profile LIKE '%Fix%'
          AND threat_profile NOT LIKE '%New Entry%'
          AND threat_profile NOT LIKE '%Withdrawn%'
    """, (start_str, relaxed_like_pattern))
    total_resolved = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM vulnerabilities 
        WHERE last_modified >= ? AND ecosystems LIKE ? 
          AND (threat_profile LIKE '%Withdrawn%' OR threat_profile = 'Withdrawn / Retracted Advisory')
    """, (start_str, relaxed_like_pattern))
    total_withdrawn = cursor.fetchone()[0]

    print(f"\n📊 EXECUTIVE BRIEFING VELOCITY GRAPH: {registry_target.upper()} THREE-WAY BALANCE")
    print("="*115)
    
    max_metric = max(total_new_hotness, total_resolved, total_withdrawn, 1)
    bar_max_width = 40
    
    hotness_bar_len = int((total_new_hotness / max_metric) * bar_max_width)
    resolved_bar_len = int((total_resolved / max_metric) * bar_max_width)
    withdrawn_bar_len = int((total_withdrawn / max_metric) * bar_max_width)
    
    hotness_spark = "█" * hotness_bar_len if total_new_hotness > 0 else " "
    resolved_spark = "█" * resolved_bar_len if total_resolved > 0 else " "
    withdrawn_spark = "█" * withdrawn_bar_len if total_withdrawn > 0 else " "
    
    print(f"{'Metric Profile Classification Category':<40} | {'Volume':<8} | Visual Velocity Sparkline")
    print("-" * 115)
    print(f"{'🔥 New Threat Arrivals (Hotness)':<42} | {total_new_hotness:<8,} | {RED}{hotness_spark}{RESET}")
    print(f"{'🛡️ Actual Code Patches (Resolved)':<43} | {total_resolved:<8,} | {GREEN}{resolved_spark}{RESET}")
    print(f"{'🚫 Retracted Database Noise (Withdrawn)':<42} | {total_withdrawn:<8,} | {YELLOW}{withdrawn_spark}{RESET}")
    print("-" * 115)
    
    healing_ratio = (total_resolved / total_new_hotness) if total_new_hotness > 0 else (float('inf') if total_resolved > 0 else 1.0)
    if healing_ratio >= 1.0:
        healing_status = f"{GREEN}Net Healing State (Upstream fixes outpace threat delivery arrivals){RESET}"
    elif healing_ratio >= 0.5:
        healing_status = f"{YELLOW}Strained Exposure State (Remediation backlogs growing incrementally){RESET}"
    else:
        healing_status = f"{RED}Critical Calcification Alert (Threat volume vastly outpacing patch velocity){RESET}"
        
    print(f"-> Supply Chain Healing Index Ratio:  {healing_ratio:.2f}")
    print(f"-> Strategic Briefing Guidance:       {healing_status}")
    print("="*115 + "\n")
    
    conn.close()

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
    parser.add_argument("--trends", action="store_true", help="Activate chronological trend and mutation velocity analysis.")
    parser.add_argument("--window-days", type=int, default=30, help="Telescoping trend evaluation window constraint (Defaults to 30 days).")
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

    # Uniform environmental allocation
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    target_registries = [r.strip() for r in args.registry.split(",")] if args.registry else None
    
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

    # =========================================================================
    # FEATURE ROUTING LAYER: TRENDS TIMELINE CALCULATOR
    # =========================================================================
    if args.trends:
        if not args.database:
            parser.error("[!] The trend velocity analysis engine requires the --database relational warehouse active.")
        
        if not args.registry:
            print(f"\n{BOLD}{RED}[!] CONFIGURATION ERROR: Trend analysis requires an explicit repository filter.{RESET}")
            print(f"    -> Usage: python top10ecosystems.py --trends --registry <repo_name>\n")
            sys.exit(1)

        if args.to:
            date_str = args.to[0]
            parsed_date = None
            for fmt in ("%Y-%m-%d", "%m-%d-%Y", "%d-%m-%Y"):
                try:
                    parsed_date = datetime.datetime.strptime(date_str, fmt).date()
                    break
                except ValueError: continue
            if not parsed_date:
                print(f"{RED}[-] Invalid --to date format string provided.{RESET}")
                sys.exit(1)
            end_window_dt = datetime.datetime.combine(parsed_date, datetime.time.max, tzinfo=datetime.timezone.utc)
        else:
            end_window_dt = now_utc

        if args.from_date:
            start_window_dt = datetime.datetime.combine(datetime.date.fromisoformat(args.from_date), datetime.time.min, tzinfo=datetime.timezone.utc)
        elif args.window_days or args.days:
            lookback_days = args.window_days if args.window_days else args.days
            start_window_dt = end_window_dt - datetime.timedelta(days=lookback_days)
        else:
            start_window_dt = datetime.datetime(2026, 4, 18, 0, 0, 0, tzinfo=datetime.timezone.utc)
        
        print(f"\n[*] Launching Telescoping AppSec Trend Analysis Module")
        print(f"    -> Lookback Evaluation Window: {start_window_dt.date()} to {end_window_dt.date()}")
        
        for registry in target_registries:
            generate_ecosystem_trend_briefing(
                db_path="database/threat_stream.db",
                start_date=start_window_dt,
                end_date=end_window_dt,
                registry_target=registry,
                manifest_rows=cached_manifest_rows
            )
        return
    
    if args.database:
        global_ghsa_lookup = build_ghsa_from_db(db_path="database/threat_stream.db", target_registries=target_registries)
    else:
        global_ghsa_lookup = build_ghsa_ecosystem_map()

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
