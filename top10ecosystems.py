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
OSV Threat Stream Campaign Dashboard Indicator
=================================================================================
A security engineering tool designed to track software supply chain fluctuations 
by aggregating upstream vulnerability mutations from the Open Source Vulnerability 
(OSV) database.

CRITICAL ARCHITECTURAL NOTE ON METRICS:
---------------------------------------------------------------------------------
The "Activity Delta" column DOES NOT measure individual, real-world exploit attacks.
Instead, it measures upstream VULNERABILITY DATABASE CHURN (mutations) over a 
user-defined day window. 

A single unit added to the Activity Delta column indicates one of three events:
  1. A Brand New Vulnerability Entry: Creation of a new CVE, GHSA, or malware 
     advisory (e.g., active typosquatting campaigns in npm/PyPI).
  2. A Structural Patch/Version Update: An existing advisory was modified to 
     expand/contract affected version ranges, or to inject newly patched versions.
  3. Metadata Correction: Minor back-end adjustments, such as updating CVSS 
     severity ratings or updating vendor description logs.
     
     

Why Operating Systems (Debian/Ubuntu) volume dwarfs Application Registries (npm):
---------------------------------------------------------------------------------
Linux distributions run massive automated tracking systems. When a core utility 
(like glibc or openssl) receives a security patch, the maintainers backport and 
update thousands of historical records across multiple supported OS releases and 
architectures simultaneously. This causes massive, automated, non-malicious 
database spikes. 

Conversely, Application Registry spikes (like npm) are heavily driven by active, 
targeted software supply chain injections, malicious packages, or distinct library 
vulnerabilities impacting application runtime code.

WARNING ON LAYER FILTERING & MALWARE METRICS BEHAVIOR:
---------------------------------------------------------------------------------
Virtually 100% of cataloged open-source malware payloads live natively within 
Application Layer registries (npm/PyPI). Operating system distributions track 
vulnerabilities strictly as system CVEs (Vulnerability Fixes/Updates). 

As a result:
  - Running the script with '--layer app' yields malware vector counts that are 
    IDENTICAL to a default run, because no malware data is omitted by removing 
    containers. However, the Layer Threat Profile percentages will correctly scale
    upward to reflect malware's true dominance over application-only churn.
  - Running the script with '--layear container' suppresses the "MALWARE ATTACK 
    VECTOR ANALYSIS" panel entirely, as the targeted malware metrics drop to zero.
=================================================================================
"""

"""
OSV Threat Stream Campaign Dashboard Indicator - Version 1.2
=================================================================================
A security engineering tool designed to track software supply chain fluctuations 
by aggregating upstream vulnerability mutations from the Open Source Vulnerability 
(OSV) database and cross-referencing strict local project manifest pins.

CRITICAL ARCHITECTURAL NOTE ON METRICS:
---------------------------------------------------------------------------------
The "Activity Delta" column DOES NOT measure individual, real-world exploit attacks.
Instead, it measures upstream VULNERABILITY DATABASE CHURN (mutations) over a 
user-defined day window. 
=================================================================================
"""

import csv
import datetime
import json
import os
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

def generate_html_report(snapshots, output_html="briefing.html"):
    """
    Generate a briefing-ready HTML report from chronological JSON snapshots.

    The snapshots are cumulative windows. For that reason the report renders two
    separate registry charts:
      1. cumulative totals by snapshot date
      2. true day-over-day / snapshot-over-snapshot deltas

    It also renders threat-profile deltas so the briefing shows whether the
    movement is malware, vulnerability update churn, or metadata adjustment churn.
    """
    print(f"[*] Generating Professional Briefing: {output_html}")

    if not snapshots:
        print("[-] No snapshots supplied to HTML report generator.")
        return

    snapshots = sorted(snapshots, key=lambda x: x["metadata"]["interval_to"])
    dates = [s["metadata"]["interval_to"] for s in snapshots]

    def fig_to_base64(fig):
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        encoded = base64.b64encode(buf.getvalue()).decode("utf-8")
        mplplt.close(fig)
        return encoded

    def choose_top_keys(section_name, limit=5):
        all_keys = set().union(*[s.get(section_name, {}).keys() for s in snapshots])
        key_totals = {
            key: sum(s.get(section_name, {}).get(key, 0) for s in snapshots)
            for key in all_keys
        }
        return sorted(key_totals, key=key_totals.get, reverse=True)[:limit]

    def values_for(section_name, key):
        return [s.get(section_name, {}).get(key, 0) for s in snapshots]

    # ------------------------------------------------------------------
    # Chart 1: Cumulative / snapshot totals. This is the "how big is the
    # stream window now?" chart.
    # ------------------------------------------------------------------
    top_ecosystems = choose_top_keys("leaderboard", 5)
    fig_totals, ax_totals = mplplt.subplots(figsize=(11, 6))
    for eco in top_ecosystems:
        ax_totals.plot(dates, values_for("leaderboard", eco), label=eco, marker="o")

    ax_totals.set_title("Registry Churn Totals by Snapshot Date")
    ax_totals.set_xlabel("Snapshot End Date")
    ax_totals.set_ylabel("Cumulative Mutations in Window")
    ax_totals.legend()
    ax_totals.grid(True, alpha=0.25)
    mplplt.setp(ax_totals.get_xticklabels(), rotation=45, ha="right")
    totals_img_data = fig_to_base64(fig_totals)

    # ------------------------------------------------------------------
    # Chart 2: True delta velocity. The first snapshot has no previous
    # snapshot, so we intentionally start this chart at the second date.
    # ------------------------------------------------------------------
    fig_delta, ax_delta = mplplt.subplots(figsize=(11, 6))
    if len(snapshots) > 1:
        delta_dates = dates[1:]
        for eco in top_ecosystems:
            totals = values_for("leaderboard", eco)
            deltas = [totals[i] - totals[i - 1] for i in range(1, len(totals))]
            ax_delta.plot(delta_dates, deltas, label=eco, marker="o")
        ax_delta.set_xlabel("Snapshot End Date")
        ax_delta.set_ylabel("Net New Mutations Since Previous Snapshot")
    else:
        ax_delta.text(0.5, 0.5, "Need at least two snapshots for velocity deltas", ha="center", va="center")
        ax_delta.set_axis_off()

    ax_delta.set_title("Threat Churn Velocity: Registry Deltas")
    ax_delta.legend() if len(snapshots) > 1 else None
    ax_delta.grid(True, alpha=0.25) if len(snapshots) > 1 else None
    mplplt.setp(ax_delta.get_xticklabels(), rotation=45, ha="right")
    delta_img_data = fig_to_base64(fig_delta)

    # ------------------------------------------------------------------
    # Chart 3: Threat behavior deltas. This answers "what kind of churn
    # changed?" rather than only "which registry moved?"
    # ------------------------------------------------------------------
    top_profiles = choose_top_keys("threat_profile", 5)
    fig_profile, ax_profile = mplplt.subplots(figsize=(11, 6))
    if len(snapshots) > 1 and top_profiles:
        profile_delta_dates = dates[1:]
        for profile in top_profiles:
            totals = values_for("threat_profile", profile)
            deltas = [totals[i] - totals[i - 1] for i in range(1, len(totals))]
            ax_profile.plot(profile_delta_dates, deltas, label=profile, marker="o")
        ax_profile.set_xlabel("Snapshot End Date")
        ax_profile.set_ylabel("Net New Signals Since Previous Snapshot")
    else:
        ax_profile.text(0.5, 0.5, "Need at least two snapshots with threat profile data", ha="center", va="center")
        ax_profile.set_axis_off()

    ax_profile.set_title("Threat Behavior Velocity: Profile Deltas")
    ax_profile.legend() if len(snapshots) > 1 and top_profiles else None
    ax_profile.grid(True, alpha=0.25) if len(snapshots) > 1 and top_profiles else None
    mplplt.setp(ax_profile.get_xticklabels(), rotation=45, ha="right")
    profile_img_data = fig_to_base64(fig_profile)

    # ------------------------------------------------------------------
    # Evidence table. Keep the raw dict, but make the page easier to scan.
    # ------------------------------------------------------------------
    table_rows = "".join([
        f"<tr><td>{d}</td><td><code>{s.get('leaderboard', {})}</code></td><td><code>{s.get('threat_profile', {})}</code></td></tr>"
        for d, s in zip(dates, snapshots)
    ])

    html = f"""
    <html>
    <head>
        <meta charset='utf-8'/>
        <title>AppSec Threat Briefing</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 24px; line-height: 1.35; }}
            h1 {{ margin-bottom: 0.2rem; }}
            .subtitle {{ color: #555; margin-top: 0; }}
            .chart {{ margin: 28px 0 36px 0; }}
            .chart img {{ max-width: 100%; border: 1px solid #ddd; }}
            table {{ border-collapse: collapse; width: 100%; font-size: 0.92rem; }}
            td, th {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
            th {{ background: #f5f5f5; }}
            code {{ white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <h1>AppSec Threat Briefing</h1>
        <p class='subtitle'>Generated from {len(snapshots)} chronological OSV snapshot(s).</p>

        <div class='chart'>
            <h2>1. Registry Churn Totals</h2>
            <p>Cumulative mutation volume inside each snapshot window.</p>
            <img src='data:image/png;base64,{totals_img_data}'/>
        </div>

        <div class='chart'>
            <h2>2. Registry Churn Velocity</h2>
            <p>Snapshot-over-snapshot deltas. The first snapshot is excluded because it has no prior baseline.</p>
            <img src='data:image/png;base64,{delta_img_data}'/>
        </div>

        <div class='chart'>
            <h2>3. Threat Behavior Velocity</h2>
            <p>Snapshot-over-snapshot movement by threat classification.</p>
            <img src='data:image/png;base64,{profile_img_data}'/>
        </div>

        <h2>Daily Raw Data</h2>
        <table>
            <tr><th>Date</th><th>Registry Totals</th><th>Threat Profile Totals</th></tr>
            {table_rows}
        </table>
    </body>
    </html>
    """

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Briefing generated successfully.")

def generate_velocity_matrix(target_dir: str, output_path: str = "./output/velocity_matrix.csv", render_terminal_plot: bool = False):
    """
    Ingests a directory of daily JSON snapshots and stitches them into a time-series CSV matrix.
    """
    if not os.path.isdir(target_dir):
        print(f"[-] Velocity Engine Error: The directory '{target_dir}' does not exist.")
        return

    print("\n" + "="*85)
    print(f"  {BOLD}THREAT VELOCITY AGGREGATION ENGINE{RESET}")
    print("="*85)

    snapshots = []
    
    # 1. Vacuum up the JSONs
    for filename in os.listdir(target_dir):
        if not filename.endswith(".json"): continue
        
        filepath = os.path.join(target_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # We need a valid metadata block to anchor it in time
                if "metadata" in data and "interval_to" in data["metadata"]:
                    snapshots.append(data)
        except Exception as e:
            print(f"[-] Failed to read snapshot {filename}: {e}")

    if not snapshots:
        print("[-] No valid JSON snapshots found in the target directory.")
        return

    # 2. Sort chronologically by the end date
    snapshots.sort(key=lambda x: x["metadata"]["interval_to"])
    
    # 3. Discover all unique tracking columns across the timeline
    all_ecosystems = set()
    all_threat_profiles = set()
    
    for s in snapshots:
        all_ecosystems.update(s.get("leaderboard", {}).keys())
        all_threat_profiles.update(s.get("threat_profile", {}).keys())

    sorted_ecosystems = sorted(list(all_ecosystems))
    sorted_profiles = sorted(list(all_threat_profiles))

    # 4. Build the CSV Header
    headers = ["Date_End", "Layer_Filter"] + sorted_ecosystems + sorted_profiles

    # 5. Write the Matrix
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            for s in snapshots:
                row = [
                    s["metadata"]["interval_to"],
                    s["metadata"].get("target_layer_filter", "all")
                ]
                
                # Append Ecosystem Counts
                for eco in sorted_ecosystems:
                    row.append(s.get("leaderboard", {}).get(eco, 0))
                    
                # Append Threat Profile Counts
                for profile in sorted_profiles:
                    row.append(s.get("threat_profile", {}).get(profile, 0))
                    
                writer.writerow(row)
                
        print(f"[+] Aggregation Complete: Processed {len(snapshots)} chronological snapshots.")
        print(f"[+] Velocity Matrix Saved: {output_path}")
        print("="*85 + "\n")
        
        # Terminal plotting is intentionally opt-in. plotext.clt() clears the terminal,
        # which hides the dashboard output that was printed immediately before this step.
        if not render_terminal_plot:
            return
        
        # 6. Render Velocity Visualization (Multi-Series)
        print("[*] Generating Multi-Series Terminal Velocity Plot...")
        
        # Identify the Top 10 by total volume
        eco_totals = {eco: sum(s.get("leaderboard", {}).get(eco, 0) for s in snapshots) for eco in sorted_ecosystems}
        top_10 = sorted(eco_totals, key=eco_totals.get, reverse=True)[:10]
        
        dates = [s["metadata"]["interval_to"] for s in snapshots]
        
        # Configure plotext. Do not call pltx.clt() here; it clears the entire terminal.
        # clear_data() resets plot state without erasing prior program output.
        pltx.clear_data()
        pltx.date_form(input_form="Y-m-d")
        
        for eco in top_10:
            # Calculate DAILY DELTAS instead of totals
            totals = [s.get("leaderboard", {}).get(eco, 0) for s in snapshots]
            deltas = [totals[0]] + [totals[i] - totals[i-1] for i in range(1, len(totals))]
            
            # Only plot if there's activity
            if any(d != 0 for d in deltas):
                pltx.plot(dates, deltas, label=f"{eco} (Delta)")
                
        pltx.title("Threat Churn Velocity (Daily Deltas)")
        pltx.xlabel("Timeline")
        pltx.ylabel("Net New Mutations")
        pltx.plotsize(100, 25) 
        pltx.show()
        
    except Exception as e:
        print(f"[-] Velocity Matrix export failed: {e}")

def extract_cvss_score(vuln_data):
    """
    Parses OSV severity vectors using the official FIRST cvss library.
    Enforces a default score of 10.0 for explicitly malicious packages.
    """
    vuln_id = vuln_data.get("id", "")
    if vuln_id.startswith("MAL-") or "malware" in json.dumps(vuln_data).lower():
        return 10.0
        
    severity_list = vuln_data.get("severity", [])
    if not severity_list:
        return 0.0
        
    for sev in severity_list:
        sev_type = sev.get("type", "")
        vector_str = sev.get("score", "")
        if not vector_str:
            continue
            
        try:
            if sev_type == "CVSS_V3" or "CVSS:3" in vector_str:
                return float(CVSS3(vector_str).base_score)
            elif sev_type == "CVSS_V4" or "CVSS:4" in vector_str:
                return float(CVSS4(vector_str).base_score)
            elif sev_type == "CVSS_V2" or "RUSTSEC" in vuln_id:
                return float(CVSS2(vector_str).base_score)
        except Exception:
            continue
            
    return 0.0

# ==============================================================================
# MODULAR PLUG-AND-PLAY DECOUPLED MANIFEST PARSERS (STRATEGY PATTERN)
# ==============================================================================

def parse_maven_dependency_tree(file_path: str) -> dict:
    """Extracts unique groupId:artifactId pairs mapped to pinned versions, navigating raw CLI noise."""
    discovered_packages = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                clean_line = re.sub(r'^\[(?:INFO|WARNING|ERROR)\]\s*', '', clean_line)
                
                if not clean_line or ":" not in clean_line or clean_line.startswith("-"):
                    continue
                if any(x in clean_line for x in ["Total time:", "Finished at:", "BUILD SUCCESS", "BUILD FAILURE"]):
                    continue
                clean_line = clean_line.replace(" (optional)", "")
                if re.match(r'^[a-zA-Z0-9]', clean_line) and line_num < 10:
                    continue

                illegal_maven_indicators = ["[", "]", "(", ")", "LATEST", "RELEASE", "SNAPSHOT"]
                if any(indicator in clean_line for indicator in illegal_maven_indicators):
                    print(f"\n{BOLD}{RED}[!] MAVEN TREE LINTING FAILURE (Line {line_num}):{RESET}")
                    print(f"    -> Offending Line: '{line.strip()}'")
                    print(f"    -> Reason: Dynamic ranges, SNAPSHOTs, or LATEST keywords are forbidden to ensure build determinism.")
                    exit(1)
                
                parts = clean_line.split(":")
                if len(parts) >= 4:
                    raw_group = parts[0]
                    group_id = re.sub(r'^[\\|\s\+\-]+', '', raw_group).strip()
                    package_key = f"{group_id}:{parts[1].strip()}".lower().strip()
                    if package_key:
                        discovered_packages[package_key] = parts[3].strip()
                        
    except SystemExit:
        raise
    except Exception as e:
        print(f"[-] Error executing strict Maven tree parser strategy: {e}")
        exit(1)
        
    return discovered_packages

def parse_cyclonedx_sbom(file_path: str) -> dict:
    """Extracts package names mapped to versions from a CycloneDX JSON SBOM, rejecting unpinned elements."""
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
                        print(f"    -> Offending Component: '{full_name}'")
                        print(f"    -> Reason: Missing or dynamic version tag detected. Strict pinning is required.")
                        print(f"    -> Action: Regenerate your SBOM using a locked or fully resolved build state.\n")
                        exit(1)
                        
                    discovered_packages[full_name_clean] = version
    except SystemExit:
        raise
    except Exception as e:
        print(f"[-] Error executing strict CycloneDX JSON strategy: {e}")
        exit(1)
    return discovered_packages

def parse_pypi_requirements(file_path: str) -> dict:
    """Extracts exact package names mapped to pinned versions, rejecting dynamic operators."""
    discovered_packages = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("-r"):
                    continue
                
                illegal_operators = [">=", "<=", ">", "<", "~=", "!="]
                if any(op in clean_line for op in illegal_operators):
                    print(f"\n{BOLD}{RED}[!] MANIFEST LINTING FAILURE (Line {line_num}):{RESET}")
                    print(f"    -> Offending Line: '{clean_line}'")
                    print(f"    -> Reason: Dynamic range operators are forbidden to ensure build determinism.")
                    print(f"    -> Action: Please compile your lockfile or freeze the library to a strict pin ('==').\n")
                    exit(1)
                
                parts = clean_line.split("==")
                package_name = parts[0].strip().lower().replace('_', '-')
                version_pin = "0.0.0"
                if len(parts) > 1:
                    version_pin = parts[1].split(";")[0].split("#")[0].strip()
                        
                if package_name:
                    discovered_packages[package_name] = version_pin
    except SystemExit:
        raise
    except Exception as e:
        print(f"[-] Error executing strict PyPI parser strategy: {e}")
        exit(1)
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
# CORE ANALYTICAL ENGINES
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
                            if "withdrawn" in vuln_data:
                                continue
                                
                            vuln_id = vuln_data.get("id", "")
                            ecosystems = set()
                            has_fixes = False
                            is_malware = False
                            p_name = "N/A"
                            vuln_versions = set() 
                            
                            if vuln_id.startswith("MAL-") or "malicious" in file_name.lower():
                                is_malware = True
                                
                            summary = vuln_data.get("summary", "").lower()
                            details = vuln_data.get("details", "").lower()
                            if "backdoor" in summary or "typosquat" in summary or "malicious package" in summary:
                                is_malware = True

                            max_versions_found = 0
                            for affected in vuln_data.get("affected", []):
                                eco = affected.get("package", {}).get("ecosystem")
                                name = affected.get("package", {}).get("name")
                                if eco: ecosystems.add(eco)
                                if name: p_name = name.strip()
                                
                                for v in affected.get("versions", []):
                                    vuln_versions.add(str(v).strip())
                                
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
                                if "typosquat" in summary or "typosquat" in details:
                                    malware_vector = "Typosquatting / Brand Hijacking"
                                elif "dependency confusion" in summary or "dependency confusion" in details:
                                    malware_vector = "Dependency Confusion Campaign"
                                elif any(x in summary or x in details for x in ["exfiltrat", "token", "credential", "steal"]):
                                    malware_vector = "Data Exfiltration / Credential Stealer"
                                elif any(x in summary or x in details for x in ["reverse shell", "backdoor", "remote code"]):
                                    malware_vector = "Persistent Backdoor / Execution Shell"

                            if is_malware:
                                classification = "Malware (New Entry)" if is_new_entry else "Malware (Incremental Update)"
                            elif has_fixes:
                                classification = "Vulnerability Fix (New Entry)" if is_new_entry else "Vulnerability Fix (Update)"
                            else:
                                classification = "Metadata Correction / Adjustments"

                            if vuln_id and ecosystems:
                                id_to_meta[vuln_id] = {
                                    "ecosystems": list(ecosystems),
                                    "package_name": p_name,
                                    "type": classification,
                                    "vector": malware_vector,
                                    "dwell_days": dwell_days,
                                    "blast_radius": max_versions_found,
                                    "vulnerable_versions": vuln_versions,
                                    "cvss_score": extract_cvss_score(vuln_data)
                                }
                        except json.JSONDecodeError: continue 
        print(f"[+] Successfully indexed {len(id_to_meta):,} global advisory mappings.")
    except Exception as e:
        print(f"[-] Failed to read master archive: {e}")
    return id_to_meta

def get_artifact_layer(eco_name):
    container_images = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    app_registries = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]
    if eco_name in container_images: return "Container Base Image"
    elif eco_name in app_registries: return "App Software Registry"
    elif eco_name == "GIT": return "Source Control (SCM)"
    return "Global Baseline Noise"

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
                if abs(diff) < 0.05:
                    diff = 0.0
                    
                diff_str = f"{diff:+.1f}{suffix}" if diff != 0 else f"0.0{suffix}"
                raw_str = f"{diff_str:<12} (from {base_val:.1f})"
                padded_raw = f"{raw_str:<{width_size}}"
                
                if diff == 0.0:
                    return padded_raw
                
                return f"{RED}{padded_raw}{RESET}" if diff > 0 else f"{GREEN}{padded_raw}{RESET}"

            dm_str = color_metric_string(dm_diff, dm_base, " Days", 26)
            dc_str = color_metric_string(dc_diff, dc_base, " Days", 26)
            br_str = color_metric_string(br_diff, br_base, " Vers", 26)

            print(f"{eco:<22} | {dm_str} | {dc_str} | {br_str}")
        print("="*115)
        
    if "outliers_leaderboards" in base and "outliers_leaderboards" in current:
        print(f"\n{BOLD}V. CRITICAL OUTLIER ATTACK SURFACE RADIUS POOLS VARIANCE ANALYSIS:{RESET}")
        print("="*145)
        
        for eco in sorted(list(current["outliers_leaderboards"].keys())):
            base_pool = base["outliers_leaderboards"].get(eco, {})
            curr_pool = current["outliers_leaderboards"].get(eco, {})
            
            if not base_pool and not curr_pool: continue
                
            print(f"\n{BOLD}[+] {eco} Outlier Tracking Shifts (Top 10):{RESET}")
            w_rank, w_id, w_name, w_cvss, w_radius = 5, 20, 28, 6, 22
            print(f"    {'Rank':<{w_rank}} | {'Advisory ID':<{w_id}} | {'Artifact Name':<{w_name}} | {'CVSS':<{w_cvss}} | {'Current Impact':<16} | {'Impact Delta':<18} | {'Rank Shift'}")
            print(f"    {'-'*135}")
            
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

                sortable_pool.append({
                    "id": r_id, "name": p_name, "b_radius": b_item["radius"], "c_radius": c_item["radius"], "cvss": c_score
                })
                
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
                elif not b_rank and c_rank:
                    raw_r_str = "New to Radar"
                else:
                    raw_r_str = "-"
                    
                if radius_diff != 0 or (b_rank and c_rank and b_rank != c_rank) or (not b_rank and c_rank):
                    has_shifts = True
                    
                if radius_diff > 0: diff_display = f"{GREEN}{raw_diff_str:<18}{RESET}"
                elif radius_diff < 0: diff_display = f"{RED}{raw_diff_str:<18}{RESET}"
                else: diff_display = f"{raw_diff_str:<18}"
                    
                if "Up" in raw_r_str or "New" in raw_r_str: r_display = f"{GREEN}{raw_r_str}{RESET}"
                elif "Down" in raw_r_str: r_display = f"{RED}{raw_r_str}{RESET}"
                else: r_display = raw_r_str
                    
                c_str = f"{c_radius:,} Vers"
                p_name_display = p_name[:25] + "..." if len(p_name) > 28 else p_name
                cvss_display = f"{item['cvss']:.1f}"
                
                print(f"    #{rank:<{w_rank-1}} | {r_id:<{w_id}} | {p_name_display:<{w_name}} | {cvss_display:<{w_cvss}} | {c_str:<16} | {diff_display} | {r_display}")
                
            if dropped_out:
                print(f"    {'-'*135}")
                print(f"    {YELLOW}* The following advisories mitigated or dropped out of the {eco} Top 10:{RESET}")
                for item in dropped_out:
                    r_id = item['id']
                    b_rank = base_ranks.get(r_id, "N/A")
                    c_rank = curr_ranks.get(r_id, ">50") if item['c_radius'] > 0 else "Mitigated (0)"
                    p_name_display = item["name"][:25] + "..." if len(item["name"]) > 28 else item["name"]
                    print(f"      - {r_id:<20} | {p_name_display:<28} | Base Rank: #{b_rank:<3} -> Current Rank: {c_rank}")
                
            if not has_shifts and not dropped_out:
                print(f"    -> All tracked critical outlier thresholds remained static between snapshots.")
        print("="*145 + "\n")

    # -------------------------------------------------------------------------
    # VI. ANSI TERMINAL COMPARISON GRAPH
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # CONDITIONAL COMPARISON HTML EXPORT
    # -------------------------------------------------------------------------
    if html_output:
        print(f"\n[*] Generating base64-embedded HTML comparison visualization...")
        try:
            # --- Chart 1: Volume Delta (Grouped Bar) ---
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

            # --- Chart 2: Profile Matrix (Diverging Bars) ---
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
            
            # --- Assemble HTML ---
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

# ==============================================================================
# MAIN ENGINE EXECUTION
# ==============================================================================

def generate_enterprise_threat_leaderboard(
    start_date, end_date, 
    target_layer: str = None, debug_mode: bool = False, 
    custom_export_arg=None, run_speedway: bool = False, 
    project_file_path: str = None, forced_format: str = None, 
    audit_mode: bool = False, ghsa_lookup: dict = None
    ):
    now = datetime.datetime.now(datetime.timezone.utc)
    
    final_leaderboard = Counter()
    target_inventory_map = {} 
    is_project_mode = False
    allowed_project_ecosystems = []
    
    known_containers = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
    known_registries = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]

    master_tracks = known_containers + known_registries + ["GIT", "Untagged Commit Hash/CVE Noise", "Android"]
    
    if target_layer == "app":
        final_leaderboard.update({k: 0 for k in known_registries})
    elif target_layer == "container":
        final_leaderboard.update({k: 0 for k in known_containers})
    else:
        final_leaderboard.update({k: 0 for k in master_tracks if k not in ["GIT", "Untagged Commit Hash/CVE Noise"]})

    manifest_target = project_file_path if project_file_path else (audit_mode if isinstance(audit_mode, str) else None)
    
    if manifest_target:
        strategy = forced_format if forced_format else auto_sniff_manifest_strategy(manifest_target)
        if strategy and strategy in MANIFEST_PARSER_REGISTRY:
            print(f"[*] Ingesting project manifest file using strategy profile: {strategy}...")
            target_inventory_map = MANIFEST_PARSER_REGISTRY[strategy](manifest_target)
            is_project_mode = True
            print(f"[+] Loaded {len(target_inventory_map)} project unique package tracking keys.")
            
            STRATEGY_ECOSYSTEM_WHITELIST = {
                "pypi_requirements": ["PyPI"],
                "maven_tree": ["Maven (Java)", "Maven"], 
                "cyclonedx_json": ["npm", "PyPI", "Maven (Java)", "Maven", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems"]
            }
            allowed_project_ecosystems = STRATEGY_ECOSYSTEM_WHITELIST.get(strategy, [])
        else:
            print(f"[-] Configuration Error: Unable to accurately parse layout structure for: {manifest_target}")
            exit(1)

    if ghsa_lookup is None:
        ghsa_lookup = build_ghsa_ecosystem_map()
        
    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"   
    total_raw_rows = 0
    project_intercept_alerts = []

    bucket_counts = Counter({"Malware (New Entry)": 0, "Malware (Incremental Update)": 0, "Vulnerability Fix (New Entry)": 0, "Vulnerability Fix (Update)": 0, "Metadata Correction / Adjustments": 0})
    malware_vector_counts = Counter({"Typosquatting / Brand Hijacking": 0, "Dependency Confusion Campaign": 0, "Data Exfiltration / Credential Stealer": 0, "Persistent Backdoor / Execution Shell": 0, "Unclassified Malicious Payload": 0})

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
            if mod_time < start_date: break
            
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
                
                hard_mappings = {
                    "maven": "Maven (Java)",
                    "go": "Go (Golang)",
                    "packagist": "Packagist (PHP)",
                    "git": "GIT",
                    "crates.io": "Crates.io"
                }
                
                eco_clean = None
                if eco_lower in hard_mappings:
                    eco_clean = hard_mappings[eco_lower]
                else:
                    for track in master_tracks:
                        if eco_lower in track.lower() or track.lower() in eco_lower:
                            eco_clean = track
                            break
                
                if not eco_clean:
                    eco_clean = "Android" if eco_lower not in ["git", "untagged commit hash/cve noise"] else "Untagged Commit Hash/CVE Noise"

                if eco_clean == "Untagged Commit Hash/CVE Noise" and not debug_mode: continue

                layer = get_artifact_layer(eco_clean)
                if target_layer == "container" and layer != "Container Base Image": continue
                if target_layer == "app" and layer != "App Software Registry": continue

                if is_project_mode and current_id in ghsa_lookup:
                    m_name = ghsa_lookup[current_id]["package_name"].lower().strip()
                    if m_name in target_inventory_map:
                        if allowed_project_ecosystems and eco_clean not in allowed_project_ecosystems:
                            continue
                            
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
        print("\n" + "="*95)
        title_source = project_file_path if project_file_path else audit_mode
        print(f"  {BOLD}LOCAL REPOSITORY INTERSECTION REPORT: {os.path.basename(title_source)}{RESET}")
        print("="*95)
        if project_intercept_alerts:
            print(f"{BOLD}{RED}[!] LOCAL BLAST RADIUS BREACH ALERT:{RESET}")
            print("-"*95)
            print(f"{'Advisory ID':<22} | {'Package Name':<20} | {'Ecosystem/Registry':<22} | {'Threat Profile'}")
            print("-"*95)
            for r_id, p_name, eco, u_type in sorted(list(set(project_intercept_alerts)), key=lambda x: x[1]):
                print(f"{r_id:<22} | {p_name:<20} | {eco:<22} | {u_type}")
        else:
            print(f" {GREEN}[+] Clean Bill of Health: Zero active package mutations match your local manifest elements within this timeframe.{RESET}")
        print("="*95 + "\n")
        return

    # ==============================================================================
    # ONSCREEN RENDER OUTPUT GENERATION
    # ==============================================================================

    print("\n" + "="*85)
    print(f"  {BOLD}VERIFIED ENTERPRISE ECOSYSTEM LEADERBOARD{RESET}")
    print(f"  Chronological Box Window: {start_date.date()} to {end_date.date()}")
    print("="*85)
    print(f"{'Rank':<5} | {'Ecosystem/Registry':<32} | {'Activity Delta':<14} | {'Artifact Layer'}")
    print("-"*85)
    for rank, (eco, count, layer) in enumerate(filtered_results[:10], start=1):
        print(f"#{rank:<3} | {eco:<32} | {count:<14,} | {layer}")
    print("="*85)
    print(f"Raw Entry Stream Items:    {total_raw_rows:,}")
    print(f"Ecosystem Attributions:    {sum(count for _, count, _ in filtered_results):,}")

    total_buckets = sum(bucket_counts.values())
    print("\n" + "="*50)
    print(f"  {BOLD}II. DATA ENRICHMENT: LAYER THREAT PROFILE{RESET}")
    print("="*50)
    for b_type in ["Malware (New Entry)", "Malware (Incremental Update)", "Vulnerability Fix (New Entry)", "Vulnerability Fix (Update)", "Metadata Correction / Adjustments"]:
        b_count = bucket_counts[b_type]
        percentage = (b_count / total_buckets) * 100 if total_buckets > 0 else 0.0
        print(f"-> {b_type:<32} | {b_count:<6,} ({percentage:.1f}%)")
    print("="*50)

    total_malware_signals = sum(malware_vector_counts.values())
    if total_malware_signals > 0:
        print("\n" + "="*50)
        print(f"  {BOLD}III. DEEP DIVE: MALWARE ATTACK VECTOR ANALYSIS{RESET}")
        print("="*50)
        for vector_name, vector_count in malware_vector_counts.most_common():
            v_p = (vector_count / total_malware_signals) * 100 if total_malware_signals > 0 else 0.0
            print(f"-> {vector_name:<38} | {vector_count:<4,} ({v_p:.1f}%)")
        print("="*50)

    print("\n" + "="*95)
    print(f"  {BOLD}IV. ECOSYSTEM THREAT DWELL TIME & BLAST RADIUS PROFILE MATRIX{RESET}")
    print("="*95)
    print(f"{'Ecosystem/Registry':<22} | {'Avg Dwell (Malware)':<20} | {'Avg Dwell (CVE)':<16} | {'Avg Blast Radius'}")
    print("-"*95)
    
    export_profile_matrix = {}
    active_matrix_ecosystems = [eco for eco, _, _ in filtered_results[:10]]
    
    for eco in active_matrix_ecosystems:
        m_list, c_list, r_list = spatial_dwell_malware.get(eco, []), spatial_dwell_cve.get(eco, []), spatial_blast_radius.get(eco, [])
        raw_avg_m = sum(m_list)/len(m_list) if m_list else 0.0
        raw_avg_c = sum(c_list)/len(c_list) if c_list else 0.0
        raw_avg_r = sum(r_list)/len(r_list) if r_list else 0.0
        
        export_profile_matrix[eco] = {"avg_dwell_mal": raw_avg_m, "avg_dwell_cve": raw_avg_c, "avg_blast_radius": raw_avg_r}
        print(f"{eco:<22} | {f'{raw_avg_m:.1f} Days':<20} | {f'{raw_avg_c:.1f} Days':<16} | {raw_avg_r:.1f} Versions")
    print("="*95)

    print("\n" + "="*95)
    print(f"  {BOLD}V. CRITICAL OUTLIER ATTACK SURFACE RADIUS POOLS (TOP 10 PER ECOSYSTEM){RESET}")
    print("="*95)
    
    export_outlier_manifests = {}
    for eco in active_matrix_ecosystems:
        pool = ecosystem_outlier_pools.get(eco, {})
        if pool:
            print(f"\n{BOLD}[+] {eco} Top Impact Outliers:{RESET}")
            w_rank, w_id, w_name, w_cvss, w_radius = 5, 20, 28, 6, 22
            print(f"    {'Rank':<{w_rank}} | {'Advisory ID':<{w_id}} | {'Artifact Name':<{w_name}} | {'CVSS':<{w_cvss}} | {'Impact Blast Radius':<{w_radius}} | {'Threat Profile'}")
            print(f"    {'-'*116}")
            
            flat_pool = [{"id": r_id, "radius": item[0], "type": item[1], "name": item[2], "cvss": item[3] if len(item) > 3 else 0.0} for r_id, item in pool.items()]
            full_sorted_pool = sorted(flat_pool, key=lambda x: (-x["cvss"], -x["radius"], x["id"]))
            export_outlier_manifests[eco] = {item["id"]: [item["radius"], item["type"], item["name"], item["cvss"]] for item in full_sorted_pool[:50]}
            
            for rank, item in enumerate(full_sorted_pool[:10], start=1):
                p_name_display = item["name"][:25] + "..." if len(item["name"]) > 28 else item["name"]
                c_score_str = f"{item['cvss']:.1f}"
                r_radius_str = f"{item['radius']:,} Vers"
                
                print(f"    #{rank:<{w_rank-1}} | {item['id']:<{w_id}} | {p_name_display:<{w_name}} | {c_score_str:<{w_cvss}} | {r_radius_str:<{w_radius}} | {item['type']}")
        else:
            export_outlier_manifests[eco] = {}
            print(f"\n[+] {eco}: No critical outliers tracked in this window.")
    print("\n" + "="*95)

    if custom_export_arg:
        output_dir = "./output"
        os.makedirs(output_dir, exist_ok=True)
        
        if isinstance(custom_export_arg, str):
            # Respect explicit paths, including custom velocity snapshot directories.
            # Bare filenames still land in ./output for backwards compatibility.
            if os.path.dirname(custom_export_arg):
                export_path = custom_export_arg
            else:
                export_path = os.path.join(output_dir, os.path.basename(custom_export_arg))
        else:
            filename = f"{start_date.strftime('%d-%m-%y')}_to_{end_date.strftime('%d-%m-%y')}_{target_layer if target_layer else 'all'}.json"
            export_path = os.path.join(output_dir, filename)

        os.makedirs(os.path.dirname(export_path) or ".", exist_ok=True)
        
        export_payload = {
            "metadata": {"generated_at": now.isoformat(), "interval_from": start_date.date().isoformat(), "interval_to": end_date.date().isoformat(), "target_layer_filter": target_layer if target_layer else "all"},
            "leaderboard": {eco: count for eco, count, _ in filtered_results},
            "threat_profile": dict(bucket_counts),
            "malware_vectors": dict(malware_vector_counts) if sum(malware_vector_counts.values()) > 0 else {},
            "profile_matrix": export_profile_matrix,
            "outliers_leaderboards": export_outlier_manifests
        }
        try:
            with open(export_path, 'w', encoding='utf-8') as ef: json.dump(export_payload, ef, indent=4)
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
    """Resolve CLI date flags into one or more report windows without changing legacy defaults."""
    if args.to:
        target_to_dates = " ".join(args.to).replace(",", " ").split()
    else:
        target_to_dates = [None]

    windows = []
    for date_str in target_to_dates:
        if date_str:
            parsed_date = None
            for fmt in ("%Y-%m-%d", "%m-%d-%Y", "%d-%m-%Y"):
                try:
                    parsed_date = datetime.datetime.strptime(date_str, fmt).date()
                    break
                except ValueError:
                    continue
            if not parsed_date:
                print(f"[-] Configuration Error: Unable to parse date '{date_str}'. Skipping.")
                continue
            calculated_end = datetime.datetime.combine(parsed_date, datetime.time.max, tzinfo=datetime.timezone.utc)
        else:
            calculated_end = now_utc

        if args.days:
            calculated_start = calculated_end - datetime.timedelta(days=args.days)
        elif args.from_date:
            calculated_start = datetime.datetime.combine(datetime.date.fromisoformat(args.from_date), datetime.time.min, tzinfo=datetime.timezone.utc)
        else:
            calculated_start = datetime.datetime(2026, 4, 18, 0, 0, 0, tzinfo=datetime.timezone.utc)

        windows.append((calculated_start, calculated_end))

    return windows


def build_snapshot_filename(start_date, end_date, target_layer=None):
    """Match the existing auto-export filename convention for daily snapshot reports."""
    layer_label = target_layer if target_layer else "all"
    return f"{start_date.strftime('%d-%m-%y')}_to_{end_date.strftime('%d-%m-%y')}_{layer_label}.json"


def run_velocity_update(args):
    """
    Append a freshly generated report snapshot into the velocity time series,
    then refresh the velocity CSV/terminal plot and the HTML briefing.
    """
    snapshot_dir = args.velocity or "./output"
    os.makedirs(snapshot_dir, exist_ok=True)

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    windows = calculate_report_windows(args, now_utc)

    print(f"[*] Initializing Velocity Update Pipeline...")
    print(f"[*] Snapshot Directory: {snapshot_dir}")
    global_ghsa_lookup = build_ghsa_ecosystem_map()

    for calculated_start, calculated_end in windows:
        snapshot_name = build_snapshot_filename(calculated_start, calculated_end, args.layer)
        snapshot_path = os.path.join(snapshot_dir, snapshot_name)

        print(f"\n[*] Appending Velocity Snapshot: {snapshot_path}")
        generate_enterprise_threat_leaderboard(
            start_date=calculated_start,
            end_date=calculated_end,
            target_layer=args.layer,
            debug_mode=args.debug,
            custom_export_arg=snapshot_path,
            run_speedway=args.speedway,
            project_file_path=args.project_file,
            forced_format=args.project_format,
            audit_mode=args.audit,
            ghsa_lookup=global_ghsa_lookup
        )

    matrix_path = os.path.join(snapshot_dir, "velocity_matrix.csv")
    generate_velocity_matrix(target_dir=snapshot_dir, output_path=matrix_path, render_terminal_plot=args.terminal_plot)

    html_path = args.html if args.html else os.path.join(snapshot_dir, "briefing.html")
    snapshots = load_snapshots_from_dir(snapshot_dir)
    if snapshots:
        generate_html_report(snapshots, html_path)
    else:
        print("[-] HTML report skipped: no valid snapshots available after velocity update.")

# ==============================================================================
# ENTRY ENGINE EXECUTIVE PARSER ROUTINES
# ==============================================================================
def main(): 
    parser = argparse.ArgumentParser(description="OSV Threat Stream Campaign Dashboard Indicator.")
    parser.add_argument("--layer", choices=["container", "app"], help="Isolate the dashboard layout by layer type.")
    parser.add_argument("--days", type=int, help="Relative lookback day window shortcut from today.")
    parser.add_argument("--from", metavar="YYYY-MM-DD", dest="from_date", help="Explicit chronological interval starting boundary.")
    parser.add_argument("--to", nargs='+', metavar="YYYY-MM-DD", help="Explicit chronological interval ending boundary. Accepts multiple dates for batch generation.")
    parser.add_argument("--debug", action="store_true", help="Surface raw, untagged noise.")
    parser.add_argument("--export", nargs='?', const=True, default=False, help="Auto-generate or name a static JSON snapshot payload.")
    parser.add_argument("--compare", nargs=2, metavar=('BASE_JSON', 'CURRENT_JSON'), help="Compare two snapshots to output dynamic variance metrics.")
    parser.add_argument("--speedway", action="store_true", help="Analyze live timeline log velocity distribution metrics.")
    parser.add_argument("--project-file", metavar="PATH", help="Path to project dependency tree output or standard SBOM.")
    parser.add_argument("--project-format", choices=list(MANIFEST_PARSER_REGISTRY.keys()), help="Force a manual schema parser profile selection.")
    parser.add_argument("--audit", metavar="MANIFEST_PATH", help="Ingest a local lockfile/requirements format directly to track active blast radius breaches.")
    parser.add_argument("--velocity", nargs="?", const="./output", metavar="DIR_PATH", help="Append a new snapshot to DIR_PATH, then refresh the velocity CSV, terminal plot, and HTML briefing. Defaults to ./output when no path is supplied.")
    parser.add_argument("--html", metavar="OUTPUT_FILE", help="Generate or override the briefing-ready HTML report path. With --velocity, defaults to DIR_PATH/briefing.html.")
    parser.add_argument("--terminal-plot", action="store_true", help="With --velocity, also render the plotext terminal chart. Off by default because plotext can obscure prior terminal output.")
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
    
    print(f"[*] Initializing Batch Execution Environment...")
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
            ghsa_lookup=global_ghsa_lookup
        )

if __name__ == "__main__":
    main()