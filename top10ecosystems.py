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


# Cross-registry product-identity signal: matches "github.com/OWNER/REPO" wherever it shows up,
# either in an advisory's own reference links or embedded directly in a Go-ecosystem purl
# (pkg:golang/github.com/OWNER/REPO...). Mirrors db_warehouse.py's own copy of this constant/
# helper (the two modules don't import each other, matching the existing extract_cvss_score /
# extract_production_cvss split), used by extract_repo_anchor() below for the ZIP-fallback
# ingestion path in build_ghsa_ecosystem_map().
GITHUB_REPO_URL_REGEX = re.compile(r'github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)', re.IGNORECASE)
_GITHUB_REPO_ANCHOR_SKIP = {"advisories", "security", "security-advisories", ".github"}

# Namespace prefixes that mark a MECHANICAL, unmodified repackaging of another ecosystem's
# artifact -- not a native release. Maven's "webjars" project is the textbook example: it wraps
# npm/Bower JS libraries into Maven coordinates verbatim, byte-identical code, different registry.
# This is the same pattern the user described for RHEL/Debian OS-vendor repackaging.
_REPACKAGE_PURL_NAMESPACES = ("pkg:maven/org.webjars",)


def extract_repo_anchor(vuln_data):
    """Derives a canonical 'owner/repo' identity string for an advisory (see db_warehouse.py's
    identical helper for the full rationale). Used by the Section VIII cross-registry
    classification to recognize a genuinely multi-ecosystem NATIVE release of the same upstream
    project, as distinct from one ecosystem mechanically vendoring another's code as-is."""
    candidates = Counter()

    for ref in vuln_data.get("references", []):
        url = ref.get("url", "") or ""
        m = GITHUB_REPO_URL_REGEX.search(url)
        if m:
            owner, repo = m.group(1).lower(), re.sub(r'\.git$', '', m.group(2), flags=re.IGNORECASE).lower()
            if repo in _GITHUB_REPO_ANCHOR_SKIP:
                continue
            candidates[f"{owner}/{repo}"] += 1

    for affected in vuln_data.get("affected", []):
        purl = affected.get("package", {}).get("purl", "") or ""
        m = GITHUB_REPO_URL_REGEX.search(purl)
        if m:
            owner, repo = m.group(1).lower(), re.sub(r'\.git$', '', m.group(2), flags=re.IGNORECASE).lower()
            if repo in _GITHUB_REPO_ANCHOR_SKIP:
                continue
            candidates[f"{owner}/{repo}"] += 2

    if not candidates:
        return None
    return candidates.most_common(1)[0][0]


def normalize_package_token(name: str) -> str:
    """Strips punctuation/casing so the same underlying product name can be recognized across
    ecosystem naming conventions (e.g. 'org.apache.spark:spark-core_2.12' vs 'pyspark')."""
    if not name:
        return ""
    return re.sub(r'[^a-z0-9]+', '', name.strip().lower())


# Confidence ranking for the signals classify_cross_registry_pair() can fire on -- only the
# webjars-style namespace check is an explicit, known convention; everything else is a naming
# heuristic that can misfire on coincidence, so callers that render this to a human (Section VIII)
# should say so rather than presenting every verdict as equally certain. Higher = more trustworthy.
_CROSS_REGISTRY_CONFIDENCE_RANK = {"confirmed": 3, "high": 2, "medium": 1, "low": 0}

_CROSS_REGISTRY_SIGNAL_LABELS = {
    "known-repackaging-namespace": "known repackaging convention (e.g. Maven webjars)",
    "shared-upstream-repo": "both trace to the same upstream repo",
    "exact-name-match": "identical name, no other corroborating evidence",
    "name-substring-wrap": "one name wraps the other",
}


def _classify_cross_registry_pair_detailed(name_a: str, purl_a: str, name_b: str, purl_b: str, repo_anchor: str):
    """Does the actual classification work for classify_cross_registry_pair() (see that function
    for the rule-by-rule rationale), additionally returning a confidence tier and a short signal
    tag so callers can be honest about how much to trust the verdict instead of asserting it as
    fact. Returns (verdict, confidence, signal) -- all three None when unrelated/no match."""
    if any((purl_a or "").startswith(p) or (purl_b or "").startswith(p) for p in _REPACKAGE_PURL_NAMESPACES):
        return "repackaged", "confirmed", "known-repackaging-namespace"

    norm_a, norm_b = normalize_package_token(name_a), normalize_package_token(name_b)
    if not norm_a or not norm_b:
        return None, None, None

    if repo_anchor:
        owner, _, repo = repo_anchor.partition("/")
        owner_tok, repo_tok = normalize_package_token(owner), normalize_package_token(repo)
        for tok in (repo_tok, owner_tok):
            if tok and len(tok) >= 3 and tok in norm_a and tok in norm_b:
                return "cross_compiled", "high", "shared-upstream-repo"

    if norm_a == norm_b:
        # Weakest signal in the set: two identical short names could just as easily be an
        # unrelated coincidence (a generic word like "core" or "utils") as a genuine parallel
        # native release, and we have no corroborating repo/namespace evidence either way.
        return "cross_compiled", "low", "exact-name-match"

    if norm_a in norm_b or norm_b in norm_a:
        return "repackaged", "medium", "name-substring-wrap"

    return None, None, None


def classify_cross_registry_pair(name_a: str, purl_a: str, name_b: str, purl_b: str, repo_anchor: str):
    """Classifies a pair of same-advisory, different-ecosystem package identities as either a
    genuinely 'cross-compiled' native release of the same project, or a mechanical repackaging
    of one into the other. Returns 'cross_compiled', 'repackaged', or None (unrelated/no
    recognizable relationship). Method order matches the agreed design: try the repo-identity
    cross-reference first (purl/reference-derived), fall back to normalized name matching.

    1. Maven webjars namespace on either side -> always 'repackaged' (mechanical, unambiguous;
       checked first so an incidentally-matching name/repo token doesn't override it).
    2. Both normalized names contain the repo_anchor's owner or repo token -> 'cross_compiled'
       (both trace back to the same canonical upstream project; a strong, explicit signal).
    3. Exact normalized-name match with no wrapping evidence -> 'cross_compiled' (parallel
       identical-name releases, e.g. the same 'bootstrap' name ported to several registries).
    4. One normalized name is a proper substring of the other -> 'repackaged' (a decorated/
       prefixed/suffixed wrap of the shorter core name -- 'bootstrap-sass' wraps 'bootstrap',
       'python3-jinja2' wraps 'jinja2').
    5. Otherwise -> None.

    See _classify_cross_registry_pair_detailed() for the confidence-tagged version of this same
    logic, used by Section VIII's rendering so low-confidence verdicts (rule 3) aren't shown with
    the same certainty as confirmed ones (rule 1).
    """
    return _classify_cross_registry_pair_detailed(name_a, purl_a, name_b, purl_b, repo_anchor)[0]


def classify_advisory_cross_registry(package_names_by_ecosystem: dict, purls_by_ecosystem: dict, repo_anchor: str):
    """Given one advisory's per-ecosystem package names/purls, returns (is_cross_compiled,
    is_repackaged) booleans -- an advisory can exhibit both patterns across different ecosystem
    pairs (e.g. bootstrap: natively ported to several registries AND separately repackaged into
    Maven via webjars), so this reports both rather than forcing a single verdict per advisory."""
    ecosystems = sorted(package_names_by_ecosystem.keys())
    found_cross_compiled = False
    found_repackaged = False

    for i in range(len(ecosystems)):
        for j in range(i + 1, len(ecosystems)):
            eco_a, eco_b = ecosystems[i], ecosystems[j]
            names_a = package_names_by_ecosystem.get(eco_a) or []
            names_b = package_names_by_ecosystem.get(eco_b) or []
            purls_a = (purls_by_ecosystem or {}).get(eco_a) or []
            purls_b = (purls_by_ecosystem or {}).get(eco_b) or []
            for na in names_a:
                for nb in names_b:
                    pa = purls_a[0] if purls_a else ""
                    pb = purls_b[0] if purls_b else ""
                    verdict = classify_cross_registry_pair(na, pa, nb, pb, repo_anchor)
                    if verdict == "cross_compiled": found_cross_compiled = True
                    elif verdict == "repackaged": found_repackaged = True

    return found_cross_compiled, found_repackaged


def classify_advisory_cross_registry_evidence(package_names_by_ecosystem: dict, purls_by_ecosystem: dict, repo_anchor: str):
    """Like classify_advisory_cross_registry(), but instead of plain booleans returns the
    strongest piece of evidence found for each verdict, so Section VIII can show a reader WHICH
    ecosystem pair and WHICH signal drove a classification instead of asserting it with false
    certainty. Returns (cross_compiled_evidence, repackaged_evidence); each is either None (no
    matching pair found) or a dict: {eco_a, eco_b, name_a, name_b, confidence, signal}. When
    multiple pairs support the same verdict, the highest-confidence one wins."""
    ecosystems = sorted(package_names_by_ecosystem.keys())
    best_cross_compiled = None
    best_repackaged = None

    for i in range(len(ecosystems)):
        for j in range(i + 1, len(ecosystems)):
            eco_a, eco_b = ecosystems[i], ecosystems[j]
            names_a = package_names_by_ecosystem.get(eco_a) or []
            names_b = package_names_by_ecosystem.get(eco_b) or []
            purls_a = (purls_by_ecosystem or {}).get(eco_a) or []
            purls_b = (purls_by_ecosystem or {}).get(eco_b) or []
            for na in names_a:
                for nb in names_b:
                    pa = purls_a[0] if purls_a else ""
                    pb = purls_b[0] if purls_b else ""
                    verdict, confidence, signal = _classify_cross_registry_pair_detailed(na, pa, nb, pb, repo_anchor)
                    if verdict is None:
                        continue
                    entry = {"eco_a": eco_a, "eco_b": eco_b, "name_a": na, "name_b": nb,
                              "confidence": confidence, "signal": signal}
                    if verdict == "cross_compiled":
                        if best_cross_compiled is None or _CROSS_REGISTRY_CONFIDENCE_RANK[confidence] > _CROSS_REGISTRY_CONFIDENCE_RANK[best_cross_compiled["confidence"]]:
                            best_cross_compiled = entry
                    elif verdict == "repackaged":
                        if best_repackaged is None or _CROSS_REGISTRY_CONFIDENCE_RANK[confidence] > _CROSS_REGISTRY_CONFIDENCE_RANK[best_repackaged["confidence"]]:
                            best_repackaged = entry

    return best_cross_compiled, best_repackaged


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
                            names_by_eco = {}
                            purls_by_eco = {}
                            for affected in vuln_data.get("affected", []):
                                pkg_block = affected.get("package", {})
                                eco = pkg_block.get("ecosystem")
                                name = pkg_block.get("name")
                                purl = pkg_block.get("purl")
                                if eco: ecosystems.add(eco)
                                if name: p_name = name.strip()
                                for v in affected.get("versions", []): vuln_versions.add(str(v).strip())
                                v_len = len(affected.get("versions", []))
                                if v_len > max_versions_found: max_versions_found = v_len
                                for ranges in affected.get("ranges", []):
                                    for events in ranges.get("events", []):
                                        if "fixed" in events: has_fixes = True
                                # Per-ecosystem package identity (see db_warehouse.py's parse_osv_json
                                # for the full rationale) -- keyed by the SAME raw eco tag this
                                # function already stores in `ecosystems`, not the hard-mapped name.
                                if eco and name:
                                    clean_name = name.strip()
                                    bucket = names_by_eco.setdefault(eco, [])
                                    if clean_name and clean_name not in bucket:
                                        bucket.append(clean_name)
                                if eco and purl:
                                    bucket = purls_by_eco.setdefault(eco, [])
                                    if purl not in bucket:
                                        bucket.append(purl)
                            
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
                                    "last_modified": modified_str[:10],
                                    "package_names_by_ecosystem": names_by_eco,
                                    "purls_by_ecosystem": purls_by_eco,
                                    "repo_anchor": extract_repo_anchor(vuln_data)
                                }
                        except json.JSONDecodeError: continue 
        print(f"[+] Successfully indexed {len(id_to_meta):,} global advisory mappings.")
    except Exception as e:
        print(f"[-] Failed to read master archive: {e}")
    return id_to_meta


def _priority_sort_key(entry: dict, id_val: str, priority_sort_active: bool = False):
    """
    Shared sort key used everywhere a vulnerability list gets ranked: the
    global/per-ecosystem rank maps, and the Section V/VI/VII top-N picks.

    When priority_sort_active is False, this is exactly the original
    (-cvss_score, -blast_radius, id) tuple -- unchanged sort order, so
    default (--priority-sort omitted) output and golden masters are
    unaffected byte-for-byte.

    When True, ranking becomes KEV catalog hit (desc) -> EPSS score (desc)
    -> CVSS (desc) -> blast radius (desc) -> id (asc), matching the same
    KEV -> EPSS -> OSV/CVSS priority already used by --crosscheck.
    """
    cvss = entry.get("cvss_score", 0.0) or 0.0
    radius = entry.get("blast_radius", 0) or 0

    if not priority_sort_active:
        return (-cvss, -radius, id_val)

    kev_hit = 0 if entry.get("kev_date_added") else 1
    epss = entry.get("epss_score") or 0.0
    return (kev_hit, -epss, -cvss, -radius, id_val)


def build_ghsa_from_db(db_path: str = "database/threat_stream.db", target_registries: list = None, *, priority_sort: bool = False) -> dict:
    """Queries the local SQLite warehouse to build a legacy-compatible memory lookup map.

    priority_sort=False (default): identical query/behavior to before this
    flag existed -- no join, no new dict keys, zero risk to existing output.
    priority_sort=True: additionally LEFT JOINs epss_scores/kev_catalog on
    cve_alias, adding epss_score/epss_percentile/kev_date_added/kev_due_date
    to each entry for the ranking sites that opt into _priority_sort_key().
    """
    id_to_meta = {}
    if not os.path.exists(db_path):
        return build_ghsa_ecosystem_map()
        
    filter_set = {r.strip().lower() for r in target_registries} if target_registries else None
    print(f"[*] Extracting global context from SQLite warehouse: {db_path}...")
    if filter_set:
        print(f"    -> Applying localized registry isolation filter: {list(filter_set)}")
    if priority_sort:
        print(f"    -> --priority-sort active: joining EPSS/KEV enrichment into rank map.")
        
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # BACKWARD COMPAT: package_names_by_ecosystem/purls_by_ecosystem/repo_anchor are new
        # columns (Section VIII cross-registry rework). A warehouse that hasn't been re-ingested
        # since the schema migration still gets these columns via ALTER TABLE (see
        # db_warehouse.py's init_database), but the values are NULL until --rebuild re-ingests --
        # so we always select them when present rather than crashing on an older physical file.
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        available_cols = {row[1] for row in cursor.fetchall()}
        has_cross_registry_cols = {"package_names_by_ecosystem", "purls_by_ecosystem", "repo_anchor"} <= available_cols

        if priority_sort:
            cross_reg_select = ", v.package_names_by_ecosystem, v.purls_by_ecosystem, v.repo_anchor" if has_cross_registry_cols else ""
            cursor.execute(f"""
                SELECT v.advisory_id, v.package_name, v.cvss_score, v.blast_radius, v.threat_profile,
                       v.ecosystems, v.last_modified, v.malware_vector, v.vulnerable_versions, v.dwell_days,
                       e.epss_score, e.percentile, k.date_added, k.due_date{cross_reg_select}
                FROM vulnerabilities v
                LEFT JOIN epss_scores e ON v.cve_alias = e.cve_id
                LEFT JOIN kev_catalog k ON v.cve_alias = k.cve_id
            """)
        else:
            cross_reg_select = ", package_names_by_ecosystem, purls_by_ecosystem, repo_anchor" if has_cross_registry_cols else ""
            cursor.execute(f"""
                SELECT advisory_id, package_name, cvss_score, blast_radius, threat_profile, ecosystems, last_modified, malware_vector, vulnerable_versions, dwell_days{cross_reg_select}
                FROM vulnerabilities
            """)

        for row in cursor.fetchall():
            row = list(row)
            names_by_eco_json = purls_by_eco_json = repo_anchor = None
            if has_cross_registry_cols:
                names_by_eco_json, purls_by_eco_json, repo_anchor = row[-3], row[-2], row[-1]
                row = row[:-3]

            if priority_sort:
                v_id, p_name, cvss, radius, t_profile, ecos_json, last_mod, m_vector, v_versions_json, dwell_days, epss_score, epss_pct, kev_added, kev_due = row
            else:
                v_id, p_name, cvss, radius, t_profile, ecos_json, last_mod, m_vector, v_versions_json, dwell_days = row
            ecosystems_list = json.loads(ecos_json) if ecos_json else ["Android"]

            # PERFORMANCE WIN: Early rejection exit prior to heavy allocations
            if filter_set:
                if not any(e.lower() in filter_set for e in ecosystems_list):
                    continue

            version_set = set(json.loads(v_versions_json)) if v_versions_json else set()
            meta_entry = {
                "ecosystems": ecosystems_list,
                "package_name": p_name,
                "type": t_profile,
                "vector": m_vector,
                "dwell_days": dwell_days,
                "blast_radius": radius,
                "vulnerable_versions": version_set,
                "cvss_score": cvss,
                "last_modified": last_mod,
                "package_names_by_ecosystem": json.loads(names_by_eco_json) if names_by_eco_json else {},
                "purls_by_ecosystem": json.loads(purls_by_eco_json) if purls_by_eco_json else {},
                "repo_anchor": repo_anchor
            }
            if priority_sort:
                meta_entry["epss_score"] = epss_score
                meta_entry["epss_percentile"] = epss_pct
                meta_entry["kev_date_added"] = kev_added
                meta_entry["kev_due_date"] = kev_due
            id_to_meta[v_id] = meta_entry
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


def print_section_v_outlier_pools(active_matrix_ecosystems, ecosystem_outlier_pools, eco_absolute_ranks, global_absolute_ranks, export_outlier_manifests, *, priority_sort_active: bool = False):
    """Renders Section V: Critical Outlier Attack Surface Radius Pools."""
    print("\n" + "="*115)
    print(f"  {BOLD}V. CRITICAL OUTLIER ATTACK SURFACE RADIUS POOLS{RESET}")
    if priority_sort_active:
        print(f"  {YELLOW}[--priority-sort active] Ranked KEV -> EPSS -> CVSS/Blast Radius{RESET}")
    print("="*115)
    
    for eco in active_matrix_ecosystems:
        pool = ecosystem_outlier_pools.get(eco, {})
        if pool:
            print(f"\n{BOLD}[+] {eco} Top Impact Outliers:{RESET}")
            w_rank, w_id, w_name, w_cvss, w_radius = 6, 56, 22, 6, 22
            w_type = 34
            w_epss_kev = 28
            # Default-mode width is untouched (pre-existing, out of scope here). Priority-sort mode
            # bolts an EPSS/KEV column onto the end without ever widening this divider to match, so
            # the column (and most data rows) print past the right edge of the box -- widen it to
            # actually cover every column + separator once that column exists.
            if priority_sort_active:
                total_line_len = w_rank + w_id + w_name + w_cvss + w_radius + w_type + w_epss_kev + 3 * 6
            else:
                total_line_len = w_rank + w_id + w_name + w_cvss + w_radius + 16

            if priority_sort_active:
                print(f"    {'Rank':<{w_rank}} | {'Advisory ID / Rank Tracking Matrix':<{w_id}} | {'Artifact Name':<{w_name}} | {'CVSS':<{w_cvss}} | {'Impact Blast Radius':<{w_radius}} | {'Threat Profile':<{w_type}} | {'EPSS / KEV':<{w_epss_kev}}")
            else:
                print(f"    {'Rank':<{w_rank}} | {'Advisory ID / Rank Tracking Matrix':<{w_id}} | {'Artifact Name':<{w_name}} | {'CVSS':<{w_cvss}} | {'Impact Blast Radius':<{w_radius}} | {'Threat Profile'}")
            print(f"    {'-' * total_line_len}")
            
            flat_pool = [{
                "id": r_id, "radius": item[0], "type": item[1], "name": item[2],
                "cvss": item[3] if len(item) > 3 else 0.0,
                "epss": item[4] if len(item) > 4 else None,
                "kev": item[5] if len(item) > 5 else None,
            } for r_id, item in pool.items()]
            full_sorted_pool = sorted(
                flat_pool,
                key=lambda x: _priority_sort_key(
                    {"cvss_score": x["cvss"], "blast_radius": x["radius"], "epss_score": x["epss"], "kev_date_added": x["kev"]},
                    x["id"], priority_sort_active
                )
            )
            if priority_sort_active:
                export_outlier_manifests[eco] = {item["id"]: [item["radius"], item["type"], item["name"], item["cvss"], item["epss"], item["kev"]] for item in full_sorted_pool[:50]}
            else:
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

                if priority_sort_active:
                    type_str = (item['type'][:w_type-1] + "\u2026") if len(item['type']) > w_type else item['type']
                    epss_str = f"{item['epss']*100:.1f}%" if item['epss'] is not None else "N/A"
                    kev_str = f"{RED}KEV: {item['kev']}{RESET}" if item['kev'] else "-"
                    epss_kev_str = f"{epss_str} / {kev_str}"
                    print(f"    {rank_str:<{w_rank}} | {id_column_display:<{w_id}} | {artifact_str:<{w_name}} | {cvss_str:<{w_cvss}} | {radius_str:<{w_radius}} | {type_str:<{w_type}} | {epss_kev_str:<{w_epss_kev}}")
                else:
                    print(f"    {rank_str:<{w_rank}} | {id_column_display:<{w_id}} | {artifact_str:<{w_name}} | {cvss_str:<{w_cvss}} | {radius_str:<{w_radius}} | {item['type']}")
        else: export_outlier_manifests[eco] = {}


def print_section_vi_new_arrivals(active_matrix_ecosystems, live_window_new_arrivals, ghsa_lookup, global_absolute_ranks, *, priority_sort_active: bool = False):
    """Renders Section VI: New Arrivals & Campaign Discoveries Within Timeframe."""
    print(f"\n{BOLD}VI. NEW ARRIVALS & CAMPAIGN DISCOVERIES WITHIN TIMEFRAME{RESET}")
    if priority_sort_active:
        print(f"{YELLOW}[--priority-sort active] Ranked KEV -> EPSS -> CVSS/Blast Radius{RESET}")
    print("=" * 115)
    
    # Priority-sort mode bolts an EPSS/KEV column onto a box sized for the three original columns
    # (52 + 30 + 28 wide); without widening the divider to match, the new column and most rows
    # print past the right edge of the box. Padding the cell itself to a fixed width (below) keeps
    # every row's right edge in the same place the divider now expects.
    w_epss_kev = 28
    divider_width = (52 + 3 + 30 + 3 + 28 + 3 + w_epss_kev) if priority_sort_active else 115

    for eco in active_matrix_ecosystems:
        print(f"\n{BOLD}[+] Ecosystem/Registry New Entries: {eco}{RESET}")
        print("-" * divider_width)
        if priority_sort_active:
            print(f"{'New Threat Arrival Matrix':<52} | {'Artifact Name':<30} | {'Discovery Impact':<28} | {'EPSS / KEV':<{w_epss_kev}}")
        else:
            print(f"{'New Threat Arrival Matrix':<52} | {'Artifact Name':<30} | {'Discovery Impact'}")
        print("-" * divider_width)
        
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
            key=lambda x: _priority_sort_key(x, x['injected_id'], priority_sort_active)
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

                if priority_sort_active:
                    epss_score = vuln.get('epss_score')
                    epss_str = f"{epss_score*100:.1f}%" if epss_score is not None else "N/A"
                    kev_due = vuln.get('kev_date_added')
                    kev_str = f"{RED}KEV: {kev_due}{RESET}" if kev_due else "-"
                    epss_kev_str = f"{epss_str} / {kev_str}"
                    print(f"{id_column_display:<52} | {p_name[:27]:<30} | {severity_display:<28} | {epss_kev_str:<{w_epss_kev}}")
                else:
                    print(f"{id_column_display:<52} | {p_name[:27]:<30} | {severity_display}")
        else:
            print("    [-] Zero newly published threat profiles or malicious entry drops recorded in this lookback window.")
        print("-" * divider_width)


def print_section_vii_attention_deficit(active_matrix_ecosystems, ghsa_lookup, global_absolute_ranks, end_date, *, priority_sort_active: bool = False):
    """Renders Section VII: Systemic Risk Vs. Active Exposure (The Attention Deficit)."""
    print(f"\n{BOLD}VII. SYSTEMIC RISK VS. ACTIVE EXPOSURE (THE ATTENTION DEFICIT){RESET}")
    if priority_sort_active:
        print(f"{YELLOW}[--priority-sort active] Ranked KEV -> EPSS -> CVSS/Blast Radius{RESET}")
    print("=" * 115)
    # Same fix as Section VI: --priority-sort adds an EPSS/KEV column to a box drawn for the three
    # original columns, so the divider needs widening (and the new cell fixed-width-padded) to
    # actually contain it instead of trailing off mid-row.
    w_epss_kev = 28
    divider_width = (52 + 3 + 30 + 3 + 28 + 3 + w_epss_kev) if priority_sort_active else 115
    for eco in active_matrix_ecosystems:
        print(f"\n{BOLD}[+] Ecosystem/Registry Hierarchy: {eco}{RESET}")
        print("-" * divider_width)
        if priority_sort_active:
            print(f"{'Static Risk Position Matrix':<52} | {'Artifact Name':<30} | {'Last Active':<28} | {'EPSS / KEV':<{w_epss_kev}}")
        else:
            print(f"{'Static Risk Position Matrix':<52} | {'Artifact Name':<30} | {'Last Active'}")
        print("-" * divider_width)
        
        valid_eco_records = []
        eco_lower_def = eco.lower()
        for vuln_id, meta in ghsa_lookup.items():
            if any(raw_eco.lower() in eco_lower_def for raw_eco in meta.get('ecosystems', [])) and isinstance(vuln_id, str) and vuln_id.strip():
                meta_with_id = meta.copy()
                meta_with_id['injected_id'] = vuln_id
                valid_eco_records.append(meta_with_id)

        static_top_10 = sorted(
            valid_eco_records, 
            key=lambda x: _priority_sort_key(x, x['injected_id'], priority_sort_active)
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

            if priority_sort_active:
                epss_score = vuln.get('epss_score')
                epss_str = f"{epss_score*100:.1f}%" if epss_score is not None else "N/A"
                kev_due = vuln.get('kev_date_added')
                kev_str = f"{RED}KEV: {kev_due}{RESET}" if kev_due else "-"
                epss_kev_str = f"{epss_str} / {kev_str}"
                print(f"{id_column_display:<52} | {p_name[:27]:<30} | {status_display:<28} | {epss_kev_str:<{w_epss_kev}}")
            else:
                print(f"{id_column_display:<52} | {p_name[:27]:<30} | {status_display}")
        print("-" * divider_width)


def rank_cross_registry_tables(ghsa_lookup: dict, session_advisory_ids: set, top_n: int = 10):
    """Scans this session's in-scope advisories for cross-registry package relationships and
    ranks the top N for each of the two Section VIII tables:
      - Table A (true cross-compiled): the same project natively released to multiple registries.
      - Table B (repackaged-as-is): one registry's package is a mechanical, unmodified vendoring
        of another's code (the RHEL/Debian-style repackaging pattern the user flagged).
    An advisory can land in both tables (e.g. Bootstrap: natively ported to several registries
    AND separately vendored into Maven via webjars) -- see classify_advisory_cross_registry().
    Ranked by ecosystem span (desc, i.e. how many registries it touches), then CVSS (desc).
    Returns (table_a_rows, table_b_rows); each row is (advisory_id, ecosystem_count, cvss_score,
    package_names_by_ecosystem, evidence) -- evidence is the dict from
    classify_advisory_cross_registry_evidence() explaining which specific ecosystem pair and
    signal earned this row its table membership (see that function for the shape)."""
    table_a_candidates = []
    table_b_candidates = []

    for v_id in session_advisory_ids:
        meta = ghsa_lookup.get(v_id)
        if not meta:
            continue
        names_by_eco = meta.get("package_names_by_ecosystem") or {}
        if len(names_by_eco) < 2:
            continue

        cross_compiled_evidence, repackaged_evidence = classify_advisory_cross_registry_evidence(
            names_by_eco, meta.get("purls_by_ecosystem") or {}, meta.get("repo_anchor")
        )
        cvss = meta.get("cvss_score", 0.0) or 0.0
        if cross_compiled_evidence:
            table_a_candidates.append((v_id, len(names_by_eco), cvss, names_by_eco, cross_compiled_evidence))
        if repackaged_evidence:
            table_b_candidates.append((v_id, len(names_by_eco), cvss, names_by_eco, repackaged_evidence))

    sort_key = lambda r: (-r[1], -r[2], r[0])
    table_a = sorted(table_a_candidates, key=sort_key)[:top_n]
    table_b = sorted(table_b_candidates, key=sort_key)[:top_n]
    return table_a, table_b


_CROSS_REGISTRY_EVIDENCE_MAX_WIDTH = 62


def _format_cross_registry_evidence(evidence: dict, max_width: int = _CROSS_REGISTRY_EVIDENCE_MAX_WIDTH) -> str:
    """Renders the specific ecosystem pair and signal that earned a Section VIII row its table
    membership, so a reader can see WHY it was classified that way instead of taking the verdict
    on faith -- two rows for the same advisory across tables A/B will cite different pairs/signals
    rather than looking like duplicates of each other."""
    if not evidence:
        return ""
    label = _CROSS_REGISTRY_SIGNAL_LABELS.get(evidence["signal"], evidence["signal"])
    text = f"{evidence['eco_a']} \"{evidence['name_a']}\" vs {evidence['eco_b']} \"{evidence['name_b']}\" -- {label}"
    if len(text) > max_width:
        text = text[:max_width - 1] + "…"
    return text


def print_section_viii_cross_registry_tables(table_a, table_b):
    """Renders the two Section VIII replacement tables (see rank_cross_registry_tables): true
    cross-compiled native multi-registry releases, and repackaged-as-is mechanical vendoring.
    Each row shows a Confidence tier and the ecosystem-pair evidence behind it -- classification
    here is a naming/purl heuristic, not a verified fact, so the weakest signal (two identical
    names with no other corroboration) is labeled LOW rather than presented as certain."""
    print("\n" + "="*125)
    print(f"  {BOLD}VIII-A. TRUE CROSS-COMPILED ADVISORIES (SAME PROJECT, NATIVE MULTI-REGISTRY RELEASE){RESET}")
    print("="*125)
    if not table_a:
        print("  [+] Zero advisories in this execution frame matched a same-project, multi-registry native-release pattern.")
    else:
        print(f"{'Advisory ID':<24} | {'Registries':<11} | {'CVSS':<6} | {'Confidence':<10} | {'Evidence'}")
        print("-" * 125)
        for v_id, eco_count, cvss, names_by_eco, evidence in table_a:
            print(f"{v_id:<24} | {eco_count:<11} | {cvss:<6.1f} | {evidence['confidence'].upper():<10} | {_format_cross_registry_evidence(evidence)}")
    print("="*125)

    print("\n" + "="*125)
    print(f"  {BOLD}VIII-B. REPACKAGED-AS-IS ADVISORIES (VENDORED UNMODIFIED ACROSS REGISTRIES){RESET}")
    print("="*125)
    if not table_b:
        print("  [+] Zero advisories in this execution frame matched a mechanical repackaging pattern (e.g. Maven webjars, distro rewraps).")
    else:
        print(f"{'Advisory ID':<24} | {'Registries':<11} | {'CVSS':<6} | {'Confidence':<10} | {'Evidence'}")
        print("-" * 125)
        for v_id, eco_count, cvss, names_by_eco, evidence in table_b:
            print(f"{v_id:<24} | {eco_count:<11} | {cvss:<6.1f} | {evidence['confidence'].upper():<10} | {_format_cross_registry_evidence(evidence)}")
    print("="*125 + "\n")


def serialize_snapshot_payload(custom_export_arg, now, start_date, end_date, target_layer, filtered_results, bucket_counts, layer_bucket_counts, intel_feed_matrix, malware_vector_counts, export_profile_matrix, export_outlier_manifests, *, priority_sort_active: bool = False):
    """Handles snapshot backup serialization routines to disk schema layout."""
    if not custom_export_arg:
        return

    output_dir = "./output"
    os.makedirs(output_dir, exist_ok=True)
    if isinstance(custom_export_arg, str):
        export_path = custom_export_arg
    else:
        layer_tag = target_layer if target_layer else 'all'
        suffix = "_priority" if priority_sort_active else ""
        export_path = os.path.join(output_dir, f"threat_landscape_{end_date.strftime('%Y-%m-%d')}_{layer_tag}{suffix}.json")

    os.makedirs(os.path.dirname(export_path) or ".", exist_ok=True)
    try:
        with open(export_path, 'w', encoding='utf-8') as ef:
            json.dump({
                "metadata": {
                    "generated_at": now.isoformat(), 
                    "interval_from": start_date.date().isoformat(), 
                    "interval_to": end_date.date().isoformat(), 
                    "target_layer_filter": target_layer if target_layer else "all",
                    "priority_sort_active": priority_sort_active
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
    manifest_rows: list = None, *, priority_sort_active: bool = False, target_registries: list = None
    ):
    now = datetime.datetime.now(datetime.timezone.utc)

    # FIX: --registry has always filtered ghsa_lookup (via build_ghsa_from_db) but was never
    # applied to THIS function's own raw manifest-stream counting pass -- the loop below that
    # produces Sections I/II/III and total_raw_rows walks the full unfiltered OSV stream index
    # regardless of --registry, bucketing purely by path prefix. That's why a bare --registry
    # run (no --layer) looked "dead": container OS churn (Chainguard/Debian/etc.) swamps the
    # unfiltered top-10, so the requested registries never surface. Mirrors the exact filter_set
    # construction/semantics already used in build_ghsa_from_db for consistency between the two
    # filtered code paths (case-insensitive exact match on the raw, pre-hard-mapping ecosystem tag).
    registry_filter_set = {r.strip().lower() for r in target_registries} if target_registries else None

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
        key=lambda x: _priority_sort_key(x[1], x[0], priority_sort_active)
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
        sorted_bucket = sorted(advisories, key=lambda x: _priority_sort_key(x[1], x[0], priority_sort_active))
        eco_absolute_ranks[eco_name] = {advisory_id: rank for rank, (advisory_id, _) in enumerate(sorted_bucket, start=1)}

    manifest_url = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"   
    total_raw_rows = 0
    project_intercept_alerts = []

    bucket_counts = Counter({"Malware (New Entry)": 0, "Malware (Incremental Update)": 0, "Vulnerability Fix (New Entry)": 0, "Vulnerability Fix (Update)": 0, "Metadata Correction / Adjustments": 0})
    layer_bucket_counts = defaultdict(Counter)
    
    intel_feed_matrix = defaultdict(lambda: {"total": 0, "malware": 0, "cve": 0, "max_radius": 0})
    intel_sig_regex = re.compile(r'(x86|amd64|x64|intel|elf64|pe32|win-64|linux-64)', re.IGNORECASE)
    malware_vector_counts = Counter({"Typosquatting / Brand Hijacking": 0, "Dependency Confusion Campaign": 0, "Data Exfiltration / Credential Stealer": 0, "Persistent Backdoor / Execution Shell": 0, "Unclassified Malicious Payload": 0})

    # Advisory IDs actually in scope for this run (post layer/--registry filtering), fed to
    # rank_cross_registry_tables() below for the Section VIII cross-registry replacement tables.
    session_advisory_ids = set()

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

                # FIX: apply --registry here too, not just to ghsa_lookup -- see the note at
                # the top of this function. Same exact-match-on-raw-tag semantics as
                # build_ghsa_from_db's filter_set, so a term like "Java" that doesn't match the
                # OSV ecosystem tag "Maven" behaves identically in both filtered code paths.
                if registry_filter_set and eco_lower not in registry_filter_set:
                    continue

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

                if current_id in ghsa_lookup:
                    session_advisory_ids.add(current_id)

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
                            pool[current_id] = (
                                meta_entry["blast_radius"], update_type, meta_entry["package_name"], meta_entry.get("cvss_score", 0.0),
                                meta_entry.get("epss_score"), meta_entry.get("kev_date_added")
                            )
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
        eco_absolute_ranks, global_absolute_ranks, export_outlier_manifests,
        priority_sort_active=priority_sort_active
    )
    
    print_section_vi_new_arrivals(
        active_matrix_ecosystems, live_window_new_arrivals, 
        ghsa_lookup, global_absolute_ranks, priority_sort_active=priority_sort_active
    )
    
    print_section_vii_attention_deficit(
        active_matrix_ecosystems, ghsa_lookup, global_absolute_ranks, end_date,
        priority_sort_active=priority_sort_active
    )
    
    table_a_cross_compiled, table_b_repackaged = rank_cross_registry_tables(ghsa_lookup, session_advisory_ids)
    print_section_viii_cross_registry_tables(table_a_cross_compiled, table_b_repackaged)
    
    # Save Snapshot Disk Serialization Routine
    serialize_snapshot_payload(
        custom_export_arg, now, start_date, end_date, target_layer,
        filtered_results, bucket_counts, layer_bucket_counts, intel_feed_matrix,
        malware_vector_counts, export_profile_matrix, export_outlier_manifests,
        priority_sort_active=priority_sort_active
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

    # De-duplicate same day/layer snapshots: a --priority-sort run and a default run for the
    # same date/layer carry identical leaderboard/threat_profile totals (priority-sort only
    # re-orders outlier ranking -- see _priority_sort_key -- it never changes the counts), so
    # keep one entry per (date, layer) instead of plotting/aggregating the same day twice.
    # Prefer the default (non-priority-sort) file when both exist on disk.
    deduped = {}
    for s in snapshots:
        key = (s["metadata"]["interval_to"], s["metadata"].get("target_layer_filter", "all"))
        existing = deduped.get(key)
        if existing is None or (existing["metadata"].get("priority_sort_active") and not s["metadata"].get("priority_sort_active")):
            deduped[key] = s

    return sorted(deduped.values(), key=lambda x: x["metadata"]["interval_to"])


def generate_velocity_matrix(target_dir: str, output_path: str = "./output/velocity_matrix.csv", render_terminal_plot: bool = False):
    """
    Ingests a directory of chronological JSON snapshots and stitches them into a time-series
    CSV matrix, with an optional inline terminal (plotext) velocity chart.

    RESTORED: this function and its wiring into run_velocity_update() were silently dropped
    during commit 1df05c7 (the call site remained, calling an undefined function, until a
    later commit quietly deleted the call too rather than restoring the function). Recovered
    verbatim in spirit from commit 8e21ec0 via `git log --all -S"pltx." -- top10ecosystems.py`,
    then re-styled to match the current console conventions (BOLD section banners, GREEN/RED
    status lines) used throughout the rest of the dashboard.
    """
    if not os.path.isdir(target_dir):
        print(f"{RED}[-] Velocity Engine Error: The directory '{target_dir}' does not exist.{RESET}")
        return

    print("\n" + "="*85 + f"\n  {BOLD}THREAT VELOCITY AGGREGATION ENGINE{RESET}\n" + "="*85)

    snapshots = load_snapshots_from_dir(target_dir)
    if not snapshots:
        print(f"{RED}[-] No valid JSON snapshots found in the target directory.{RESET}")
        return

    # Discover all unique tracking columns across the timeline
    all_ecosystems = set()
    all_threat_profiles = set()
    for s in snapshots:
        all_ecosystems.update(s.get("leaderboard", {}).keys())
        all_threat_profiles.update(s.get("threat_profile", {}).keys())

    sorted_ecosystems = sorted(all_ecosystems)
    sorted_profiles = sorted(all_threat_profiles)
    headers = ["Date_End", "Layer_Filter"] + sorted_ecosystems + sorted_profiles

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            for s in snapshots:
                row = [s["metadata"]["interval_to"], s["metadata"].get("target_layer_filter", "all")]
                row += [s.get("leaderboard", {}).get(eco, 0) for eco in sorted_ecosystems]
                row += [s.get("threat_profile", {}).get(profile, 0) for profile in sorted_profiles]
                writer.writerow(row)

        print(f"{GREEN}[+] Aggregation Complete: Processed {len(snapshots):,} chronological snapshots.{RESET}")
        print(f"{GREEN}[+] Velocity Matrix Saved: {output_path}{RESET}")
        print("="*85 + "\n")

        # Terminal plotting is intentionally opt-in. plotext.clt() clears the terminal,
        # which would hide the dashboard output printed immediately before this step, so
        # it is never called here -- only clear_data(), which resets plot state in place.
        if not render_terminal_plot:
            return

        print(f"[*] Generating Multi-Series Terminal Velocity Plot...")

        # Identify the Top 10 ecosystems by total volume across the window
        eco_totals = {eco: sum(s.get("leaderboard", {}).get(eco, 0) for s in snapshots) for eco in sorted_ecosystems}
        top_10 = sorted(eco_totals, key=eco_totals.get, reverse=True)[:10]
        dates = [s["metadata"]["interval_to"] for s in snapshots]

        pltx.clear_data()
        pltx.date_form(input_form="Y-m-d")

        plotted_any = False
        for eco in top_10:
            # Daily/period-over-period deltas, not cumulative totals -- this is the actual
            # "velocity" signal (net new mutations since the previous snapshot).
            totals = [s.get("leaderboard", {}).get(eco, 0) for s in snapshots]
            deltas = [totals[0]] + [totals[i] - totals[i - 1] for i in range(1, len(totals))]
            if any(d != 0 for d in deltas):
                pltx.plot(dates, deltas, label=f"{eco} (Delta)")
                plotted_any = True

        if not plotted_any:
            print(f"{RED}[-] No non-zero ecosystem deltas to plot across this window.{RESET}")
            return

        pltx.title("Threat Churn Velocity (Daily Deltas)")
        pltx.xlabel("Timeline")
        pltx.ylabel("Net New Mutations")
        pltx.plotsize(100, 25)
        pltx.show()

    except Exception as e:
        print(f"{RED}[-] Velocity Matrix export failed: {e}{RESET}")


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


def build_snapshot_filename(start_date, end_date, target_layer=None, *, priority_sort_active: bool = False):
    suffix = "_priority" if priority_sort_active else ""
    return f"{start_date.strftime('%d-%m-%y')}_to_{end_date.strftime('%d-%m-%y')}_{target_layer if target_layer else 'all'}{suffix}.json"


def run_velocity_update(args):
    snapshot_dir = args.velocity or "./output"
    os.makedirs(snapshot_dir, exist_ok=True)
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    windows = calculate_report_windows(args, now_utc)
    global_ghsa_lookup = build_ghsa_ecosystem_map()

    for calculated_start, calculated_end in windows:
        snapshot_path = os.path.join(snapshot_dir, build_snapshot_filename(calculated_start, calculated_end, args.layer, priority_sort_active=args.priority_sort))
        generate_enterprise_threat_leaderboard(start_date=calculated_start, end_date=calculated_end, target_layer=args.layer, debug_mode=args.debug, custom_export_arg=snapshot_path, run_speedway=args.speedway, project_file_path=args.project_file, forced_format=args.project_format, audit_mode=args.audit, ghsa_lookup=global_ghsa_lookup, priority_sort_active=args.priority_sort)

    # RESTORED: stitch the accumulated snapshots into a CSV velocity matrix, with an
    # opt-in terminal (plotext) chart via --terminal-plot -- see generate_velocity_matrix().
    generate_velocity_matrix(target_dir=snapshot_dir, output_path=os.path.join(snapshot_dir, "velocity_matrix.csv"), render_terminal_plot=args.terminal_plot)

    # RESTORED: --velocity combined with --html is meant to produce the historical trend
    # briefing directly (main()'s standalone --html branch is unreachable here because it
    # explicitly excludes args.velocity, and this function used to return before ever
    # generating the report). Without this, --html was silently ignored whenever it was
    # combined with --velocity.
    if args.html:
        snapshots = load_snapshots_from_dir(snapshot_dir)
        if snapshots:
            generate_html_report(snapshots, args.html)


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

def display_all_time_retraction_stats(db_path="database/threat_stream.db"):
    """
    Computes global macro-distribution metrics and age brackets for all
    withdrawn advisories relative to today's date.
    """
    if not os.path.exists(db_path):
        print(f"\n[!] Analytics Skipped: Target database missing at {db_path}")
        return

    # RESTORED 2026: previously hardcoded to a fixed 2026-05-28 date, which
    # froze every age bracket at that point in time. Now anchored to the
    # real current date so vintage/retraction-age math stays accurate.
    today = datetime.datetime.now(datetime.timezone.utc).date()

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

def generate_supply_chain_crosscheck(db_path: str, start_date, end_date, registries: list, export_path=None, *, console_limit: int = 100):
    """
    Cross-checks the CISA KEV catalog, EPSS exploitation probability, and raw
    OSV/CVSS severity against the vulnerability catalog for the given window
    and explicit registry set, producing the prioritized "act on this now"
    dispatch list for operational developer teams.

    Deliberate sort priority (highest to lowest):
        1. KEV catalog hit          -> confirmed active exploitation in the wild
        2. EPSS score, descending   -> probability of exploitation in next 30 days
        3. CVSS / blast radius      -> raw theoretical severity, as tiebreaker only

    CVE resolution fallback: some advisory rows (notably ROOT-APP-* synthetic
    entries from direct-dependency lockfile audits) carry no cve_alias even
    when a CVE is embedded directly in their advisory_id (e.g.
    ROOT-APP-NPM-CVE-2026-40175). Those never match epss_scores/kev_catalog
    on a pure SQL join. This extracts CVE-YYYY-NNNNN from advisory_id as a
    fallback resolution target so EPSS/KEV enrichment still applies.

    console_limit caps how many rows print to the terminal (default 100,
    pass 0 or a negative number for no cap). The JSON export (export_path)
    is always the complete, unfiltered dispatch list regardless of this cap.
    """
    if not os.path.exists(db_path):
        print(f"{RED}[-] Cross-Check Aborted: Relational warehouse missing at {db_path}{RESET}")
        return

    if not registries:
        print(f"{RED}[-] Cross-Check Aborted: --registry is required (no default registry scope).{RESET}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")

    registry_clause = " OR ".join(["v.ecosystems LIKE ?"] * len(registries))
    registry_params = [f"%{r.strip()}%" for r in registries]

    # Base pull -- deliberately NOT joined to epss_scores/kev_catalog here,
    # since the join key (cve_alias) is missing on some rows that still
    # carry a resolvable CVE inside their advisory_id string.
    base_query = f"""
        SELECT
            v.advisory_id,
            v.cve_alias,
            v.cwe_ids,
            v.package_name,
            v.ecosystems,
            v.cvss_score,
            v.blast_radius
        FROM vulnerabilities v
        WHERE v.withdrawn_date IS NULL
          AND v.last_modified BETWEEN ? AND ?
          AND ({registry_clause})
    """
    cursor.execute(base_query, [start_str, end_str] + registry_params)
    base_rows = cursor.fetchall()

    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    enriched = []
    resolved_cves = set()
    for advisory_id, cve_alias, cwe_json, pkg, ecos_json, cvss, radius in base_rows:
        cve_id = cve_alias
        cve_source = "db" if cve_alias else None

        if not cve_id:
            match = cve_pattern.search(advisory_id or "")
            if match:
                cve_id = match.group(0).upper()
                cve_source = "id-pattern"

        if cve_id:
            resolved_cves.add(cve_id)

        enriched.append({
            "advisory_id": advisory_id,
            "cve_id": cve_id,
            "cve_source": cve_source,
            "cwe_json": cwe_json,
            "package_name": pkg,
            "ecosystems_json": ecos_json,
            "cvss_score": cvss,
            "blast_radius": radius,
        })

    # Batch-fetch EPSS/KEV only for the CVEs actually present in this window
    # (real cve_alias values plus id-pattern fallbacks), instead of a blind
    # full-table join.
    epss_map = {}
    kev_map = {}
    if resolved_cves:
        cve_list = list(resolved_cves)
        chunk_size = 500
        for i in range(0, len(cve_list), chunk_size):
            chunk = cve_list[i:i + chunk_size]
            placeholders = ",".join(["?"] * len(chunk))

            cursor.execute(f"SELECT cve_id, epss_score, percentile FROM epss_scores WHERE cve_id IN ({placeholders})", chunk)
            for cve_id, score, pct in cursor.fetchall():
                epss_map[cve_id] = (score, pct)

            cursor.execute(f"SELECT cve_id, date_added, due_date, known_ransomware_use FROM kev_catalog WHERE cve_id IN ({placeholders})", chunk)
            for cve_id, date_added, due_date, ransom in cursor.fetchall():
                kev_map[cve_id] = (date_added, due_date, ransom)

    conn.close()

    for rec in enriched:
        cve_id = rec["cve_id"]
        epss_score, epss_pct = epss_map.get(cve_id, (None, None)) if cve_id else (None, None)
        kev_added, kev_due, kev_ransom = kev_map.get(cve_id, (None, None, None)) if cve_id else (None, None, None)
        rec["epss_score"] = epss_score
        rec["epss_percentile"] = epss_pct
        rec["kev_date_added"] = kev_added
        rec["kev_due_date"] = kev_due
        rec["kev_known_ransomware_use"] = kev_ransom

    # Sort in Python (KEV hit desc, EPSS desc, CVSS desc, blast_radius desc,
    # advisory_id asc) -- can no longer be a pure SQL ORDER BY now that CVE
    # resolution includes the id-pattern fallback.
    enriched.sort(key=lambda r: (
        0 if r["kev_date_added"] else 1,
        -(r["epss_score"] or 0.0),
        -(r["cvss_score"] or 0.0),
        -(r["blast_radius"] or 0.0),
        r["advisory_id"] or "",
    ))

    total_rows = len(enriched)
    kev_hits = sum(1 for r in enriched if r["kev_date_added"])
    id_pattern_resolved = sum(1 for r in enriched if r["cve_source"] == "id-pattern")

    print("\n" + "="*140)
    print(f"   {BOLD}SUPPLY CHAIN THREAT INTEL CROSS-CHECK: KEV -> EPSS -> OSV/CVSS PRIORITY DISPATCH LIST{RESET}")
    print(f"   Window: {start_str} to {end_str}  |  Registries: {', '.join(registries)}")
    print("="*140)

    if not enriched:
        print("    [+] Zero advisories matched this window/registry scope. Nothing to dispatch.")
        print("="*140 + "\n")
        return

    print(f"{'Advisory ID':<20} | {'CVE ID':<16} | {'CWE ID(s)':<20} | {'Package':<28} | {'Ecosystems':<14} | {'CVSS':<5} | {'EPSS':<7} | {'KEV Status'}")
    print("-"*140)

    display_rows = enriched if console_limit is None or console_limit <= 0 else enriched[:console_limit]

    def _fit(value, width):
        """Truncates a display value to fit its fixed-width table column,
        adding an ellipsis marker when truncated, so a single overlong field
        (namely ROOT-APP-* synthetic advisory IDs, which can run 24-38+
        chars vs a normal 19-char GHSA-xxxx-xxxx-xxxx ID) can never push
        every '|' after it out of alignment with the header row."""
        s = str(value) if value is not None else ""
        if len(s) <= width:
            return s
        if width <= 1:
            return s[:width]
        return s[:width - 1] + "\u2026"

    for rec in display_rows:
        cwe_list = json.loads(rec["cwe_json"]) if rec["cwe_json"] else []
        cwe_display = _fit(", ".join(cwe_list) if cwe_list else "N/A", 20)
        ecos_list = json.loads(rec["ecosystems_json"]) if rec["ecosystems_json"] else []
        ecos_display = _fit(", ".join(ecos_list), 14)

        cvss = rec["cvss_score"]
        cvss_display = f"{cvss:.1f}" if cvss else "N/A"
        epss_score = rec["epss_score"]
        epss_display = f"{epss_score*100:.1f}%" if epss_score is not None else "N/A"
        pkg_display = _fit(rec["package_name"] if rec["package_name"] else "N/A", 28)
        advisory_id_display = _fit(rec["advisory_id"], 20)

        cve_display = rec["cve_id"] or "N/A"
        if rec["cve_source"] == "id-pattern":
            cve_display = f"{cve_display}*"
        cve_display = _fit(cve_display, 16)

        if rec["kev_date_added"]:
            kev_hits_flag = " [RANSOMWARE]" if rec["kev_known_ransomware_use"] == "Known" else ""
            kev_display = f"{RED}KEV Due: {rec['kev_due_date'] or 'N/A'}{kev_hits_flag}{RESET}"
        else:
            kev_display = "-"

        print(f"{advisory_id_display:<20} | {cve_display:<16} | {cwe_display:<20} | {pkg_display:<28} | {ecos_display:<14} | {cvss_display:<5} | {epss_display:<7} | {kev_display}")

    print("-"*140)
    if len(display_rows) < total_rows:
        print(f"[!] Console capped at {len(display_rows):,} of {total_rows:,} rows (--crosscheck-limit). Use --crosscheck-export for the full list.")
    if id_pattern_resolved:
        print(f"[*] {id_pattern_resolved:,} row(s) marked '*' resolved their CVE from advisory_id text (no cve_alias on record).")
    print(f"-> Total Advisories: {total_rows:,}  |  KEV-Confirmed Exploited: {kev_hits:,}")
    print("="*140 + "\n")

    if export_path:
        if not isinstance(export_path, str):
            output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)
            export_path = os.path.join(output_dir, f"supply_chain_crosscheck_{end_date.strftime('%Y-%m-%d')}.json")

        export_records = []
        for rec in enriched:
            export_records.append({
                "advisory_id": rec["advisory_id"],
                "cve_id": rec["cve_id"] or "N/A",
                "cve_id_source": rec["cve_source"],
                "cwe_ids": json.loads(rec["cwe_json"]) if rec["cwe_json"] else [],
                "package_name": rec["package_name"],
                "ecosystems": json.loads(rec["ecosystems_json"]) if rec["ecosystems_json"] else [],
                "cvss_score": rec["cvss_score"],
                "blast_radius": rec["blast_radius"],
                "epss_score": rec["epss_score"],
                "epss_percentile": rec["epss_percentile"],
                "kev_date_added": rec["kev_date_added"],
                "kev_due_date": rec["kev_due_date"],
                "kev_known_ransomware_use": rec["kev_known_ransomware_use"]
            })

        payload = {
            "metadata": {
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "interval_from": start_str,
                "interval_to": end_str,
                "registries": registries,
                "total_advisories": total_rows,
                "kev_confirmed_count": kev_hits,
                "cve_resolved_from_id_pattern_count": id_pattern_resolved,
                "console_limit_applied": console_limit if console_limit and console_limit > 0 else None
            },
            "dispatch_list": export_records
        }

        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"{GREEN}[+] Cross-check dispatch list exported to: {export_path} ({total_rows:,} rows, uncapped){RESET}")

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
    parser.add_argument("--registry", type=str, help='Isolate evaluation strictly to a comma-separated registry array subset (e.g., --registry "npm,PyPI,Maven (Java)").')
    parser.add_argument("--hunt-retracted", action="store_true", help="Execute an advanced research hunt for suspicious retracted advisories.")
    parser.add_argument("--trends", action="store_true", help="Activate chronological trend and mutation velocity analysis.")
    parser.add_argument("--window-days", type=int, default=30, help="Telescoping trend evaluation window constraint (Defaults to 30 days).")
    parser.add_argument("--crosscheck", action="store_true", help="Generate the KEV -> EPSS -> OSV/CVSS prioritized developer dispatch list.")
    parser.add_argument("--crosscheck-export", nargs='?', const=True, default=False, metavar="PATH", help="Export the cross-check dispatch list as JSON (optionally provide a path). Always exports the FULL list, uncapped.")
    parser.add_argument("--crosscheck-limit", type=int, default=100, metavar="N", help="Cap console output to the top N rows (default 100). Use 0 for no cap. Never affects --crosscheck-export.")
    parser.add_argument("--priority-sort", action="store_true", help="Rank Sections I/V/VI/VII by KEV -> EPSS -> CVSS/blast-radius instead of CVSS/blast-radius alone. Default (omitted) behavior is completely unchanged.")
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

    # =========================================================================
    # FEATURE ROUTING LAYER: KEV/EPSS/OSV SUPPLY CHAIN CROSS-CHECK DISPATCH LIST
    # =========================================================================
    if args.crosscheck:
        if not args.database:
            parser.error("[!] The --crosscheck engine requires the --database relational warehouse active.")

        if not target_registries:
            print(f"\n{BOLD}{RED}[!] CONFIGURATION ERROR: --crosscheck requires an explicit --registry filter.{RESET}")
            print(f"    -> Usage: python top10ecosystems.py --database --crosscheck --registry npm,PyPI --from 2026-08-18 --to 2026-09-17\n")
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
        elif args.days:
            start_window_dt = end_window_dt - datetime.timedelta(days=args.days)
        else:
            start_window_dt = datetime.datetime(2026, 4, 18, 0, 0, 0, tzinfo=datetime.timezone.utc)

        generate_supply_chain_crosscheck(
            db_path="database/threat_stream.db",
            start_date=start_window_dt,
            end_date=end_window_dt,
            registries=target_registries,
            export_path=args.crosscheck_export,
            console_limit=args.crosscheck_limit
        )
        return

    if args.database:
        global_ghsa_lookup = build_ghsa_from_db(db_path="database/threat_stream.db", target_registries=target_registries, priority_sort=args.priority_sort)
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
            manifest_rows=cached_manifest_rows,
            priority_sort_active=args.priority_sort,
            target_registries=target_registries
        )


if __name__ == "__main__":
    main()
