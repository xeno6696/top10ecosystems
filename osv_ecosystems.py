"""Single source of truth for how OSV ecosystem tags are classified.

Both db_warehouse.py (at ingest, from each record's affected[].package.ecosystem) and
top10ecosystems.py (reading the live modification stream's path prefixes) bucket raw OSV ecosystem
tags into the same canonical tracks and layers. These used to be copy-pasted into both modules --
five copies of each ecosystem list, two of the hard-mapping table, two of the matcher -- on the
rationale that the two modules shouldn't import each other (a leftover from when a second,
file-only ingestion path had to stay self-contained). A fix then had to be hand-mirrored, which is
how the "pub" vs "Public" bug survived in one place after being fixed in another. This module
exists so there is exactly one copy.
"""

import functools
import re

# Language/package registries (where maintainers actually publish releases) vs. OS/container image
# vendors (which only ever re-bundle someone else's already-published code, never originate it).
# Used by generate_enterprise_threat_leaderboard()'s own layer routing AND by Section VIII-C's
# presence grid to mark which columns could plausibly be "where the fix ships first" -- a
# container-ecosystem column can never be that, by definition, so it's never highlighted.
KNOWN_CONTAINER_ECOSYSTEMS = ["Debian", "Ubuntu", "MinimOS", "Azure Linux", "Alpine Linux", "Alpaquita Linux", "Chainguard", "Bitnami", "Echo", "Android"]
KNOWN_REGISTRY_ECOSYSTEMS = ["npm", "PyPI", "Maven (Java)", "Packagist (PHP)", "Go (Golang)", "NuGet", "Crates.io", "RubyGems", "Hex", "Pub", "ConanCenter", "SwiftURL"]

# Order matters: the first track a tag matches wins.
MASTER_TRACKS = KNOWN_CONTAINER_ECOSYSTEMS + KNOWN_REGISTRY_ECOSYSTEMS + ["GIT", "Untagged Commit Hash/CVE Noise", "Android"]
ECO_HARD_MAPPINGS = {"maven": "Maven (Java)", "go": "Go (Golang)", "packagist": "Packagist (PHP)", "git": "GIT", "crates.io": "Crates.io"}

_CONTAINER_SET = frozenset(KNOWN_CONTAINER_ECOSYSTEMS)
_REGISTRY_SET = frozenset(KNOWN_REGISTRY_ECOSYSTEMS)


def ecosystem_tag_matches_track(eco_lower: str, track_lower: str) -> bool:
    """Whether a raw OSV ecosystem tag (e.g. "Debian:11") should bucket into a known track,
    without a short track name (e.g. "Pub", "GIT", "Hex") accidentally matching as a substring
    embedded inside an unrelated longer word. FIX: a plain `eco_lower in track_lower or
    track_lower in eco_lower` check let "pub" (the Dart/Flutter registry track) match inside
    "SUSE:Linux Enterprise Module for Public Cloud 12" purely because "pub" is a substring of
    "Public" -- silently bucketing unrelated SUSE Linux packages (python-pip, python-ply, ...)
    into the Pub/Android tracks, which then fed Section VIII's cross-registry classifier a
    spurious "same package released to two registries" false positive (verified: 1,183 such
    pairs in the live warehouse, all Android<->Pub, all traced back to this exact collision).
    Requires the shorter string to appear at a token boundary in the longer one -- flanked by
    start/end of string or a non-alphanumeric character -- rather than embedded inside a longer
    alphanumeric word. "debian:11" still matches "debian" (boundary is the colon); "public cloud"
    no longer matches "pub" (boundary would have to fall mid-word, on the "l" of "public")."""
    def _boundary_match(needle, haystack):
        if not needle:
            return False
        pattern = r'(?<![a-z0-9])' + re.escape(needle) + r'(?![a-z0-9])'
        return re.search(pattern, haystack) is not None
    return _boundary_match(eco_lower, track_lower) or _boundary_match(track_lower, eco_lower)


@functools.lru_cache(maxsize=None)
def clean_ecosystem_tag(eco_raw: str) -> str:
    """Buckets a raw OSV ecosystem tag (e.g. "maven", "Debian:11") into its canonical track name
    (e.g. "Maven (Java)", "Debian"): a hard-mapping table first, then a boundary-aware substring
    match against the known tracks (see ecosystem_tag_matches_track). db_warehouse.py (at ingest) and top10ecosystems.py (reading the live modification stream) both use this one implementation.

    Consolidated into one helper so every call site in this file buckets identically; section
    VIII's classifier and its registry/container gate both key on the CANONICAL names, so a raw
    tag like "Go" or "Debian:11" leaking through un-bucketed produces wrong cross-registry output.

    Memoized: it is a pure function of one string but is called once per stream row per ecosystem
    (~4M times per dashboard window) with a small set of distinct inputs, and each uncached call
    runs a regex-based boundary match against ~25 tracks. Caching took one window from 64s to 25s
    with byte-identical output."""
    eco_lower = eco_raw.strip().lower()
    eco_clean = ECO_HARD_MAPPINGS.get(eco_lower, None)
    if not eco_clean:
        for track in MASTER_TRACKS:
            if ecosystem_tag_matches_track(eco_lower, track.lower()):
                eco_clean = track
                break
    return eco_clean or "Android"


def get_artifact_layer(eco_name):
    """Buckets ecosystems into their proper architectural tracking layers."""
    if eco_name in _CONTAINER_SET: return "Container Base Image"
    elif eco_name in _REGISTRY_SET: return "App Software Registry"
    elif eco_name == "GIT": return "Source Control (SCM)"
    return "Global Baseline Noise"
