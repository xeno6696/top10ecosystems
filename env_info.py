"""What Python and packages this project is supported on, and whether the running interpreter matches.

The supported environment is exactly the interpreter named in `.python-version` plus the packages
pinned (with hashes) in `requirements.lock`. `python setup_env.py` builds it; this module only reads
it, so the tools can say plainly when they're running somewhere else.
"""
import hashlib
import importlib.metadata
import importlib.util
import os
import platform
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PIN_FILE = ROOT / ".python-version"
LOCK_FILE = ROOT / "requirements.lock"
OVERRIDE_ENV = "TOP10_ALLOW_UNSUPPORTED_ENV"

_LOCK_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)==([^\s\\;]+)\s*(?:;\s*([^\\]+?))?\s*\\?\s*$")


def pinned_python(path: Path = PIN_FILE):
    """The exact Python version this project supports (first non-comment line of .python-version)."""
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    return None


def current_python() -> str:
    return platform.python_version()


def lock_digest(path: Path = LOCK_FILE, length: int = 12):
    """Short SHA-256 of the lock file with line endings normalised (a CRLF checkout matches an LF one)."""
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()[:length]


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_pins(path: Path = LOCK_FILE) -> dict:
    """{package: version} for every pin that applies to this platform. Pins carrying an environment
    marker (e.g. `; sys_platform == 'win32'`) are evaluated when `packaging` is importable and skipped
    when it isn't, so a Windows-only package never reads as "missing" on Linux."""
    pins = {}
    if not path.exists():
        return pins
    try:
        from packaging.markers import Marker
    except ImportError:
        Marker = None
    for line in path.read_text().splitlines():
        match = _LOCK_LINE.match(line)
        if not match:
            continue
        name, version, marker = match.groups()
        if marker and (Marker is None or not Marker(marker).evaluate()):
            continue
        pins[_normalise(name)] = version
    return pins


def lock_mismatches(path: Path = LOCK_FILE) -> list:
    """Packages installed in THIS interpreter whose version differs from the lock, or that are absent."""
    problems = []
    for name, wanted in sorted(lock_pins(path).items()):
        try:
            have = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            problems.append(f"{name} missing (lock {wanted})")
            continue
        if have != wanted:
            problems.append(f"{name} {have} (lock {wanted})")
    return problems


def support_line() -> str:
    pinned = pinned_python()
    python_part = f"Python {current_python()} (supported: {pinned or 'unpinned'})"
    lock = lock_digest()
    problems = lock_mismatches() if lock else []
    return f"{python_part} | lock {lock or 'missing'} | packages: " + ("match" if lock and not problems else f"{len(problems)} differ")


def is_supported() -> bool:
    pinned = pinned_python()
    return (pinned is None or current_python() == pinned) and not lock_mismatches()


def warn_if_unsupported(stream=None) -> bool:
    """One stderr line when the running interpreter or packages differ from the supported environment.
    Never blocks: set TOP10_ALLOW_UNSUPPORTED_ENV=1 to silence it for deliberate experiments. Returns
    True when a warning was printed."""
    if os.environ.get(OVERRIDE_ENV) or is_supported():
        return False
    print(f"[!] Unsupported environment -- {support_line()}. Results may differ and bug reports from here "
          f"can't be supported; run `python setup_env.py` to build the supported one.",
          file=stream or sys.stderr)
    return True


def exit_if_packages_missing(names) -> None:
    """Exit with one actionable line instead of a bare ModuleNotFoundError when a required package isn't
    importable -- the usual cause is running a bare `python` that isn't the project's .venv."""
    absent = [name for name in names if importlib.util.find_spec(name) is None]
    if absent:
        sys.exit(f"[-] Missing package(s): {', '.join(absent)} -- this interpreter ({sys.executable}) isn't the project's "
                 f"environment. Run `python setup_env.py`, then use the .venv interpreter it prints.")
