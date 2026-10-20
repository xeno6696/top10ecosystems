#!/usr/bin/env python3
"""Builds (or repairs) the project's .venv and installs the tested package versions into it.

The supported environment is the Python in .python-version with the exact package versions in
requirements.lock. Nothing here is mandatory: another Python still builds a working venv, it is just
flagged as unsupported. pip has no hook that runs when a requirements file is installed, so this is
the one entry point -- run it after cloning, after pulling a changed lock file, or when an import fails.
It is safe to repeat; it only installs when the lock file changed since the last run.

    python setup_env.py              create .venv if missing, install from the lock file, verify
    python setup_env.py --check      read-only: report whether .venv is the supported environment
    python setup_env.py --force      reinstall even if the lock file is unchanged
    python setup_env.py --recreate   delete and rebuild .venv (its base Python was removed or replaced)
    python setup_env.py --relock     maintainers: regenerate requirements.lock from requirements.txt

The venv is built from whichever Python runs this script, so run it with the one you want. Afterwards
run the tools with the venv's own interpreter (path printed at the end), or activate it, instead of
whatever `python` happens to be first on PATH.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

import env_info

ROOT = env_info.ROOT
VENV_DIR = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"
LOCK = env_info.LOCK_FILE
STAMP_NAME = ".lock.sha256"
IMPORT_CHECKS = ("cvss", "matplotlib", "plotext", "requests")


def venv_python(venv_dir: Path, windows: bool = None) -> Path:
    windows = (os.name == "nt") if windows is None else windows
    return venv_dir / ("Scripts/python.exe" if windows else "bin/python")


def needs_install(stamp_path: Path, digest: str) -> bool:
    return not stamp_path.exists() or stamp_path.read_text().strip() != digest


def format_lock(freeze_output: str, pin) -> str:
    """requirements.lock text from `pip freeze` output: a short header, then one sorted name==version
    line per package (editable installs, comments and options are dropped)."""
    pins = sorted({line.strip() for line in freeze_output.splitlines()
                   if "==" in line and not line.lstrip().startswith(("#", "-"))}, key=str.lower)
    header = ["# Exact package versions the supported environment was tested with"
              + (f" (Python {pin})." if pin else "."),
              "# Regenerate with: python setup_env.py --relock", ""]
    return "\n".join(header + pins) + "\n"


def _capture(python: Path, code: str):
    try:
        result = subprocess.run([str(python), "-c", code], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def venv_python_version(python: Path):
    """The venv interpreter's version, or None if it's missing or won't start (typically its base
    Python was uninstalled)."""
    return _capture(python, "import platform; print(platform.python_version())") if python.exists() else None


def missing_imports(python: Path) -> list:
    code = ("import importlib.util; "
            f"print(' '.join(m for m in {list(IMPORT_CHECKS)!r} if importlib.util.find_spec(m) is None))")
    return (_capture(python, code) or "").split()


def venv_lock_mismatches(python: Path) -> list:
    code = f"import sys; sys.path.insert(0, {str(ROOT)!r}); import env_info; print(chr(10).join(env_info.lock_mismatches()))"
    return [line for line in (_capture(python, code) or "").splitlines() if line]


def _run(cmd: list) -> bool:
    print("    $ " + " ".join(str(c) for c in cmd))
    return subprocess.run([str(c) for c in cmd]).returncode == 0


def relock(pin) -> int:
    """Install requirements.txt into a scratch venv on the current Python, freeze what pip resolved, and
    write that to requirements.lock. A scratch venv, so stray packages in .venv can't leak into the lock."""
    if pin and env_info.current_python() != pin:
        print(f"[!] Relocking on Python {env_info.current_python()}, but the supported version is {pin}; "
              "the lock will reflect this interpreter.")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        scratch = Path(tmp) / "venv"
        print(f"[*] Resolving {REQUIREMENTS.name} in a scratch venv ...")
        venv.create(scratch, with_pip=True)
        python = venv_python(scratch)
        if not _run([python, "-m", "pip", "install", "-r", REQUIREMENTS]):
            print("[-] Installing requirements.txt failed; the existing lock file was left as-is.")
            return 1
        frozen = subprocess.run([str(python), "-m", "pip", "freeze", "--exclude-editable"], capture_output=True, text=True)
        if frozen.returncode != 0:
            print("[-] pip freeze failed; the existing lock file was left as-is.")
            return 1
    LOCK.write_text(format_lock(frozen.stdout, pin))
    print(f"[+] {LOCK.name} updated. Review the diff, run the tests, then: python setup_env.py --recreate")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build/repair the project's .venv and install the tested package versions.")
    parser.add_argument("--check", action="store_true", help="read-only readiness check; exit 1 if not ready")
    parser.add_argument("--force", action="store_true", help="reinstall even if the lock file is unchanged")
    parser.add_argument("--recreate", action="store_true", help="delete and rebuild the venv")
    parser.add_argument("--relock", action="store_true", help="regenerate requirements.lock from requirements.txt")
    args = parser.parse_args(argv)

    pin = env_info.pinned_python()
    python = venv_python(VENV_DIR)
    stamp = VENV_DIR / STAMP_NAME

    if args.relock:
        return relock(pin)

    if not LOCK.exists():
        print(f"[-] {LOCK.name} is missing. Restore it from git, or install with: pip install -r {REQUIREMENTS.name}")
        return 1

    if args.check:
        problems = []
        have = venv_python_version(python)
        if have is None:
            problems.append(f"no working venv at {VENV_DIR}")
        else:
            if pin and have != pin:
                problems.append(f"venv is Python {have}, supported is {pin}")
            if not stamp.exists():
                problems.append(f"{LOCK.name} hasn't been installed through setup_env.py yet")
            elif needs_install(stamp, env_info.lock_digest(length=64)):
                problems.append(f"{LOCK.name} has changed since the last install")
            absent = missing_imports(python)
            if absent:
                problems.append("missing packages: " + ", ".join(absent))
            drift = venv_lock_mismatches(python)
            if drift:
                problems.append("packages differ from the lock: " + "; ".join(drift))
        print("[+] .venv is the supported environment." if not problems else "[-] .venv is not ready: " + "; ".join(problems) + ". Run: python setup_env.py")
        return 1 if problems else 0

    if args.recreate and VENV_DIR.exists():
        print(f"[*] Removing {VENV_DIR} ...")
        shutil.rmtree(VENV_DIR)

    if not VENV_DIR.exists():
        if pin and env_info.current_python() != pin:
            print(f"[!] Building on Python {env_info.current_python()}; the supported version is {pin}. "
                  "This will work but is unsupported.")
        print(f"[*] Creating {VENV_DIR} with {sys.executable} (Python {env_info.current_python()}) ...")
        venv.create(VENV_DIR, with_pip=True)
    else:
        have = venv_python_version(python)
        if have is None:
            print(f"[-] {VENV_DIR} exists but its interpreter won't start (the Python it was built from is probably gone).")
            print("    Rebuild it with: python setup_env.py --recreate")
            return 1
        if pin and have != pin:
            print(f"[!] {VENV_DIR} is Python {have}; the supported version is {pin}. Continuing, but this is unsupported "
                  "(rebuild with --recreate, using the supported Python, to fix that).")
        else:
            print(f"[+] Using existing {VENV_DIR} (Python {have})")

    digest = env_info.lock_digest(length=64)
    if args.force or needs_install(stamp, digest):
        print(f"[*] Installing the versions in {LOCK.name} ...")
        if not _run([python, "-m", "pip", "install", "-r", LOCK]):
            print("[-] Installing from the lock file failed; .venv left as-is. Fix the error above and re-run.")
            print(f"    On a different Python some pinned versions may not exist: `pip install -r {REQUIREMENTS.name}` "
                  "into the venv is an unsupported way around that.")
            return 1
        stamp.write_text(digest + "\n")
    else:
        print(f"[+] {LOCK.name} unchanged since the last install; skipping.")

    absent = missing_imports(python)
    if absent:
        print("[-] Installed, but these packages still fail to import: " + ", ".join(absent))
        return 1

    print("[+] Environment ready. Run the tools with the venv's interpreter:")
    print(f"      {python} top10ecosystems.py --help")
    print(f"    or activate it first ({VENV_DIR / ('Scripts/Activate.ps1' if os.name == 'nt' else 'bin/activate')}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
