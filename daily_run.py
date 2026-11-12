"""The once-a-day job: check CISA's KEV catalog for changes, refresh the warehouse, export yesterday's snapshot, rebuild the report.

Meant to be started by Windows Task Scheduler (see schedule_daily.ps1) but runnable by hand: `python daily_run.py`.

Order matters:
  1. KEV check first, on its own. It needs only the network, so a broken sync can't stop an alert. A new KEV entry or a
     ransomware flip plays the alert chime and opens the digest right away.
  2. Warehouse sync (db_warehouse.py --sync).
  3. Snapshot export for YESTERDAY (UTC), the last complete day. Skipped if the sync failed: a snapshot built from a stale
     warehouse would be quietly wrong, which is worse than a missing one.
  4. Report over the last REPORT_DAYS days, written to output/daily_report.html (overwritten each day).
A step that fails is logged, plays a different (lower) chime and opens the status file; later steps that don't depend on it still run.

Everything each step printed goes to output/daily/<date>.log, and output/daily/latest_status.txt says what happened in one screen.
Quiet days are silent: no sound, no window. Sounds and file-opening are injected so the tests make none.
"""
import datetime
import os
import subprocess
import sys

import kev_watch

REPORT_DAYS = 30
OUT_DIR = os.path.join("output", "daily")
REPORT_PATH = os.path.join("output", "daily_report.html")
STEP_TIMEOUT_SECONDS = {"sync": 4 * 3600, "export": 3600, "report": 1800}

# (frequency Hz, milliseconds). Alert: a rising three-note figure, repeated; failure: two low notes. Different enough to tell apart unseen.
ALERT_TUNE = [(660, 160), (880, 160), (1320, 320)]
FAILURE_TUNE = [(330, 400), (247, 600)]
ALERT_REPEATS = 3


def play_chime(kind: str) -> None:
    """Sound for 'alert' or 'failure'. Windows: tones through the PC speakers. Elsewhere: the terminal bell."""
    tune, repeats = (ALERT_TUNE, ALERT_REPEATS) if kind == "alert" else (FAILURE_TUNE, 2)
    try:
        import winsound
    except ImportError:
        sys.stdout.write("\a")
        return
    for _ in range(repeats):
        for freq, ms in tune:
            winsound.Beep(freq, ms)


def open_file(path: str) -> None:
    """Put a text file on screen (Windows: the default editor)."""
    if hasattr(os, "startfile"):
        os.startfile(os.path.abspath(path))     # noqa: the Windows-only call, guarded by hasattr


def _run_step(argv, timeout):
    kwargs = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    try:
        done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                              env=dict(os.environ, PYTHONIOENCODING="utf-8", NO_COLOR="1"), **kwargs)
        return done.returncode, (done.stdout or "") + (done.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 127, f"could not start: {exc}"


def plan(today: datetime.date, python: str = None) -> list:
    """[(name, argv)] for the warehouse steps. 'today' is the date in UTC; snapshots cover complete days, so the last one is yesterday."""
    python = python or sys.executable
    yesterday = today - datetime.timedelta(days=1)
    start = yesterday - datetime.timedelta(days=REPORT_DAYS - 1)
    return [
        ("sync", [python, "db_warehouse.py", "--sync"]),
        ("export", [python, "top10ecosystems.py", "--layer", "app", "--to", yesterday.isoformat(), "--export"]),
        ("report", [python, "top10ecosystems.py", "--layer", "app", "--from", start.isoformat(), "--to", yesterday.isoformat(), "--report", REPORT_PATH]),
    ]


def run(now=None, out_dir: str = OUT_DIR, kev_dir: str = kev_watch.STATE_DIR, kev_check=kev_watch.check,
        step_runner=_run_step, chime=play_chime, opener=open_file, python: str = None) -> int:
    """Run the day's job. Returns 0 when everything worked, 1 if any step failed (a KEV alert alone is not a failure)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    stamp = now.strftime("%Y-%m-%d")
    os.makedirs(out_dir, exist_ok=True)
    log_lines, status = [], []
    failed = False

    def log(text):
        log_lines.append(text)

    # 1. KEV check
    try:
        kev = kev_check(kev_dir)
    except Exception as exc:                      # the job must go on to the warehouse steps whatever this does
        kev = {"exit": kev_watch.EXIT_ERROR, "digest": f"KEV check crashed: {exc!r}\n", "changes": []}
    log("== kev_watch ==\n" + kev["digest"])
    kev_digest_path = os.path.join(kev_dir, kev_watch.DIGEST_NAME)
    if kev["exit"] == kev_watch.EXIT_ALERT:
        alerts = [c for c in kev["changes"] if c["kind"] in kev_watch.ALERT_KINDS]
        status.append(f"KEV: {len(alerts)} alert-worthy change(s) -- see {kev_digest_path}")
        chime("alert")
        opener(kev_digest_path)
    elif kev["exit"] == kev_watch.EXIT_ERROR:
        failed = True
        status.append("KEV: check FAILED -- " + kev["digest"].strip())
    elif kev["exit"] == kev_watch.EXIT_DIGEST:
        status.append("KEV: minor changes only (due dates, edits, removals); no sound")
    else:
        status.append("KEV: no changes")

    # 2-4. warehouse steps
    sync_ok = True
    for name, argv in plan(now.date(), python):
        if name != "sync" and not sync_ok:
            status.append(f"{name}: skipped because the sync failed")
            continue
        code, output = step_runner(argv, STEP_TIMEOUT_SECONDS[name])
        log(f"== {name}: {' '.join(argv)} (exit {code}) ==\n{output}")
        if code == 0:
            status.append(f"{name}: ok")
        else:
            failed = True
            status.append(f"{name}: FAILED (exit {code}) -- see {os.path.join(out_dir, stamp + '.log')}")
            if name == "sync":
                sync_ok = False

    log_path = os.path.join(out_dir, f"{stamp}.log")
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(log_lines))
    status_path = os.path.join(out_dir, "latest_status.txt")
    with open(status_path, "w", encoding="utf-8") as handle:
        handle.write(f"Daily run {now.strftime('%Y-%m-%d %H:%M UTC')}\n" + "\n".join(status) + "\n")
    if failed:
        chime("failure")
        opener(status_path)
    return 1 if failed else 0


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))   # Task Scheduler's working directory is not ours to trust
    sys.exit(run())
