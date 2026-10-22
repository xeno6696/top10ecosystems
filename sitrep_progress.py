"""Live status for --sitrep: which source is being contacted, and how long it has been going.

It writes to STDERR, so `--json` output on stdout stays clean, and only when stderr is a terminal:
  - "live" mode redraws one block in place (a spinner, the state and a running seconds counter per source);
  - "plain" mode (a terminal that cannot redraw) prints one line as each source finishes;
  - "off" prints nothing (output redirected, --no-progress, tests).

Worker threads report through update()/finish(); only one thread ever draws. The thread-local ACTIVE lets code deep inside
a request (the rate-limit wait in the fetcher) report "waiting" for whichever source is running on that thread without the
fetch function's signature changing.
"""
import collections
import os
import shutil
import sys
import threading
import time

ACTIVE = threading.local()      # .hook(state, detail) for the source running on this thread, or absent

SPINNER = "|/-" + chr(92)
MARKS = {"ok": "[ok]", "nothing": "[--]", "error": "[!!]", "blocked": "[xx]"}
COLORS = {"ok": "32", "nothing": "33", "error": "31", "blocked": "31", "active": "36"}
CLEAR_LINE = "\x1b[2K"


def ansi_ok(stream) -> bool:
    """True when `stream` is a terminal that will honour cursor movement (turning it on in a Windows console if it can)."""
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    if os.name != "nt":
        return os.environ.get("TERM", "") not in ("", "dumb")
    try:
        import ctypes
        kernel = ctypes.windll.kernel32
        handle = kernel.GetStdHandle(-12 if stream is sys.stderr else -11)
        mode = ctypes.c_uint32()
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class Progress:
    def __init__(self, stream=None, mode="live", clock=time.monotonic, interval=0.15, threaded=True, width=None):
        self.stream = stream if stream is not None else sys.stderr
        self.mode, self.clock, self.interval, self.threaded = mode, clock, interval, threaded
        self.width = width
        self._rows = collections.OrderedDict()
        self._lock = threading.Lock()
        self._title, self._t0, self._drawn, self._stop, self._thread = "", None, 0, threading.Event(), None

    @classmethod
    def auto(cls, disabled=False, stream=None):
        """live on a terminal that can redraw, plain on one that cannot, otherwise off."""
        stream = stream if stream is not None else sys.stderr
        if disabled:
            return cls(stream, "off")
        try:
            tty = stream.isatty()
        except (AttributeError, ValueError):
            tty = False
        if not tty:
            return cls(stream, "off")
        return cls(stream, "live" if ansi_ok(stream) else "plain")

    # ---- reporting (called from any thread) ----
    def begin(self, title):
        with self._lock:
            self._title, self._t0, self._rows, self._drawn = title, self.clock(), collections.OrderedDict(), 0
        self._stop.clear()
        if self.mode == "live" and self.threaded:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def add(self, key, label):
        with self._lock:
            self._rows[key] = {"label": label, "state": "queued", "detail": "", "started": None, "finished": None, "outcome": None}

    def update(self, key, state, detail=""):
        with self._lock:
            row = self._rows.get(key)
            if row and row["finished"] is None:
                row["state"], row["detail"] = state, detail
                if row["started"] is None:
                    row["started"] = self.clock()

    def finish(self, key, outcome, detail=""):
        with self._lock:
            row = self._rows.get(key)
            if not row:
                return
            now = self.clock()
            row["started"] = row["started"] if row["started"] is not None else now
            row["finished"], row["outcome"], row["detail"], row["state"] = now, outcome, detail, "done"
            line = self._row_line(row, now, 0) if self.mode == "plain" else None
        if line:
            self._write(line + "\n")

    def hook_for(self, key):
        """A (state, detail) callback bound to one source, for ACTIVE."""
        return lambda state, detail="": self.update(key, state, detail)

    # ---- drawing ----
    def lines(self, now=None):
        """The block as text lines (pure; no escape codes), for drawing and for tests."""
        now = self.clock() if now is None else now
        with self._lock:
            tick = int((now - (self._t0 or now)) / self.interval) if self.interval else 0
            out = [f"{self._title}   {now - (self._t0 or now):4.0f} s"]
            out += [self._row_line(row, now, tick) for row in self._rows.values()]
        return out

    def _row_line(self, row, now, tick):
        seconds = ((row["finished"] if row["finished"] is not None else now) - row["started"]) if row["started"] is not None else 0.0
        if row["finished"] is not None:
            mark, text = MARKS.get(row["outcome"], "[??]"), row["detail"] or row["outcome"]
        elif row["started"] is None:
            mark, text = "   ", "queued"
        else:
            mark, text = " " + SPINNER[tick % len(SPINNER)] + " ", (row["state"] + (" " + row["detail"] if row["detail"] else ""))
        return f"  {mark} {row['label'][:26]:<26} {text[:52]:<52} {seconds:5.1f} s"

    def _draw(self):
        if self.mode != "live":
            return
        width = self.width or shutil.get_terminal_size((100, 24)).columns
        lines = [line[:max(20, width - 1)] for line in self.lines()]
        with self._lock:
            rows = list(self._rows.values())
        out = [f"\x1b[{self._drawn}A"] if self._drawn else []
        for index, line in enumerate(lines):
            if 0 < index <= len(rows):
                row = rows[index - 1]
                key = row["outcome"] if row["finished"] is not None else ("active" if row["started"] is not None else None)
                if key:
                    line = f"\x1b[{COLORS[key]}m{line}\x1b[0m"
            out.append(f"{CLEAR_LINE}{line}\n")
        self._drawn = len(lines)
        self._write("".join(out))

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                self._draw()
            except Exception:
                pass

    def end(self, summary=""):
        """Stop drawing, erase the live block, and leave one summary line."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        if self.mode == "live" and self._drawn:
            self._write(f"\x1b[{self._drawn}A" + (CLEAR_LINE + "\n") * self._drawn + f"\x1b[{self._drawn}A")
            self._drawn = 0
        if self.mode != "off" and summary:
            self._write(summary + "\n")

    def _write(self, text):
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):
            pass
