"""Colour for the console text of --sitrep and --watch (see termcolor.py for what each colour means).

Both reports are rendered as plain text first; these functions take the finished lines and return the same lines with colour added.
Nothing here changes a character: it only decides which spans of an existing line to paint.
"""
import re

from termcolor import paint_spans

SECTION_KEYS = ("STATE", "REACH", "SEVERITY", "EXPLOIT", "AFFECTED", "FIXES", "DETAIL", "SOURCES", "COVERAGE GAPS", "TIMELINE", "LEADS", "REFERENCES", "NEXT")
FACT_SECTIONS = ("STATE", "SEVERITY", "EXPLOIT", "AFFECTED", "FIXES", "DETAIL")
_KEY_LINE = re.compile(r"^(  )(" + "|".join(re.escape(k) for k in SECTION_KEYS) + r")(\s+)(.*)$")
_SPEAKER = re.compile(r"(EPSS(?= )|[^:\[\]()]{2,44}:(?= ))")
_TAIL_TAG = re.compile(r"(?<=\s\s)(\[[^\[\]]+(?: \([^()]*\))?\])$")
_MARKS = re.compile(r"\[(ok|--|!!|xx|x)\]")
_MARK_STYLE = {"ok": ("green",), "x": ("green",), "--": ("dim",), "!!": ("red",), "xx": ("red",)}
_CLOCK = re.compile(r"^(    \d{4}-\d{2}-\d{2}(?: \d{2}:\d{2} UTC| \(date only\))\s+)(declared|header|ingested|approximate)(?=\s)")
_HIGHLIGHT = ((re.compile(r"\bLISTED\b"), ("red", "bold")), (re.compile(r"Exploitation active"), ("red", "bold")), (re.compile(r"Exploitation poc"), ("yellow",)))


def colorize_sitrep(lines):
    out, section, rules, caution = [], None, 0, False
    for line in lines:
        if line and set(line) == {"="}:
            rules += 1
            caution = rules == 2
            out.append(paint_spans(line, [(0, len(line), ("dim",))]))
            continue
        if caution:
            caution = bool(line.strip())
            out.append(paint_spans(line, [(0, len(line), ("dim",))]) if line.strip() else line)
            continue
        spans = []
        if line.startswith("  SITREP  "):
            out.append(paint_spans(line, [(0, len(line), ("bold",))]))
            continue
        if line.startswith("  [!] "):
            out.append(paint_spans(line, [(2, 5, ("yellow",))]))
            continue
        if line.startswith("  Nothing found"):
            out.append(paint_spans(line, [(0, len(line), ("yellow",))]))
            continue
        key = _KEY_LINE.match(line)
        body_start = 15 if (section == "SEVERITY" and not key and line.startswith(" " * 15) and line[15:16].strip()) else None
        if key:
            section = key.group(2)
            spans.append((key.start(2), key.end(2), ("bold",)))
            body_start = key.start(4)
            if section in ("TIMELINE", "COVERAGE GAPS", "LEADS") and key.group(4).startswith(("(", "pages")):
                spans.append((key.start(4), len(line), ("dim",)))
        if body_start is not None and section in FACT_SECTIONS:
            speaker = _SPEAKER.match(line, body_start)
            if speaker:
                spans.append((speaker.start(1), speaker.end(1), ("cyan",)))
        if section in FACT_SECTIONS + ("TIMELINE", "LEADS"):
            tag = _TAIL_TAG.search(line)
            if tag:
                spans.append((tag.start(1), tag.end(1), ("dim",)))
        if section in ("SOURCES", "REFERENCES"):
            spans += [(m.start(), m.end(), _MARK_STYLE[m.group(1)]) for m in _MARKS.finditer(line)]
        if section == "REFERENCES" and re.fullmatch(r"    [a-z][a-z-]+", line):
            spans.append((4, len(line), ("bold",)))
        if section == "EXPLOIT":
            for pattern, styles in _HIGHLIGHT:
                spans += [(m.start(), m.end(), styles) for m in pattern.finditer(line)]
        if section == "SEVERITY" and "sources disagree" in line:
            at = line.index("sources disagree")
            spans.append((at, len(line), ("yellow",)))
        if section == "TIMELINE":
            clock = _CLOCK.match(line)
            if clock:
                spans.append((clock.start(2), clock.end(2), ("dim",) if clock.group(2) == "declared" else ("yellow",)))
            if line.strip().startswith(("WHEN", "ingested =")):
                spans.append((0, len(line), ("dim",)))
        out.append(paint_spans(line, spans))
    return out


_WATCH_CLASS = re.compile(r"^(    )(EXPLOITATION|DISCLOSURE|EXPOSURE|SEVERITY|FIX|RECORDS)(?=\s)")
_WATCH_TAIL = re.compile(r"  \((?:was[: ]|event time|first seen by us).*$")


def colorize_watch(lines):
    out = []
    for line in lines:
        spans = []
        stripped = line.strip()
        if line and set(line) == {"="}:
            spans.append((0, len(line), ("dim",)))
        elif line.startswith("  WATCH  "):
            spans.append((0, len(line), ("bold",)))
        elif line.startswith("  WATCH "):                      # baseline and quiet-poll lines
            spans.append((0, len(line), ("dim",)))
        elif stripped == "!! IMMEDIATE":
            spans.append((2, len(line), ("red", "bold")))
        elif stripped == "digest":
            spans.append((2, len(line), ("dim", "bold")))
        elif line.startswith("  [!] "):
            spans.append((2, 5, ("yellow",)))
        else:
            cls = _WATCH_CLASS.match(line)
            if cls:
                spans.append((cls.start(2), cls.end(2), ("cyan", "bold")))
            tail = _WATCH_TAIL.search(line)
            if tail:
                spans.append((tail.start() + 2, len(line), ("dim",)))
        out.append(paint_spans(line, spans))
    return out
