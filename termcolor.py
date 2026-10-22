"""Terminal colour for the --sitrep and --watch reports.

The scheme is deliberately small, and the colours carry a fixed meaning so a glance is enough:
  teal (cyan)  who is speaking: "CISA-ADP SSVC:", "Red Hat rating:", "Debian fixed:", "EPSS". Neutral, so it never implies good or bad.
  green        a source answered ([ok]) or a page was read ([x])
  yellow       a caution: sources disagree, or a time is on a clock that is not the source's own
  red          an alarm or a failure: KEV LISTED, exploitation active, [!!] / [xx]
  dim          what should recede: rules, the source tag at the end of a line, "nothing there"
  bold         section keys and titles

Colour is only ever added to text that is already there: spans are found in the plain line and painted afterwards, so stripping the
escape codes gives back the plain report exactly. It is used only when stdout is a terminal that understands it: never for --json, a
pipe or a file, and never when NO_COLOR is set or --no-color is given.
"""
import os
import re
import sys

CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "cyan": "36"}
_ANSI = re.compile("\x1b\\[[0-9;]*m")


def paint(text, *styles) -> str:
    codes = ";".join(CODES[s] for s in styles)
    return f"\x1b[{codes}m{text}\x1b[0m" if codes and text else text


def paint_spans(line, spans) -> str:
    """`line` with each (start, end, styles) span painted. Overlapping spans: the earlier one wins. Never changes the text itself."""
    out, position = [], 0
    for start, end, styles in sorted(spans, key=lambda s: (s[0], s[1])):
        if start < position or end <= start:
            continue
        out.append(line[position:start])
        out.append(paint(line[start:end], *styles))
        position = end
    out.append(line[position:])
    return "".join(out)


def strip(text) -> str:
    """The text with every colour code removed."""
    return _ANSI.sub("", text)


def use_color(stream=None, disabled=False) -> bool:
    """True only for a real terminal that will show colour, with NO_COLOR and --no-color honoured."""
    stream = stream if stream is not None else sys.stdout
    if disabled or os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    import sitrep_progress
    return sitrep_progress.ansi_ok(stream)
