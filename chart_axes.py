"""Date-axis helpers shared by the --report charts."""

import math


_DATE_LABEL_THIN_ABOVE = 20       # windows with more dates than this never label every date
_DATE_LABEL_MIN_SPACING_PX = 48   # labels are kept at least this far apart (a rotated YYYY-MM-DD is about this wide)
_PLOT_WIDTH_FRACTION = 0.85       # share of the figure width the plot area occupies, for estimating room per tick


def date_label_step(count: int, fig_width_px: float) -> int:
    """Label every Nth date: 1 up to _DATE_LABEL_THIN_ABOVE dates; beyond that at least every other, and more
    when the dates would otherwise sit closer than _DATE_LABEL_MIN_SPACING_PX. In a 12-inch figure that is every
    other date for about a month and every third for about two."""
    if count <= _DATE_LABEL_THIN_ABOVE:
        return 1
    per_tick = fig_width_px * _PLOT_WIDTH_FRACTION / count
    return max(2, math.ceil(_DATE_LABEL_MIN_SPACING_PX / per_tick))


def thin_date_ticks(ax, dates):
    """Keeps a tick mark (and gridline) for EVERY date but labels only every Nth, starting with the first, so a long
    window's labels stop crowding each other while no date loses its mark."""
    if not ax.has_data():
        return
    dates = list(dates)
    step = date_label_step(len(dates), ax.figure.get_figwidth() * ax.figure.dpi)
    ax.set_xticks(range(len(dates)))
    ax.set_xticklabels([d if i % step == 0 else "" for i, d in enumerate(dates)], rotation=30, ha="right")
