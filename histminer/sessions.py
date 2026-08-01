"""Cutting a history into sessions.

Two commands four hours apart are not a workflow, so mining has to happen inside sessions
rather than across the whole file. Everything here exists to make the session boundary an
argued number rather than a round one somebody liked the look of.

The argument: inter-command gaps in a real history are bimodal in log space. Within a burst
of work the gaps cluster around a few seconds; between bursts they cluster around hours.
The natural cut is the ANTIMODE, the density minimum between the two peaks. `estimate_gap`
finds it from the data and reports which mode structure it found. When the distribution is
not bimodal it says so and falls back to a documented default rather than inventing a knee.

The second thing this file does is refuse to pretend. A plain bash history has no
timestamps at all, and the honest response is not to silently treat the whole file as one
session while returning the same type as a real segmentation. `SessionModel.kind` carries
the distinction into every downstream consumer, and the report prints it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .parse import Event

DEFAULT_GAP = 300.0  # seconds; used only when the data cannot supply one, and labelled as such


@dataclass(frozen=True)
class GapEstimate:
    seconds: float
    method: str  # "antimode" | "fallback-unimodal" | "fallback-untimestamped"
    modes: tuple[float, ...]  # peak locations in seconds
    n_gaps: int
    note: str


@dataclass(frozen=True)
class SessionModel:
    """How a history was cut. `kind` distinguishes a real segmentation from a stand-in."""

    kind: str  # "timestamp-gap" | "single-block"
    gap: GapEstimate | None

    @property
    def trustworthy(self) -> bool:
        return self.kind == "timestamp-gap"

    def describe(self) -> str:
        if self.kind == "single-block":
            return (
                "single-block (history has no timestamps, so no session boundary can be "
                "computed; set HISTTIMEFORMAT='%s ' in bash or EXTENDED_HISTORY in zsh to fix)"
            )
        assert self.gap is not None
        return f"timestamp-gap at {self.gap.seconds:.0f}s via {self.gap.method}"


def gaps(events: list[Event]) -> list[float]:
    out = []
    for a, b in zip(events, events[1:]):
        if a.ts is None or b.ts is None:
            continue
        d = b.ts - a.ts
        if d > 0:
            out.append(d)
    return out


def _smoothed_histogram(values: list[float], lo: float, hi: float, width: float,
                        sigma_bins: float = 1.5) -> tuple[list[float], list[float]]:
    n = max(1, int(math.ceil((hi - lo) / width)))
    counts = [0.0] * n
    for v in values:
        i = int((v - lo) / width)
        if 0 <= i < n:
            counts[i] += 1.0
    # Gaussian smoothing so single-bin noise does not create spurious modes.
    radius = int(math.ceil(3 * sigma_bins))
    kernel = [math.exp(-0.5 * (k / sigma_bins) ** 2) for k in range(-radius, radius + 1)]
    ksum = sum(kernel)
    kernel = [k / ksum for k in kernel]
    smooth = [0.0] * n
    for i in range(n):
        acc = 0.0
        for j, w in enumerate(kernel):
            src = i + j - radius
            if 0 <= src < n:
                acc += counts[src] * w
        smooth[i] = acc
    centres = [lo + (i + 0.5) * width for i in range(n)]
    return centres, smooth


def estimate_gap(events: list[Event], *, min_gaps: int = 200) -> GapEstimate:
    """Find the session boundary from the inter-command gap distribution."""
    g = gaps(events)
    if len(g) < min_gaps:
        return GapEstimate(
            DEFAULT_GAP,
            "fallback-untimestamped" if not g else "fallback-unimodal",
            (),
            len(g),
            f"only {len(g)} usable gaps, need {min_gaps} to estimate; using default",
        )

    logs = [math.log10(v) for v in g]
    centres, dens = _smoothed_histogram(logs, -1.0, 6.0, 0.1)

    peaks = [
        i
        for i in range(1, len(dens) - 1)
        if dens[i] > dens[i - 1] and dens[i] >= dens[i + 1] and dens[i] > 0
    ]
    peaks.sort(key=lambda i: dens[i], reverse=True)

    for j in range(len(peaks)):
        for k in range(j + 1, len(peaks)):
            a, b = sorted((peaks[j], peaks[k]))
            if centres[b] - centres[a] < 0.7:
                continue  # peaks less than ~5x apart are the same mode
            trough = min(range(a, b + 1), key=lambda i: dens[i])
            if dens[trough] > 0.6 * min(dens[a], dens[b]):
                continue  # not a real valley, just a shoulder
            return GapEstimate(
                10 ** centres[trough],
                "antimode",
                (10 ** centres[a], 10 ** centres[b]),
                len(g),
                f"bimodal log-gap density, peaks at {10 ** centres[a]:.1f}s and "
                f"{10 ** centres[b]:.0f}s, antimode at {10 ** centres[trough]:.0f}s",
            )

    return GapEstimate(
        DEFAULT_GAP,
        "fallback-unimodal",
        tuple(10 ** centres[i] for i in peaks[:1]),
        len(g),
        "log-gap density is not bimodal, so no antimode exists; using documented default",
    )


def model_for(events: list[Event]) -> SessionModel:
    if any(e.ts is None for e in events) or len(gaps(events)) < 2:
        return SessionModel("single-block", None)
    return SessionModel("timestamp-gap", estimate_gap(events))


def segment(events: list[Event], gap_seconds: float | None) -> list[list[Event]]:
    """Split into sessions. `gap_seconds=None` means one block, for untimestamped input."""
    if not events:
        return []
    if gap_seconds is None:
        return [list(events)]
    out: list[list[Event]] = [[events[0]]]
    for prev, cur in zip(events, events[1:]):
        if prev.ts is None or cur.ts is None or (cur.ts - prev.ts) > gap_seconds:
            out.append([cur])
        else:
            out[-1].append(cur)
    return out
