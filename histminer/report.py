"""Assemble the analysis and render it.

The ordering rule for the whole tool lives here: suggestions are ranked by estimated time
saved, never by frequency. `ls` will be the most frequent command in the input and will not
appear in the output, because abstracting it saves nothing.

Three diagnostics ship with every report rather than being hidden behind a flag, because
each one is the negative control for a claim the report makes:

  session model     says whether the boundary was computed from the data or stood in for
  threshold sweep   says whether the findings survive a different boundary
  permutation null  says whether the findings survive destroying command order
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import mine as mining
from .normalize import Command, normalize
from .parse import History
from .sessions import SessionModel, model_for, segment
from .suggest import SavingsModel, Suggestion, build

SWEEP_GAPS = (30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0)


@dataclass
class MineOptions:
    min_support: int = 2
    min_occurrences: int = 3
    max_len: int = 6
    max_gap: int = 1
    min_confidence: float = 0.5
    top: int = 10
    permutation_rounds: int = 20

    def as_mine_kwargs(self) -> dict:
        return {
            "min_support": self.min_support,
            "min_occurrences": self.min_occurrences,
            "max_len": self.max_len,
            "max_gap": self.max_gap,
            "min_confidence": self.min_confidence,
        }


@dataclass
class Analysis:
    history: History
    model: SessionModel
    n_commands: int
    n_sessions: int
    n_templates: int
    n_redacted: int
    redaction_kinds: dict[str, int]
    suggestions: list[Suggestion]
    savings: SavingsModel
    opts: MineOptions
    sweep: list[tuple[float, float, int]] = field(default_factory=list)
    null_max: list[int] = field(default_factory=list)
    null_threshold: int = 0
    top_frequency: list[tuple[str, int]] = field(default_factory=list)
    degraded: str = ""

    @property
    def observed_top(self) -> int:
        return max((s.pattern.n_occ for s in self.suggestions), default=0)

    @property
    def null_p(self) -> float | None:
        """Fraction of order-destroyed shuffles that reach the observed top occurrence count."""
        if not self.null_max:
            return None
        hits = sum(1 for v in self.null_max if v >= self.observed_top)
        return (hits + 1) / (len(self.null_max) + 1)


MIN_SPAN_DAYS = 1.0


def _weeks(history: History) -> float | None:
    """Weeks of history, or None when the span is too short to extrapolate from.

    Dividing 8 occurrences by a 7 minute span produces "1,600 times a week", which is not a
    cautious estimate but a fabricated one. Below a day of history there is no rate to
    report, and the report falls back to total time saved over the recorded period.
    """
    d = history.span_days
    if d is None or d < MIN_SPAN_DAYS:
        return None
    return d / 7.0


def analyze(
    history: History,
    *,
    opts: MineOptions | None = None,
    savings: SavingsModel | None = None,
    gap_override: float | None = None,
    do_sweep: bool = True,
    do_permutation: bool = True,
    max_overlap: float = 0.5,
) -> Analysis:
    opts = opts or MineOptions()
    savings = savings or SavingsModel()

    model = model_for(history.events)
    gap = gap_override if gap_override is not None else (
        model.gap.seconds if model.gap else None
    )
    override_ignored = ""
    if model.kind == "single-block":
        if gap_override is not None:
            override_ignored = (
                f"--gap {gap_override:.0f} ignored: this history has no timestamps, so there "
                f"is nothing to measure a gap against"
            )
        gap = None

    raw_sessions = segment(history.events, gap)
    sessions: list[list[Command]] = [[normalize(e.text) for e in s] for s in raw_sessions]
    seqs = [[c.template for c in s] for s in sessions]

    # Support is measured in sessions, so a history with fewer sessions than the requested
    # support can never produce a result. Rather than return a silent empty list, the
    # threshold degrades to what the data can support and the report says it degraded.
    mine_kw = opts.as_mine_kwargs()
    degraded = override_ignored
    if mine_kw["min_support"] > len(raw_sessions):
        degraded = (degraded + "; " if degraded else "") + (
            f"min-support lowered from {mine_kw['min_support']} to {len(raw_sessions)}: "
            f"the history yields only {len(raw_sessions)} session(s), so a higher "
            f"session-support threshold can never be met"
        )
        mine_kw["min_support"] = max(1, len(raw_sessions))

    patterns = mining.mine(seqs, **mine_kw)
    patterns_ungated = list(patterns)

    # Significance gate. Shuffling each session preserves how often every command was run
    # and destroys only the order, so any pattern that a shuffle can match as often as the
    # real history did is a coincidence of frequency. Requiring a pattern to beat EVERY
    # shuffle is a one-sided test at p <= 1/(rounds+1). This is the gate that keeps a
    # structureless history from producing confident nonsense, and it is why the control
    # fixture returns nothing at all rather than something small and plausible.
    null_max: list[int] = []
    null_threshold = 0
    if do_permutation and seqs:
        null_max = mining.permutation_null(
            seqs, rounds=opts.permutation_rounds, **mine_kw
        )
        null_threshold = max(null_max) if null_max else 0
        patterns = [p for p in patterns if p.n_occ > null_threshold]

    weeks = _weeks(history)
    rate_basis = (
        f"{weeks:.1f} weeks of history"
        if weeks
        else (
            "no timestamps, so per-week rate is not derivable"
            if not history.timestamped
            else f"history spans under {MIN_SPAN_DAYS:.0f} day, too short for a weekly rate"
        )
    )

    used: set[str] = set()
    suggestions: list[Suggestion] = []
    for p in patterns:
        if p.length < 2:
            continue
        per_week = (p.n_occ / weeks) if weeks else None
        s = build(
            p,
            sessions,
            per_week=per_week,
            rate_basis=rate_basis,
            lift_value=mining.lift(p, seqs),
            used_names=used,
        )
        suggestions.append(s)

    def rank(s: Suggestion) -> float:
        spw = s.seconds_per_week(savings)
        return spw if spw is not None else s.seconds_saved_each(savings) * s.occurrences

    suggestions.sort(key=rank, reverse=True)
    suggestions = [s for s in suggestions if s.keystrokes_saved > 0]

    # Greedy disjoint cover. Savings only add up if the suggestions describe different parts
    # of the history. A repetitive stream produces every rotation and echo of its real
    # pattern, each matching the same commands over again; keeping them all would let the
    # report claim the same minute of typing three times. So a pattern is kept only if most
    # of the commands it matches are not already explained by a higher-value suggestion.
    covered: set[tuple[int, int]] = set()
    kept: list[Suggestion] = []
    for s in suggestions:
        cells = {(o.session, p) for o in s.pattern.occurrences for p in o.positions}
        if not cells:
            continue
        overlap = len(cells & covered) / len(cells)
        if overlap > max_overlap:
            continue
        covered |= cells
        kept.append(s)
        if len(kept) >= opts.top:
            break
    suggestions = kept

    counts: dict[str, int] = {}
    for s in sessions:
        for c in s:
            counts[c.template] = counts.get(c.template, 0) + 1
    top_freq = sorted(counts.items(), key=lambda kv: -kv[1])[:5]

    redaction_kinds: dict[str, int] = {}
    for e in history.events:
        for k in e.redactions:
            redaction_kinds[k] = redaction_kinds.get(k, 0) + 1

    def top_keys(pats: list) -> set[str]:
        # Deterministic: sorted by occurrences then lexically, never by set iteration order.
        ranked = sorted(
            (p for p in pats if p.length >= 2), key=lambda p: (-p.n_occ, p.key())
        )
        return {p.key() for p in ranked[: max(opts.top, 10)]}

    sweep: list[tuple[float, float, int]] = []
    if do_sweep and model.kind == "timestamp-gap":
        # Compare like with like: the same selection at the chosen gap against the same
        # selection at each swept gap. Comparing the post-cover suggestion list against a
        # raw pattern list would report instability that is an artefact of the comparison.
        chosen = top_keys(patterns_ungated)
        for g in SWEEP_GAPS:
            alt_sess = segment(history.events, g)
            alt_seq = [[normalize(e.text).template for e in s] for s in alt_sess]
            alt = mining.mine(alt_seq, **{**mine_kw, "min_support": opts.min_support})
            alt_keys = top_keys(alt)
            union = chosen | alt_keys
            j = len(chosen & alt_keys) / len(union) if union else 1.0
            sweep.append((g, j, len(alt_sess)))

    return Analysis(
        history=history,
        model=model,
        n_commands=len(history.events),
        n_sessions=len(raw_sessions),
        n_templates=len(counts),
        n_redacted=sum(1 for e in history.events if e.redactions),
        redaction_kinds=redaction_kinds,
        suggestions=suggestions,
        savings=savings,
        opts=opts,
        sweep=sweep,
        null_max=null_max,
        null_threshold=null_threshold,
        top_frequency=top_freq,
        degraded=degraded,
    )


def render_text(a: Analysis) -> str:
    m = a.savings
    L: list[str] = []
    add = L.append
    add(f"history      {a.history.path}  ({a.history.fmt})")
    add(f"commands     {a.n_commands} -> {a.n_templates} distinct templates")
    add(f"sessions     {a.n_sessions} via {a.model.describe()}")
    if a.model.gap and a.model.gap.method == "antimode":
        add(f"             {a.model.gap.note}")
    elif a.model.gap:
        add(f"             {a.model.gap.note}")
    if a.degraded:
        add(f"NOTE         {a.degraded}")
    add(f"redacted     {a.n_redacted} of {a.n_commands} commands touched by redaction")
    if a.redaction_kinds:
        kinds = ", ".join(f"{k}x{v}" for k, v in sorted(a.redaction_kinds.items()))
        add(f"             {kinds}")
    add("")
    add("most frequent single commands (shown to be ignored, automating them saves nothing):")
    for t, c in a.top_frequency:
        add(f"  {c:5d}  {t}")
    add("")
    add("savings model")
    for line in m.describe():
        add(f"  - {line}")
    add(f"  - occurrence rate basis: {a.suggestions[0].rate_basis if a.suggestions else 'n/a'}")
    add("")

    if not a.suggestions:
        add("no multi-command workflow met the thresholds. Nothing to suggest.")
    else:
        add(f"top {len(a.suggestions)} workflows by estimated time saved")
        for i, s in enumerate(a.suggestions, 1):
            spw = s.seconds_per_week(m)
            each = s.seconds_saved_each(m)
            add("")
            add(f"{i}. {s.name}  [{s.kind}, {s.n_params} param(s)]")
            add(f"   {' ; '.join(s.pattern.items)}")
            add(
                f"   seen {s.occurrences}x across {s.pattern.support} session(s), "
                f"lift {s.lift:.1f}x over order-independent chance"
            )
            saved = f"{s.keystrokes_saved:.0f} keystrokes and {each:.1f}s per run"
            if spw is not None:
                pb = s.payback_weeks(m)
                saved += f", {spw / 60:.1f} min/week"
                if pb is not None:
                    saved += f", pays back in {pb:.1f} week(s)"
            add(f"   saves {saved}")
            for line in s.body.split("\n"):
                add(f"     {line}")
            if s.examples:
                add(f"   e.g. {s.examples[0]}")

    add("")
    add("diagnostics")
    if a.null_max:
        add(
            f"  order matters: shuffling each session {len(a.null_max)} times gives a best "
            f"pattern of {max(a.null_max)} occurrences (median "
            f"{sorted(a.null_max)[len(a.null_max) // 2]}); everything reported above had to "
            f"beat that, so p <= {1 / (len(a.null_max) + 1):.3f} for each"
        )
    else:
        add("  order matters: NOT RUN, so the significance gate is DISABLED and the "
            "suggestions above are unfiltered by any null model")
    if a.sweep:
        worst = min(j for _, j, _ in a.sweep)
        add(f"  threshold sensitivity: top-set Jaccard vs chosen gap, worst {worst:.2f}")
        for g, j, ns in a.sweep:
            add(f"    gap {g:6.0f}s -> {ns:5d} sessions, jaccard {j:.2f}")
    else:
        add("  threshold sensitivity: not applicable (no timestamps to sweep)")
    return "\n".join(L)


def to_json(a: Analysis) -> str:
    m = a.savings
    return json.dumps(
        {
            "format": a.history.fmt,
            "commands": a.n_commands,
            "templates": a.n_templates,
            "sessions": a.n_sessions,
            "session_model": a.model.kind,
            "session_model_detail": a.model.describe(),
            "gap_seconds": a.model.gap.seconds if a.model.gap else None,
            "gap_method": a.model.gap.method if a.model.gap else None,
            "redacted_commands": a.n_redacted,
            "redaction_kinds": a.redaction_kinds,
            "savings_model": {
                "typing_cps": m.typing_cps,
                "switch_cost": m.switch_cost,
                "setup_seconds": m.setup_seconds,
            },
            "top_frequency": [{"template": t, "count": c} for t, c in a.top_frequency],
            "suggestions": [
                {
                    "name": s.name,
                    "kind": s.kind,
                    "params": s.n_params,
                    "sequence": list(s.pattern.items),
                    "occurrences": s.occurrences,
                    "support": s.pattern.support,
                    "lift": round(s.lift, 3),
                    "keystrokes_saved": round(s.keystrokes_saved, 1),
                    "seconds_each": round(s.seconds_saved_each(m), 2),
                    "seconds_per_week": (
                        round(s.seconds_per_week(m), 2)
                        if s.seconds_per_week(m) is not None
                        else None
                    ),
                    "body": s.body,
                }
                for s in a.suggestions
            ],
            "diagnostics": {
                "null_max": a.null_max,
                "observed_top": a.observed_top,
                "null_p": a.null_p,
                "sweep": [
                    {"gap": g, "jaccard": round(j, 3), "sessions": n} for g, j, n in a.sweep
                ],
            },
        },
        indent=2,
        sort_keys=True,
    )
