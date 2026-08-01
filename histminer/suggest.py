"""Turn a mined pattern into a shell alias or function, and cost the saving honestly.

Two decisions live here.

ALIAS OR FUNCTION. A sequence that recurs with identical arguments every time is a fixed
incantation and wants an alias. A sequence that recurs with different arguments is a
parameterised workflow and wants a function. The second case is the interesting one and is
also the one a frequency counter cannot see, because with concrete arguments each instance
looks unique. Slots that vary together, holding the same value as each other in every single
occurrence, become ONE parameter used twice rather than two parameters, which is what makes
`gcb feature-x` possible instead of `gcb feature-x feature-x`.

WHAT IT SAVES. Every ranking here is by estimated time or keystrokes, never by frequency,
and the model is printed with the numbers rather than compressed into an unexplained score.
The model is simple and stated so it can be argued with:

    keystrokes_saved  = characters typed today - characters typed with the suggestion
    seconds_saved     = keystrokes_saved / typing_rate + (n_commands - 1) * switch_cost

`switch_cost` is the per-command-boundary overhead that is not typing: recalling what comes
next, waiting to see the previous command succeeded, deciding. It is the parameter with the
least evidence behind it, so `histmine report --switch-cost` exists and the report shows how
the ranking moves when it changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .mine import Pattern
from .normalize import Command

# Names never to shadow. Static rather than probed from PATH so that the same history always
# produces the same suggestion, on any machine.
RESERVED = frozenset(
    """
    ls cd cp mv rm mkdir rmdir cat less more head tail grep sed awk find sort uniq wc
    echo printf test true false time env export set unset alias unalias source exec
    git npm node python python3 pip make cargo go docker kubectl ssh scp curl wget
    tar gzip zip diff patch chmod chown ln pwd which type man kill ps top df du
    if then else fi for while do done case esac function return local read
    """.split()
)

_SLOT = re.compile(r"^<[A-Z]+>$")
_FLAG_SLOT = re.compile(r"^(--[A-Za-z0-9][A-Za-z0-9-]*=)(<[A-Z]+>)$")


@dataclass(frozen=True)
class SavingsModel:
    """Every constant used to convert a pattern into a claim about time."""

    typing_cps: float = 5.0
    switch_cost: float = 0.8
    setup_seconds: float = 90.0

    def describe(self) -> list[str]:
        return [
            f"typing rate {self.typing_cps:.1f} chars/sec "
            f"(~{self.typing_cps * 60 / 5:.0f} wpm at 5 chars per word)",
            f"switch cost {self.switch_cost:.2f}s per command boundary "
            f"(recall, wait, decide; the weakest constant in the model)",
            f"setup cost {self.setup_seconds:.0f}s to write and install one suggestion",
        ]


@dataclass
class Suggestion:
    name: str
    kind: str  # "alias" | "function"
    body: str
    pattern: Pattern
    n_params: int
    keystrokes_before: float
    keystrokes_after: float
    occurrences: int
    per_week: float | None
    rate_basis: str
    lift: float = 0.0
    examples: list[str] = field(default_factory=list)

    @property
    def keystrokes_saved(self) -> float:
        return max(0.0, self.keystrokes_before - self.keystrokes_after)

    def seconds_saved_each(self, m: SavingsModel) -> float:
        return self.keystrokes_saved / m.typing_cps + (self.pattern.length - 1) * m.switch_cost

    def seconds_per_week(self, m: SavingsModel) -> float | None:
        if self.per_week is None:
            return None
        return self.seconds_saved_each(m) * self.per_week

    def payback_weeks(self, m: SavingsModel) -> float | None:
        spw = self.seconds_per_week(m)
        if not spw:
            return None
        return m.setup_seconds / spw


def render(template: str, values: list[str]) -> str:
    """Rebuild a command line from a template, filling slots left to right."""
    out: list[str] = []
    vi = 0
    for tok in template.split(" "):
        m = _FLAG_SLOT.match(tok)
        if m:
            out.append(m.group(1) + (values[vi] if vi < len(values) else m.group(2)))
            vi += 1
        elif _SLOT.match(tok):
            out.append(values[vi] if vi < len(values) else tok)
            vi += 1
        else:
            out.append(tok)
    return " ".join(out)


def _name_for(commands: list[str]) -> str:
    parts: list[str] = []
    for c in commands:
        words = [w for w in c.split(" ") if w and not w.startswith("<") and not w.startswith("-")]
        if not words:
            continue
        if len(words) > 1:
            # `git commit` -> "gc": the subcommand is the distinguishing part.
            parts.append(words[0][:1] + "".join(w[:1] for w in words[1:3]))
        else:
            parts.append(words[0][:2])
    name = "".join(parts)[:8] or "wf"
    if not name[0].isalpha():
        name = "wf" + name
    if name in RESERVED:
        name += "w"
    return name


def build(
    pattern: Pattern,
    sessions: list[list[Command]],
    *,
    per_week: float | None,
    rate_basis: str,
    lift_value: float = 0.0,
    used_names: set[str] | None = None,
) -> Suggestion:
    used_names = used_names if used_names is not None else set()

    # Collect, for every occurrence, the concrete commands it matched.
    matched: list[list[Command]] = [
        [sessions[o.session][p] for p in o.positions] for o in pattern.occurrences
    ]

    # (element index, slot index) -> list of values, one per occurrence.
    slot_values: dict[tuple[int, int], list[str]] = {}
    for occ in matched:
        for ei, cmd in enumerate(occ):
            for si, val in enumerate(cmd.slots):
                slot_values.setdefault((ei, si), []).append(val)

    varying = [k for k, v in sorted(slot_values.items()) if len(set(v)) > 1]

    # Slots that hold the same value AS EACH OTHER in every occurrence are one parameter.
    param_of: dict[tuple[int, int], int] = {}
    groups: list[list[tuple[int, int]]] = []
    for k in varying:
        placed = False
        for gi, g in enumerate(groups):
            if slot_values[k] == slot_values[g[0]]:
                g.append(k)
                param_of[k] = gi
                placed = True
                break
        if not placed:
            param_of[k] = len(groups)
            groups.append([k])

    kind = "function" if groups else "alias"

    lines: list[str] = []
    for ei, item in enumerate(pattern.items):
        n_slots = len(matched[0][ei].slots) if matched else 0
        values: list[str] = []
        for si in range(n_slots):
            k = (ei, si)
            if k in param_of:
                values.append(f'"${param_of[k] + 1}"')
            else:
                vals = slot_values.get(k, [])
                values.append(vals[0] if vals else "<ARG>")
        lines.append(render(item, values))

    base = _name_for(list(pattern.items))
    name = base
    n = 2
    while name in used_names:
        name = f"{base}{n}"
        n += 1
    used_names.add(name)

    if kind == "alias":
        body = "alias {}='{}'".format(name, " && ".join(lines))
    else:
        indented = "\n".join("  " + l for l in lines)
        body = "{}() {{\n{}\n}}".format(name, indented)

    before = sum(sum(len(c.raw) + 1 for c in occ) for occ in matched) / max(1, len(matched))
    if kind == "alias":
        after = len(name) + 1.0
    else:
        after = len(name) + 1.0
        for g in groups:
            vals = slot_values[g[0]]
            after += sum(len(v) + 1 for v in vals) / len(vals)

    examples = []
    for occ in matched[:3]:
        examples.append(" ; ".join(c.raw for c in occ))

    return Suggestion(
        name=name,
        kind=kind,
        body=body,
        pattern=pattern,
        n_params=len(groups),
        keystrokes_before=before,
        keystrokes_after=after,
        occurrences=pattern.n_occ,
        per_week=per_week,
        rate_basis=rate_basis,
        lift=lift_value,
        examples=examples,
    )
