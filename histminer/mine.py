"""Sequential pattern mining over sessions of normalized commands.

Not `sort | uniq -c`. That gives you `ls`, which is the most frequent command in every shell
history ever recorded and which no amount of automation makes faster. What is wanted is the
recurring MULTI-command pattern, which requires three things a frequency count does not have:

1. Order. `git add` then `git commit` is a workflow; the reverse is a mistake.
2. Gap tolerance. Real workflows have noise in them. `git add`, `ls`, `git commit` is the
   same workflow as `git add`, `git commit`, so occurrence matching allows up to `max_gap`
   unrelated commands between consecutive pattern elements.
3. Closure. If `git add -> git commit` and `git add -> git commit -> git push` have the same
   support, reporting both is padding. Only the maximal one carries information, so
   non-closed patterns are dropped.

Support is counted in SESSIONS, not occurrences, so one pathological afternoon of repetition
cannot manufacture a pattern. Occurrences are counted separately because savings scale with
occurrences, and the two numbers answer different questions.

Generation is level-wise (GSP): frequent k-patterns extended by frequent single commands,
with the anti-monotone pruning that a pattern cannot be more frequent than its prefix.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Occurrence:
    session: int
    positions: tuple[int, ...]


@dataclass
class Pattern:
    items: tuple[str, ...]
    support: int  # sessions containing it
    occurrences: list[Occurrence] = field(default_factory=list)

    @property
    def n_occ(self) -> int:
        return len(self.occurrences)

    @property
    def length(self) -> int:
        return len(self.items)

    def key(self) -> str:
        return " ; ".join(self.items)


def find_occurrences(seq: list[str], items: tuple[str, ...], max_gap: int) -> list[tuple[int, ...]]:
    """Leftmost, non-overlapping, bounded-gap occurrences of `items` in `seq`.

    Non-overlapping matters: with overlapping matches a run of ten `git status` calls would
    report nine occurrences of `git status -> git status`, which overstates savings.
    """
    out: list[tuple[int, ...]] = []
    i = 0
    n = len(seq)
    while i < n:
        if seq[i] != items[0]:
            i += 1
            continue
        pos = [i]
        cur = i
        ok = True
        for want in items[1:]:
            found = -1
            for j in range(cur + 1, min(n, cur + 2 + max_gap)):
                if seq[j] == want:
                    found = j
                    break
            if found < 0:
                ok = False
                break
            pos.append(found)
            cur = found
        if ok:
            out.append(tuple(pos))
            i = cur + 1
        else:
            i += 1
    return out


def mine(
    sessions: list[list[str]],
    *,
    min_support: int = 2,
    min_occurrences: int = 3,
    max_len: int = 6,
    max_gap: int = 1,
    min_confidence: float = 0.5,
    max_candidates: int = 20000,
) -> list[Pattern]:
    """Return closed frequent sequential patterns of length >= 2."""
    unigrams = Counter()
    for s in sessions:
        for t in set(s):
            unigrams[t] += 1
    frequent_items = [t for t, c in unigrams.items() if c >= min_support]
    frequent_items.sort()

    def build(items: tuple[str, ...]) -> Pattern | None:
        occ: list[Occurrence] = []
        sup = 0
        for si, s in enumerate(sessions):
            hits = find_occurrences(s, items, max_gap)
            if hits:
                sup += 1
                occ.extend(Occurrence(si, h) for h in hits)
        if sup < min_support or len(occ) < min_occurrences:
            return None
        return Pattern(items, sup, occ)

    level: list[Pattern] = []
    for t in frequent_items:
        p = build((t,))
        if p:
            level.append(p)

    all_patterns: list[Pattern] = []
    candidates_seen = 0
    for _k in range(2, max_len + 1):
        nxt: list[Pattern] = []
        for base in level:
            for t in frequent_items:
                candidates_seen += 1
                if candidates_seen > max_candidates:
                    break
                p = build(base.items + (t,))
                # Confidence: given that you just did `base`, how often does `t` follow?
                # A workflow you would actually wrap in a function is one whose steps
                # reliably follow each other. Without this, a repetitive stream generates
                # every long echo of its real two-command pattern at a third of the
                # frequency, and the genuine finding drowns in its own reflections.
                if p and base.n_occ and (p.n_occ / base.n_occ) < min_confidence:
                    p = None
                if p:
                    nxt.append(p)
            if candidates_seen > max_candidates:
                break
        if not nxt:
            break
        all_patterns.extend(nxt)
        level = nxt

    return close(all_patterns)


def _is_subsequence(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
    it = iter(b)
    return all(x in it for x in a)


def is_periodic(items: tuple[str, ...]) -> bool:
    """True if the sequence is a repetition of a shorter prefix.

    A history full of `cd X`, `claude`, `cd Y`, `claude` yields `cd -> claude -> cd -> claude`
    and every longer rotation of it, all with high support, all describing the one two-command
    workflow that is already mined on its own. Reporting them buries the real finding under
    its own echoes, and the generated function is nonsense: a two-parameter `cdcl` that cds
    twice. The period is mined separately, so the repetition carries no information.
    """
    n = len(items)
    for p in range(1, n):
        if all(items[i] == items[i - p] for i in range(p, n)):
            return True
    return False


def close(patterns: list[Pattern]) -> list[Pattern]:
    """Drop any pattern that a longer pattern subsumes at identical support and occurrences."""
    patterns = [p for p in patterns if not is_periodic(p.items)]
    by_len: dict[int, list[Pattern]] = {}
    for p in patterns:
        by_len.setdefault(p.length, []).append(p)
    out: list[Pattern] = []
    for p in patterns:
        subsumed = False
        for longer_len in range(p.length + 1, max(by_len, default=0) + 1):
            for q in by_len.get(longer_len, []):
                if (
                    q.support == p.support
                    and q.n_occ == p.n_occ
                    and _is_subsequence(p.items, q.items)
                ):
                    subsumed = True
                    break
            if subsumed:
                break
        if not subsumed:
            out.append(p)
    return out


def lift(pattern: Pattern, sessions: list[list[str]]) -> float:
    """Observed occurrences over occurrences expected if commands were order-independent.

    Approximated with a contiguous-position model, which is conservative: allowing gaps only
    increases the expected count, so a lift computed this way overstates nothing it should
    understate. A lift near 1 means the pattern is frequent only because its parts are.
    """
    counts = Counter(t for s in sessions for t in s)
    n = sum(counts.values())
    if n == 0:
        return 0.0
    positions = sum(max(0, len(s) - pattern.length + 1) for s in sessions)
    expected = positions * math.prod(counts[t] / n for t in pattern.items)
    if expected <= 0:
        return float("inf")
    return pattern.n_occ / expected


def permutation_null(
    sessions: list[list[str]],
    *,
    rounds: int = 20,
    seed: int = 0,
    **mine_kw,
) -> list[int]:
    """Occurrence count of the best length>=2 pattern when order is destroyed.

    This is the negative control for the whole mining claim. Shuffling within each session
    preserves every command's frequency and every session's length, and destroys only the
    ORDER. If the miner's top pattern does not stand well clear of this null, the pattern is
    an artefact of frequency and the tool is reporting noise as insight.
    """
    rng = random.Random(seed)
    out = []
    for _ in range(rounds):
        shuffled = []
        for s in sessions:
            c = list(s)
            rng.shuffle(c)
            shuffled.append(c)
        pats = mine(shuffled, **mine_kw)
        out.append(max((p.n_occ for p in pats if p.length >= 2), default=0))
    return out
