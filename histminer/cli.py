"""histmine: mine a shell history for recurring workflows.

    python3 -m histminer.cli report ~/.bash_history
    python3 -m histminer.cli report ~/.zsh_history --json
    python3 -m histminer.cli sessions ~/.zsh_history
    python3 -m histminer.cli redact ~/.bash_history    # what the tool is allowed to see

Nothing this tool prints has passed through an unredacted stage; redaction happens as the
file is read. See histminer/redact.py, and tools/leakcheck.py which checks it independently.
"""

from __future__ import annotations

import argparse
import sys

from .parse import read
from .redact import Redactor
from .report import MineOptions, analyze, render_text, to_json
from .sessions import estimate_gap, gaps, model_for
from .suggest import SavingsModel


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("path", help="history file, or a directory of *.jsonl transcripts")
    p.add_argument("--format", dest="fmt", default=None,
                   choices=["bash-plain", "bash-timestamp", "zsh-extended", "jsonl"])
    p.add_argument("--split-compound", action="store_true",
                   help="treat `a && b; c` as three commands (right for machine-written "
                        "histories, wrong for interactive ones)")
    p.add_argument("--keep-home", action="store_true",
                   help="do not rewrite /home/<user> to ~ (still redacts everything else)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="histmine", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("report", help="mine workflows and propose aliases/functions")
    _common(rp)
    rp.add_argument("--json", action="store_true")
    rp.add_argument("--top", type=int, default=10)
    rp.add_argument("--min-support", type=int, default=2, help="minimum distinct sessions")
    rp.add_argument("--min-occurrences", type=int, default=3)
    rp.add_argument("--max-len", type=int, default=6)
    rp.add_argument("--max-gap", type=int, default=1,
                    help="unrelated commands tolerated between pattern elements")
    rp.add_argument("--min-confidence", type=float, default=0.5,
                    help="how often the next step must follow the previous one")
    rp.add_argument("--gap", type=float, default=None,
                    help="session boundary in seconds; default is estimated from the data")
    rp.add_argument("--typing-cps", type=float, default=5.0)
    rp.add_argument("--switch-cost", type=float, default=0.8)
    rp.add_argument("--rounds", type=int, default=20, help="permutation null rounds")
    rp.add_argument("--no-diagnostics", action="store_true")

    sp = sub.add_parser("sessions", help="inter-command gap distribution and chosen boundary")
    _common(sp)

    dp = sub.add_parser("redact", help="print the history as the miner sees it")
    _common(dp)

    a = ap.parse_args(argv)
    red = Redactor(redact_home=not a.keep_home)
    hist = read(a.path, fmt=a.fmt, redactor=red, split=a.split_compound)

    if not hist.events:
        print(f"no commands parsed from {a.path} (format {hist.fmt})", file=sys.stderr)
        return 2

    if a.cmd == "redact":
        for e in hist.events:
            print(e.text)
        return 0

    if a.cmd == "sessions":
        g = gaps(hist.events)
        m = model_for(hist.events)
        print(f"format        {hist.fmt}")
        print(f"commands      {len(hist.events)}")
        print(f"usable gaps   {len(g)}")
        if not g:
            print("NO TIMESTAMPS. A session boundary cannot be computed from this file.")
            print("Set HISTTIMEFORMAT='%s ' (bash) or setopt EXTENDED_HISTORY (zsh).")
            print(f"model         {m.describe()}")
            return 0
        est = estimate_gap(hist.events)
        print(f"model         {m.describe()}")
        print(f"note          {est.note}")
        buckets = [1, 5, 15, 60, 300, 900, 3600, 14400, 86400]
        prev = 0
        for b in buckets:
            n = sum(1 for v in g if prev < v <= b)
            print(f"  {prev:>7d}-{b:<7d}s  {n:6d}  {'#' * int(60 * n / max(1, len(g)))}")
            prev = b
        print(f"  {prev:>7d}+{'':<8}s  {sum(1 for v in g if v > prev):6d}")
        return 0

    opts = MineOptions(
        min_support=a.min_support,
        min_occurrences=a.min_occurrences,
        max_len=a.max_len,
        max_gap=a.max_gap,
        min_confidence=a.min_confidence,
        top=a.top,
        permutation_rounds=a.rounds,
    )
    model = SavingsModel(typing_cps=a.typing_cps, switch_cost=a.switch_cost)
    an = analyze(
        hist,
        opts=opts,
        savings=model,
        gap_override=a.gap,
        do_sweep=not a.no_diagnostics,
        do_permutation=not a.no_diagnostics,
    )
    print(to_json(an) if a.json else render_text(an))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
