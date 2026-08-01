#!/usr/bin/env python3
"""Regenerate docs/index.html and the numbers block in README.md from a real run.

Both outputs are derived from `fixtures/planted.history`, which is committed, so anyone can
reproduce them exactly. Nothing here is derived from a real history: the page and the README
would then carry numbers nobody else could check and that could not be regenerated without
the private file that produced them.

`scripts/verify.sh` runs this with --check, which regenerates into a temporary directory and
diffs. A number in a README is a claim like any other, and one that cannot be regenerated
goes stale the first time the ranking changes.
"""

from __future__ import annotations

import argparse
import html
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from histminer.parse import read  # noqa: E402
from histminer.report import MineOptions, analyze  # noqa: E402
from histminer.suggest import SavingsModel  # noqa: E402

BEGIN = "<!-- NUMBERS:BEGIN -->"
END = "<!-- NUMBERS:END -->"


def build_analysis():
    hist = read(ROOT / "fixtures" / "planted.history")
    return analyze(hist, opts=MineOptions(permutation_rounds=20), savings=SavingsModel())


def numbers_markdown(a) -> str:
    m = a.savings
    lines = [
        BEGIN,
        "",
        f"`fixtures/planted.history`: **{a.n_commands} commands**, "
        f"**{a.n_templates} distinct templates**, cut into **{a.n_sessions} sessions** at a "
        f"**{a.model.gap.seconds:.0f}s** boundary found by {a.model.gap.method}.",
        "",
        f"The gap distribution is bimodal: peaks at "
        f"{a.model.gap.modes[0]:.1f}s and {a.model.gap.modes[1]:.0f}s. The boundary is the "
        f"density minimum between them, not a round number chosen by hand.",
        "",
        "| # | name | kind | params | seq len | seen | lift | keystrokes saved | min/week |",
        "|---|------|------|--------|---------|------|------|------------------|----------|",
    ]
    for i, s in enumerate(a.suggestions, 1):
        spw = s.seconds_per_week(m)
        lines.append(
            f"| {i} | `{s.name}` | {s.kind} | {s.n_params} | {s.pattern.length} | "
            f"{s.occurrences} | {s.lift:.0f}x | {s.keystrokes_saved:.0f} | "
            f"{(spw / 60 if spw else 0):.1f} |"
        )
    worst = min((j for g, j, _ in a.sweep if g >= 120), default=0.0)
    lines += [
        "",
        f"The most frequent single command is `{a.top_frequency[0][0]}` at "
        f"{a.top_frequency[0][1]} runs, and it appears in none of the suggestions.",
        "",
        f"Order-destroyed null over {len(a.null_max)} shuffles: best pattern "
        f"{max(a.null_max)} occurrences against {a.observed_top} observed, so every "
        f"suggestion above clears p <= {1 / (len(a.null_max) + 1):.3f}.",
        "",
        f"Boundary sensitivity: top-set Jaccard against the chosen {a.model.gap.seconds:.0f}s "
        f"stays at {worst:.2f} or better for every boundary from 120s to 3600s.",
        "",
        END,
    ]
    return "\n".join(lines)


CSS = """
:root {
  color-scheme: light dark;
  --bg: #fbfaf8; --fg: #16150f; --muted: #5d5a4e; --line: #ded9c8;
  --card: #ffffff; --accent: #7a4a00; --code: #f2efe4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12120f; --fg: #ece7d8; --muted: #9c968a; --line: #2e2c25;
    --card: #1a1a16; --accent: #e0a44a; --code: #201f1a;
  }
}
:root[data-theme="dark"] {
  --bg: #12120f; --fg: #ece7d8; --muted: #9c968a; --line: #2e2c25;
  --card: #1a1a16; --accent: #e0a44a; --code: #201f1a;
}
:root[data-theme="light"] {
  --bg: #fbfaf8; --fg: #16150f; --muted: #5d5a4e; --line: #ded9c8;
  --card: #ffffff; --accent: #7a4a00; --code: #f2efe4;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 1.25rem 1rem 4rem;
  background: var(--bg); color: var(--fg);
  font: 16px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 46rem; margin: 0 auto; }
h1 { font-size: 1.5rem; line-height: 1.2; margin: 0 0 .35rem; letter-spacing: -.02em; }
h2 { font-size: 1.05rem; margin: 2rem 0 .6rem; color: var(--accent); }
p, li { color: var(--fg); }
.lede { color: var(--muted); margin: 0 0 1.5rem; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
code { background: var(--code); padding: .1em .3em; border-radius: 3px; font-size: .9em; }
pre {
  background: var(--code); border: 1px solid var(--line); border-radius: 6px;
  padding: .7rem .8rem; overflow-x: auto; font-size: .82rem; margin: .5rem 0 0;
}
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(7.5rem, 1fr)); gap: .6rem; }
.stat {
  background: var(--card); border: 1px solid var(--line); border-radius: 8px;
  padding: .6rem .7rem; min-width: 0;
}
.stat b { display: block; font-size: 1.35rem; line-height: 1.1; font-variant-numeric: tabular-nums; }
.stat span { display: block; font-size: .74rem; color: var(--muted); margin-top: .15rem; }
.wf {
  background: var(--card); border: 1px solid var(--line); border-radius: 8px;
  padding: .8rem; margin: .7rem 0; min-width: 0;
}
.wf header { display: flex; flex-wrap: wrap; gap: .4rem; align-items: baseline; }
.wf h3 { margin: 0; font-size: 1rem; font-family: ui-monospace, monospace; }
.tag {
  font-size: .68rem; text-transform: uppercase; letter-spacing: .05em;
  border: 1px solid var(--line); border-radius: 999px; padding: .05rem .45rem; color: var(--muted);
}
.seq { color: var(--muted); font-size: .8rem; margin: .45rem 0 0; overflow-wrap: anywhere; }
.savings { font-size: .85rem; margin: .5rem 0 0; }
table { border-collapse: collapse; width: 100%; font-size: .82rem; }
.scroll { overflow-x: auto; }
th, td { border-bottom: 1px solid var(--line); padding: .3rem .45rem; text-align: right; white-space: nowrap; }
th:first-child, td:first-child { text-align: left; }
th { color: var(--muted); font-weight: 600; }
footer { margin-top: 2.5rem; color: var(--muted); font-size: .8rem; }
"""


def page(a) -> str:
    m = a.savings
    e = html.escape
    parts: list[str] = []
    add = parts.append
    add("<!doctype html>")
    add('<html lang="en">')
    add("<head>")
    add('<meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add("<title>histminer: what a shell history is hiding</title>")
    add(f"<style>{CSS}</style>")
    add("</head>")
    add("<body>")
    add("<main>")
    add("<h1>histminer</h1>")
    add(
        '<p class="lede">A shell history is a record of what you actually do. '
        "This is what mining one for recurring multi-command workflows produces, run over "
        "the committed synthetic fixture so every number on this page can be reproduced.</p>"
    )

    add('<div class="stats">')
    for value, label in [
        (a.n_commands, "commands read"),
        (a.n_templates, "distinct templates"),
        (a.n_sessions, "sessions"),
        (f"{a.model.gap.seconds:.0f}s", "session boundary"),
        (len(a.suggestions), "workflows worth automating"),
        (a.top_frequency[0][1], f"runs of {a.top_frequency[0][0]}, suggested 0 times"),
    ]:
        add(f'<div class="stat"><b>{e(str(value))}</b><span>{e(label)}</span></div>')
    add("</div>")

    add("<h2>Why frequency is the wrong ranking</h2>")
    add(
        "<p>The most common command in any history is the one that costs nothing to run. "
        f"Here it is <code>{e(a.top_frequency[0][0])}</code>, {a.top_frequency[0][1]} times, "
        "and wrapping it saves nothing. Everything below is ranked by estimated time saved "
        "instead, under a model stated in full so it can be argued with:</p>"
    )
    add("<ul>")
    for line in m.describe():
        add(f"<li>{e(line)}</li>")
    add("</ul>")

    add("<h2>Workflows found</h2>")
    for s in a.suggestions:
        spw = s.seconds_per_week(m)
        add('<div class="wf"><header>')
        add(f"<h3>{e(s.name)}</h3>")
        add(f'<span class="tag">{e(s.kind)}</span>')
        add(f'<span class="tag">{s.n_params} param</span>')
        add(f'<span class="tag">seen {s.occurrences}x</span>')
        add(f'<span class="tag">lift {s.lift:.0f}x</span>')
        add("</header>")
        add(f'<p class="seq">{e(" ; ".join(s.pattern.items))}</p>')
        add(f"<pre>{e(s.body)}</pre>")
        add(
            f'<p class="savings">{s.keystrokes_saved:.0f} keystrokes and '
            f"{s.seconds_saved_each(m):.1f}s per run"
            + (f", {spw / 60:.1f} min/week" if spw else "")
            + "</p>"
        )
        add("</div>")

    add("<h2>Is any of this real?</h2>")
    add(
        "<p>Two controls run on every report. Shuffling each session preserves how often "
        "every command was run and destroys only the order; a pattern that a shuffle can "
        "match as often as the real history is a coincidence of frequency and is dropped.</p>"
    )
    add(
        f"<p>Over {len(a.null_max)} shuffles the best pattern reached "
        f"<b>{max(a.null_max)}</b> occurrences, against <b>{a.observed_top}</b> observed.</p>"
    )
    add(
        "<p>The second control is the session boundary itself. It is the density minimum "
        f"between the two modes of the gap distribution ({a.model.gap.modes[0]:.0f}s and "
        f"{a.model.gap.modes[1]:.0f}s), and the findings have to survive moving it:</p>"
    )
    add('<div class="scroll"><table>')
    add("<tr><th>boundary</th><th>sessions</th><th>top-set overlap</th></tr>")
    for g, j, ns in a.sweep:
        add(f"<tr><td>{g:.0f}s</td><td>{ns}</td><td>{j:.2f}</td></tr>")
    add("</table></div>")

    add("<h2>Secrets</h2>")
    add(
        "<p>A history holds tokens, database URLs with passwords in them, ssh targets and "
        "internal hostnames. Redaction runs as the file is read, so no later stage ever "
        "holds an unredacted command, and the redactor is checked by a scanner that shares "
        "no code with it. On this fixture the redactor fired "
        f"{sum(a.redaction_kinds.values())} times.</p>"
    )
    add(
        "<footer>Generated by <code>scripts/build_docs.py</code> from "
        "<code>fixtures/planted.history</code>. MIT licensed.</footer>"
    )
    add("</main>")
    add("</body>")
    add("</html>")
    return "\n".join(parts) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if the outputs are stale")
    args = ap.parse_args()

    a = build_analysis()
    html_out = page(a)
    readme_path = ROOT / "README.md"
    docs_path = ROOT / "docs" / "index.html"

    readme = readme_path.read_text() if readme_path.exists() else ""
    block = numbers_markdown(a)
    if BEGIN in readme and END in readme:
        head, rest = readme.split(BEGIN, 1)
        _, tail = rest.split(END, 1)
        new_readme = head + block + tail
    else:
        new_readme = readme + "\n" + block + "\n"

    if args.check:
        stale = []
        if not docs_path.exists() or docs_path.read_text() != html_out:
            stale.append("docs/index.html")
        if new_readme != readme:
            stale.append("README.md numbers block")
        if stale:
            print("STALE: " + ", ".join(stale) + " (run scripts/build_docs.py)")
            return 1
        print("docs/index.html and README numbers match a fresh run")
        return 0

    docs_path.parent.mkdir(exist_ok=True)
    docs_path.write_text(html_out)
    readme_path.write_text(new_readme)
    print(f"wrote {docs_path.relative_to(ROOT)} and the README numbers block")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
