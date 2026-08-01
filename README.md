# histminer

Mine a shell history for recurring **multi-command workflows** and propose an alias or a
shell function for each one, ranked by the time it would save.

`history | sort | uniq -c` tells you that you run `ls` a lot. That is true, useless, and the
reason most shell-history tools get uninstalled in a week. The thing worth finding is the
sequence: the four commands you type in the same order every time you ship a branch, where
only the branch name changes. This finds those, tells you which are fixed incantations
(an alias) and which are parameterised (a function taking arguments), and prices each one.

```
python3 -m histminer.cli report ~/.bash_history
python3 -m histminer.cli report ~/.zsh_history --json
python3 -m histminer.cli sessions ~/.zsh_history     # the gap distribution and the boundary
python3 -m histminer.cli redact ~/.bash_history      # exactly what the tool is allowed to see
```

No dependencies beyond the Python standard library. Python 3.10+.

## The three problems this actually solves

**Frequency is a trap.** `ls` is the most frequent command in every history ever recorded and
automating it saves nothing. Suggestions are ranked by estimated keystrokes and seconds
saved, under a model printed alongside the numbers rather than compressed into a score:

```
keystrokes_saved = characters typed today - characters typed with the suggestion
seconds_saved    = keystrokes_saved / typing_rate + (n_commands - 1) * switch_cost
```

Defaults are 5.0 chars/sec and 0.8s per command boundary, both settable with `--typing-cps`
and `--switch-cost`. The switch cost is the weakest constant in the model and is labelled as
such in the output. Each suggestion also reports how many weeks of use it takes to repay the
90 seconds of writing it down.

**A session boundary has to come from the data.** Two commands four hours apart are not a
workflow. Inter-command gaps are bimodal in log space: seconds within a burst of work, hours
between bursts. The boundary is the ANTIMODE, the density minimum between the two peaks,
found by smoothing the log-gap histogram. When the distribution is not bimodal the tool says
so and falls back to a documented default rather than inventing a knee. When the history has
no timestamps at all, which is what plain bash gives you, it does not quietly substitute a
default gap: `session_model` becomes `single-block`, every consumer can see it, and the
report prints the `HISTTIMEFORMAT` setting that would fix it.

**Same sequence, different arguments, is the interesting case.** A sequence whose arguments
are identical every time is an alias. A sequence whose arguments vary is a function. Slots
that vary *together*, holding the same value as each other in every occurrence, collapse into
one parameter, which is what makes this

```sh
gcgp() {
  git checkout -b "$1"
  git push -u origin "$1"
}
```

rather than a two-argument function that makes you type the branch name twice.

## How the mining works

1. **Redact** every command as the file is read, before any other stage sees it.
2. **Normalize** each command into a template with arguments abstracted
   (`git commit -m <ARG>`), keeping the concrete values as slot bindings.
3. **Segment** into sessions at the data-derived gap.
4. **Mine** closed sequential patterns, level-wise (GSP), with support counted in sessions
   rather than occurrences, tolerance for `--max-gap` interleaved commands, and a confidence
   floor so a step only joins a workflow if it reliably follows the previous one.
5. **Gate on significance.** Shuffling each session preserves every command's frequency and
   destroys only the order. A pattern that a shuffle matches as often as the real history is
   a coincidence of frequency and is dropped. Beating every one of 20 shuffles is p <= 0.048.
6. **Select a disjoint cover.** Savings only add up if suggestions describe different parts
   of the history, so a pattern whose commands are already explained by a higher-value
   suggestion is skipped instead of double counting the same minute of typing.

## Security

A shell history is one of the most secret-dense files on a developer machine.

- Redaction runs **at ingest**, in `histminer/parse.py`, so no downstream stage, cache, or
  traceback ever holds an unredacted command.
- It covers `NAME=value` where the name looks secret, secret-looking flags and their values
  (including `mysql -phunter2`, which has no separator), `Authorization` headers, credentials
  and query strings in URLs, ssh and scp targets, internal hostnames, IP addresses, email
  addresses, `/home/<user>`, UUIDs, and a dozen vendor credential shapes. Anything left that
  is long and high-entropy is redacted on entropy alone.
- Replacement placeholders carry a 4-hex-digit digest **salted per process**, so two
  different secrets never collapse into the same token (which would misclassify a
  parameterised workflow as a fixed alias) and no digest is stable across runs.
- **The checker is independent.** `tools/leakcheck.py` imports nothing from `histminer` and
  reuses none of its patterns. It asks a different question, "is there a run of characters
  here too dense to be prose", and only then consults its own list of formats. A checker
  built on the redactor's regexes agrees with the redactor exactly where it is wrong.
- It reads **bytes**, and it detects NUL bytes **in Python**. One NUL makes a file binary to
  `git grep`, which then skips it silently and reports a clean tree it never read.
  `tools/leakcheck.py --selftest` proves both halves live: that the checker finds a token
  hidden behind a NUL, and that `git grep -I` in that same file finds nothing.
- No real history is committed. The fixtures are synthetic, and the credential-shaped one is
  stored as `{FILL n}` templates expanded at runtime, so **no complete credential pattern
  exists anywhere on disk**. Verify checks that claim rather than restating it.

Known gap, stated rather than hidden: a raw base64 blob containing slashes, passed as a bare
positional argument, is not caught by the entropy heuristic, because directory paths are
indistinguishable from it at that length and redacting every path would gut the tool. Such
blobs are caught when they appear after a secret-named flag, in a header, in a URL, or in an
environment assignment, which is where they occur in practice.

## Measured on a real history

Run against this machine's own `~/.bash_history` on 2026-08-01. Not reproducible from this
repo by design: the file is private and is not committed. Run it on your own.

```
$ python3 -m histminer.cli report ~/.bash_history
history      ~/.bash_history  (bash-plain)
commands     218 -> 50 distinct templates
sessions     1 via single-block (history has no timestamps, so no session boundary can be
             computed; set HISTTIMEFORMAT='%s ' in bash or EXTENDED_HISTORY in zsh to fix)
NOTE         min-support lowered from 2 to 1: the history yields only 1 session(s), so a
             higher session-support threshold can never be met
redacted     5 of 218 commands touched by redaction
             ID:uuid x3, SECRET:env x2

most frequent single commands (shown to be ignored, automating them saves nothing):
     72  cd <PATH>
     57  claude
     16  ls
      6  ollama launch claude --model <ARG>
      5  codex

top 1 workflows by estimated time saved

1. cdcl  [function, 1 param(s)]
   cd <PATH> ; claude
   seen 49x across 1 session(s), lift 2.6x over order-independent chance
   saves 5 keystrokes and 1.8s per run
     cdcl() {
       cd "$1"
       claude
     }
   e.g. cd Projects/ ; claude

diagnostics
  order matters: shuffling each session 20 times gives a best pattern of 32 occurrences
  (median 10); everything reported above had to beat that, so p <= 0.048 for each
  threshold sensitivity: not applicable (no timestamps to sweep)
```

218 commands, 50 distinct templates, one workflow reported. That is the point. 49 of those
218 commands are a `cd` immediately followed by `claude`, and nothing else in the file has
structure that survives the null. The two most frequent commands, `cd` at 72 and `ls` at 16, are suggested
zero times on their own. Redaction fired on 5 commands: two `export` lines holding API keys
and three session UUIDs passed to `claude --resume`.

The gap-threshold argument needs timestamps, and a default bash history has none. Measured
instead against this machine's timestamped record of 7,019 commands actually executed in
shells here (Claude Code transcripts, read through the same `jsonl` adapter):

```
$ python3 -m histminer.cli sessions ~/.claude/projects
format        jsonl
commands      7019
usable gaps   6811
model         timestamp-gap at 1122s via antimode
note          bimodal log-gap density, peaks at 8.9s and 3548s, antimode at 1122s
        0-1      s     794  ######
        1-5      s    1891  ################
        5-15     s    2067  ##################
       15-60     s    1340  ###########
       60-300    s     240  ##
      300-900    s      55                     <- the valley
      900-3600   s     160  #
     3600-14400  s     156  #
    14400-86400  s     105
    86400+       s       3
```

Two clean modes about 2.6 decades apart with a real valley between them. The boundary is not
a round number somebody liked the look of; it is where the density is lowest.

## Numbers, regenerated from the committed fixture

<!-- NUMBERS:BEGIN -->

`fixtures/planted.history`: **329 commands**, **23 distinct templates**, cut into **30 sessions** at a **282s** boundary found by antimode.

The gap distribution is bimodal: peaks at 28.2s and 17783s. The boundary is the density minimum between them, not a round number chosen by hand.

| # | name | kind | params | seq len | seen | lift | keystrokes saved | min/week |
|---|------|------|--------|---------|------|------|------------------|----------|
| 1 | `gcgp` | function | 1 | 2 | 12 | 30x | 39 | 2.3 |
| 2 | `cdnidbdp` | function | 2 | 4 | 8 | 61277x | 46 | 2.0 |
| 3 | `nrbnrtnr` | alias | 0 | 3 | 10 | 1324x | 31 | 1.7 |

The most frequent single command is `ls` at 22 runs, and it appears in none of the suggestions.

Order-destroyed null over 20 shuffles: best pattern 4 occurrences against 12 observed, so every suggestion above clears p <= 0.048.

Boundary sensitivity: top-set Jaccard against the chosen 282s stays at 1.00 or better for every boundary from 120s to 3600s.

<!-- NUMBERS:END -->

`scripts/build_docs.py --check` regenerates this block and `docs/index.html` and fails if
either has drifted, so the numbers cannot go stale while the ranking changes underneath them.

## Fixtures

| file | what it is | what it proves |
|---|---|---|
| `fixtures/planted.history` | 30 sessions, zsh extended format, four **known** workflows planted | that the miner finds what is definitely there, and labels alias against function correctly |
| `fixtures/control.history` | the identical commands with the order destroyed | that it finds **nothing** when there is nothing, which is the harder half |
| `fixtures/secrets.template.history` | 20 commands full of credential-shaped holes | that redaction removes the exact planted values, confirmed by an independent scanner |

Both history fixtures are generated by `scripts/make_fixtures.py` from a fixed seed.

## Sabotage log

Three deliberate breakages, each confirmed to change real output **before** any conclusion
was drawn about the verify suite. An attack that did not apply proves nothing.

| # | sabotage | observed change | caught by |
|---|---|---|---|
| 1 | Removed the permutation significance gate in `report.analyze` | the control fixture went from 0 suggestions to 1: `npm run build ; top`, 5 occurrences, presented with a lift of 12x and a payback estimate | check 4 |
| 2 | Made co-varying slots into separate parameters in `suggest.build` | `gcgp` became a 2-parameter function whose body was `git checkout -b "$1"` then `git push -u origin "$2"` | check 3, plus 2 unit tests |
| 3 | Deleted the attached-password rule from `histminer/redact.py` | `mysql -u root -pGPykw3YToN` came back verbatim in the redacted output | check 6 |

Sabotage 3 is the interesting one. The pattern-based half of check 6, piping the output
through `tools/leakcheck.py`, **passed**: `-pGPykw3YToN` matches no vendor format and is too
short to trip the entropy rule. Only the exact-value comparison caught it, which is why that
check compares against the list of strings the fixture actually planted rather than asking
whether the output looks clean.

That rule also did not exist until the secrets fixture was run for the first time and the
password came through in cleartext. The sabotage confirmed a check that a real bug had
already justified.

## Verify

```
bash scripts/verify.sh
```

On success the last line is `ALL CHECKS PASSED` and the unit suite line reads
`Ran 76 tests`. Check 11 asserts both of those strings against the live run and against this
file, so a stale count or a suite that stopped passing cannot sit here unnoticed.

Needs Chrome or Chromium for check 9, which renders `docs/index.html` at 390px and measures
it. If none is found the check FAILS with the install command rather than skipping, because
a skipped check reports the same success as one that ran. Point `HISTMINER_CHROME` at a
binary to override discovery.

## What is unfinished

- Only `bash` (plain and timestamped), `zsh` (extended) and JSONL are parsed. `fish` history
  and the `atuin` sqlite database are not.
- Multi-line commands in a plain bash history are read as separate commands, because that
  format genuinely does not record where one ends. The timestamped and zsh-extended formats
  do not have this problem.
- The savings model treats every command as typed in full. Shell history search and
  completion already recover part of that cost, so the keystroke estimates are an upper
  bound, and the report says so rather than pretending otherwise.
- Suggestions are printed, never installed. Nothing writes to your shell rc.

## Status

Verified 2026-08-01. Pasted output of `bash scripts/verify.sh`:

```
1. module names do not shadow the standard library

  ok    no module shadows a stdlib name

2. unit suite
  ok    Ran 76 tests passed

3. the planted workflows are found, and classified correctly
  ok    all 4 planted workflows found, alias and function distinguished

4. NEGATIVE CONTROL: the same commands with the order destroyed yield nothing
  ok    control fixture produced 0 suggestions
  ok    the control holds exactly the same commands, so it is a shuffle and not an empty file

5. THE FREQUENCY TRAP: the most common command is suggested zero times
most frequent: 'ls' x22
  ok    top-frequency command appears in no suggestion; ranking is by time saved

6. SECRETS: an independent checker, including a Python NUL scan
  ok    leakcheck selftest: 10 detections proven, including NUL
  ok    the checker flags the raw fixture, so a clean result on our output means something
  ok    no credential-shaped string survives into the tool's own output
  ok    not one of the planted secret VALUES appears in the output (exact match, not pattern)
  ok    scanned 26 file(s), 0 finding(s)

7. no absolute home path in any tracked file
  ok    git ls-files carries no /home/<user> path

8. the README and the page regenerate to exactly what is committed
  ok    docs/index.html and README numbers match a fresh run

9. the page renders at 390px in a real browser
  ok    rendered at 390px in google-chrome: no overflow (scrollWidth 390 = clientWidth 390), data-theme switches rgb(251, 250, 248) <-> rgb(18, 18, 15), 1 prefers-color-scheme block(s) parsed

10. output is deterministic
  ok    two runs produce byte-identical JSON

11. the README describes this project and carries this script's output
  ok    README has a Status section with this script's success line and Ran 76 tests

ALL CHECKS PASSED (16 checks)
```

## License

MIT.
