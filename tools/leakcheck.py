#!/usr/bin/env python3
"""An independent leak checker for this repository.

INDEPENDENCE IS THE POINT. This file imports nothing from `histminer` and reuses none of its
patterns. A checker built on the redactor's own regexes cannot see the redactor's bugs: it
agrees with it exactly where it is wrong. So the detection here is written from a different
starting point. Where the redactor asks "does this match a known credential format", this
asks "is there any run of characters here that carries too much information to be prose",
and only then consults a short list of formats as a second opinion.

It reads bytes, not text, and it reads every tracked file including the ones git considers
binary. That is deliberate. A single NUL byte anywhere in a file makes `git grep` and
`grep -I` classify the whole file as binary and skip it silently, reporting a clean tree
they never read. This checker therefore does the NUL detection itself, in Python, and treats
the presence of a NUL as a finding in its own right rather than a reason to stop looking.

Usage:
    python3 tools/leakcheck.py                 scan every tracked file
    python3 tools/leakcheck.py --paths a b     scan specific files
    python3 tools/leakcheck.py --stdin         scan piped text (for checking tool output)
    python3 tools/leakcheck.py --selftest      prove the checker can still detect

Exit status is 0 only when nothing was found.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import subprocess
import sys
import tempfile

# Character classes, used to decide what a run of text IS before deciding whether it is
# secret. This is a different question from "which vendor prefix does it start with", which
# is why the two checkers fail differently.
_HEX = set("0123456789abcdefABCDEF")
_B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

# Words that legitimately appear as long runs in source and would otherwise trip the
# information-density test. Kept short; a long allowlist is how a scanner goes blind.
_ALLOW_SUBSTRINGS = (
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
)

# Second opinion only. Deliberately NOT the same list as the redactor's, and written against
# the vendor documentation rather than copied, so an error in one is unlikely to be an error
# in both. Case-sensitive where the real format is: AWS key ids are uppercase, and matching
# them case-insensitively turns every base64 blob in the repo into a false alarm.
_FORMATS: tuple[tuple[str, str], ...] = (
    ("github personal access token", r"gh[pousr]_[A-Za-z0-9]{30,}"),
    ("github fine grained token", r"github_pat_[0-9a-zA-Z_]{50,}"),
    ("aws access key id", r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])"),
    ("google api key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("slack token", r"xox[abprs]-[0-9A-Za-z-]{12,}"),
    ("openai style key", r"sk-[A-Za-z0-9_\-]{32,}"),
    ("gitlab token", r"glpat-[0-9A-Za-z_\-]{20}"),
    ("npm token", r"npm_[A-Za-z0-9]{36}"),
    ("stripe key", r"[rs]k_(live|test)_[0-9A-Za-z]{24,}"),
    ("json web token", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("private key block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("password in url", r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/@]+:[^\s/@]+@"),
    # Case-insensitive in the username, which the first version was not. `[a-z]` missed a
    # capitalised account name under the macOS Users directory, which is the normal shape there,
    # so the scanner had a hole exactly where the most common home path lives. The example is
    # described rather than written out, because a literal one is a finding in this repo's own
    # scan and the scanner is right about that.
    #
    # It went unnoticed because the selftest canary expands to a random mixed-case name and was
    # being caught by the ENTROPY heuristic instead, which looks identical from the outside. It
    # only surfaced when a path exemption was added to that heuristic and the canary stopped
    # being detected at all. A canary that passes for a different reason than the one intended
    # is a canary that is not testing what it says.
    ("absolute home path", r"/(home|Users)/[A-Za-z][A-Za-z0-9._\-]{1,31}(?![A-Za-z0-9._-])"),
    ("email address", r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
)

_COMPILED = [(name, re.compile(pat)) for name, pat in _FORMATS]

def entropy(chunk: str) -> float:
    if not chunk:
        return 0.0
    freq: dict[str, int] = {}
    for c in chunk:
        freq[c] = freq.get(c, 0) + 1
    total = len(chunk)
    acc = 0.0
    for n in freq.values():
        p = n / total
        acc -= p * math.log(p, 2)
    return acc


def _path_like(s: str) -> bool:
    """True when a run is a slash-separated path rather than one dense token.

    `/` is in the base64 alphabet, so a URL path scans as a single long run:
    `com/JesseRWeigel/722-things-to-build` is 36 characters and clears the entropy bar purely
    because concatenating unrelated words flattens the character distribution. Shell history is
    full of git remotes and curl URLs, so without this the checker cries wolf constantly, and a
    checker that cries wolf is one whose output people stop reading.

    The test is deliberately conservative, and it is about the SEGMENTS, not the whole run. A
    run counts as a path only when every slash-separated piece is short enough that it could not
    be a token on its own. A genuine base64 token that happens to contain a slash still has at
    least one long dense piece, so it is not exempted here.

    Nothing about this weakens the vendor-format patterns. A token embedded in a URL query
    string, `?api_key=sk-...`, is matched by format and never reaches this function.
    """
    if "/" not in s:
        return False
    parts = [p for p in s.split("/") if p]
    if len(parts) < 2:
        return False
    # 20 rather than the 28-character run bar: a piece long enough to be a plausible secret on
    # its own disqualifies the whole run from the exemption.
    return all(len(p) < 20 for p in parts)


def dense_runs(text: str) -> list[tuple[str, str]]:
    """Find runs of characters that carry more information than prose or code normally does.

    Scans for maximal runs drawn from the base64 alphabet, then judges each by length and by
    entropy. A 40 character hex string and a 32 character base64 string both clear the bar; a
    long CamelCase identifier does not, because its character distribution is far from flat.
    """
    out: list[tuple[str, str]] = []
    run: list[str] = []

    def flush() -> None:
        if not run:
            return
        s = "".join(run)
        run.clear()
        if any(a in s for a in _ALLOW_SUBSTRINGS):
            return
        if len(s) >= 32 and all(c in _HEX for c in s):
            out.append(("high entropy hex run", s))
            return
        if len(s) >= 28 and entropy(s) >= 4.0:
            # Distinguish a token from an identifier: identifiers have vowels and repeated
            # short substrings, tokens do not. A crude but independent signal is the ratio
            # of distinct characters to length.
            if len(set(s)) / len(s) >= 0.5 and not _path_like(s):
                out.append(("high entropy run", s))

    for ch in text:
        if ch in _B64:
            run.append(ch)
        else:
            flush()
    flush()
    return out


def scan_bytes(path: str, blob: bytes) -> list[str]:
    """No allowlist and no exceptions: every finding in every file is reported."""
    findings: list[str] = []

    if b"\x00" in blob:
        # Not a warning. A NUL byte makes git and grep treat this file as binary and skip
        # it, so a tree containing one has a hole in every text-based scan run over it.
        # Write the escape sequence \0 in source instead; the semantics are identical and
        # the file stays readable to every tool.
        idx = blob.index(b"\x00")
        findings.append(f"NUL byte at offset {idx}: this file is invisible to git grep")

    text = blob.decode("utf-8", errors="replace")
    for name, pat in _COMPILED:
        for m in pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            findings.append(f"line {line}: {name}: {_mask(m.group(0))}")
    for kind, run in dense_runs(text):
        line = text.count("\n", 0, text.find(run)) + 1
        findings.append(f"line {line}: {kind}: {_mask(run)}")
    return findings


def _mask(s: str) -> str:
    """Never print a finding in full; a leak report that quotes the leak is another copy."""
    if len(s) <= 12:
        return s[:4] + "..."
    return f"{s[:6]}...{s[-2:]} ({len(s)} chars)"


def tracked_files(root: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", root, "ls-files", "-z"], capture_output=True, text=True, check=True
    )
    return [p for p in out.stdout.split("\0") if p]


_FILL = re.compile(r"\{(FILL|HEX|UPPER) (\d+)\}")


def expand(template: str, seed: int = 0) -> str:
    """Fill `{FILL n}` style holes with random characters.

    Canaries are stored with holes in them rather than as finished credentials. A file
    containing a complete `ghp_` token gets a push rejected by GitHub's secret scanning, and
    that scan covers full history, so a later fix does not help. The space inside the
    placeholder is load bearing: it stops the on-disk form from matching the very patterns
    below, which would otherwise make this file its own first finding.
    """
    import random

    rng = random.Random(seed or 1)
    alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    def one(m: re.Match[str]) -> str:
        kind, n = m.group(1), int(m.group(2))
        pool = {"FILL": alnum, "HEX": "0123456789abcdef", "UPPER": "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}[kind]
        return "".join(rng.choice(pool) for _ in range(n))

    return _FILL.sub(one, template)


def selftest() -> int:
    """Prove the checker can still detect. A clean scan from a blind checker looks identical
    to a clean scan from a working one, so the difference has to be demonstrated."""
    canaries = [
        ("github token", expand("ghp_{FILL 36}", 1)),
        ("aws key id", expand("AKIA{UPPER 16}", 2)),
        ("home path", expand("/home/{FILL 8}/Projects/thing", 3)),
        ("url password", expand("postgres://admin:{FILL 8}@db.internal.example:5432/app", 4)),
        ("private key", expand("-----BEGIN {UPPER 3} PRIVATE KEY-----", 5)),
        ("hex blob", expand("{HEX 40}", 6)),
        ("email", expand("person{FILL 4}@example.com", 7)),
    ]
    failures = 0
    for label, payload in canaries:
        found = scan_bytes("<canary>", payload.encode())
        if not found:
            print(f"  SELFTEST FAIL  {label} was not detected")
            failures += 1
        else:
            print(f"  ok    detects {label}")

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "withnul.txt")
        with open(p, "wb") as f:
            f.write(b"harmless\x00" + expand("ghp_{FILL 36}", 11).encode())
        blob = open(p, "rb").read()
        found = scan_bytes(p, blob)
        if not any("NUL" in f for f in found):
            print("  SELFTEST FAIL  NUL byte not detected")
            failures += 1
        else:
            print("  ok    detects a NUL byte")
        if not any("github" in f for f in found):
            print("  SELFTEST FAIL  token hidden behind a NUL byte was not detected")
            failures += 1
        else:
            print("  ok    reads past a NUL byte, which git grep will not")

        # The complement: git grep really does go blind here, which is why the check above
        # cannot be delegated to it.
        subprocess.run(["git", "-C", d, "init", "-q"], check=True)
        subprocess.run(["git", "-C", d, "add", "-A"], check=True)
        r = subprocess.run(
            ["git", "-C", d, "grep", "-I", "-n", "ghp_"], capture_output=True, text=True
        )
        if r.returncode == 0 and r.stdout.strip():
            print("  SELFTEST FAIL  git grep found it, so the NUL premise no longer holds")
            failures += 1
        else:
            print("  ok    git grep -I reports nothing in that same file")

    print(f"selftest: {'PASS' if not failures else f'{failures} FAILURE(S)'}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--paths", nargs="*", default=None)
    ap.add_argument("--stdin", action="store_true", help="scan piped text instead of files")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(__file__), ".."))
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    if a.stdin:
        blob = sys.stdin.buffer.read()
        found = scan_bytes("<stdin>", blob)
        for f in found:
            print(f"  <stdin> {f}")
        print(f"stdin: {len(found)} finding(s)")
        return 1 if found else 0

    root = os.path.abspath(a.root)
    paths = a.paths if a.paths else tracked_files(root)
    total = 0
    for rel in paths:
        full = rel if os.path.isabs(rel) else os.path.join(root, rel)
        if not os.path.isfile(full):
            continue
        with open(full, "rb") as f:
            blob = f.read()
        for finding in scan_bytes(rel, blob):
            print(f"  {rel}: {finding}")
            total += 1
    print(f"scanned {len(paths)} file(s), {total} finding(s)")
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
