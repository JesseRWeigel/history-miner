#!/usr/bin/env bash
# Verification for histminer.
#
# The checks that matter are 4, 5 and 6.
#
# Check 4 is the negative control for the whole tool. The control fixture holds exactly the
# same commands as the planted one with the ORDER destroyed, so anything reported on it is
# something the miner invented. A workflow miner that always finds workflows is a random
# suggestion generator with a progress bar.
#
# Check 5 is the frequency trap. `ls` is the most frequent command in the fixture, as it is
# in every real history, and it must appear in zero suggestions. A tool that ranks by count
# will fail this and nothing else will catch it.
#
# Check 6 is the leak check, and it is run by a scanner that shares no code with the
# redactor. A checker built on the redactor's own patterns agrees with it exactly where it
# is wrong. It includes a NUL byte scan done in Python, because one NUL makes a file binary
# to git grep, which then skips it and reports a tree it never read.
#
# Attacked on 2026-08-01 by disabling the significance gate, by breaking the co-varying
# slot merge, and by removing the attached-password rule from the redactor. Checks 4, 3 and
# 6 caught them respectively; each sabotage was confirmed to change real output first. See
# the Sabotage section of the README.
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0
fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; fail=$((fail + 1)); }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

PY=${PYTHON:-python3}

echo "1. module names do not shadow the standard library"
if $PY - <<'EOF'
import pathlib, sys
names = {p.stem for p in pathlib.Path("histminer").glob("*.py")}
names |= {p.stem for p in pathlib.Path("tools").glob("*.py")}
names |= {p.stem for p in pathlib.Path("scripts").glob("*.py")}
names.discard("__init__")
clash = sorted(names & set(sys.stdlib_module_names))
print(",".join(clash))
raise SystemExit(1 if clash else 0)
EOF
then ok "no module shadows a stdlib name"
else bad "a module name shadows the standard library (see above)"; fi

echo
echo "2. unit suite"
if out=$($PY -m unittest discover -s tests -t . 2>&1); then
  ran=$(printf '%s' "$out" | grep -oE 'Ran [0-9]+ tests' | head -1)
  ok "$ran passed"
  echo "$ran" > "$work/ran.txt"
else
  printf '%s\n' "$out" | tail -30
  bad "unit suite"
  echo "Ran 0 tests" > "$work/ran.txt"
fi

echo
echo "3. the planted workflows are found, and classified correctly"
$PY -m histminer.cli report fixtures/planted.history --json > "$work/planted.json" 2>"$work/err" \
  || { cat "$work/err"; bad "report crashed on the planted fixture"; }
if [ -s "$work/planted.json" ]; then
  $PY - "$work/planted.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
sugg = d["suggestions"]
problems = []

def find(*frag):
    for s in sugg:
        key = " ; ".join(s["sequence"])
        if all(f in key for f in frag):
            return s
    return None

a = find("git checkout -b", "git push")
if a is None:
    problems.append("workflow A (branch then push) was not found")
elif a["kind"] != "function" or a["params"] != 1:
    problems.append(f"workflow A should be a 1-param function, got {a['kind']}/{a['params']}")
elif a["body"].count('"$1"') != 2:
    problems.append("workflow A: the branch name should be ONE parameter used twice")

b = find("npm run build", "npm run test", "npm run lint")
if b is None:
    problems.append("workflow B (build/test/lint) was not found")
elif b["kind"] != "alias" or b["params"] != 0:
    problems.append(f"workflow B should be a 0-param alias, got {b['kind']}/{b['params']}")

c = find("cd <PATH>", "npm install")
if c is None:
    problems.append("workflow C (cd then install, with an interleaved command) was not found")

dd = find("docker build", "docker push")
if dd is None:
    problems.append("workflow D (build then push, shared tag) was not found")

if d["session_model"] != "timestamp-gap":
    problems.append("the session boundary was not computed from timestamps")
if d["gap_method"] != "antimode":
    problems.append(f"gap method was {d['gap_method']}, expected antimode")

for p in problems:
    print(p)
raise SystemExit(1 if problems else 0)
EOF
  if [ $? -eq 0 ]; then ok "all 4 planted workflows found, alias and function distinguished"
  else bad "planted fixture (see above)"; fi
fi

echo
echo "4. NEGATIVE CONTROL: the same commands with the order destroyed yield nothing"
n=$($PY -m histminer.cli report fixtures/control.history --json 2>/dev/null \
    | $PY -c 'import json,sys; print(len(json.load(sys.stdin)["suggestions"]))')
if [ "$n" = "0" ]; then ok "control fixture produced 0 suggestions"
else bad "control fixture produced $n suggestion(s); the miner is inventing structure"; fi

same=$($PY - <<'EOF'
from histminer.parse import read
a = sorted(e.text for e in read("fixtures/planted.history").events)
b = sorted(e.text for e in read("fixtures/control.history").events)
print("yes" if a == b and a else "no")
EOF
)
if [ "$same" = "yes" ]; then ok "the control holds exactly the same commands, so it is a shuffle and not an empty file"
else bad "the control is not a permutation of the planted fixture; check 4 proves nothing"; fi

echo
echo "5. THE FREQUENCY TRAP: the most common command is suggested zero times"
$PY - "$work/planted.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
top = d["top_frequency"][0]
bad = [s for s in d["suggestions"] if s["sequence"] == [top["template"]]]
singles = [s for s in d["suggestions"] if len(s["sequence"]) < 2]
print(f"most frequent: {top['template']!r} x{top['count']}")
if bad or singles:
    print("a single frequent command was suggested")
    raise SystemExit(1)
raise SystemExit(0)
EOF
if [ $? -eq 0 ]; then ok "top-frequency command appears in no suggestion; ranking is by time saved"
else bad "a frequent single command was suggested"; fi

echo
echo "6. SECRETS: an independent checker, including a Python NUL scan"
if $PY tools/leakcheck.py --selftest > "$work/self.txt" 2>&1; then
  ok "leakcheck selftest: $(grep -c '^  ok' "$work/self.txt") detections proven, including NUL"
else
  cat "$work/self.txt"; bad "leakcheck cannot detect its own canaries, so a clean scan means nothing"
fi

$PY - > "$work/secrets.history" <<'EOF'
import sys
sys.path.insert(0, ".")
from tests.support import expand_secrets
text, planted = expand_secrets(seed=99)
sys.stdout.write(text)
EOF
if $PY tools/leakcheck.py --stdin < "$work/secrets.history" > /dev/null 2>&1; then
  bad "the checker did NOT flag a history full of credentials; it is blind"
else
  ok "the checker flags the raw fixture, so a clean result on our output means something"
fi

$PY -m histminer.cli redact "$work/secrets.history" > "$work/redacted.txt" 2>/dev/null
$PY -m histminer.cli report "$work/secrets.history" --rounds 3 --no-diagnostics \
  >> "$work/redacted.txt" 2>/dev/null
if $PY tools/leakcheck.py --stdin < "$work/redacted.txt" > "$work/leak.txt" 2>&1; then
  ok "no credential-shaped string survives into the tool's own output"
else
  cat "$work/leak.txt"; bad "the tool leaked a secret into its output"
fi

if $PY - "$work/redacted.txt" <<'EOF'
import sys
sys.path.insert(0, ".")
from tests.support import expand_secrets, LITERAL_SECRETS
_, planted = expand_secrets(seed=99)
out = open(sys.argv[1]).read()
leaked = [s for s in list(planted) + list(LITERAL_SECRETS) if s in out]
for s in leaked:
    print(f"leaked a value {len(s)} chars long")
raise SystemExit(1 if leaked else 0)
EOF
then ok "not one of the planted secret VALUES appears in the output (exact match, not pattern)"
else bad "a planted secret value survived redaction"; fi

if $PY tools/leakcheck.py > "$work/tree.txt" 2>&1; then
  ok "$(tail -1 "$work/tree.txt")"
else
  cat "$work/tree.txt"; bad "a tracked file contains a secret, a home path, or a NUL byte"
fi

echo
echo "7. no absolute home path in any tracked file"
if hits=$(git ls-files -z | xargs -0 grep -l -E '/(home|Users)/[a-z]' 2>/dev/null); then
  printf '%s\n' "$hits"; bad "tracked files contain an absolute home path"
else
  ok "git ls-files carries no /home/<user> path"
fi

echo
echo "8. the README and the page regenerate to exactly what is committed"
if $PY scripts/build_docs.py --check > "$work/docs.txt" 2>&1; then
  ok "$(cat "$work/docs.txt")"
else
  cat "$work/docs.txt"; bad "docs/index.html or the README numbers are stale"
fi

echo
echo "9. the page renders at 390px in a real browser"
if page_out=$($PY scripts/checkpage.py 2>&1); then
  printf '%s\n' "$page_out"
  pass=$((pass + 1))
else
  printf '%s\n' "$page_out"
  bad "the page did not render clean at 390px"
fi

echo
echo "10. output is deterministic"
$PY -m histminer.cli report fixtures/planted.history --json > "$work/a.json" 2>/dev/null
$PY -m histminer.cli report fixtures/planted.history --json > "$work/b.json" 2>/dev/null
if cmp -s "$work/a.json" "$work/b.json"; then ok "two runs produce byte-identical JSON"
else bad "the report is not deterministic"; fi

echo
echo "11. the README describes this project and carries this script's output"
ran=$(cat "$work/ran.txt")
if [ ! -f README.md ]; then
  bad "README.md is missing"
else
  miss=""
  grep -q '^## Status' README.md || miss="$miss no-Status-section"
  grep -q 'ALL CHECKS PASSED' README.md || miss="$miss no-success-line"
  grep -qF "$ran" README.md || miss="$miss test-count-stale($ran)"
  grep -q 'TODO' README.md && miss="$miss contains-TODO"
  if [ -z "$miss" ]; then ok "README has a Status section with this script's success line and $ran"
  else bad "README:$miss"; fi
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL CHECKS PASSED ($pass checks)"
  exit 0
fi
echo "$fail FAILED, $pass passed"
exit 1
