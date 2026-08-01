#!/usr/bin/env python3
"""Generate the two synthetic fixtures. Committed output; re-run only to change the design.

planted.history carries FOUR known workflows, so "did the miner find the thing that is
definitely there" is a checkable question rather than a judgement call:

  A  git checkout -b <b> ; git push -u origin <b>     parameterised, ONE branch name in two
                                                      places, so the suggestion must be a
                                                      function of one argument, not two
  B  npm run build ; npm run test ; npm run lint      identical every time, so an alias
  C  cd <dir> ; [ls] ; npm install                    parameterised, with an interleaved
                                                      command in half the instances to
                                                      exercise gap tolerance
  D  docker build -t <tag> . ; docker push <tag>      parameterised, co-varying tag

control.history is the same 30 sessions with the same commands and the same timing skeleton
and the ORDER destroyed. Every workflow above is present in it as a multiset and absent as a
sequence, so anything the miner reports on it is something it invented.
"""
import pathlib
import random

SEED = 20260801
BASE = 1767225600  # 2026-01-01T00:00:00Z, fixed so the fixture is byte-stable
SESSIONS = 30

BRANCHES = ["fix-parser", "add-cache", "bump-deps", "retry-logic", "dark-mode", "csv-export",
            "audit-log", "rate-limit", "i18n", "webhooks", "sso", "billing"]
SERVICES = ["api", "worker", "web", "scheduler", "indexer", "gateway", "mailer", "cron"]
DIRS = ["frontend", "backend", "tools", "docs", "infra", "packages/core"]
NOISE = ["ls", "pwd", "ls -la", "git status", "cat README.md", "clear", "htop", "df -h",
         "echo hi", "which node", "git diff", "top", "date", "env | sort"]


def build() -> tuple[list[str], list[str]]:
    rng = random.Random(SEED)
    lines: list[str] = []
    t = BASE

    def emit(cmd: str, dt: int) -> None:
        nonlocal t
        t += dt
        lines.append(f": {t}:0;{cmd}")

    for s in range(SESSIONS):
        if s:
            t += rng.randint(7200, 21600)
        if s < 12:
            b = BRANCHES[s]
            emit(f"git checkout -b {b}", rng.randint(3, 20))
            emit(f"git push -u origin {b}", rng.randint(3, 20))
        for _ in range(rng.randint(1, 3)):
            emit(rng.choice(NOISE), rng.randint(3, 40))
        if s < 10:
            emit("npm run build", rng.randint(5, 60))
            emit("npm run test", rng.randint(5, 60))
            emit("npm run lint", rng.randint(5, 60))
        for _ in range(rng.randint(1, 3)):
            emit(rng.choice(NOISE), rng.randint(3, 40))
        if s < 10:
            emit(f"cd {DIRS[s % len(DIRS)]}", rng.randint(3, 20))
            if s % 2 == 0:
                emit("ls", rng.randint(2, 10))
            emit("npm install", rng.randint(10, 90))
        if s < 8:
            svc = SERVICES[s]
            emit(f"docker build -t {svc}:v{s + 1} .", rng.randint(10, 60))
            emit(f"docker push {svc}:v{s + 1}", rng.randint(10, 60))
        for _ in range(rng.randint(2, 5)):
            emit(rng.choice(NOISE), rng.randint(3, 60))

    cmds = [l.split(";", 1)[1] for l in lines]
    shuffle_rng = random.Random(SEED + 1)
    shuffle_rng.shuffle(cmds)
    ctrl: list[str] = []
    t = BASE
    gap_rng = random.Random(SEED + 2)
    for i, c in enumerate(cmds):
        t += gap_rng.randint(7200, 21600) if i and i % 12 == 0 else gap_rng.randint(3, 60)
        ctrl.append(f": {t}:0;{c}")
    return lines, ctrl


if __name__ == "__main__":
    here = pathlib.Path(__file__).resolve().parent.parent / "fixtures"
    planted, control = build()
    (here / "planted.history").write_text("\n".join(planted) + "\n")
    (here / "control.history").write_text("\n".join(control) + "\n")
    print(f"planted {len(planted)} commands, control {len(control)} commands")
