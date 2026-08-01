"""Turn a command into a template plus the concrete values that filled it.

`git commit -m "fix parser"` and `git commit -m "bump deps"` are the same act. Counting them
as two different commands is why naive frequency analysis of a shell history finds nothing
but `ls`. So each command becomes a TEMPLATE with its arguments abstracted, and the concrete
tokens are kept alongside as SLOT BINDINGS.

The bindings are what later separates an alias from a function. A sequence whose slots hold
the same value every time is a fixed incantation and wants an alias. A sequence whose slots
vary is a parameterised workflow and wants a function taking arguments. Throwing the
bindings away at this stage makes that distinction unrecoverable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Commands whose first argument is a subcommand rather than data. Keeping the subcommand in
# the template is the difference between a useful `git commit <STR>` and a useless `git <ARG>`.
MULTIPLEXERS = frozenset(
    """
    git npm pnpm yarn bun deno cargo go docker podman kubectl helm terraform
    apt apt-get dnf yum brew pip pip3 uv poetry conda systemctl journalctl
    gh glab vercel netlify fly wrangler aws gcloud az
    ollama claude codex nix make just task
    python python3 node tsx ts-node
    """.split()
)

# Verbs that name a namespace rather than an action, so the word after them is still part of
# the command: `npm run build`, `gh pr create`, `docker compose up`.
NESTED_VERBS = frozenset(
    """
    run compose remote submodule stash worktree bisect get
    pr repo issue release workflow secret gist
    launch machine node image container volume network context config
    env project domains certs alias
    """.split()
)

_SUBCOMMAND = re.compile(r"^[a-z][a-z0-9_-]*$")
_NUM = re.compile(r"^[+-]?\d+(?:\.\d+)?[a-zA-Z%]{0,3}$")
_URL = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_PLACEHOLDER = re.compile(r"^<([A-Z-]+)#[0-9a-f]{4}>$")
_LONG_FLAG_EQ = re.compile(r"^(--[A-Za-z0-9][A-Za-z0-9-]*)=(.*)$")


def tokenize(cmd: str) -> list[str]:
    """Whitespace split that respects quotes, keeping the original token text."""
    out: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    esc = False
    for ch in cmd:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif quote:
            cur.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            cur.append(ch)
            quote = ch
        elif ch.isspace():
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


# Commands whose positional argument is a directory or file even when it carries no slash.
# Without this `cd Projects` and `cd Projects/` normalise to two different templates and the
# single most common workflow on the machine splits in half.
PATH_TAKING = frozenset("cd pushd mkdir rmdir rm touch cat source . popd".split())


def classify(token: str, head: str = "") -> str:
    m = _PLACEHOLDER.match(token)
    if m:
        kind = m.group(1)
        return "<SECRET>" if kind.startswith("SECRET") else f"<{kind.split('-')[0]}>"
    bare = token.strip("\"'")
    if _URL.match(bare):
        return "<URL>"
    if _NUM.match(bare):
        return "<NUM>"
    if bare.startswith("~") or "/" in bare or bare.startswith("."):
        return "<PATH>"
    if head in PATH_TAKING:
        return "<PATH>"
    return "<ARG>"


@dataclass(frozen=True)
class Command:
    template: str
    slots: tuple[str, ...]  # concrete token text for each abstracted position
    raw: str

    @property
    def head(self) -> str:
        return self.template.split(" ", 1)[0]


def normalize(cmd: str) -> Command:
    toks = tokenize(cmd)
    if not toks:
        return Command("", (), cmd)

    parts: list[str] = []
    slots: list[str] = []
    i = 0
    head = toks[0]
    parts.append(head)
    i = 1

    # Absorb subcommands: for a multiplexer, the leading verb is part of the command, not
    # data. Exactly one word by default. `docker push api:v1` must not swallow the tag, or
    # every push becomes its own template and the build/push pair can never be mined. A
    # second word is absorbed only after a verb that is itself a namespace, which is how
    # `npm run build` and `gh pr create` stay distinguishable.
    if head in MULTIPLEXERS:
        if i < len(toks) and _SUBCOMMAND.match(toks[i]):
            parts.append(toks[i])
            first = toks[i]
            i += 1
            if first in NESTED_VERBS and i < len(toks) and _SUBCOMMAND.match(toks[i]):
                parts.append(toks[i])
                i += 1

    while i < len(toks):
        t = toks[i]
        if t in ("&&", "||", "|", ";", ">", ">>", "2>&1"):
            parts.append(t)
            i += 1
            continue
        m = _LONG_FLAG_EQ.match(t)
        if m:
            parts.append(m.group(1) + "=" + classify(m.group(2), head))
            slots.append(m.group(2))
            i += 1
            continue
        if t.startswith("-") and len(t) > 1:
            parts.append(t)
            i += 1
            continue
        parts.append(classify(t, head))
        slots.append(t)
        i += 1

    return Command(" ".join(parts), tuple(slots), cmd)
