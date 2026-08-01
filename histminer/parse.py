"""Read shell history files into redacted events.

Four real formats are supported, because "shell history" is not one thing:

  bash-plain      one command per line, NO timestamps. This is the default bash gives you
                  and it is what most machines actually have.
  bash-timestamp  HISTTIMEFORMAT set, so `#<epoch>` comment lines precede each command.
  zsh-extended    `: <epoch>:<elapsed>;<command>`, with backslash continuations.
  jsonl           one JSON object per line carrying a timestamp and a command string.
                  Covers ~/.codex/history.jsonl and Claude Code transcripts, which are the
                  only large TIMESTAMPED command corpora on a machine whose bash history has
                  no timestamps at all.

Redaction happens here, in the constructor of every Event, so that nothing downstream can
hold an unredacted command even transiently.
"""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass

from .redact import Redactor

TS_COMMENT = re.compile(r"^#(\d{9,11})$")
ZSH_EXT = re.compile(r"^: (\d{9,11}):(\d+);(.*)$")


@dataclass(frozen=True)
class Event:
    """One command. `text` is always already redacted."""

    ts: float | None
    text: str
    redactions: tuple[str, ...] = ()


@dataclass
class History:
    events: list[Event]
    fmt: str
    path: str
    skipped: int = 0

    @property
    def timestamped(self) -> bool:
        return bool(self.events) and all(e.ts is not None for e in self.events)

    @property
    def span_days(self) -> float | None:
        ts = [e.ts for e in self.events if e.ts is not None]
        if len(ts) < 2:
            return None
        return (max(ts) - min(ts)) / 86400.0


def sniff(text: str) -> str:
    head = text.split("\n", 400)[:400]
    if any(ZSH_EXT.match(l) for l in head):
        return "zsh-extended"
    if any(TS_COMMENT.match(l) for l in head):
        return "bash-timestamp"
    stripped = [l for l in head if l.strip()]
    if stripped and sum(1 for l in stripped[:50] if l.lstrip().startswith("{")) >= max(
        1, len(stripped[:50]) // 2
    ):
        return "jsonl"
    return "bash-plain"


_JSON_CMD_KEYS = ("command", "text", "display", "cmd")
_JSON_TS_KEYS = ("ts", "timestamp", "time", "epoch")


def _json_events(line: str) -> list[tuple[float | None, str]]:
    """Pull (ts, command) pairs out of one JSON line.

    Handles both flat records and Claude Code transcript records, where the command sits
    inside a tool_use content block and the timestamp is an ISO string on the envelope.
    """
    try:
        rec = json.loads(line)
    except (ValueError, RecursionError):
        return []
    if not isinstance(rec, dict):
        return []

    ts: float | None = None
    for k in _JSON_TS_KEYS:
        v = rec.get(k)
        if isinstance(v, (int, float)):
            ts = float(v) / 1000.0 if v > 1e11 else float(v)
            break
        if isinstance(v, str):
            try:
                from datetime import datetime

                ts = datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except ValueError:
                ts = None
            break

    out: list[tuple[float | None, str]] = []
    msg = rec.get("message")
    if isinstance(msg, dict) and isinstance(msg.get("content"), list):
        for block in msg["content"]:
            if (
                isinstance(block, dict)
                and block.get("type") == "tool_use"
                and block.get("name") == "Bash"
            ):
                cmd = (block.get("input") or {}).get("command")
                if isinstance(cmd, str) and cmd.strip():
                    out.append((ts, cmd))
    if out:
        return out

    for k in _JSON_CMD_KEYS:
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return [(ts, v)]
    return []


_SPLIT_OPS = (";", "&&", "||", "\n")


def split_compound(cmd: str) -> list[str]:
    """Break `cd x && npm test; echo done` into its component commands.

    Off by default. For a human's interactive history a compound one-liner is already
    automated and splitting it invents a workflow the person never performed by hand. For a
    machine-written history, where one entry is a twelve-line script, not splitting means
    every entry is unique and nothing can be mined at all. The two corpora need opposite
    treatment, so this is a flag rather than a default.
    """
    out: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            elif ch == "\\" and i + 1 < len(cmd):
                cur.append(cmd[i + 1])
                i += 1
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
            i += 1
            continue
        if cmd.startswith("&&", i) or cmd.startswith("||", i):
            out.append("".join(cur))
            cur = []
            i += 2
            continue
        if ch in (";", "\n"):
            out.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    out.append("".join(cur))
    return [p.strip() for p in out if p.strip()]


def parse_text(text: str, *, fmt: str | None = None, path: str = "-",
               redactor: Redactor | None = None, split: bool = False) -> History:
    red = redactor or Redactor()
    fmt = fmt or sniff(text)
    raw: list[tuple[float | None, str]] = []
    skipped = 0

    if fmt == "zsh-extended":
        pending_ts: float | None = None
        pending: list[str] = []
        for line in text.split("\n"):
            m = ZSH_EXT.match(line)
            if m:
                if pending:
                    raw.append((pending_ts, "\n".join(pending)))
                pending_ts, pending = float(m.group(1)), [m.group(3)]
            elif pending:
                pending.append(line)
            elif line.strip():
                skipped += 1
        if pending:
            raw.append((pending_ts, "\n".join(pending)))

    elif fmt == "bash-timestamp":
        ts: float | None = None
        for line in text.split("\n"):
            m = TS_COMMENT.match(line)
            if m:
                ts = float(m.group(1))
            elif line.strip():
                raw.append((ts, line))

    elif fmt == "jsonl":
        for line in text.split("\n"):
            if not line.strip():
                continue
            got = _json_events(line)
            if not got:
                skipped += 1
            raw.extend(got)

    else:  # bash-plain
        for line in text.split("\n"):
            if line.strip():
                raw.append((None, line))

    events = []
    for ts, cmd in raw:
        cmd = cmd.strip()
        if not cmd:
            continue
        for piece in (split_compound(cmd) if split else [cmd]):
            r = red.apply(piece)
            events.append(Event(ts, r.text, r.kinds))
    return History(events, fmt, path, skipped)


def read(path: str | pathlib.Path, *, fmt: str | None = None,
         redactor: Redactor | None = None, split: bool = False) -> History:
    """Read one history file, or every *.jsonl under a directory."""
    p = pathlib.Path(path).expanduser()
    if p.is_dir():
        red = redactor or Redactor()
        events: list[Event] = []
        skipped = 0
        for f in sorted(p.rglob("*.jsonl")):
            h = parse_text(f.read_text(errors="replace"), fmt="jsonl", path=str(f),
                           redactor=red, split=split)
            events.extend(h.events)
            skipped += h.skipped
        events.sort(key=lambda e: (e.ts is None, e.ts or 0.0))
        return History(events, "jsonl", str(p), skipped)
    return parse_text(p.read_text(errors="replace"), fmt=fmt, path=str(p), redactor=redactor,
                      split=split)
