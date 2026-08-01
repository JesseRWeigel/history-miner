"""Redaction of shell history.

A shell history is one of the most secret-dense files on a developer machine. It holds
tokens passed as flags, database URLs with passwords in them, `export API_KEY=...`, ssh
targets, internal hostnames, and the operator's own home directory path. This module runs
BEFORE anything else in the pipeline, so no later stage ever holds an unredacted string.
That ordering is the actual safety property; a redactor applied at print time leaks through
every intermediate file, cache, and traceback.

Redaction is deliberately lossy in one direction only: a false positive costs a slightly
worse suggestion, a false negative costs a leaked credential. Where the two trade off, this
file always chooses the false positive.

Replacement tokens carry a short digest so that two DIFFERENT secrets do not collapse into
the same placeholder. That matters for correctness, not just cosmetics: if every token
became the identical string, a workflow that is parameterised over a secret would be
misclassified as a fixed alias. The digest is salted with a per-process random value, so it
is meaningless outside a single run and cannot be used to confirm a guess at the underlying
secret across runs.

This module is checked by tools/leakcheck.py, which shares no code with it. That is
deliberate: a checker built on this file's regexes cannot see this file's bugs.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass, field

# Salt regenerated every process. Digests in output are therefore not stable across runs and
# cannot be accumulated into a rainbow table by anyone reading two reports.
_SALT = os.urandom(16)


def _tag(kind: str, secret: str) -> str:
    d = hashlib.sha256(_SALT + secret.encode("utf-8", "replace")).hexdigest()[:4]
    # The separator is a hyphen and not a colon on purpose. A placeholder containing a colon,
    # sitting where a URL's userinfo goes, matches the standard credentials-in-URL shape, so
    # the REDACTED output would trip every third party secret scanner it is ever piped into.
    return f"<{kind.replace(':', '-')}#{d}>"


# Hosts that are safe to keep in cleartext. Everything else is treated as potentially an
# internal hostname. The list is short on purpose; the cost of redacting a public host is a
# marginally less readable suggestion, the cost of leaking an internal one is real.
PUBLIC_HOSTS = frozenset(
    """
    localhost 127.0.0.1 0.0.0.0 ::1
    github.com raw.githubusercontent.com gist.github.com codeload.github.com
    gitlab.com bitbucket.org
    npmjs.com registry.npmjs.org www.npmjs.com
    pypi.org files.pythonhosted.org
    crates.io static.crates.io
    golang.org proxy.golang.org
    hf.co huggingface.co
    ollama.com registry.ollama.ai
    docs.python.org developer.mozilla.org stackoverflow.com
    """.split()
)

# Environment variable / flag names whose VALUE is assumed secret. Matched case-insensitively
# because shell variables are conventionally upper case but flags are not.
_SECRET_NAME = re.compile(
    r"(?:^|[^A-Za-z0-9_])("
    r"[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY"
    r"|CREDENTIAL|AUTH|SESSION_KEY|COOKIE|DSN|DATABASE_URL|CONNECTION_STRING|BEARER)"
    r"[A-Za-z0-9_]*)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)",
    re.IGNORECASE,
)

_SECRET_FLAG = re.compile(
    r"(--?(?:token|password|passwd|pass|secret|api[-_]?key|apikey|access[-_]?token"
    r"|auth[-_]?token|auth|bearer|credential|private[-_]?key|client[-_]?secret))"
    r"(=|\s+)(\"[^\"]*\"|'[^']*'|\S+)",
    re.IGNORECASE,
)

# Authorization headers, which are usually passed as one quoted argument to -H.
_AUTH_HEADER = re.compile(
    r"((?:Authorization|X-Api-Key|X-Auth-Token|Proxy-Authorization)\s*:\s*)([^\"'\\]+)",
    re.IGNORECASE,
)

# A URL. userinfo and host are handled separately from the rest.
_URL = re.compile(
    r"\b([a-zA-Z][a-zA-Z0-9+.-]{1,15})://(?:([^/@\s]*)@)?([A-Za-z0-9._\[\]:-]+)([^\s\"']*)"
)

# user@host as used by ssh/scp/rsync. Distinguished from an email by the absence of a dot in
# the local part and by the surrounding command, but we redact both anyway.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSH_TARGET = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._-]+)@([A-Za-z0-9._-]+)(?=[:\s]|$)")

_HOME_PATH = re.compile(r"(?:/home/|/Users/|\\Users\\)([A-Za-z0-9._-]+)")

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_INTERNAL_HOST = re.compile(
    r"\b[A-Za-z0-9][A-Za-z0-9.-]*\.(?:local|internal|lan|corp|home|intranet|test|localdomain)"
    r"(?:\.[A-Za-z0-9-]+)*\b",
    re.IGNORECASE,
)

# Passwords attached to their flag with no separator. `mysql -phunter2` is the classic, and
# it defeats every rule that expects a flag and a value to be separate tokens. Scoped to the
# commands that actually use the form, because `-p` means port, print, or parents elsewhere.
_ATTACHED_PW_COMMANDS = frozenset(
    "mysql mysqldump mysqladmin mariadb smbclient mosquitto_pub mosquitto_sub".split()
)
_ATTACHED_PW = re.compile(r"(?<![\w-])(-p)(\S{4,})")
# `curl -u user:password` and `-u user password` in the same family.
_USERPASS_FLAG = re.compile(r"(?<![\w-])(-u|--user)(=|\s+)(\S+:\S+)")

# High-confidence credential shapes. Case sensitivity matters: AWS access key ids are
# uppercase by definition, and a case-insensitive match for AKIA[0-9A-Z]{16} fires on
# ordinary base64, which is how a previous project in this workspace turned every embedded
# PNG into a security incident.
_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SECRET:pem", re.compile(r"-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----")),
    ("SECRET:github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("SECRET:github", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("SECRET:gitlab", re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b")),
    ("SECRET:slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("SECRET:aws", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b")),
    ("SECRET:google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SECRET:openai", re.compile(r"\bsk-(?:ant-|or-v1-|proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("SECRET:npm", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("SECRET:jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("SECRET:stripe", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("SECRET:hex", re.compile(r"\b[0-9a-f]{40,}\b")),
    # A UUID is rarely a credential but is always an identifier: session ids, container ids,
    # and tenant ids all leak something about the machine, and none of them are worth keeping.
    (
        "ID:uuid",
        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    ),
)

# Tokens that look like a plain word or a path are never treated as high-entropy secrets.
_WORDISH = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
_PATHISH = re.compile(r"^[~./][\w./~-]*$")
_B64ISH = re.compile(r"^[A-Za-z0-9+/=_-]{24,}$")


_REMOTE_COMMANDS = frozenset("ssh scp rsync sftp mosh ssh-copy-id git mysql psql".split())
_VERSIONISH = re.compile(r"^(?:v?\d[\w.+-]*|latest|next|beta|alpha|canary|stable|edge)$")


def _first_word(text: str) -> str:
    t = text.strip()
    if t.startswith("sudo "):
        t = t[5:].strip()
    return t.split(" ", 1)[0] if t else ""


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class Redaction:
    """One redaction applied to one command."""

    kind: str
    placeholder: str


@dataclass
class Result:
    text: str
    redactions: list[Redaction] = field(default_factory=list)

    @property
    def kinds(self) -> tuple[str, ...]:
        return tuple(r.kind for r in self.redactions)


class Redactor:
    """Stateless apart from the accounting it returns. Call `apply` per command."""

    def __init__(self, *, entropy_threshold: float = 3.6, redact_home: bool = True):
        self.entropy_threshold = entropy_threshold
        self.redact_home = redact_home

    # -- helpers ---------------------------------------------------------------

    def _sub(self, out: list[Redaction], kind: str, secret: str) -> str:
        ph = _tag(kind, secret)
        out.append(Redaction(kind, ph))
        return ph

    # -- the pipeline ----------------------------------------------------------

    def apply(self, text: str) -> Result:
        found: list[Redaction] = []

        def repl_named(m: re.Match[str]) -> str:
            name, value = m.group(1), m.group(2)
            prefix = m.group(0)[: m.start(1) - m.start(0)]
            return prefix + name + "=" + self._sub(found, "SECRET:env", value)

        text = _SECRET_NAME.sub(repl_named, text)
        text = _SECRET_FLAG.sub(
            lambda m: m.group(1) + m.group(2) + self._sub(found, "SECRET:flag", m.group(3)), text
        )
        text = _AUTH_HEADER.sub(
            lambda m: m.group(1) + self._sub(found, "SECRET:header", m.group(2)), text
        )
        text = _USERPASS_FLAG.sub(
            lambda m: m.group(1) + m.group(2) + self._sub(found, "SECRET:userpass", m.group(3)),
            text,
        )
        if _first_word(text) in _ATTACHED_PW_COMMANDS:
            text = _ATTACHED_PW.sub(
                lambda m: m.group(1) + self._sub(found, "SECRET:attached", m.group(2)), text
            )

        # Credential shapes before anything that might chop them up.
        for kind, pat in _SHAPES:
            text = pat.sub(lambda m, k=kind: self._sub(found, k, m.group(0)), text)

        text = _URL.sub(lambda m: self._url(m, found), text)
        text = _EMAIL.sub(lambda m: self._sub(found, "EMAIL", m.group(0)), text)

        # `user@host` is an ssh target, but `pkg@1.2.3` and `pkg@latest` are npm specifiers
        # and redacting them destroys a very common command for no security gain. Redact
        # when the right-hand side looks like a host, or when the command is one that takes
        # a remote target, in which case even a bare `user@buildbox` is a private hostname.
        remote_cmd = _first_word(text) in _REMOTE_COMMANDS

        def ssh(m: re.Match[str]) -> str:
            host = m.group(2)
            if not remote_cmd and (_VERSIONISH.match(host) or "." not in host):
                return m.group(0)
            return m.group(1) + "@" + self._host(host, found)

        text = _SSH_TARGET.sub(ssh, text)
        text = _INTERNAL_HOST.sub(lambda m: self._sub(found, "HOST", m.group(0)), text)
        text = _IPV4.sub(lambda m: self._ip(m.group(0), found), text)

        if self.redact_home:

            def home(m: re.Match[str]) -> str:
                # Record the redaction for accounting, then emit "~" rather than a tagged
                # placeholder: the home directory of the machine's owner is the one secret
                # whose replacement has a natural, readable form.
                self._sub(found, "USER", m.group(1))
                return "~"

            text = _HOME_PATH.sub(home, text)

        text = self._entropy_pass(text, found)
        return Result(text, found)

    def _url(self, m: re.Match[str], found: list[Redaction]) -> str:
        scheme, userinfo, host, rest = m.group(1), m.group(2), m.group(3), m.group(4)
        out = scheme + "://"
        if userinfo:
            out += self._sub(found, "SECRET:urlauth", userinfo) + "@"
        bare = host.split(":")[0].lower()
        if bare in PUBLIC_HOSTS:
            out += host
        else:
            out += self._host(host, found)
        # Query strings routinely carry tokens; drop everything after ? unconditionally.
        if "?" in rest:
            path, _ = rest.split("?", 1)
            out += path + "?" + self._sub(found, "SECRET:query", rest.split("?", 1)[1])
        else:
            out += rest
        return out

    def _host(self, host: str, found: list[Redaction]) -> str:
        if host.split(":")[0].lower() in PUBLIC_HOSTS:
            return host
        return self._sub(found, "HOST", host)

    def _ip(self, ip: str, found: list[Redaction]) -> str:
        if ip in PUBLIC_HOSTS:
            return ip
        octets = ip.split(".")
        try:
            nums = [int(o) for o in octets]
        except ValueError:
            return ip
        if any(n > 255 for n in nums):
            return ip  # a version number like 1.2.3.400 is not an address
        return self._sub(found, "IP", ip)

    def _entropy_pass(self, text: str, found: list[Redaction]) -> str:
        out = []
        for token in re.split(r"(\s+)", text):
            if token.strip() and self._looks_secret(token):
                out.append(self._sub(found, "SECRET:entropy", token))
            else:
                out.append(token)
        return "".join(out)

    def _looks_secret(self, token: str) -> bool:
        core = token.strip("\"'`,;()[]{}")
        if len(core) < 24:
            return False
        if core.startswith("<") and core.endswith(">"):
            return False  # already a placeholder
        if core.startswith("-"):
            return False
        if _PATHISH.match(core):
            return False
        if "/" in core:
            # A slashed token is almost always a path, and paths are exactly the arguments
            # this tool exists to parameterise, so redacting them all would gut it. Only a
            # long, high-entropy, extensionless slashed token is treated as a blob. Base64
            # payloads passed as bare positional arguments below that bar are the documented
            # gap in this heuristic; they are still caught by the env-name, flag, header and
            # URL rules, which is where they occur in practice.
            return len(core) >= 44 and "." not in core and shannon(core) >= 4.5
        if _WORDISH.match(core) and shannon(core) < 4.2:
            return False
        if not _B64ISH.match(core):
            return False
        return shannon(core) >= self.entropy_threshold


def redact(text: str, **kw) -> str:
    """Convenience wrapper used in tests and by the `redact` subcommand."""
    return Redactor(**kw).apply(text).text
