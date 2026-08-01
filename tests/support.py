"""Expand the credential-shaped fixture at runtime.

`fixtures/secrets.template.history` is stored with holes in it. No complete credential
pattern exists anywhere on disk in this repository, which is the only version of "we do not
commit secrets" that survives GitHub's push protection: it scans full history, so committing
a realistic fake once and removing it later does not help.

The expander returns both the filled history and the exact list of strings it planted, so a
test can ask the strictly stronger question "does this specific value appear in the output"
rather than the weaker "does the output look clean".
"""

from __future__ import annotations

import pathlib
import random
import re

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures"
_HOLE = re.compile(r"\{(FILL|HEX|UPPER) (\d+)\}")

_POOLS = {
    "FILL": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "HEX": "0123456789abcdef",
    "UPPER": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
}


def expand_secrets(seed: int = 4242) -> tuple[str, list[str]]:
    """Return (history text, every secret value planted in it)."""
    rng = random.Random(seed)
    template = (FIXTURES / "secrets.template.history").read_text()
    planted: list[str] = []

    def fill(m: re.Match[str]) -> str:
        pool = _POOLS[m.group(1)]
        val = "".join(rng.choice(pool) for _ in range(int(m.group(2))))
        planted.append(val)
        return val

    return _HOLE.sub(fill, template), planted


# Values that are not filled at runtime but are still private: internal hostnames and
# addresses written literally into the template. The redactor must remove these too.
LITERAL_SECRETS = (
    "api.internal.example",
    "db-prod-01.internal",
    "registry.internal.example",
    "hooks.internal.example",
    "10.4.2.19",
)
