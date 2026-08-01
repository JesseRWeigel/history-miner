"""Redaction, with a negative control beside every positive one.

A redactor that replaces everything passes every "the secret is gone" test and is useless.
So each assertion that something IS removed is paired with an assertion that something
similar in shape is NOT, because the failure that actually gets a tool abandoned is
`npm install -g pkg@latest` coming back as `npm install -g pkg@<HOST>`.
"""

import unittest

from histminer.redact import Redactor, redact, shannon

from .support import hole


class TestSecretsRemoved(unittest.TestCase):
    def assertGone(self, cmd, secret):
        out = redact(cmd)
        self.assertNotIn(secret, out, f"leaked from: {cmd!r} -> {out!r}")

    def test_named_env_assignment(self):
        self.assertGone('export ANTHROPIC_API_KEY="abc123def456"', "abc123def456")
        self.assertGone("export DB_PASSWORD=hunter2", "hunter2")
        self.assertGone("MY_SECRET_TOKEN=zzz ./run.sh", "zzz")

    def test_flag_value(self):
        self.assertGone("gh auth login --with-token abcdefghijklmnop", "abcdefghijklmnop")
        self.assertGone("docker login --password s3cr3tpw registry.io", "s3cr3tpw")
        self.assertGone("kubectl --token=abc.def.ghi get pods", "abc.def.ghi")

    def test_attached_password(self):
        # `mysql -phunter2` has no separator and defeats every flag-and-value rule.
        self.assertGone("mysql -u root -phunter2xyz db", "hunter2xyz")

    def test_userpass_flag(self):
        self.assertGone("curl -u admin:letmein https://api.example.com", "admin:letmein")

    def test_auth_header(self):
        self.assertGone(
            'curl -H "Authorization: Bearer eyJhbGciOi.payload.sig" https://x.io',
            "eyJhbGciOi.payload.sig",
        )

    def test_url_credentials_and_query(self):
        pw = hole("{FILL 8}", 21)
        # Concatenated rather than interpolated: `user:{pw}@host` in an f-string is a
        # complete credentials-in-URL pattern ON DISK, and this repository's own leak scan
        # is right to flag it.
        url = "postgres://user:" + pw + "@db.acme.io/app"
        self.assertGone(f"psql {url}", pw)
        self.assertGone("curl 'https://api.acme.io/x?api_key=abc123'", "api_key=abc123")

    def test_credential_shapes(self):
        cases = [
            "ghp_" + "a" * 36,
            "AKIA" + "ABCDEFGHIJKLMNOP",
            "AIza" + "b" * 35,
            hole("xoxb-{FILL 20}", 22),
            "sk-" + "c" * 40,
            "glpat-" + "d" * 20,
            "npm_" + "e" * 36,
            "f" * 44,
        ]
        for c in cases:
            with self.subTest(c=c[:8]):
                self.assertGone(f"echo {c}", c)

    def test_private_hostnames_and_addresses(self):
        host = hole("build{FILL 3}.internal", 23)
        self.assertGone(f"ssh deploy@{host}", host)
        self.assertGone("curl http://192.168.4.19:8080/health", "192.168.4.19")

    def test_home_directory(self):
        user = hole("user{FILL 4}", 24)
        out = redact(f"cd /home/{user}/Projects/thing")
        self.assertNotIn(user, out)
        self.assertIn("~/Projects/thing", out)

    def test_uuid_is_an_identifier(self):
        u = "a8c262c5-474d-456e-8f0a-68d06c665cec"
        self.assertGone(f"claude --resume {u}", u)


class TestNotOverRedacted(unittest.TestCase):
    """The negative controls. Each of these is a command a real history is full of."""

    def assertUnchanged(self, cmd):
        self.assertEqual(redact(cmd), cmd)

    def test_npm_version_specifier_is_not_an_ssh_target(self):
        self.assertUnchanged("npm install -g clawdbot@latest")
        self.assertUnchanged("npm install react@18.2.0")

    def test_public_hosts_survive(self):
        self.assertUnchanged("git clone https://github.com/acme/thing")
        self.assertUnchanged("curl -s http://localhost:11434/api/tags")
        self.assertUnchanged("pip install -i https://pypi.org/simple requests")

    def test_ordinary_paths_survive(self):
        self.assertUnchanged("cd Projects/HunterPath")
        self.assertUnchanged("cat src/components/DashboardContainer/index.tsx")

    def test_docker_tag_survives(self):
        self.assertUnchanged("docker push api:v1")

    def test_version_numbers_are_not_addresses(self):
        self.assertUnchanged("nvm install v0.39.7")


class TestPlaceholderIdentity(unittest.TestCase):
    def test_different_secrets_get_different_placeholders(self):
        # If every secret collapsed to one placeholder, a workflow parameterised over a
        # secret would be misread as a fixed alias. This is a correctness property, not a
        # cosmetic one.
        r = Redactor()
        a = r.apply("export API_TOKEN=aaaaaaaaaaaa").text
        b = r.apply("export API_TOKEN=bbbbbbbbbbbb").text
        self.assertNotEqual(a, b)

    def test_same_secret_gets_the_same_placeholder_within_a_run(self):
        r = Redactor()
        a = r.apply("export API_TOKEN=aaaaaaaaaaaa").text
        b = r.apply("export API_TOKEN=aaaaaaaaaaaa").text
        self.assertEqual(a, b)

    def test_accounting_is_reported(self):
        res = Redactor().apply(
            "export API_TOKEN=abcdef ssh me@" + hole("host{FILL 3}.internal", 25)
        )
        self.assertIn("SECRET:env", res.kinds)
        self.assertTrue(any(k in ("HOST", "EMAIL") for k in res.kinds))


class TestEntropy(unittest.TestCase):
    def test_flat_beats_repetitive(self):
        self.assertGreater(shannon("abcdefghijklmnop"), shannon("aaaaaaaaaaaaaaaa"))


if __name__ == "__main__":
    unittest.main()
