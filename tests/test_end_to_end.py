"""Whole-pipeline checks against fixtures whose contents are known in advance.

The planted fixture answers "did it find the thing that is definitely there". The control
fixture answers the question that matters more, "does it stay quiet when there is nothing
there", because a miner that always reports something is indistinguishable from a random
suggestion generator on any single run.
"""

import json
import pathlib
import subprocess
import sys
import unittest

from histminer.parse import parse_text, read
from histminer.report import MineOptions, analyze, to_json

from .support import LITERAL_SECRETS, expand_secrets

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def run(path, **kw):
    hist = read(path)
    return analyze(hist, opts=MineOptions(permutation_rounds=20, **kw))


class TestPlanted(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = run(FIXTURES / "planted.history")
        cls.by_seq = {" ; ".join(s.pattern.items): s for s in cls.a.suggestions}

    def find(self, *fragments):
        for key, s in self.by_seq.items():
            if all(f in key for f in fragments):
                return s
        self.fail(f"no suggestion matching {fragments}; got {list(self.by_seq)}")

    def test_workflow_a_is_a_function_of_one_argument(self):
        s = self.find("git checkout -b", "git push")
        self.assertEqual(s.kind, "function")
        self.assertEqual(s.n_params, 1, f"branch name used twice must be ONE param:\n{s.body}")
        self.assertEqual(s.body.count('"$1"'), 2)

    def test_workflow_b_is_an_alias(self):
        s = self.find("npm run build", "npm run test", "npm run lint")
        self.assertEqual(s.kind, "alias")
        self.assertEqual(s.n_params, 0)

    def test_workflow_c_survives_an_interleaved_command(self):
        # `cd X; ls; npm install` in half the sessions and `cd X; npm install` in the rest.
        s = self.find("cd <PATH>", "npm install")
        self.assertGreaterEqual(s.occurrences, 8)

    def test_workflow_d_shares_the_tag_between_build_and_push(self):
        s = self.find("docker build", "docker push")
        self.assertEqual(s.kind, "function")
        # The tag appears in both commands and is one argument, not two.
        self.assertGreaterEqual(s.body.count('"$2"') + s.body.count('"$1"'), 2)

    def test_the_most_frequent_command_is_not_suggested(self):
        top_template = self.a.top_frequency[0][0]
        self.assertEqual(top_template, "ls")
        for s in self.a.suggestions:
            self.assertNotEqual(list(s.pattern.items), ["ls"])
            self.assertGreater(s.pattern.length, 1)

    def test_session_boundary_came_from_the_data(self):
        self.assertEqual(self.a.model.kind, "timestamp-gap")
        self.assertEqual(self.a.model.gap.method, "antimode")
        self.assertGreater(self.a.model.gap.seconds, 60)
        self.assertLess(self.a.model.gap.seconds, 3600)

    def test_findings_are_stable_across_plausible_boundaries(self):
        stable = [j for g, j, _ in self.a.sweep if g >= 120]
        self.assertTrue(stable)
        self.assertGreaterEqual(min(stable), 0.8, f"sweep unstable: {self.a.sweep}")

    def test_findings_beat_the_order_destroyed_null(self):
        self.assertTrue(self.a.null_max)
        self.assertGreater(self.a.observed_top, max(self.a.null_max))

    def test_json_is_deterministic(self):
        self.assertEqual(to_json(self.a), to_json(run(FIXTURES / "planted.history")))


class TestControl(unittest.TestCase):
    def test_no_workflows_in_a_structureless_history(self):
        a = run(FIXTURES / "control.history")
        self.assertEqual(
            a.suggestions,
            [],
            "control fixture produced suggestions: "
            + "; ".join(" ".join(s.pattern.items) for s in a.suggestions),
        )

    def test_the_control_still_contains_the_same_commands(self):
        # Proves the control is a shuffle and not an empty file, so "found nothing" means
        # "found no ORDER" rather than "had nothing to look at".
        planted = read(FIXTURES / "planted.history")
        control = read(FIXTURES / "control.history")
        self.assertEqual(len(planted.events), len(control.events))
        self.assertEqual(
            sorted(e.text for e in planted.events), sorted(e.text for e in control.events)
        )


class TestNoSecretsInOutput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.planted = expand_secrets()
        cls.hist = parse_text(cls.text, fmt="bash-timestamp")
        cls.analysis = analyze(
            cls.hist, opts=MineOptions(permutation_rounds=3), do_sweep=False
        )

    def all_output(self):
        return "\n".join(
            [
                "\n".join(e.text for e in self.hist.events),
                to_json(self.analysis),
            ]
        )

    def test_no_planted_secret_survives(self):
        out = self.all_output()
        leaked = [s for s in self.planted if s in out]
        self.assertEqual(leaked, [], f"{len(leaked)} secret(s) reached the output")

    def test_no_private_hostname_survives(self):
        out = self.all_output()
        leaked = [s for s in LITERAL_SECRETS if s in out]
        self.assertEqual(leaked, [])

    def test_the_fixture_really_contained_them(self):
        # Negative control for the test above: if the expander stopped planting anything,
        # "no secret survived" would pass vacuously.
        self.assertGreaterEqual(len(self.planted), 15)
        for s in self.planted:
            self.assertIn(s, self.text)

    def test_the_committed_template_holds_no_complete_credential(self):
        raw = (FIXTURES / "secrets.template.history").read_bytes()
        self.assertNotIn(b"\x00", raw)
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "leakcheck.py"),
             "--paths", str(FIXTURES / "secrets.template.history")],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_the_independent_checker_flags_the_expanded_fixture(self):
        # Without this, "the checker passes on our output" could mean the checker is blind.
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "leakcheck.py"), "--stdin"],
            input=self.text, capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1, "checker did not flag raw secrets: " + r.stdout)

    def test_the_independent_checker_passes_the_redacted_output(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "leakcheck.py"), "--stdin"],
            input=self.all_output(), capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, "checker flagged redacted output: " + r.stdout)

    def test_the_checker_shares_no_code_with_the_redactor(self):
        # Parsed, not grepped: a docstring may name the module it is independent OF, and a
        # substring search would either miss `import  histminer` or ban the explanation.
        import ast

        tree = ast.parse((ROOT / "tools" / "leakcheck.py").read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("histminer", imported)
        self.assertNotIn("tests", imported)


class TestUntimestamped(unittest.TestCase):
    def test_a_plain_bash_history_reports_its_weaker_model(self):
        text = "\n".join(["cd a", "claude", "cd b", "claude", "cd c", "claude"] * 6)
        a = analyze(parse_text(text), opts=MineOptions(permutation_rounds=5), do_sweep=False)
        self.assertEqual(a.model.kind, "single-block")
        self.assertFalse(a.model.trustworthy)
        self.assertIn("no timestamps", json.loads(to_json(a))["session_model_detail"])
        self.assertIn("min-support lowered", a.degraded)


if __name__ == "__main__":
    unittest.main()
