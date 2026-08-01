"""Parsing, normalization, sessioning, mining, and suggestion generation."""

import math
import unittest

from histminer.mine import (
    Occurrence,
    Pattern,
    close,
    find_occurrences,
    is_periodic,
    lift,
    mine,
    permutation_null,
)
from histminer.normalize import normalize, tokenize
from histminer.parse import Event, parse_text, sniff, split_compound
from histminer.sessions import estimate_gap, model_for, segment
from histminer.suggest import SavingsModel, build, render


class TestParse(unittest.TestCase):
    def test_sniff_each_format(self):
        self.assertEqual(sniff("ls\ncd x\n"), "bash-plain")
        self.assertEqual(sniff("#1767225600\nls\n"), "bash-timestamp")
        self.assertEqual(sniff(": 1767225600:0;ls\n"), "zsh-extended")
        self.assertEqual(sniff('{"ts":1,"command":"ls"}\n'), "jsonl")

    def test_bash_plain_has_no_timestamps(self):
        h = parse_text("ls\ncd x\n")
        self.assertEqual([e.text for e in h.events], ["ls", "cd x"])
        self.assertTrue(all(e.ts is None for e in h.events))
        self.assertFalse(h.timestamped)

    def test_bash_timestamp(self):
        h = parse_text("#1767225600\nls\n#1767225660\ncd x\n")
        self.assertEqual([e.ts for e in h.events], [1767225600.0, 1767225660.0])
        self.assertTrue(h.timestamped)

    def test_zsh_extended_with_continuation(self):
        h = parse_text(": 1767225600:0;for i in 1 2\\\ndo echo $i\ndone\n: 1767225700:0;ls\n")
        self.assertEqual(len(h.events), 2)
        self.assertIn("do echo", h.events[0].text)

    def test_jsonl_flat_and_transcript(self):
        flat = '{"ts": 1767225600, "text": "ls -la"}'
        transcript = (
            '{"timestamp": "2026-01-01T00:00:00Z", "message": {"content": '
            '[{"type": "tool_use", "name": "Bash", "input": {"command": "git status"}}]}}'
        )
        h = parse_text(flat + "\n" + transcript + "\n", fmt="jsonl")
        self.assertEqual([e.text for e in h.events], ["ls -la", "git status"])

    def test_millisecond_timestamps_are_detected(self):
        h = parse_text('{"timestamp": 1769528164301, "display": "ls"}\n', fmt="jsonl")
        self.assertAlmostEqual(h.events[0].ts, 1769528164.301, places=2)

    def test_parse_redacts_before_anything_downstream_sees_it(self):
        h = parse_text("export API_KEY=supersecretvalue\n")
        self.assertNotIn("supersecretvalue", h.events[0].text)

    def test_split_compound_respects_quotes(self):
        self.assertEqual(
            split_compound('echo "a; b" && ls; pwd'), ['echo "a; b"', "ls", "pwd"]
        )

    def test_split_is_off_by_default(self):
        h = parse_text("cd x && npm test\n")
        self.assertEqual(len(h.events), 1)
        h2 = parse_text("cd x && npm test\n", split=True)
        self.assertEqual([e.text for e in h2.events], ["cd x", "npm test"])


class TestNormalize(unittest.TestCase):
    def test_tokenize_keeps_quotes(self):
        self.assertEqual(tokenize('git commit -m "a b"'), ["git", "commit", "-m", '"a b"'])

    def test_arguments_become_slots(self):
        c = normalize("git commit -m fix")
        self.assertEqual(c.template, "git commit -m <ARG>")
        self.assertEqual(c.slots, ("fix",))

    def test_two_commits_share_a_template(self):
        self.assertEqual(normalize("git commit -m one").template,
                         normalize("git commit -m two").template)

    def test_subcommand_is_kept_but_data_is_not(self):
        # `docker push api:v1` must not absorb the tag, or every push is its own template
        # and the build/push pair can never be mined.
        self.assertEqual(normalize("docker push api:v1").template, "docker push <ARG>")

    def test_nested_verb_absorbs_two_words(self):
        self.assertEqual(normalize("npm run build").template, "npm run build")
        self.assertNotEqual(normalize("npm run build").template,
                            normalize("npm run test").template)

    def test_cd_argument_is_a_path_even_without_a_slash(self):
        self.assertEqual(normalize("cd Projects").template, "cd <PATH>")
        self.assertEqual(normalize("cd Projects/").template, "cd <PATH>")

    def test_flags_are_preserved(self):
        self.assertEqual(normalize("ls -la").template, "ls -la")

    def test_flag_with_attached_value(self):
        c = normalize("kubectl get pods --namespace=prod")
        self.assertIn("--namespace=<ARG>", c.template)
        self.assertEqual(c.slots, ("prod",))


class TestSessions(unittest.TestCase):
    def _bimodal(self, n=400):
        """Gaps drawn from two clusters: seconds within a burst, hours between bursts."""
        ts = [0.0]
        for i in range(n):
            ts.append(ts[-1] + (7200.0 if i % 20 == 19 else 5.0 + (i % 7)))
        return [Event(t, f"cmd{i % 5}") for i, t in enumerate(ts)]

    def test_antimode_is_found_between_the_two_modes(self):
        est = estimate_gap(self._bimodal())
        self.assertEqual(est.method, "antimode")
        self.assertGreater(est.seconds, 20)
        self.assertLess(est.seconds, 7200)

    def test_unimodal_data_reports_a_fallback_rather_than_inventing_a_knee(self):
        events = [Event(float(i * 10), "ls") for i in range(400)]
        est = estimate_gap(events)
        self.assertEqual(est.method, "fallback-unimodal")
        self.assertIn("not bimodal", est.note)

    def test_untimestamped_history_is_a_different_model_not_a_default_gap(self):
        m = model_for([Event(None, "ls"), Event(None, "cd x")])
        self.assertEqual(m.kind, "single-block")
        self.assertFalse(m.trustworthy)
        self.assertIn("no timestamps", m.describe())

    def test_segment_splits_on_the_gap(self):
        ev = [Event(0.0, "a"), Event(10.0, "b"), Event(10000.0, "c")]
        self.assertEqual([len(s) for s in segment(ev, 300.0)], [2, 1])

    def test_segment_with_no_gap_is_one_block(self):
        ev = [Event(None, "a"), Event(None, "b")]
        self.assertEqual(len(segment(ev, None)), 1)


class TestMine(unittest.TestCase):
    def test_occurrences_are_non_overlapping(self):
        # Ten `a` in a row is nine overlapping pairs and five real ones. Counting the nine
        # would inflate every savings estimate that follows.
        self.assertEqual(len(find_occurrences(["a"] * 10, ("a", "a"), 0)), 5)

    def test_gap_tolerance(self):
        seq = ["a", "x", "b"]
        self.assertEqual(len(find_occurrences(seq, ("a", "b"), 0)), 0)
        self.assertEqual(len(find_occurrences(seq, ("a", "b"), 1)), 1)

    def test_periodic_patterns_are_dropped(self):
        self.assertTrue(is_periodic(("a", "b", "a", "b")))
        self.assertTrue(is_periodic(("a", "b", "a")))
        self.assertFalse(is_periodic(("a", "b", "c")))

    def test_closure_drops_a_subsumed_pattern(self):
        short = Pattern(("a", "b"), 2, [Occurrence(0, (0, 1)), Occurrence(1, (0, 1))])
        long = Pattern(("a", "b", "c"), 2, [Occurrence(0, (0, 1, 2)), Occurrence(1, (0, 1, 2))])
        kept = close([short, long])
        self.assertEqual([p.items for p in kept], [("a", "b", "c")])

    def test_closure_keeps_a_more_frequent_short_pattern(self):
        short = Pattern(("a", "b"), 3, [Occurrence(i, (0, 1)) for i in range(3)])
        long = Pattern(("a", "b", "c"), 2, [Occurrence(i, (0, 1, 2)) for i in range(2)])
        kept = {p.items for p in close([short, long])}
        self.assertIn(("a", "b"), kept)

    def test_mining_finds_a_planted_sequence(self):
        sessions = [["x", "a", "b", "y"], ["a", "b", "z"], ["q", "a", "b"]]
        found = {p.items for p in mine(sessions, min_support=2, min_occurrences=3)}
        self.assertIn(("a", "b"), found)

    def test_mining_finds_nothing_in_structureless_input(self):
        sessions = [[f"c{i}{j}" for j in range(6)] for i in range(6)]
        self.assertEqual(mine(sessions, min_support=2, min_occurrences=3), [])

    def test_confidence_prunes_an_unreliable_extension(self):
        # `a -> b` always; `b -> c` only a third of the time. The three-step workflow is not
        # one you would ever wrap in a function.
        sessions = [["a", "b", "c"]] + [["a", "b", "d"] for _ in range(6)]
        got = {p.items for p in mine(sessions, min_support=2, min_occurrences=3,
                                     min_confidence=0.5)}
        self.assertIn(("a", "b"), got)
        self.assertNotIn(("a", "b", "c"), got)

    def test_lift_is_near_one_for_independent_commands(self):
        sessions = [["a", "b"], ["b", "a"], ["a", "b"], ["b", "a"]]
        p = Pattern(("a", "b"), 2, [Occurrence(0, (0, 1)), Occurrence(2, (0, 1))])
        self.assertLess(lift(p, sessions), 3.0)

    def test_permutation_null_is_low_for_structured_input(self):
        sessions = [["a", "b"] + [f"n{i}{j}" for j in range(6)] for i in range(10)]
        nulls = permutation_null(sessions, rounds=10, min_support=2, min_occurrences=3)
        self.assertLess(max(nulls), 10)


class TestSuggest(unittest.TestCase):
    def _sessions(self, rows):
        return [[normalize(c) for c in row] for row in rows]

    def test_identical_arguments_produce_an_alias(self):
        rows = [["npm run build", "npm run test"] for _ in range(4)]
        sess = self._sessions(rows)
        seqs = [[c.template for c in s] for s in sess]
        p = [x for x in mine(seqs, min_support=2, min_occurrences=3) if x.length == 2][0]
        s = build(p, sess, per_week=1.0, rate_basis="test")
        self.assertEqual(s.kind, "alias")
        self.assertEqual(s.n_params, 0)
        self.assertIn("alias ", s.body)

    def test_varying_arguments_produce_a_function(self):
        rows = [[f"git checkout -b b{i}", f"git push -u origin b{i}"] for i in range(5)]
        sess = self._sessions(rows)
        seqs = [[c.template for c in s] for s in sess]
        p = [x for x in mine(seqs, min_support=2, min_occurrences=3) if x.length == 2][0]
        s = build(p, sess, per_week=1.0, rate_basis="test")
        self.assertEqual(s.kind, "function")
        self.assertEqual(s.n_params, 1, f"co-varying slots not merged:\n{s.body}")
        self.assertEqual(s.body.count('"$1"'), 2)

    def test_independent_arguments_stay_separate(self):
        rows = [[f"cd d{i}", f"git commit -m m{i * 7}"] for i in range(5)]
        sess = self._sessions(rows)
        seqs = [[c.template for c in s] for s in sess]
        p = [x for x in mine(seqs, min_support=2, min_occurrences=3) if x.length == 2][0]
        s = build(p, sess, per_week=1.0, rate_basis="test")
        self.assertEqual(s.n_params, 2)

    def test_savings_arithmetic_matches_the_stated_model(self):
        rows = [["npm run build", "npm run test"] for _ in range(4)]
        sess = self._sessions(rows)
        seqs = [[c.template for c in s] for s in sess]
        p = [x for x in mine(seqs, min_support=2, min_occurrences=3) if x.length == 2][0]
        s = build(p, sess, per_week=2.0, rate_basis="test")
        m = SavingsModel(typing_cps=5.0, switch_cost=0.8)
        expected = s.keystrokes_saved / 5.0 + 1 * 0.8
        self.assertTrue(math.isclose(s.seconds_saved_each(m), expected))
        self.assertTrue(math.isclose(s.seconds_per_week(m), expected * 2.0))

    def test_render_fills_slots_left_to_right(self):
        self.assertEqual(render("git commit -m <ARG>", ['"$1"']), 'git commit -m "$1"')
        self.assertEqual(render("ls -la", []), "ls -la")

    def test_generated_name_does_not_shadow_a_real_command(self):
        rows = [["ls", "ls -la"] for _ in range(4)]
        sess = self._sessions(rows)
        seqs = [[c.template for c in s] for s in sess]
        pats = [x for x in mine(seqs, min_support=2, min_occurrences=3) if x.length == 2]
        for p in pats:
            s = build(p, sess, per_week=1.0, rate_basis="test")
            self.assertNotIn(s.name, ("ls", "cd", "rm", "git"))


if __name__ == "__main__":
    unittest.main()
