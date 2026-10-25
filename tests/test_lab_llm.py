import asyncio
import json
import re
import unittest
from unittest.mock import AsyncMock, patch

from agents import lab_operator
from core import state_store as store


class AIMessage:
    def __init__(self, tool_calls):
        self.tool_calls = tool_calls


class ToolMessage:
    def __init__(self, call_id, payload):
        self.tool_call_id = call_id
        self.content = json.dumps(payload)


def _transcript(method, url, status, body):
    """One AIMessage tool_call paired with its ToolMessage result, in the
    shape agent.ainvoke's real output takes -- see operator._extract_tool_calls."""
    return [
        AIMessage([{"id": "call-1", "args": {"method": method, "url": url}}]),
        ToolMessage("call-1", {"status_code": status, "body": body}),
    ]


class LabLLMCheckTests(unittest.TestCase):
    def test_check_grades_vulnerable_secure_and_missing_call(self):
        # Vulnerable: 200 with the victim's data in the body.
        ok, evidence = lab_operator._check(
            [{"args": {"method": "GET", "url": "http://x/api/collection_0001/documents/1"},
              "content": json.dumps({"status_code": 200, "body": '{"owner":"alice"}'})}],
            "collection_0001", "B1")
        self.assertTrue(ok)
        self.assertIn("alice", evidence)

        # Secure: blocked with 403.
        ok, _ = lab_operator._check(
            [{"args": {"method": "GET", "url": "http://x/api/collection_0001/documents/1"},
              "content": json.dumps({"status_code": 403, "body": "Resource belongs to another user"})}],
            "collection_0001", "B1")
        self.assertFalse(ok)

        # Inconclusive: the agent never actually sent the described call.
        ok, evidence = lab_operator._check(
            [{"args": {"method": "GET", "url": "http://x/api/collection_0001/items"},
              "content": json.dumps({"status_code": 200, "body": "[]"})}],
            "collection_0001", "B1")
        self.assertIsNone(ok)
        self.assertIn("never sent", evidence)

    def test_check_200_without_needle_is_not_vulnerable(self):
        # A 200 on an unrelated call must not count as proof.
        ok, _ = lab_operator._check(
            [{"args": {"method": "GET", "url": "http://x/api/collection_0001/documents/1"},
              "content": json.dumps({"status_code": 200, "body": '{"owner":"bob"}'})}],
            "collection_0001", "B1")
        self.assertFalse(ok)

    def test_b6_and_v1_need_no_needle(self):
        # B6/V1 responses don't echo alice's data -- any 200 is proof enough.
        ok, _ = lab_operator._check(
            [{"args": {"method": "POST", "url": "http://x/api/collection_0001/documents/1/share"},
              "content": json.dumps({"status_code": 200, "body": '{"token":"abc"}'})}],
            "collection_0001", "B6")
        self.assertTrue(ok)


class RunLlmSampleTests(unittest.TestCase):
    def _run(self, candidates, sample_size, transcript_for, should_stop=None,
             policy_file=None, upsert_side_effect=None):
        agent = AsyncMock()
        agent.ainvoke.side_effect = lambda messages, config: {
            "messages": transcript_for(messages["messages"][0][1])
        }
        # Mirror store.upsert_finding's status rule: a positive verdict is
        # always "open"; a blocked one is "patched" only when the policy says
        # a defender patch is in effect, else it stays "open" (always-secure).
        upsert_default = lambda finding, round_id, policy_patched=False: {
            **finding,
            "status": "open" if finding.get("verdict") is True
                      else "patched" if policy_patched else "open"}
        with patch.object(lab_operator, "_login_bob", return_value="bob-token"), \
             patch.object(lab_operator, "build_agent", new_callable=AsyncMock, return_value=agent), \
             patch.object(store, "log_event"), \
             patch.object(store, "upsert_finding",
                          side_effect=upsert_side_effect or upsert_default) as upsert, \
             patch.object(store, "finding_id", side_effect=lambda target, mod: f"{target}::{mod}"):
            findings = asyncio.run(lab_operator.run_llm_sample(
                "http://lab", "qwen2.5", candidates, round_id=1, sample_size=sample_size,
                rng_seed=1, should_stop=should_stop, policy_file=policy_file))
        return findings, upsert

    def test_samples_at_most_sample_size_and_saves_distinct_finding_ids(self):
        candidates = [(f"collection_{i:04d}", "B1") for i in range(10)]

        def transcript(prompt):
            # Every mission "succeeds": reuse the exact request line the
            # prompt asked for, with 200 + alice's owner field back.
            method, url = re.search(r"\n(GET|POST|PATCH) (\S+)\n", prompt).groups()
            return _transcript(method, url, 200, '{"owner":"alice"}')

        findings, upsert = self._run(candidates, sample_size=3, transcript_for=transcript)
        self.assertEqual(len(findings), 3)
        self.assertEqual(upsert.call_count, 3)
        self.assertTrue(all(f["module_id"] == "lab-llm" for f in findings))
        self.assertTrue(all(f["verdict"] is True for f in findings))
        # Sampled collections must be an actual subset of the candidates, no duplicates.
        names = [f["collection"] for f in findings]
        self.assertEqual(len(set(names)), len(names))
        self.assertTrue(set(names) <= {c[0] for c in candidates})

    def test_blocked_attack_is_patched_only_when_the_policy_enforces_it(self):
        # Two collections the LLM attack can't exploit (both come back 403).
        # Without the policy they're indistinguishable; with it, only the one
        # the defender actually patched carries status "patched" -- the other
        # was never vulnerable ("always secure"). This is the whole reason the
        # LLM summary can report "N defended (P patched, M always secure)"
        # instead of a flat "defended" for every secure collection.
        candidates = [("collection_0001", "B1"), ("collection_0002", "B1")]
        policy = {"version": 1, "collections": {"collection_0001": {"B1": True}}}

        def transcript(prompt):
            method, url = re.search(r"\n(GET|POST|PATCH) (\S+)\n", prompt).groups()
            return _transcript(method, url, 403, '{"detail":"Resource belongs to another user"}')

        with patch.object(lab_operator, "read_policy", return_value=policy):
            findings, _ = self._run(candidates, sample_size=2, transcript_for=transcript,
                                    policy_file="policy.json")
        by_name = {f["collection"]: f for f in findings}
        self.assertEqual(by_name["collection_0001"]["verdict"], False)
        self.assertEqual(by_name["collection_0001"]["status"], "patched")
        self.assertEqual(by_name["collection_0002"]["verdict"], False)
        self.assertEqual(by_name["collection_0002"]["status"], "open")  # always secure, not patched

    def test_no_policy_file_leaves_blocked_attacks_unpatched(self):
        # With no policy to consult, a blocked attack can't be proven to be a
        # defender patch, so it stays "open" (always-secure) -- the documented
        # fallback, same as the deterministic path without --policy-file.
        candidates = [("collection_0001", "B1")]

        def transcript(prompt):
            method, url = re.search(r"\n(GET|POST|PATCH) (\S+)\n", prompt).groups()
            return _transcript(method, url, 403, '{"detail":"Resource belongs to another user"}')

        findings, _ = self._run(candidates, sample_size=1, transcript_for=transcript, policy_file=None)
        self.assertEqual(findings[0]["verdict"], False)
        self.assertEqual(findings[0]["status"], "open")

    def test_zero_sample_or_no_candidates_is_a_noop(self):
        findings, upsert = self._run([("collection_0001", "B1")], sample_size=0, transcript_for=lambda p: [])
        self.assertEqual(findings, [])
        upsert.assert_not_called()
        findings, upsert = self._run([], sample_size=5, transcript_for=lambda p: [])
        self.assertEqual(findings, [])
        upsert.assert_not_called()

    def test_stops_cooperatively_between_collections(self):
        candidates = [(f"collection_{i:04d}", "V1") for i in range(5)]
        calls = {"n": 0}

        def should_stop():
            calls["n"] += 1
            return calls["n"] > 1  # let the first one run, then stop

        def transcript(prompt):
            method, url = re.search(r"\n(GET|POST|PATCH) (\S+)\n", prompt).groups()
            return _transcript(method, url, 200, '{"disabled":true}')

        findings, upsert = self._run(candidates, sample_size=5, transcript_for=transcript, should_stop=should_stop)
        self.assertLess(len(findings), 5)
        self.assertEqual(upsert.call_count, len(findings))

    def test_login_failure_short_circuits_without_building_an_agent(self):
        with patch.object(lab_operator, "_login_bob", return_value=None), \
             patch.object(lab_operator, "build_agent", new_callable=AsyncMock) as build, \
             patch.object(store, "log_event"), \
             patch.object(store, "upsert_finding") as upsert:
            findings = asyncio.run(lab_operator.run_llm_sample(
                "http://lab", "qwen2.5", [("collection_0001", "B1")], round_id=1, sample_size=1))
        self.assertEqual(findings, [])
        build.assert_not_called()
        upsert.assert_not_called()

    def test_module_failure_is_inconclusive_not_a_crash(self):
        agent = AsyncMock()
        agent.ainvoke.side_effect = RuntimeError("Ollama is not running")
        with patch.object(lab_operator, "_login_bob", return_value="bob-token"), \
             patch.object(lab_operator, "build_agent", new_callable=AsyncMock, return_value=agent), \
             patch.object(store, "log_event"), \
             patch.object(store, "upsert_finding") as upsert, \
             patch.object(store, "finding_id", side_effect=lambda target, mod: f"{target}::{mod}"):
            findings = asyncio.run(lab_operator.run_llm_sample(
                "http://lab", "qwen2.5", [("collection_0001", "B1")], round_id=1, sample_size=1))
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]["verdict"])
        self.assertIn("Ollama is not running", findings[0]["evidence"])
        upsert.assert_called_once()


if __name__ == "__main__":
    unittest.main()
