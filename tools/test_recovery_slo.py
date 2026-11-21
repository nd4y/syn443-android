import json
import tempfile
import unittest
from pathlib import Path

from recovery_slo import Campaign, DEADLINE_MS, RecoveryTimeout, initial, publish, summarize


class RecoverySLOTest(unittest.TestCase):
    def test_restored_hops_have_fixed_denominator_and_nearest_rank(self):
        with tempfile.TemporaryDirectory() as folder:
            raw, dest = Path(folder) / "raw.json", Path(folder) / "safe.json"
            clock = [0]
            campaign = Campaign(raw, lambda: clock[0])
            for hop, duration in (("ingress", 11), ("egress", DEADLINE_MS)):
                with campaign.measure(hop):
                    clock[0] += duration * 1_000_000
            publish(raw, dest, require_success=True)
            result = json.loads(dest.read_bytes())
            self.assertEqual((2, 2, DEADLINE_MS), (result["denominator"], result["completedWithinDeadline"], result["p95Ms"]))
            with self.assertRaises(ValueError):
                with campaign.measure("ingress"):
                    pass

    def test_timeouts_misses_and_unreached_samples_never_disappear(self):
        with tempfile.TemporaryDirectory() as folder:
            raw, dest = Path(folder) / "raw.json", Path(folder) / "safe.json"
            publish(raw, dest)
            self.assertIsNone(json.loads(dest.read_bytes())["p95Ms"])
            clock = [0]
            campaign = Campaign(raw, lambda: clock[0])
            with self.assertRaises(RecoveryTimeout):
                with campaign.measure("ingress"):
                    self.assertEqual("observing", json.loads(raw.read_bytes())[0]["outcome"])
                    clock[0] += DEADLINE_MS * 1_000_000
                    raise RecoveryTimeout()
            campaign.setup_failed("egress")
            campaign.setup_failed("ingress")
            publish(raw, dest)
            result = json.loads(dest.read_bytes())
            self.assertEqual(["timeout", "setup_failed"], [r["outcome"] for r in result["samples"]])
            self.assertEqual((2, 0, None), (result["denominator"], result["completedWithinDeadline"], result["p95Ms"]))
            with self.assertRaises(ValueError):
                publish(raw, dest, require_success=True)

    def test_late_response_and_fault_are_classified_separately(self):
        with tempfile.TemporaryDirectory() as folder:
            clock = [0]
            campaign = Campaign(Path(folder) / "raw.json", lambda: clock[0])
            with campaign.measure("ingress"):
                clock[0] += DEADLINE_MS * 1_000_000 + 1
            with self.assertRaises(RuntimeError):
                with campaign.measure("egress"):
                    raise RuntimeError("fixture-private")
            result = summarize(campaign.rows)
            self.assertEqual(["late", "failed"], [r["outcome"] for r in result["samples"]])
            self.assertEqual(DEADLINE_MS + 1, result["samples"][0]["elapsedMs"])
            self.assertNotIn("fixture-private", json.dumps(result))

    def test_malformed_or_reclassified_rows_never_reach_the_public_artifact(self):
        for rows in ([], list(reversed(initial())), [initial()[0], initial()[0]]):
            with self.assertRaises(ValueError):
                summarize(rows)
        for change in ({"outcome": "cold_search"}, {"address": "fixture-private"}, {"elapsedMs": False},
                       {"outcome": "passed", "elapsedMs": DEADLINE_MS + 1}, {"outcome": "timeout", "elapsedMs": 3}):
            rows = initial()
            rows[0].update(change)
            with self.assertRaises(ValueError):
                summarize(rows)
        with tempfile.TemporaryDirectory() as folder:
            raw, dest = Path(folder) / "raw.json", Path(folder) / "safe.json"
            raw.write_text('[{"hop":"egress","hop":"ingress","outcome":"passed","elapsedMs":1}]')
            with self.assertRaises(ValueError):
                publish(raw, dest)
            self.assertFalse(dest.exists())
