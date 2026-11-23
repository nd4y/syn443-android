import json
import tempfile
import unittest
from pathlib import Path

from known_start_slo import StartupCampaign, initial, publish, summarize


class KnownStartSloTest(unittest.TestCase):
    def test_boundary_and_nearest_rank_include_every_planned_start(self):
        with tempfile.TemporaryDirectory() as folder:
            raw, output = Path(folder)/"raw.json", Path(folder)/"public.json"
            campaign = StartupCampaign(raw)
            for index, value in enumerate((3_000_000_000, 10_000_000_000, 10_000_000_001)):
                campaign.start(index)
                campaign.finish(index, value)
            with self.assertRaises(ValueError):
                publish(raw, output, require_target=True)
            report = json.loads(output.read_bytes())
            self.assertEqual([row["outcome"] for row in report["samples"]], ["passed", "passed", "late"])
            self.assertEqual((3, 2, 10_001), (report["denominator"], report["withinTarget"], report["p95Ms"]))
            with self.assertRaises(ValueError):
                campaign.start(1)

    def test_missing_interrupted_and_failed_trials_keep_the_denominator(self):
        with tempfile.TemporaryDirectory() as folder:
            raw, output = Path(folder)/"raw.json", Path(folder)/"public.json"
            publish(raw, output)
            self.assertIsNone(json.loads(output.read_bytes())["p95Ms"])
            campaign = StartupCampaign(raw)
            campaign.start(0)
            campaign.finish(0)
            campaign.start(1)
            report = summarize(campaign.rows)
            self.assertEqual(["failed", "observing", "not_started"], [row["outcome"] for row in report["samples"]])
            self.assertEqual(3, report["denominator"])
            self.assertIsNone(report["p95Ms"])

    def test_unexpected_data_and_false_success_are_rejected(self):
        for row in [
            {"outcome": "passed", "elapsedMs": True}, {"outcome": "passed", "elapsedMs": 10_001},
            {"outcome": "late", "elapsedMs": 10_000}, {"outcome": "failed", "elapsedMs": 1},
            {"outcome": "passed", "elapsedMs": 100, "endpoint": "synthetic.invalid"},
        ]:
            with self.subTest(row=row), self.assertRaises(ValueError):
                summarize([row, *initial()[1:]])
