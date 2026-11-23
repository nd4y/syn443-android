import hashlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch

from run_enrolled_vpn import exchange_through_proxy
from protected_upgrade_inputs import REPOSITORY, read_members, select_runs


class ProtectedUpgradeTest(unittest.TestCase):
    def run_record(self, number, sha, **overrides):
        record = dict(id=number, event="push", head_branch="main", conclusion="success", head_sha=sha,
                      path=".github/workflows/ci.yml", head_repository={"full_name": REPOSITORY})
        return {**record, **overrides}

    def test_closest_older_version_among_protected_ancestors(self):
        history = ["new", "same", "prior", "earlier"]
        runs = [self.run_record(i, sha) for i, sha in enumerate(history, 1)]
        runs += [self.run_record(9, "other"), self.run_record(10, "same", event="pull_request")]
        with patch("protected_upgrade_inputs.version", side_effect={"new": 7, "same": 7, "prior": 5, "earlier": 4}.__getitem__):
            old, new = select_runs(runs[::-1], history, None, None)
            self.assertEqual((old["id"], new["id"]), (3, 1))
            self.assertEqual(select_runs(runs, history, 2, 4)[0]["id"], 4)
            for previous in (1, 2, 9, 10):
                with self.subTest(previous=previous), self.assertRaises(ValueError):
                    select_runs(runs, history, 1, previous)

    def test_untrusted_job_fork_and_pr_are_excluded(self):
        good = self.run_record(1, "new")
        for invalid in ({"event": "pull_request"}, {"head_branch": "other"}, {"conclusion": "failure"},
                        {"path": ".github/workflows/unrelated.yml"}, {"head_repository": {"full_name": "elsewhere/fork"}}):
            excluded = self.run_record(2, "prior", **invalid)
            with self.subTest(invalid=invalid), patch("protected_upgrade_inputs.version", return_value=9):
                with self.assertRaises(ValueError):
                    select_runs([good, excluded], ["new", "prior"], 2, None)

    def test_corrupt_or_expired_archives_cannot_supply_a_package(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("debug/app-debug.apk", b"synthetic fixture")
        raw = data.getvalue()
        receipt = {"id": 17, "expired": False, "size_in_bytes": len(raw),
                   "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}

        def download(command, *, stdout, **kwargs):
            stdout.write(raw)

        with tempfile.TemporaryDirectory() as tmp, patch("protected_upgrade_inputs.subprocess.run", side_effect=download) as invoked:
            work = Path(tmp)
            dest = work / "verified.apk"
            members = [("debug/app-debug.apk", dest, 64)]
            with self.assertRaises(ValueError):
                read_members(work, {**receipt, "expired": True}, members, 4096)
            invoked.assert_not_called()
            with self.assertRaises(ValueError):
                read_members(work, {**receipt, "digest": "sha256:" + "0" * 64}, members, 4096)
            with self.assertRaises(ValueError):
                read_members(work, receipt, [("absent", dest, 64)], 4096)
            with self.assertRaises(ValueError):
                read_members(work, receipt, [("debug/app-debug.apk", dest, 3)], 4096)
            self.assertFalse(dest.exists())
            read_members(work, receipt, members, 4096)
            self.assertEqual(dest.read_bytes(), b"synthetic fixture")

    def test_payload_requires_both_its_own_fixture_event_and_http_response(self):
        for expected, seen, response, passes in (
            (204, True, b"HTTP/1.1 204 No Content", True),
            (204, False, b"HTTP/1.1 204 No Content", False),
            (204, True, b"HTTP/1.1 503 Unavailable", False),
            (204, True, b"", False),
            (503, True, b"HTTP/1.1 503 Unavailable", True),
            (503, False, b"HTTP/1.1 503 Unavailable", False),
            (503, True, b"HTTP/1.1 204 No Content", False),
            (503, True, b"", False),
        ):
            proxy = SimpleNamespace()
            def exchange(*args, **kwargs):
                self.assertIn("run-as io.syn443.android toybox nc", args[-1])
                self.assertIn(r"GET /syn443-payload HTTP/1.1\r\nHost:", args[-1])
                if seen:
                    proxy.payload_received.set()
                return response
            with self.subTest(seen=seen, response=response), patch("run_enrolled_vpn.adb", side_effect=exchange):
                if passes:
                    exchange_through_proxy(proxy, expected_status=expected)
                else:
                    with self.assertRaises(AssertionError):
                        exchange_through_proxy(proxy, expected_status=expected)
                self.assertIsNone(proxy.payload_received)
