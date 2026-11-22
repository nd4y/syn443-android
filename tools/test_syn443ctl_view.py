import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import patch

import syn443ctl


class NetBirdViewControlTest(unittest.TestCase):
    def test_closed_view_survives_android_shell_quoting_and_is_only_queued(self):
        request = syn443ctl.view_argument("diagnostics", 63, "test-view")
        reply = {"pending": True, "section": "diagnostics", "page": 63, "request": "test-view"}
        output = ("Result: Bundle[{ok=true, json=" + json.dumps(reply) + "}]\n").encode()
        with patch("syn443ctl.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, b"")) as run:
            actual = syn443ctl.Device("synthetic-device", 3).call("netbird-view", request)
        self.assertEqual(actual, reply)
        self.assertEqual(run.call_args.args[0][-2:], ["--arg", "'" + request + "'"])
        self.assertNotIn("checked", actual)

    def test_malformed_view_and_nonview_options_never_invoke_adb(self):
        valid = syn443ctl.view_argument("peers", 0, "test-view")
        invalid = [None, "{}", valid + "{}", valid.replace('"page":0', '"page":64'),
                   valid.replace('"page":0', '"page":true'), valid.replace('"page":0', '"page":"0"'),
                   valid.replace('"request":"test-view"', '"page":0'),
                   valid.replace("test-view", "'$(command)"), valid.replace("test-view", "é"), " " * 1025]
        for raw in invalid:
            with patch("syn443ctl.subprocess.run") as run:
                with self.assertRaises(syn443ctl.ControlError):
                    syn443ctl.Device("synthetic-device", 3).call("netbird-view", raw)
                run.assert_not_called()
        for options in (["netbird-view"], ["netbird-view", "--section", "peers"],
                        ["netbird-status", "--page", "0"], ["vpn-start", "--section", "peers", "--page", "0"]):
            with patch("syn443ctl.subprocess.run") as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(syn443ctl.main(["--serial", "synthetic-device", *options]), 2)
                run.assert_not_called()

    def test_cli_view_dispatches_once_and_does_not_probe_or_poll(self):
        receipt = {"pending": True, "section": "peers", "page": 1, "request": "test-view"}
        with patch("syn443ctl.secrets.token_hex", return_value="test-view"), \
                patch.object(syn443ctl.Device, "call", return_value=receipt) as call, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(syn443ctl.main(["--serial", "synthetic-device", "netbird-view", "--section", "peers", "--page", "1"]), 0)
        call.assert_called_once_with("netbird-view", syn443ctl.view_argument("peers", 1, "test-view"))
        self.assertEqual(json.loads(output.getvalue())["result"], receipt)

    def test_cancel_requires_the_displayed_job_and_only_queues_the_command(self):
        job = "cd" * 16
        reply = b'Result: Bundle[{ok=true, json={"pending":true}}]\n'
        with patch("syn443ctl.subprocess.run", return_value=subprocess.CompletedProcess([], 0, reply, b"")) as run, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(syn443ctl.main(["--serial", "usb-fixture", "netbird-cancel", "--job-id", job]), 0)
        self.assertEqual(run.call_args.args[0][-4:], ["--method", "netbird-cancel", "--arg", job])
        self.assertEqual(json.loads(output.getvalue())["result"], {"pending": True})
        for args in (["netbird-cancel"], ["netbird-cancel", "--job-id", "not-a-job"], ["vpn-start", "--job-id", job]):
            with patch("syn443ctl.subprocess.run") as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(syn443ctl.main(["--serial", "usb-fixture", *args]), 2)
                run.assert_not_called()

    def test_older_and_locked_clients_do_not_advertise_addressed_cancellation(self):
        for state, supported in (({}, False), ({"phase": "NeedsUnlock"}, False), ({"netbirdDiagnosticCancellation": True}, True)):
            with patch.object(syn443ctl.Device, "call", return_value=state), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(syn443ctl.main(["--serial", "usb-fixture", "capabilities"]), 0)
            self.assertEqual("netbird-cancel" in json.loads(out.getvalue())["result"]["operations"], supported)

    def test_overlay_query_requires_a_supported_apk_and_closed_provider_status(self):
        cmd = ["--serial", "usb-fixture", "overlay-status", "--provider", "tailscale"]
        def result(raw):
            return subprocess.CompletedProcess([], 0, raw, b"")
        legacy = result(b"Result: null")
        with patch("syn443ctl.subprocess.run", return_value=legacy) as run, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(syn443ctl.main(cmd), 4)
        self.assertEqual(run.call_count, 1)
        self.assertIn("gettype", run.call_args.args[0])
        self.assertEqual(json.loads(out.getvalue())["error"], "unsupported_by_device")
        detected = result(b"Result: application/vnd.syn443.overlay-status-v1")
        expected = {"schemaVersion": 1, "provider": "tailscale", "implementation": "not_implemented"}
        for value, code in [(expected, 0), (dict(expected, control="connected"), 5),
                            (dict(expected, provider="zerotier"), 5), (dict(expected, schemaVersion=True), 5),
                            (dict(expected, private="private-fixture"), 5)]:
            reply = result(("Result: Bundle[{ok=true, json=" + json.dumps(value) + "}]").encode())
            with patch("syn443ctl.subprocess.run", side_effect=[detected, reply]) as run, contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(syn443ctl.main(cmd), code)
            self.assertEqual(run.call_args.args[0][-4:], ["--method", "overlay-status", "--arg", "tailscale"])
            self.assertNotIn("private-fixture", out.getvalue())
            if code == 0:
                self.assertEqual(json.loads(out.getvalue())["result"], expected)

    def test_overlay_compatibility_rejects_inconsistent_current_transport(self):
        report = dict(schemaVersion=1, provider="netbird", implementation="available",
                      configured=True, control="connected", controlTransport="vless")
        self.assertEqual(syn443ctl.overlay_health("netbird", report), report)
        for bad in (dict(report, configured=False), dict(report, control="unknown"),
                    dict(report, controlTransport="relay"), dict(report, peer="private-fixture")):
            with self.assertRaises(syn443ctl.ControlError):
                syn443ctl.overlay_health("netbird", bad)
        for args in (["overlay-status"], ["vpn-start", "--provider", "netbird"], ["overlay-status", "--provider", "other"]):
            with patch("syn443ctl.subprocess.run") as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(syn443ctl.main(["--serial", "usb-fixture", *args]), 2)
            run.assert_not_called()
