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
