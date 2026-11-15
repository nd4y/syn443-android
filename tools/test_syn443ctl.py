import contextlib
import base64
import io
import json
import subprocess
import unittest
from unittest.mock import patch

import syn443ctl


class AdbControlTest(unittest.TestCase):
    def test_adb_uses_explicit_device_and_never_interprets_provider_json(self):
        data = {"phase": "Off", "label": "ok=false, error=command_rejected"}
        for content in ("ok=true, json=" + json.dumps(data), "json=" + json.dumps(data) + ", ok=true"):
            encoded = ("Result: Bundle[{" + content + "}]\n").encode()
            with patch("syn443ctl.subprocess.run", return_value=subprocess.CompletedProcess([], 0, encoded, b"")) as run:
                actual = syn443ctl.Device("synthetic-device", 7).call("routes-check", "route-2")
            self.assertEqual(actual, data)
            self.assertEqual(run.call_args.args[0][0:3], ["adb", "-s", "synthetic-device"])
            self.assertEqual(run.call_args.args[0][-2:], ["--arg", "route-2"])
            self.assertEqual(run.call_args.kwargs["timeout"], 7)

    def test_rejection_and_transport_timeout_remain_distinct(self):
        with patch("syn443ctl.subprocess.run", return_value=subprocess.CompletedProcess([], 0,
                   b"Result: Bundle[{error=needs_unlock, ok=false}]\n", b"")):
            with self.assertRaises(syn443ctl.ControlError) as rejected:
                syn443ctl.Device("synthetic-device", 3).call("vpn-start")
        self.assertEqual((rejected.exception.code, rejected.exception.exit_status), ("needs_unlock", 4))
        with patch("syn443ctl.subprocess.run", side_effect=subprocess.TimeoutExpired([], 3)):
            with self.assertRaises(syn443ctl.ControlError) as timeout:
                syn443ctl.Device("synthetic-device", 3).call("status")
        self.assertEqual((timeout.exception.code, timeout.exception.exit_status), ("adb_timeout", 3))

    def test_bundle_omits_peers_labels_and_free_form_fields(self):
        state = {"generation": 5, "phase": "Recovering", "desiredOn": True,
                 "routeHealth": {"routes": [{"label": "synthetic route", "state": "working"}]}, "netbird": {"peers": ["synthetic peer"]},
                 "policyChecks": {"current": True, "ageMs": 3, "target": "example.invalid"},
                 "events": [{"phase": "Recovering", "code": "network_changed", "sequence": 1, "note": "example.invalid"},
                            {"phase": "Online", "code": "private_unknown_value"}]}
        resources = {"sampleAgeMs": 3, "processes": [{"role": "engine", "rssBytes": 4096, "command": "example.invalid"}]}
        with patch.object(syn443ctl.Device, "call", side_effect=[state,resources]):
            bundle = syn443ctl.bundle(syn443ctl.Device("synthetic-device", 3))
        serialized = json.dumps(bundle)
        for excluded in ("example.invalid", "synthetic route", "synthetic peer", "private_unknown_value"):
            self.assertNotIn(excluded, serialized)
        self.assertEqual(bundle["events"][1]["code"], "redacted")
        self.assertTrue(bundle["state"]["policyChecks"]["current"])
        self.assertEqual(bundle["routeCounts"], {"working": 1})
        self.assertEqual(bundle["resources"]["processes"], [{"role": "engine", "rssBytes": 4096}])

    def test_bad_arguments_never_call_adb_and_output_a_json_error(self):
        with patch("syn443ctl.subprocess.run") as run, contextlib.redirect_stdout(io.StringIO()) as output:
            code = syn443ctl.main(["--serial", "synthetic-device", "vpn-start", "--route", "route-2"])
        run.assert_not_called()
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["error"], "invalid_arguments")

    def test_config_is_staged_on_stdin_with_hashes_and_unique_cleanup(self):
        device = syn443ctl.Device("synthetic-device", 3)
        payload = b'{"outbounds":[{"type":"direct","tag":"fixture"}]}'
        base, candidate, nonce = "none", "b"*64, "a"*32
        planned = {"baseRevision": base, "candidateRevision": candidate, "written": False}
        with patch("syn443ctl.secrets.token_hex", return_value=nonce), \
             patch.object(device, "_stage", return_value=True) as stage, patch.object(device, "call", return_value=planned) as call:
            self.assertEqual(device.config("config-plan", payload, base, candidate), planned)
        self.assertEqual(stage.call_args_list[0].args, (syn443ctl.STAGE.format(nonce), base64.b64encode(payload)+b"\n"))
        call.assert_called_once_with("config-plan", base+":"+candidate+":"+nonce)
        self.assertEqual(stage.call_args_list[1].args, (syn443ctl.CLEANUP.format(nonce),))


if __name__ == "__main__":
    unittest.main()
