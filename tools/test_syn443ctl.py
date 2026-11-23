import contextlib
import base64
import io
import json
import subprocess
import unittest
from unittest.mock import patch

import syn443ctl


class AdbControlTest(unittest.TestCase):
    def test_login_reads_are_scoped_to_the_advertised_provider_and_closed_fields(self):
        base = {"schemaVersion": 1, "operations": list(syn443ctl.LOCAL_READ_BASE)}
        current = dict(base, optionalOperations=["auth-status"])
        public = {"schemaVersion": 1, "phase": "NEEDS_REAUTH", "reason": "ACCESS_DENIED",
                  "busy": False, "canReauthenticate": True}
        private = dict(public, pairCode="sensitive fixture", owner="sensitive fixture")
        for local, replies, expected in [
            (False, [private], 0), (True, [current, public], 0),
            (True, [base], 4), (True, [current, private], 5),
            (True, [current, dict(public, schemaVersion=True)], 5),
        ]:
            calls = []
            def reply(cmd, **kwargs):
                calls.append(cmd[cmd.index("--method") + 1])
                self.assertIn(syn443ctl.LOCAL_READ_URI if local else syn443ctl.URI, cmd)
                raw = ("Result: Bundle[{ok=true, json=" + json.dumps(replies[len(calls)-1]) + "}]").encode()
                return subprocess.CompletedProcess(cmd, 0, raw, b"")
            args = ["--serial", "synthetic"] + (["--local-read"] if local else []) + ["auth-status"]
            with patch("syn443ctl.subprocess.run", side_effect=reply), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(expected, syn443ctl.main(args))
            self.assertNotIn("sensitive fixture", out.getvalue())
            self.assertEqual(calls, (["capabilities"] if local else []) + (["auth-status"] if expected != 4 else []))
            if expected == 0:
                self.assertEqual(public, json.loads(out.getvalue())["result"])

    def test_login_status_cannot_promote_unknown_fields_or_an_earlier_busy_error(self):
        closed = syn443ctl.login_read_status
        for bad in ["sensitive fixture", [], {}, 1, None]:
            self.assertEqual({"schemaVersion": 1, "phase": "unknown", "reason": "unknown"},
                             closed({"phase":bad,"reason":"ACCESS_DENIED","busy":False}, False))
            self.assertEqual("unknown", closed({"phase":"BROWSER","reason":bad}, False)["reason"])
        self.assertEqual({"schemaVersion":1, "phase":"BROWSER","reason":"","busy":True},
                         closed({"phase":"BROWSER","reason":"ACCESS_DENIED","busy":True,"canReauthenticate":1}, False))

    def test_consented_overlay_negotiates_on_the_read_endpoint_before_asking_for_health(self):
        legacy = {"schemaVersion": 1, "operations": ["capabilities","status","logs"]}
        latest = dict(legacy, optionalOperations=["overlay-status"])
        health = {"schemaVersion":1,"provider":"netbird","implementation":"available","configured":True,
                  "control":"connected","controlTransport":"vless"}
        for caps, expected in [(legacy,4),(latest,0),(dict(legacy, optionalOperations=["bad value"]),5)]:
            payloads = [caps,health]
            def reply(command, **kwargs):
                self.assertEqual(command[command.index("--uri")+1], syn443ctl.LOCAL_READ_URI)
                self.assertEqual(command[command.index("--method")+1], "capabilities" if len(payloads)==2 else "overlay-status")
                raw = ("Result: Bundle[{ok=true, json="+json.dumps(payloads.pop(0))+"}]").encode()
                return subprocess.CompletedProcess(command,0,raw,b"")
            with patch("syn443ctl.subprocess.run", side_effect=reply), contextlib.redirect_stdout(io.StringIO()) as out:
                code = syn443ctl.main(["--serial","synthetic","--local-read","overlay-status","--provider","netbird"])
            self.assertEqual(code,expected)
            if code == 0:
                self.assertEqual(json.loads(out.getvalue())["result"]["controlTransport"],"vless")
            self.assertEqual(len(payloads),int(expected!=0))

    def test_consented_route_health_has_a_closed_schema_and_uses_only_the_read_endpoint(self):
        caps = {"schemaVersion": 1, "operations": list(syn443ctl.LOCAL_READ_BASE)}
        current = dict(caps, optionalOperations=["future-operation", "routes-status"])
        row = {"position": 1, "state": "working", "required": True, "ageMs": 0, "search": "VERIFIED"}
        good = {"schemaVersion": 1, "routes": [row, {"position": 2, "state": "off", "required": False}]}
        variants = [dict(row, position=True), dict(row, required=1), dict(row, ageMs=True), dict(row, ageMs=120001),
                    dict(row, ageMs=-1), dict(row, state=[]), dict(row, search="unexpected"), dict(row, position=2),
                    dict(row, label="private-test"), dict(row, state="failed"), {k: v for k, v in row.items() if k != "ageMs"}]
        cases = [(current, good, 0), (current, dict(good, routes=[]), 0), (caps, good, 4),
                 (current, dict(good, routes=[row] * 65), 5), (current, dict(good, extra="private-test"), 5)]
        cases.extend((current, dict(good, routes=[variant]), 5) for variant in variants)
        for capability, snapshot, expected in cases:
            with self.subTest(snapshot=snapshot, expected=expected):
                payloads = [capability, snapshot]

                def reply(command, **kwargs):
                    self.assertEqual(command[command.index("--uri") + 1], syn443ctl.LOCAL_READ_URI)
                    self.assertEqual(command[command.index("--method") + 1],
                                     "capabilities" if len(payloads) == 2 else "routes-status")
                    raw = ("Result: Bundle[{ok=true, json=" + json.dumps(payloads.pop(0)) + "}]").encode()
                    return subprocess.CompletedProcess(command, 0, raw, b"")

                with patch("syn443ctl.subprocess.run", side_effect=reply), contextlib.redirect_stdout(io.StringIO()) as out:
                    code = syn443ctl.main(["--serial", "synthetic", "--local-read", "routes-status"])
                self.assertEqual(code, expected)
                self.assertEqual(len(payloads), int(expected == 4))
                self.assertNotIn("private-test", out.getvalue())
                if code == 0:
                    self.assertEqual(json.loads(out.getvalue())["result"], snapshot)

    def test_local_grant_uses_only_the_separate_read_endpoint(self):
        def invoke(operation, payload):
            wire = ("Result: Bundle[{ok=true, json=" + json.dumps(payload) + "}]").encode()
            with patch("syn443ctl.subprocess.run", return_value=subprocess.CompletedProcess([], 0, wire, b"")) as run, contextlib.redirect_stdout(io.StringIO()) as out:
                code = syn443ctl.main(["--serial", "synthetic", "--local-read", operation])
            self.assertEqual(run.call_args.args[0], ["adb", "-s", "synthetic", "shell", "content", "call", "--uri", syn443ctl.LOCAL_READ_URI, "--method", operation])
            return code, json.loads(out.getvalue())
        code, status = invoke("status", {"schemaVersion":1,"phase":"Online","reason":"required_https_ok","engineActive":True,
                                         "generation":4,"networkEpoch":-1,"address":"sensitive fixture"})
        self.assertEqual(code, 0)
        self.assertEqual(status["result"], {"phase":"Online","reason":"required_https_ok","engineActive":True,"generation":4})
        self.assertEqual(invoke("capabilities", {"schemaVersion":1,"operations":["capabilities","status","logs"]})[1]["result"]["access"], "local_read_grant")
        self.assertEqual(invoke("capabilities", {"schemaVersion":1,"operations":["status","connect"]})[0], 5)
        self.assertEqual(invoke("logs", {"events":[{"phase":"Recovering","code":"private fixture","target":"private fixture"}]})[1]["result"]["events"], [{"phase":"Recovering","code":"redacted"}])
        with patch("syn443ctl.subprocess.run") as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(syn443ctl.main(["--serial", "synthetic", "--local-read", "vpn-start"]), 4)
            run.assert_not_called()
        with patch("syn443ctl.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"Result: Bundle[{ok=false, error=local_consent_required}]", b"")), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(syn443ctl.main(["--serial", "synthetic", "--local-read", "status"]), 4)
            self.assertEqual(json.loads(out.getvalue())["error"], "local_consent_required")

    def test_network_mode_negotiates_then_issues_one_safe_serial_scoped_command(self):
        stamp = "00000000-0000-4000-8000-000000000001"
        receipt = {"admitted": True, "generation": 5, "networkEpoch": 2}
        argv = ["--serial", "synthetic", "mode-set", "--stamp", stamp, "--mode", "WIFI", "--minutes", "15"]
        with patch.object(syn443ctl.Device, "supports_type", return_value=True), patch.object(syn443ctl.Device, "call", return_value=receipt) as call:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(0, syn443ctl.main(argv))
        call.assert_called_once_with("mode-set", stamp + ":WIFI:15")
        self.assertEqual(receipt, json.loads(output.getvalue())["result"])
        with patch.object(syn443ctl.Device, "supports_type", return_value=False), patch.object(syn443ctl.Device, "call") as old:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(4, syn443ctl.main(argv))
            old.assert_not_called()
        for unsafe in (stamp + ":WIFI:0", stamp + ":AUTO:3", stamp + ":WIFI:5|other", stamp + ":WIFI:1441"):
            with patch("syn443ctl.subprocess.run") as transport, self.assertRaises(syn443ctl.ControlError):
                syn443ctl.Device("synthetic", 5).call("mode-set", unsafe)
            transport.assert_not_called()

    def test_network_mode_never_exposes_private_fields_or_invents_a_mode(self):
        stamp = "00000000-0000-4000-8000-000000000001"
        off = {"state": "unavailable", "networkEpoch": 3}
        self.assertEqual(off, syn443ctl.mode_reply("mode-get", off))
        live = dict(state="observed", effective="WIFI", source="manual", allowed=["WIFI"], maxMinutes=15,
                    generation=3, networkEpoch=2, stamp=stamp, remainingMs=40)
        self.assertEqual(live, syn443ctl.mode_reply("mode-get", live))
        for changes in ({"ssid": "synthetic"}, {"allowed": ["WIFI", "WIFI"]}, {"remainingMs": True},
                        {"stamp": "synthetic"}, {"effective": "invented"}, {"allowed": [{}]}):
            with self.assertRaises(syn443ctl.ControlError):
                syn443ctl.mode_reply("mode-get", dict(live, **changes))

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

    def test_wifi_bundle_keeps_only_public_link_facts_and_portal_reason(self):
        link = {"transport": "WIFI", "homeProof": "verified", "ipv4Address": True,
                "ipv4Default": False, "ipv6Default": "invalid", "ssid": "private-fixture",
                "address": "private-fixture", "spkiSha256": "private-fixture"}
        state = {"desiredOn": True, "phase": "NoNetwork", "reason": "captive_portal", "physicalLink": link,
                 "events": [{"phase": "NoNetwork", "code": "captive_portal"}]}
        device = syn443ctl.Device("synthetic-device", 3)
        def snapshot():
            with patch.object(device, "call", side_effect=[state, {}]):
                return syn443ctl.bundle(device)
        result = snapshot()
        self.assertEqual(result["state"]["physicalLink"], {
            "transport": "WIFI", "homeProof": "verified", "ipv4Address": True, "ipv4Default": False})
        self.assertEqual(result["state"]["reason"], "captive_portal")
        self.assertEqual(result["events"][0]["code"], "captive_portal")
        self.assertNotIn("private-fixture", json.dumps(result))
        link["transport"] = "OTHER"
        self.assertNotIn("homeProof", snapshot()["state"]["physicalLink"])
        state["desiredOn"] = False
        self.assertNotIn("physicalLink", snapshot()["state"])

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
