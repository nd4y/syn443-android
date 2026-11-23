import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
import warnings
from unittest.mock import patch
import zipfile

import syn443ctl as ctl


class ConfigRenderContractTest(unittest.TestCase):
    def test_rejects_raw_unknown_or_wrongly_typed_projection(self):
        available = {"schemaVersion": 1, "availability": "active", "generation": 7,
                     "configuration": {"schemaVersion": 1, "outboundTypes": {"http": 1},
                                       "adaptiveRouting": False, "dnsServerCount": 0}}
        unavailable = {"schemaVersion": 1, "availability": "unavailable"}
        self.assertEqual(available, ctl.local_config_render(available))
        self.assertEqual(unavailable, ctl.local_config_render(unavailable))
        for update in ({"server": "protected.example.invalid"}, {"outboundTypes": {"private": 1}},
                       {"outboundTypes": {"http": True}}, {"routeRuleCount": -1}):
            with self.subTest(update=update), self.assertRaises(ctl.ControlError):
                ctl.local_config_render({**available, "configuration": {**available["configuration"], **update}})
        for reply in ({**unavailable, "generation": 7}, {**available, "generation": True}):
            with self.assertRaises(ctl.ControlError):
                ctl.local_config_render(reply)


BUNDLE_ID = "a" * 32
GRANT = "b" * 32


def zip_bytes(entries, compression=zipfile.ZIP_STORED, comment=b""):
    out = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(out, "w", compression=compression) as archive:
            for name, data in entries:
                info = name if isinstance(name, zipfile.ZipInfo) else zipfile.ZipInfo(name, (1980, 1, 2, 0, 0, 0))
                info.compress_type = compression
                archive.writestr(info, data)
            archive.comment = comment
    return out.getvalue()


def fixture(padding=0, states=None):
    bodies = {name: (b"" if name.endswith("jsonl") else b"{}") for name in ctl.SUPPORT_FILES}
    if padding:
        bodies["health.json"] = b'{"padding":"' + b"x" * padding + b'"}'
    rows, entries = [], []
    for name in ctl.SUPPORT_FILES:
        state, reason = (states or {}).get(name, ("available", "none"))
        body = bodies[name]
        present = state in {"available", "truncated"}
        rows.append({"name": name, "state": state, "reason": reason,
                     "bytes": len(body) if present else 0,
                     "sha256": hashlib.sha256(body).hexdigest() if present else None})
        if present:
            entries.append((name, body))
    manifest = {"schemaVersion": 1, "product": "SYN443", "complete": all(row["state"] == "available" and row["reason"] == "none" for row in rows), "components": rows}
    entries.append(("manifest.json", json.dumps(manifest, separators=(",", ":")).encode()))
    return zip_bytes(entries), manifest, entries


class Clock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


class FakeDevice:
    def __init__(self, payload=None, manifest=None, clock=None):
        self.payload, self.manifest = payload, manifest
        self.timeout = 12
        self.clock = clock or Clock()
        self.calls = []
        self.mutate = {}
        self.collecting = 0

    def bundle_connection(self):
        return contextlib.nullcontext(True)

    def call(self, operation, argument=None):
        self.calls.append((operation, argument))
        if operation == "support-bundle-collect":
            value = {"state": "collecting", "id": BUNDLE_ID}
        elif operation == "support-bundle-status":
            if self.collecting:
                self.collecting -= 1
                value = {"state": "collecting", "id": BUNDLE_ID}
            else:
                value = {"state": "ready", "id": BUNDLE_ID, "bytes": len(self.payload),
                         "sha256": hashlib.sha256(self.payload).hexdigest(), "manifest": copy.deepcopy(self.manifest)}
        elif operation == "support-bundle-open":
            value = {"state": "open", "grant": GRANT, "bytes": len(self.payload), "sha256": hashlib.sha256(self.payload).hexdigest(),
                     "expiresInMs": 60_000, "manifest": copy.deepcopy(self.manifest)}
        elif operation == "support-bundle-read":
            grant, offset = argument.split(":")
            at = int(offset)
            body = self.payload[at:at + ctl.SUPPORT_CHUNK]
            value = {"grant": grant, "offset": at, "data": base64.b64encode(body).decode(),
                     "nextOffset": at + len(body), "done": at + len(body) == len(self.payload)}
        elif operation == "support-bundle-cancel":
            value = {"state": "cancelled", "id": BUNDLE_ID}
        else:
            raise AssertionError("unexpected fake operation")
        return self.mutate.get(operation, lambda result: result)(value)


class SupportBundleCliTest(unittest.TestCase):
    def test_passive_connection_negotiation_never_collects_or_replays_after_denial(self):
        device = ctl.Device("synthetic-device", 3)
        for mime, error in ((b"null", None), (b"unexpected", "invalid_reply")):
            reply = subprocess.CompletedProcess([], 0, stdout=b"Result: " + mime + b"\n")
            with patch.object(subprocess, "run", return_value=reply), patch.object(subprocess, "Popen") as holder:
                if error:
                    with self.assertRaises(ctl.ControlError) as raised, device.bundle_connection():
                        self.fail("malformed negotiation admitted a client")
                    self.assertEqual(raised.exception.code, error)
                else:
                    with device.bundle_connection() as active:
                        self.assertFalse(active)
                holder.assert_not_called()
        current = subprocess.CompletedProcess([], 0, stdout=b"Result: application/vnd.syn443.bundle-session-v1\n")
        for first, expected in (("busy", "support_bundle_busy"), ("held", "fixture_failure")):
            with patch.object(subprocess, "run", return_value=current), patch.object(subprocess, "Popen") as start, \
                    patch.object(device, "call", side_effect=[{"state": first}, {"state": "released"}]) as rpc:
                start.return_value.poll.return_value = None
                with self.assertRaises(ctl.ControlError) as raised, device.bundle_connection():
                    raise ctl.ControlError("fixture_failure", 5)
                self.assertEqual(raised.exception.code, expected)
                self.assertEqual([call.args[0] for call in rpc.call_args_list],
                                 ["support-bundle-shell-state", "support-bundle-shell-release"])
                self.assertEqual(rpc.call_args_list[0].args[1], rpc.call_args_list[1].args[1])

    def export(self, device, output, operation="support-bundle"):
        return ctl.support_operation(device, operation, output, BUNDLE_ID if operation.endswith("export") else None,
                                     clock=device.clock, sleeper=device.clock.sleep)

    def test_convenience_validates_all_bytes_before_exclusive_multichunk_export(self):
        payload, manifest, _ = fixture(40_000)
        device = FakeDevice(payload, manifest)
        device.collecting = 2
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "support.zip"
            result = self.export(device, output)
            self.assertEqual(output.read_bytes(), payload)
        self.assertEqual(result, {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "complete": True, "exported": True})
        self.assertEqual(device.calls[0], ("support-bundle-collect", None))
        self.assertEqual(sum(op == "support-bundle-open" for op, _ in device.calls), 1)
        self.assertEqual([argument for op, argument in device.calls if op == "support-bundle-read"], [GRANT + ":0", GRANT + ":32768"])
        self.assertEqual(device.clock.sleeps, [0.5, 0.5])
        self.assertEqual(device.timeout, 12)

    def test_explicit_collect_status_cancel_export_and_argument_rules_never_auto_collect(self):
        payload, manifest, _ = fixture()
        for operation in ("support-bundle-collect", "support-bundle-status", "support-bundle-cancel"):
            device = FakeDevice(payload, manifest)
            with patch.object(ctl, "Device", return_value=device), contextlib.redirect_stdout(io.StringIO()) as out:
                arguments = ["--serial", "synthetic-device", operation]
                if not operation.endswith("collect"):
                    arguments += ["--bundle-id", BUNDLE_ID]
                self.assertEqual(ctl.main(arguments), 0)
            result = json.loads(out.getvalue())["result"]
            self.assertEqual(result["id"], BUNDLE_ID)
            self.assertNotIn("manifest", result)
            self.assertNotIn("grant", out.getvalue())
            self.assertEqual(len(device.calls), 1)
        device = FakeDevice(payload, manifest)
        device.collecting = 1
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ctl.ControlError):
            self.export(device, Path(directory) / "not-ready.zip", "support-bundle-export")
        self.assertEqual(device.calls, [("support-bundle-status", BUNDLE_ID)])
        device = FakeDevice(payload, manifest)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "support.zip"
            with patch.object(ctl, "Device", return_value=device), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(ctl.main(["--serial", "synthetic-device", "support-bundle-export",
                                           "--bundle-id", BUNDLE_ID, "--output", str(output)]), 0)
            self.assertEqual(output.read_bytes(), payload)
            emitted = json.loads(out.getvalue())
            self.assertEqual(set(emitted["result"]), {"bytes", "sha256", "complete", "exported"})
            for excluded in (str(output), GRANT, "manifest", "components"):
                self.assertNotIn(excluded, out.getvalue())
        self.assertNotIn("support-bundle-collect", [op for op, _ in device.calls])
        invalid = [
            ["support-bundle"], ["support-bundle-export", "--output", "synthetic.zip"],
            ["support-bundle-status"], ["support-bundle-cancel", "--bundle-id", "not-an-id"],
            ["status", "--output", "synthetic.zip"], ["status", "--bundle-id", BUNDLE_ID],
            ["support-bundle-collect", "--output", "synthetic.zip"],
            ["support-bundle", "--output", "synthetic.zip", "--bundle-id", BUNDLE_ID],
        ]
        for arguments in invalid:
            with self.subTest(arguments=arguments), patch.object(ctl, "Device") as create, contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(ctl.main(["--serial", "synthetic-device", *arguments]), 2)
            create.assert_not_called()
            self.assertEqual(json.loads(out.getvalue())["error"], "invalid_arguments")

    def test_lost_collect_open_or_read_ack_is_never_replayed_or_written(self):
        payload, manifest, _ = fixture()
        for failed in ("support-bundle-collect", "support-bundle-open", "support-bundle-read"):
            device = FakeDevice(payload, manifest)
            def lost_ack(_):
                raise ctl.ControlError("adb_timeout", 3)
            device.mutate[failed] = lost_ack
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "support.zip"
                with self.assertRaises(ctl.ControlError) as error:
                    self.export(device, output)
                self.assertEqual(error.exception.code, "adb_timeout")
                self.assertFalse(output.exists())
            self.assertEqual(sum(op == failed for op, _ in device.calls), 1)
            self.assertEqual(device.calls[-1][0], failed)
            self.assertNotIn("support-bundle-cancel", [op for op, _ in device.calls])

    def test_export_distinguishes_provider_denial_from_malformed_chunks_without_retry(self):
        payload, manifest, _ = fixture()
        for stage in ("support-bundle-open", "support-bundle-read"):
            for state in ("not_found", "cancelled", "expired", "failed", "busy", "future", []):
                reply = {"state": state}
                if stage == "support-bundle-open":
                    reply["id"] = BUNDLE_ID
                known = state in ("not_found", "cancelled", "expired", "failed") or (
                    stage == "support-bundle-read" and state == "busy")
                with self.subTest(stage=stage, state=state), tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "support.zip"
                    device = FakeDevice(payload, manifest)
                    device.mutate[stage] = lambda _: reply
                    with self.assertRaises(ctl.ControlError) as raised:
                        self.export(device, output)
                    expected = ("support_bundle_" + state, 4) if known else ("support_bundle_invalid", 5)
                    self.assertEqual((raised.exception.code, raised.exception.exit_status), expected)
                    self.assertEqual(sum(op == stage for op, _ in device.calls), 1)
                    self.assertEqual(device.calls[-1][0], stage)
                    self.assertFalse(output.exists())
        for stage, reply in (("support-bundle-open", {"state": "expired", "id": "a" * 31}),
                             ("support-bundle-read", {"state": "not_found", "data": "untrusted"})):
            device = FakeDevice(payload, manifest)
            device.mutate[stage] = lambda _: reply
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "support.zip"
                with self.assertRaises(ctl.ControlError) as raised:
                    self.export(device, output)
                self.assertEqual(raised.exception.code, "support_bundle_invalid")
                self.assertFalse(output.exists())

    def test_poll_and_overall_or_grant_deadlines_fail_closed_without_extra_calls(self):
        payload, manifest, _ = fixture()
        device = FakeDevice(payload, manifest)
        device.collecting = 100
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ctl.ControlError):
            self.export(device, Path(directory) / "support.zip")
        self.assertEqual(sum(op == "support-bundle-status" for op, _ in device.calls), 64)
        self.assertLessEqual(device.clock.value, 32)
        self.assertNotIn("support-bundle-open", [op for op, _ in device.calls])
        for stage, elapsed in (("support-bundle-status", 32), ("support-bundle-open", 121), ("support-bundle-read", 61)):
            device = FakeDevice(payload, manifest)
            def delayed(value):
                device.clock.value += elapsed
                return value
            device.mutate[stage] = delayed
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "support.zip"
                with self.assertRaises(ctl.ControlError) as error:
                    self.export(device, output)
                self.assertEqual(error.exception.code, "support_bundle_timeout")
                self.assertFalse(output.exists())
            self.assertEqual(device.calls[-1][0], stage)
            self.assertEqual(device.timeout, 12)

    def test_wrong_ids_types_limits_and_status_open_disagreement_create_no_file(self):
        payload, manifest, _ = fixture()
        changes = [
            ("support-bundle-collect", lambda value: {**value, "id": "c" * 31}),
            ("support-bundle-collect", lambda value: {**value, "state": []}),
            ("support-bundle-status", lambda value: {**value, "id": "c" * 32}),
            ("support-bundle-status", lambda value: {**value, "state": "future"}),
            ("support-bundle-status", lambda value: {**value, "bytes": True}),
            ("support-bundle-status", lambda value: {**value, "bytes": 1.0}),
            ("support-bundle-status", lambda value: {**value, "manifest": None}),
            ("support-bundle-open", lambda value: {**value, "grant": "B" * 32}),
            ("support-bundle-open", lambda value: {**value, "bytes": ctl.SUPPORT_MAX + 1}),
            ("support-bundle-open", lambda value: {**value, "expiresInMs": 60_001}),
            ("support-bundle-open", lambda value: {**value, "expiresInMs": "60000"}),
            ("support-bundle-open", lambda value: {**value, "sha256": "0" * 64}),
            ("support-bundle-open", lambda value: {**value, "unknown": True}),
        ]
        for stage, mutation in changes:
            device = FakeDevice(payload, manifest)
            device.mutate[stage] = mutation
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "support.zip"
                with self.assertRaises(ctl.ControlError):
                    self.export(device, output)
                self.assertFalse(output.exists())

    def test_chunks_require_canonical_base64_exact_grant_offsets_lengths_and_archive_hash(self):
        payload, manifest, _ = fixture(40_000)
        mutations = [
            lambda part: {**part, "grant": "c" * 32}, lambda part: {**part, "offset": True},
            lambda part: {**part, "offset": 1}, lambda part: {**part, "nextOffset": part["nextOffset"] - 1},
            lambda part: {**part, "done": True}, lambda part: {**part, "done": 0},
            lambda part: {**part, "data": part["data"] + "\n"}, lambda part: {**part, "data": "Zg==="},
            lambda part: {**part, "data": "Zh=="}, lambda part: {**part, "data": "é"},
            lambda part: {**part, "data": base64.b64encode(b"x" * 32_769).decode()},
            lambda part: {**part, "data": base64.b64encode(b"z" * 32_768).decode()},
        ]
        for mutation in mutations:
            device = FakeDevice(payload, manifest)
            device.mutate["support-bundle-read"] = mutation
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "support.zip"
                with self.assertRaises(ctl.ControlError):
                    self.export(device, output)
                self.assertFalse(output.exists())
            self.assertLessEqual(sum(op == "support-bundle-read" for op, _ in device.calls), 2)

    def test_zip_names_framing_compression_links_zip64_and_expansion_are_rejected(self):
        payload, manifest, entries = fixture()
        link = zipfile.ZipInfo("health.json", (1980, 1, 2, 0, 0, 0))
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o600) << 16
        zip64 = zipfile.ZipInfo("health.json", (1980, 1, 2, 0, 0, 0))
        zip64.extra = struct.pack("<HH", 1, 0)
        variants = [
            zip_bytes([*entries, ("../outside.json", b"{}")]),
            zip_bytes([*entries, ("extra.json", b"{}")]),
            zip_bytes([*entries, entries[0]]), zip_bytes(entries, zipfile.ZIP_DEFLATED),
            zip_bytes([(link if name == "health.json" else name, body) for name, body in entries]),
            zip_bytes([(zip64 if name == "health.json" else name, body) for name, body in entries]),
            zip_bytes(entries, comment=b"synthetic"), b"prefix" + payload, payload + b"suffix",
            zip_bytes([(name, b"x" * 65_537 if name == "health.json" else body) for name, body in entries]),
            zip_bytes([(name, b"x" * 60_000 if name in ctl.SUPPORT_FILES[:5] else body) for name, body in entries]),
        ]
        corrupted = bytearray(payload)
        corrupted[30] ^= 1  # Local name no longer matches its central record.
        variants.append(bytes(corrupted))
        bad_crc = bytearray(payload)
        first_name_size, first_extra_size = struct.unpack_from("<HH", bad_crc, 26)
        bad_crc[30 + first_name_size + first_extra_size] ^= 1
        variants.append(bytes(bad_crc))
        encrypted = bytearray(payload)
        struct.pack_into("<H", encrypted, 6, 1)
        central = encrypted.index(b"PK\x01\x02")
        struct.pack_into("<H", encrypted, central + 8, 1)
        variants.append(bytes(encrypted))
        for archive in variants:
            with self.subTest(size=len(archive)), self.assertRaises(ctl.ControlError):
                ctl.support_archive(archive, manifest)

    def test_manifest_closed_hash_size_absence_completeness_and_json_rules_are_exact(self):
        payload, manifest, entries = fixture()
        for change in (lambda value: value.update(schemaVersion=True), lambda value: value.update(product="other"),
                       lambda value: value.update(complete=False),
                       lambda value: value.update(unknown=True), lambda value: value["components"].pop(),
                       lambda value: value["components"][0].update(bytes=1),
                       lambda value: value["components"][0].update(sha256="0" * 64),
                       lambda value: value["components"][0].update(state="missing", bytes=0, sha256=None),
                       lambda value: value["components"][0].update(reason="projection_only")):
            altered = copy.deepcopy(manifest)
            change(altered)
            archive = zip_bytes([(name, json.dumps(altered).encode() if name == "manifest.json" else body) for name, body in entries])
            with self.assertRaises(ctl.ControlError):
                ctl.support_archive(archive, altered)
        for raw in (b'{"a":1,"a":2}', br'{"a":1,"\u0061":2}', b'{"x":NaN}', b'{"x":1e999}', b'\xff', b'{}{}'):
            with self.assertRaises(ctl.ControlError):
                ctl.support_json(raw, ctl.SUPPORT_MANIFEST_MAX)
        self.assertRaises(ctl.ControlError, ctl.support_json, b" " * 16_385, ctl.SUPPORT_MANIFEST_MAX)
        for states in ({"health.json": ("missing", "unavailable")}, {"checks.json": ("error", "over_limit")},
                       {"overlay.json": ("available", "projection_only")}, {"events.jsonl": ("truncated", "over_limit")}):
            archive, partial, _ = fixture(states=states)
            self.assertFalse(ctl.support_archive(archive, partial)["complete"])
        _, missing, missing_entries = fixture(states={"health.json": ("missing", "unavailable")})
        with self.assertRaises(ctl.ControlError):
            ctl.support_archive(zip_bytes([*missing_entries, ("health.json", b"{}")]), missing)
        foreign = copy.deepcopy(manifest)
        foreign["complete"] = False
        self.assertRaises(ctl.ControlError, ctl.support_archive, payload, foreign)
        self.assertRaises(ctl.ControlError, ctl.support_manifest, foreign)
        boundary = copy.deepcopy(manifest)
        for index, row in enumerate(boundary["components"]):
            body = b"x" * 65_536 if index < 4 else b""
            row.update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        self.assertEqual(sum(row["bytes"] for row in ctl.support_manifest(boundary)["components"]), 262_144)
        oversized = copy.deepcopy(boundary)
        oversized["components"][4].update(bytes=1, sha256=hashlib.sha256(b"x").hexdigest())
        self.assertRaises(ctl.ControlError, ctl.support_manifest, oversized)

    def test_existing_outputs_symlinks_and_foreign_replacements_survive_failed_writes(self):
        payload, manifest, _ = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "support.zip"
            output.write_bytes(b"existing")
            with self.assertRaises(ctl.ControlError):
                self.export(FakeDevice(payload, manifest), output)
            self.assertEqual(output.read_bytes(), b"existing")
            link = root / "link.zip"
            os.symlink(output, link)
            with self.assertRaises(ctl.ControlError):
                self.export(FakeDevice(payload, manifest), link)
            self.assertTrue(link.is_symlink())
            self.assertEqual(output.read_bytes(), b"existing")
            partial = root / "partial.zip"
            with patch.object(ctl.os, "write", side_effect=OSError("synthetic")), self.assertRaises(ctl.ControlError):
                self.export(FakeDevice(payload, manifest), partial)
            self.assertFalse(partial.exists())
            foreign = root / "foreign.zip"
            foreign.write_bytes(b"foreign")
            original_lstat = os.lstat
            def replace_after_closed(path):
                Path(path).unlink()
                foreign.rename(path)
                return original_lstat(path)
            with patch.object(ctl.os, "write", side_effect=OSError("synthetic")), patch.object(ctl.os, "lstat", side_effect=replace_after_closed), self.assertRaises(ctl.ControlError):
                self.export(FakeDevice(payload, manifest), partial)
            self.assertEqual(partial.read_bytes(), b"foreign")

    def test_adb_aliases_strict_new_json_and_old_diagnostic_json_remain_compatible(self):
        for operation, argument in (("support-bundle-collect", None), ("support-bundle-status", BUNDLE_ID),
                                    ("support-bundle-cancel", BUNDLE_ID), ("support-bundle-open", BUNDLE_ID),
                                    ("support-bundle-read", GRANT + ":32768")):
            reply = b'Result: Bundle[{ok=true, json={"state":"collecting"}}]\n'
            with patch.object(ctl.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, reply, b"")) as run:
                self.assertEqual(ctl.Device("synthetic-device", 3).call(operation, argument), {"state": "collecting"})
            command = run.call_args.args[0]
            self.assertEqual(command[command.index("--method") + 1], "bundle-" + operation.rsplit("-", 1)[1])
            self.assertNotIn("run-as", command)
        for raw in ('{"state":"ready","state":"collecting"}', '{"state":NaN}', '{"state":1e999}'):
            reply = ("Result: Bundle[{ok=true, json=" + raw + "}]\n").encode()
            with patch.object(ctl.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, reply, b"")), self.assertRaises(ctl.ControlError):
                ctl.Device("synthetic-device", 3).call("support-bundle-status", BUNDLE_ID)
        for argument in (GRANT + ":01", GRANT + ":524289", GRANT + ":-1", "other:0"):
            with patch.object(ctl.subprocess, "run") as run, self.assertRaises(ctl.ControlError):
                ctl.Device("synthetic-device", 3).call("support-bundle-read", argument)
            run.assert_not_called()
        state = {"generation": 3, "phase": "Off", "desiredOn": False, "events": []}
        with patch.object(ctl.Device, "call", side_effect=[state, {"processes": []}]), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(ctl.main(["--serial", "synthetic-device", "diagnostic-bundle"]), 0)
        self.assertEqual(json.loads(out.getvalue()), {"schemaVersion": 1, "operation": "diagnostic-bundle", "result": {
            "state": {"generation": 3, "phase": "Off", "desiredOn": False}, "events": [], "routeCounts": {},
            "collection": "bounded_debug_snapshot", "resources": {"processes": []}}})


if __name__ == "__main__":
    unittest.main()
