#!/usr/bin/env python3
"""Bounded JSON client for the SYN443 debug ADB control provider."""
import argparse
import base64
from contextlib import contextmanager, nullcontext
import hashlib
import io
import json
import math
import os
import re
import secrets
import stat
import struct
import subprocess
import sys
import time
import zipfile

URI = "content://io.syn443.control"
METHODS = {
    "status": "status", "logs": "logs", "routes-status": "routes-status",
    "routes-check": "routes-check", "routes-cancel": "routes-cancel",
    "netbird-status": "status", "netbird-diagnose": "netbird-diagnose", "netbird-view": "netbird-view", "netbird-cancel": "netbird-cancel",
    "vpn-start": "connect", "vpn-stop": "disconnect", "vpn-resume": "resume",
    "resources": "resources", "engine-exits": "engine-exits", "health-workers": "health-workers",
    "config-plan": "config-plan-file", "config-apply": "config-apply-file",
    "support-bundle-collect": "bundle-collect", "support-bundle-status": "bundle-status",
    "support-bundle-cancel": "bundle-cancel", "support-bundle-open": "bundle-open",
    "support-bundle-read": "bundle-read",
    "support-bundle-shell-state": "bundle-shell-state", "support-bundle-shell-release": "bundle-shell-release",
}
OPERATIONS = ("capabilities", "status", "logs", "diagnostic-bundle", "routes-status",
              "routes-check", "routes-cancel", "netbird-status", "netbird-diagnose", "netbird-view", "netbird-cancel",
              "vpn-start", "vpn-stop", "vpn-resume", "config-plan", "config-apply",
              "support-bundle", "support-bundle-collect", "support-bundle-status",
              "support-bundle-cancel", "support-bundle-export")
CONFIG = {"config-plan", "config-apply"}
MAX_CONFIG = 262_144
STAGE = "run-as io.syn443.android sh -c 'umask 077; base64 -d > no_backup/operator-local-config-{}.json'"
CLEANUP = "run-as io.syn443.android rm -f no_backup/operator-local-config-{}.json"
REJECTED = {"needs_unlock": 4, "command_rejected": 4, "unauthorized": 4}
NUMBERS = ("generation", "networkEpoch", "activationGeneration", "eventSequence")
PHASES = {"Off", "NeedsLogin", "NeedsPermission", "NeedsUnlock", "NeedsAction", "NoNetwork",
          "Portal", "Detecting", "Connecting", "Online", "Degraded", "Recovering", "BlockedByPolicy"}
EVENT_CODES = {
    "awaiting_identity_release", "captive_portal", "configuration_invalid", "configuration_or_capability_invalid",
    "controller_recreated", "dns_resolution_failed", "dns_timeout", "explicit_resume_required",
    "health_policy_not_authorized", "managed_route_recheck", "native_bind_failed", "native_binding_died",
    "native_binding_timeout", "native_died", "native_disconnected", "native_handshake_failed", "native_ipc_failed",
    "native_late_start", "native_lease_update_failed", "native_null_binding", "native_progress_timeout",
    "native_restart_budget", "native_start", "native_start_failed", "network_changed", "network_unavailable",
    "network_update_failed", "overlay_credentials_pending", "overlay_material_changed", "policy_baseline_degraded",
    "policy_checks_unavailable", "policy_gate_pending", "policy_lease_time_or_scope_invalid", "policy_rollback",
    "policy_store_unavailable", "policy_waiting_restart_budget", "required_https_ok",
    "required_route_unverified_or_failed", "retry_scheduled", "start_failed", "tcp_timeout", "tls_failed",
    "tls_timeout", "transport_eof", "user_stop", "vpn_permission_required", "vpn_permission_revoked",
}
ROUTE_STATES = {"off", "unavailable", "unverified", "checking", "working", "failed", "stale", "incomplete"}
SUPPORT_OPERATIONS = {"support-bundle", "support-bundle-collect", "support-bundle-status",
                      "support-bundle-cancel", "support-bundle-export"}
SUPPORT_FILES = ("versions.json", "capabilities.json", "effective-config.json", "health.json", "events.jsonl",
                 "checks.json", "overlay.json", "crashes.json", "native-stacks.json")
SUPPORT_MAX = 524_288
SUPPORT_MANIFEST_MAX = 16_384
SUPPORT_CHUNK = 32_768
SUPPORT_STATES = {"collecting", "ready", "failed", "cancelled", "expired", "not_found"}
SUPPORT_REASONS = {"none", "unavailable", "unsupported", "over_limit", "invalid_source", "io_error", "projection_only"}


def invalid_constant(_):
    raise ValueError("non-finite JSON")


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON")
    return result


class ControlError(Exception):
    def __init__(self, code, exit_status):
        super().__init__(code)
        self.code, self.exit_status = code, exit_status


def view_argument(section, page, request):
    if section not in ("peers", "diagnostics") or type(page) is not int or not 0 <= page <= 63 or \
            not isinstance(request, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", request):
        raise ControlError("invalid_arguments", 2)
    return json.dumps({"kind": "overlay-view", "section": section, "page": page, "request": request}, separators=(",", ":"))


def canonical_view(raw):
    """Only our canonical, bounded ASCII frame may reach the Android shell."""
    if not isinstance(raw, str) or len(raw) > 1024:
        raise ControlError("invalid_arguments", 2)
    try:
        value = json.loads(raw, parse_constant=invalid_constant)
        if not isinstance(value, dict) or set(value) != {"kind", "section", "page", "request"} or value["kind"] != "overlay-view":
            raise ValueError("shape")
        canonical = view_argument(value["section"], value["page"], value["request"])
        if raw != canonical:
            raise ValueError("noncanonical")
        return canonical
    except (ValueError, TypeError, RecursionError) as err:
        raise ControlError("invalid_arguments", 2) from err


class Device:
    def __init__(self, serial, timeout):
        if not re.fullmatch(r"[A-Za-z0-9_.:%\[\]-]{1,128}", serial) or serial.startswith("-"):
            raise ControlError("invalid_serial", 2)
        self.serial, self.timeout = serial, timeout

    def call(self, operation, argument=None):
        method = METHODS[operation]
        command = ["adb", "-s", self.serial, "shell", "content", "call", "--uri", URI, "--method", method]
        if argument is not None:
            route = operation == "routes-check" and re.fullmatch(r"route-[1-9][0-9]?", argument)
            ticket = operation in CONFIG and re.fullmatch(r"(?:none|[0-9a-f]{64}):[0-9a-f]{64}:[0-9a-f]{32}", argument)
            bundle_id = operation in {"support-bundle-status", "support-bundle-cancel", "support-bundle-open",
                                      "support-bundle-shell-state", "support-bundle-shell-release"} and re.fullmatch(r"[0-9a-f]{32}", argument)
            bundle_read = operation == "support-bundle-read" and re.fullmatch(r"[0-9a-f]{32}:(?:0|[1-9][0-9]{0,5})", argument) and int(argument.split(":")[1]) <= SUPPORT_MAX
            view = canonical_view(argument) if operation == "netbird-view" else None
            cancel = operation == "netbird-cancel" and support_hex(argument, 32)
            if not cancel and not route and not ticket and not bundle_id and not bundle_read and view is None:
                raise ControlError("invalid_arguments", 2)
            # adb shell joins arguments into an Android shell command. Our closed
            # ASCII view has no apostrophe; single quoting preserves JSON quotes.
            command.extend(["--arg", "'" + view + "'" if view is not None else argument])
        elif operation in {"netbird-view", "netbird-cancel"}:
            raise ControlError("invalid_arguments", 2)
        try:
            result = subprocess.run(command, capture_output=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as err:
            raise ControlError("adb_timeout", 3) from err
        except OSError as err:
            raise ControlError("adb_unavailable", 3) from err
        if len(result.stdout) > 262_144 or len(result.stderr) > 32_768:
            raise ControlError("reply_too_large", 5)
        support = operation.startswith("support-bundle-")
        try:
            output = result.stdout.decode("utf-8", errors="strict" if support else "replace")
        except UnicodeDecodeError as err:
            raise ControlError("invalid_reply", 5) from err
        if result.returncode != 0 or "Result: Bundle[" not in output:
            if "unauthorized caller" in output + result.stderr.decode(errors="replace"):
                raise ControlError("unauthorized", 4)
            raise ControlError("adb_failed", 3)
        match = re.fullmatch(r"\s*Result: Bundle\[\{(.*)\}\]\s*", output)
        if match is None:
            raise ControlError("invalid_reply", 5)
        content = match[1]
        rejected = re.fullmatch(r"ok=false, error=([a-z_]+)|error=([a-z_]+), ok=false", content)
        if rejected:
            code = (rejected[1] or rejected[2])
            code = code if code in REJECTED else "command_rejected"
            raise ControlError(code, REJECTED[code])
        if content.startswith("ok=true, json="):
            raw = content[len("ok=true, json="):]
        elif content.startswith("json=") and content.endswith(", ok=true"):
            raw = content[len("json="):-len(", ok=true")]
        else:
            raise ControlError("invalid_reply", 5)
        try:
            options = {"object_pairs_hook": unique_pairs, "parse_float": finite_float} if support else {}
            data = json.loads(raw, parse_constant=invalid_constant, **options)
        except (ValueError, RecursionError) as err:
            raise ControlError("invalid_reply", 5) from err
        if not isinstance(data, dict):
            raise ControlError("invalid_reply", 5)
        return data

    @contextmanager
    def bundle_connection(self):
        # gettype is passive even on older clients; an unknown call() would initialize their VPN state.
        adb = ["adb", "-s", self.serial, "shell", "content"]
        try:
            reply = subprocess.run(adb + ["gettype", "--uri", URI + "/support-bundle-session"],
                                   capture_output=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as err:
            raise ControlError("adb_timeout", 3) from err
        except OSError as err:
            raise ControlError("adb_unavailable", 3) from err
        if reply.returncode:
            raise ControlError("adb_failed", 3)
        kind = reply.stdout.strip()
        if kind == b"Result: null":
            yield False  # Older APKs retain their original protocol.
            return
        if kind != b"Result: application/vnd.syn443.bundle-session-v1":
            raise ControlError("invalid_reply", 5)

        client = secrets.token_hex(16)
        try:
            holder = subprocess.Popen(adb + ["call", "--uri", URI, "--method", "bundle-shell-hold", "--arg", client],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as err:
            raise ControlError("adb_unavailable", 3) from err
        try:
            deadline = time.monotonic() + min(self.timeout, 10)
            while time.monotonic() < deadline:
                state = self.call("support-bundle-shell-state", client)
                if state == {"state": "held"} and holder.poll() is None:
                    break
                if state == {"state": "busy"}:
                    raise ControlError("support_bundle_busy", 4)
                if state != {"state": "absent"} or holder.poll() is not None:
                    raise ControlError("support_bundle_unavailable", 4)
                time.sleep(0.1)
            else:
                raise ControlError("adb_timeout", 3)
            yield True
        finally:
            # An unplugged cable cannot keep the provider occupied indefinitely.
            # The Android side enforces its own maximum lifetime.
            try:
                if holder.poll() is None:
                    self.call("support-bundle-shell-release", client)
            except ControlError:
                pass
            finally:
                try:
                    holder.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.wait(timeout=2)

    def _stage(self, script, data=None):
        command = ["adb", "-s", self.serial, "shell", "-T", script]
        try:
            return subprocess.run(command, input=data, capture_output=True, timeout=self.timeout, check=False).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def config(self, operation, payload, base, candidate):
        nonce = secrets.token_hex(16)
        try:
            if not self._stage(STAGE.format(nonce), base64.b64encode(payload) + b"\n"):
                raise ControlError("config_stage_failed", 3)
            result = self.call(operation, base + ":" + candidate + ":" + nonce)
            if result.get("baseRevision") != base or result.get("candidateRevision") != candidate:
                raise ControlError("invalid_reply", 5)
            return result
        finally:
            if not self._stage(CLEANUP.format(nonce)):
                raise ControlError("config_cleanup_unverified", 3)


def numbers(value, names):
    return {k: value[k] for k in names if type(value.get(k)) is int and 0 <= value[k] < 2**53}


def events(value):
    raw = value.get("events")
    if not isinstance(raw, list):
        return []
    clean = []
    for item in raw[-64:]:
        if not isinstance(item, dict) or not isinstance(item.get("phase"), str) or item["phase"] not in PHASES:
            continue
        row = numbers(item, ("at", "elapsed", "sequence", "intentGeneration", "networkEpoch"))
        code = item.get("code")
        row.update(phase=item["phase"], code=code if isinstance(code, str) and code in EVENT_CODES else "redacted")
        clean.append(row)
    return clean


def bundle(device):
    state = device.call("status")
    safe = numbers(state, NUMBERS)
    phase = state.get("phase")
    safe["phase"] = phase if isinstance(phase, str) and phase in PHASES else "unknown"
    safe.update({k: state[k] for k in ("desiredOn", "engineActive", "resumeRequired") if type(state.get(k)) is bool})
    reason = state.get("reason")
    if isinstance(reason, str) and reason in EVENT_CODES:
        safe["reason"] = reason
    link = state.get("physicalLink")
    if state.get("desiredOn") is True and isinstance(link, dict) and link.get("transport") in ("WIFI", "CELLULAR", "OTHER"):
        physical = {"transport": link["transport"]}
        for key in ("ipv4Address", "ipv4Default", "ipv6Address", "ipv6Default"):
            if type(link.get(key)) is bool:
                physical[key] = link[key]
        if link["transport"] == "WIFI" and link.get("homeProof") in ("verified", "unconfirmed"):
            physical["homeProof"] = link["homeProof"]
        safe["physicalLink"] = physical
    checks = state.get("policyChecks")
    if isinstance(checks, dict) and type(checks.get("current")) is bool:
        safe["policyChecks"] = {"current": checks["current"], **numbers(checks, ("ageMs",))}
    # Do not copy status wholesale: it can include route labels and peer names.
    health = state.get("routeHealth")
    route_counts = {}
    if isinstance(health, dict) and isinstance(health.get("routes"), list):
        for row in health["routes"][:64]:
            outcome = row.get("state") if isinstance(row, dict) else None
            if isinstance(outcome, str) and outcome in ROUTE_STATES:
                route_counts[outcome] = route_counts.get(outcome, 0) + 1
    report = {"state": safe, "events": events(state), "routeCounts": route_counts,
              "collection": "bounded_debug_snapshot"}
    try:
        resource = device.call("resources")
        processes = resource.get("processes")
        samples = []
        if isinstance(processes, list):
            for row in processes[:3]:
                role = row.get("role") if isinstance(row, dict) else None
                if role in ("ui", "controller", "engine"):
                    samples.append({"role": role, **numbers(row, ("cpuTimeMs", "rssBytes", "threads", "fileDescriptors"))})
        report["resources"] = {"processes": samples, **numbers(resource, ("sampleAgeMs", "sampledElapsedMs"))}
    except ControlError as error:
        report["resources"] = {"unavailable": error.code}
    return report


def support_invalid():
    raise ControlError("support_bundle_invalid", 5)


def support_int(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def support_hex(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is not None


def support_json(raw, maximum):
    try:
        if not isinstance(raw, bytes) or len(raw) > maximum:
            support_invalid()
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                          parse_constant=invalid_constant, parse_float=finite_float)
    except (ValueError, RecursionError) as err:
        raise ControlError("support_bundle_invalid", 5) from err


def support_manifest(value):
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "product", "complete", "components"}:
        support_invalid()
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1 or value["product"] != "SYN443" or type(value["complete"]) is not bool:
        support_invalid()
    rows = value["components"]
    if not isinstance(rows, list) or len(rows) != len(SUPPORT_FILES):
        support_invalid()
    seen = set()
    total = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"name", "state", "reason", "bytes", "sha256"}:
            support_invalid()
        name, state, reason = row["name"], row["state"], row["reason"]
        if not isinstance(name, str) or name not in SUPPORT_FILES or name in seen or not isinstance(state, str) or state not in {"available", "missing", "error", "truncated"} or not isinstance(reason, str) or reason not in SUPPORT_REASONS:
            support_invalid()
        seen.add(name)
        if not support_int(row["bytes"], 65_536):
            support_invalid()
        total += row["bytes"]
        if total > 262_144:
            support_invalid()
        if state in {"available", "truncated"}:
            if not support_hex(row["sha256"], 64):
                support_invalid()
        elif row["bytes"] != 0 or row["sha256"] is not None:
            support_invalid()
    if value["complete"] != all(row["state"] == "available" and row["reason"] == "none" for row in rows):
        support_invalid()
    try:
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as err:
        raise ControlError("support_bundle_invalid", 5) from err
    if len(encoded) > SUPPORT_MANIFEST_MAX:
        support_invalid()
    # Return an owned, fully typed manifest rather than an alias from a caller.
    return support_json(encoded, SUPPORT_MANIFEST_MAX)


def support_status(value, bundle_id):
    if not isinstance(value, dict) or set(value) - {"state", "id", "bytes", "sha256", "manifest"}:
        support_invalid()
    state = value.get("state")
    if not isinstance(state, str) or state not in SUPPORT_STATES:
        support_invalid()
    if "id" in value and (not support_hex(value["id"], 32) or value["id"] != bundle_id):
        support_invalid()
    if "bytes" in value and not support_int(value["bytes"], SUPPORT_MAX):
        support_invalid()
    if "sha256" in value and not support_hex(value["sha256"], 64):
        support_invalid()
    manifest = support_manifest(value["manifest"]) if "manifest" in value else None
    if state == "ready" and (value.get("id") != bundle_id or not {"bytes", "sha256", "manifest"} <= set(value)):
        support_invalid()
    return {**value, **({"manifest": manifest} if manifest is not None else {})}


class SupportDeadline:
    """One request sequence, with no retry after any uncertain RPC outcome."""
    def __init__(self, device, clock=None, sleeper=None):
        self.device = device
        self.clock = clock or time.monotonic
        self.sleep = sleeper or time.sleep
        self.started = self.last = self.clock()
        if not math.isfinite(self.started):
            support_invalid()
        self.deadline = self.started + 120.0

    def now(self, deadline=None):
        now = self.clock()
        if not math.isfinite(now) or now < self.last or now >= min(self.deadline, deadline if deadline is not None else self.deadline):
            raise ControlError("support_bundle_timeout", 3)
        self.last = now
        return now

    def call(self, operation, argument=None, deadline=None):
        now = self.now(deadline)
        previous = self.device.timeout
        self.device.timeout = min(previous, min(self.deadline, deadline if deadline is not None else self.deadline) - now)
        try:
            result = self.device.call(operation, argument)
        finally:
            self.device.timeout = previous
        self.now(deadline)
        return result


def support_collect(sequence):
    value = sequence.call("support-bundle-collect", deadline=sequence.started + 32.0)
    if not isinstance(value, dict) or set(value) != {"state", "id"} or not isinstance(value.get("state"), str) or value["state"] not in {"collecting", "ready", "busy"} or not support_hex(value.get("id"), 32):
        support_invalid()
    return dict(value)


def support_wait(sequence, bundle_id):
    deadline = sequence.started + 32.0
    for attempt in range(64):
        value = support_status(sequence.call("support-bundle-status", bundle_id, deadline), bundle_id)
        if value["state"] == "ready":
            return value
        if value["state"] != "collecting":
            raise ControlError("support_bundle_unavailable", 4)
        if attempt != 63:
            sequence.sleep(min(0.5, deadline - sequence.now(deadline)))
    raise ControlError("support_bundle_timeout", 3)


def support_extra(raw):
    # Ordinary ZIP extras are bounded; ZIP64 is never admitted, even when tiny.
    if len(raw) > 1024:
        support_invalid()
    at = 0
    while at < len(raw):
        if len(raw) - at < 4:
            support_invalid()
        kind, size = struct.unpack_from("<HH", raw, at)
        at += 4
        if kind == 1 or size > len(raw) - at:
            support_invalid()
        at += size


def support_archive(payload, expected_manifest):
    """Validate the bounded archive in memory. Never extract or print components."""
    try:
        if not isinstance(payload, bytes) or not 22 <= len(payload) <= SUPPORT_MAX:
            support_invalid()
        end = len(payload) - 22
        signature, disk, directory_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4s4H2IH", payload, end)
        if signature != b"PK\x05\x06" or disk or directory_disk or disk_count != count or not 1 <= count <= 10 or comment or offset + size != end:
            support_invalid()
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            infos = archive.infolist()
            if len(infos) != count or archive.comment:
                support_invalid()
            names, contents = set(), {}
            position = 0
            total = 0
            for info in sorted(infos, key=lambda entry: entry.header_offset):
                name = info.filename
                maximum = SUPPORT_MANIFEST_MAX if name == "manifest.json" else 65_536
                mode = stat.S_IFMT(info.external_attr >> 16)
                if name not in (*SUPPORT_FILES, "manifest.json") or name in names or name != info.orig_filename or info.header_offset != position or info.compress_type != zipfile.ZIP_STORED or info.flag_bits & ~(0x800 | 8) or info.extract_version >= 45 or info.comment or mode not in (0, stat.S_IFREG) or info.external_attr & 0x10 or not 0 <= info.file_size <= maximum or info.compress_size != info.file_size:
                    support_invalid()
                names.add(name)
                support_extra(info.extra)
                if position + 30 > offset:
                    support_invalid()
                header = struct.unpack_from("<4s5H3I2H", payload, position)
                magic, version, flags, method, _, _, crc, compressed, plain, name_size, extra_size = header
                data_start = position + 30 + name_size + extra_size
                data_end = data_start + info.file_size
                if magic != b"PK\x03\x04" or version >= 45 or flags != info.flag_bits or method != 0 or data_end > offset or payload[position + 30:position + 30 + name_size] != name.encode("ascii"):
                    support_invalid()
                support_extra(payload[position + 30 + name_size:data_start])
                if flags & 8:
                    if crc not in (0, info.CRC) or compressed not in (0, info.file_size) or plain not in (0, info.file_size):
                        support_invalid()
                    descriptor = data_end + (4 if payload[data_end:data_end + 4] == b"PK\x07\x08" else 0)
                    if descriptor + 12 > offset or struct.unpack_from("<III", payload, descriptor) != (info.CRC, info.file_size, info.file_size):
                        support_invalid()
                    position = descriptor + 12
                else:
                    if (crc, compressed, plain) != (info.CRC, info.file_size, info.file_size):
                        support_invalid()
                    position = data_end
                contents[name] = archive.read(info)
                if len(contents[name]) != info.file_size:
                    support_invalid()
                if name != "manifest.json":
                    total += info.file_size
                    if total > 262_144:
                        support_invalid()
            if position != offset or "manifest.json" not in names:
                support_invalid()
            manifest = support_manifest(support_json(contents["manifest.json"], SUPPORT_MANIFEST_MAX))
            if manifest != support_manifest(expected_manifest):
                support_invalid()
            expected = {"manifest.json"}
            for row in manifest["components"]:
                if row["state"] in {"available", "truncated"}:
                    expected.add(row["name"])
                    body = contents.get(row["name"])
                    if body is None or len(body) != row["bytes"] or hashlib.sha256(body).hexdigest() != row["sha256"]:
                        support_invalid()
            if names != expected:
                support_invalid()
            return manifest
    except (OSError, ValueError, RuntimeError, NotImplementedError, EOFError, struct.error, zipfile.BadZipFile) as err:
        raise ControlError("support_bundle_invalid", 5) from err


def support_write(path, payload, sequence):
    sequence.now()
    descriptor, identity = None, None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        identity = os.fstat(descriptor)
        if not stat.S_ISREG(identity.st_mode):
            raise OSError("output is not regular")
        at = 0
        while at < len(payload):
            sequence.now()
            written = os.write(descriptor, payload[at:])
            if written <= 0:
                raise OSError("short output write")
            at += written
        os.fsync(descriptor)
        sequence.now()
        os.close(descriptor)
        descriptor = None
    except (OSError, ValueError, TypeError, ControlError, KeyboardInterrupt) as err:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        # A replaced path is foreign state, even after our own failed write.
        if identity is not None:
            try:
                current = os.lstat(path)
                if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    os.unlink(path)
            except OSError:
                pass
        if isinstance(err, (ControlError, KeyboardInterrupt)):
            raise
        raise ControlError("support_bundle_output_exists" if isinstance(err, FileExistsError) else "support_bundle_write_failed", 3) from err


def support_export(sequence, bundle_id, output, ready=None):
    ready = support_status(sequence.call("support-bundle-status", bundle_id), bundle_id) if ready is None else ready
    if ready["state"] != "ready":
        raise ControlError("support_bundle_unavailable", 4)
    opened_at = sequence.now()
    value = sequence.call("support-bundle-open", bundle_id)
    if isinstance(value, dict) and set(value) == {"state", "id"} and value["id"] == bundle_id:
        support_export_denied(value["state"], allow_busy=False)
    if not isinstance(value, dict) or set(value) != {"state", "grant", "bytes", "sha256", "expiresInMs", "manifest"} or value.get("state") != "open" or not support_hex(value.get("grant"), 32) or not support_int(value.get("bytes"), SUPPORT_MAX) or not support_hex(value.get("sha256"), 64) or not support_int(value.get("expiresInMs"), 60_000) or value["expiresInMs"] == 0:
        support_invalid()
    manifest = support_manifest(value["manifest"])
    if (value["bytes"], value["sha256"], manifest) != (ready["bytes"], ready["sha256"], ready["manifest"]):
        support_invalid()
    deadline = opened_at + value["expiresInMs"] / 1000.0
    payload = bytearray()
    for _ in range(max(1, (value["bytes"] + SUPPORT_CHUNK - 1) // SUPPORT_CHUNK)):
        at = len(payload)
        part = sequence.call("support-bundle-read", value["grant"] + ":" + str(at), deadline)
        if isinstance(part, dict) and set(part) == {"state"}:
            support_export_denied(part["state"], allow_busy=True)
        if not isinstance(part, dict) or set(part) != {"grant", "offset", "data", "nextOffset", "done"} or part["grant"] != value["grant"] or not support_int(part["offset"], SUPPORT_MAX) or part["offset"] != at or not isinstance(part["data"], str) or len(part["data"]) > 43_692 or not support_int(part["nextOffset"], SUPPORT_MAX) or type(part["done"]) is not bool:
            support_invalid()
        try:
            data = base64.b64decode(part["data"], validate=True)
        except (ValueError, UnicodeError) as err:
            raise ControlError("support_bundle_invalid", 5) from err
        if base64.b64encode(data).decode("ascii") != part["data"] or len(data) != min(SUPPORT_CHUNK, value["bytes"] - at) or part["nextOffset"] != at + len(data) or part["done"] != (part["nextOffset"] == value["bytes"]):
            support_invalid()
        payload.extend(data)
    archive = bytes(payload)
    if len(archive) != value["bytes"] or hashlib.sha256(archive).hexdigest() != value["sha256"]:
        support_invalid()
    checked = support_archive(archive, manifest)
    support_write(output, archive, sequence)
    return {"bytes": len(archive), "sha256": value["sha256"], "complete": checked["complete"], "exported": True}


def support_export_denied(state, *, allow_busy):
    if isinstance(state, str) and (state in {"expired", "cancelled", "failed", "not_found"} or (allow_busy and state == "busy")):
        raise ControlError("support_bundle_" + state, 4)
    support_invalid()


def support_operation(device, operation, output=None, bundle_id=None, clock=None, sleeper=None):
    sequence = SupportDeadline(device, clock, sleeper)
    if operation == "support-bundle-collect":
        return support_collect(sequence)
    if operation == "support-bundle-cancel":
        value = sequence.call("support-bundle-cancel", bundle_id)
        if not isinstance(value, dict) or set(value) != {"state", "id"} or value.get("state") != "cancelled" or value.get("id") != bundle_id:
            support_invalid()
        return dict(value)
    if operation == "support-bundle-status":
        value = support_status(sequence.call("support-bundle-status", bundle_id), bundle_id)
        return {key: value[key] for key in ("state", "id", "bytes", "sha256") if key in value} | ({"complete": value["manifest"]["complete"]} if "manifest" in value else {})
    if operation == "support-bundle-export":
        return support_export(sequence, bundle_id, output)
    collected = support_collect(sequence)
    if collected["state"] == "busy":
        raise ControlError("support_bundle_busy", 4)
    ready = support_wait(sequence, collected["id"])
    return support_export(sequence, collected["id"], output, ready)


def emit(obj):
    print(json.dumps(obj, separators=(",", ":"), ensure_ascii=True, allow_nan=False), flush=True)


def follow(device, duration, interval):
    deadline = time.monotonic() + duration
    previous = None
    while previous is None or time.monotonic() < deadline:
        state = device.call("logs")
        snapshot = {**numbers(state, NUMBERS), "events": events(state)}
        if snapshot != previous:
            emit({"schemaVersion": 1, "operation": "logs", "result": snapshot})
            previous = snapshot
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(remaining, interval))


def config_input(path):
    try:
        with open(path, "rb") as source:
            payload = source.read(MAX_CONFIG + 1)
        if not 1 <= len(payload) <= MAX_CONFIG:
            raise ValueError("size")
        document = json.loads(payload.decode("utf-8"), parse_constant=invalid_constant)
        if not isinstance(document, dict):
            raise ValueError("shape")
    except (OSError, ValueError, RecursionError) as err:
        raise ControlError("invalid_config_file", 2) from err
    return payload, hashlib.sha256(payload).hexdigest()


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise ControlError("invalid_arguments", 2)


def main(argv=None):
    parser = Arguments(description=__doc__)
    parser.add_argument("--serial", required=True, help="explicit adb device serial")
    parser.add_argument("--timeout", type=int, choices=range(1, 61), default=12, metavar="1..60")
    parser.add_argument("operation", choices=OPERATIONS)
    parser.add_argument("--route")
    parser.add_argument("--section", choices=("peers", "diagnostics"))
    parser.add_argument("--page", type=int, choices=range(64))
    parser.add_argument("--file")
    parser.add_argument("--expected-revision")
    parser.add_argument("--expected-candidate")
    parser.add_argument("--output")
    parser.add_argument("--bundle-id")
    parser.add_argument("--job-id")
    parser.add_argument("--follow-seconds", type=int, choices=range(0, 301), default=0, metavar="0..300")
    try:
        args = parser.parse_args(argv)
    except ControlError as err:
        emit({"schemaVersion": 1, "operation": None, "error": err.code})
        return err.exit_status
    try:
        if (args.output is not None) != (args.operation in {"support-bundle", "support-bundle-export"}) or (
            (args.bundle_id is not None) != (args.operation in {"support-bundle-status", "support-bundle-cancel", "support-bundle-export"})
        ) or (args.bundle_id is not None and not support_hex(args.bundle_id, 32)):
            raise ControlError("invalid_arguments", 2)
        if (args.job_id is not None) != (args.operation == "netbird-cancel") or (args.job_id is not None and not support_hex(args.job_id, 32)):
            raise ControlError("invalid_arguments", 2)
        if (args.route is not None and args.operation != "routes-check") or (args.follow_seconds and args.operation != "logs"):
            raise ControlError("invalid_arguments", 2)
        if (args.operation == "netbird-view") != (args.section is not None and args.page is not None) or \
                (args.operation != "netbird-view" and (args.section is not None or args.page is not None)):
            raise ControlError("invalid_arguments", 2)
        if (args.file is not None) != (args.operation in CONFIG) or (
            args.operation != "config-apply" and (args.expected_revision is not None or args.expected_candidate is not None)
        ):
            raise ControlError("invalid_arguments", 2)
        device = Device(args.serial, args.timeout)
        if args.operation in SUPPORT_OPERATIONS:
            connection = device.bundle_connection() if args.operation in {"support-bundle", "support-bundle-export"} else nullcontext()
            with connection:
                data = support_operation(device, args.operation, args.output, args.bundle_id)
        elif args.operation == "capabilities":
            state = device.call("status")
            operations = [
                op for op in OPERATIONS
                if (op not in CONFIG or state.get("localConfigControl") is True)
                and (op != "netbird-cancel" or state.get("netbirdDiagnosticCancellation") is True)
            ]
            data = {"operations": operations, "access": "debug_adb_shell",
                    "device": {**numbers(state, NUMBERS), "unlocked": state.get("phase") != "NeedsUnlock"}}
        elif args.operation == "diagnostic-bundle":
            data = bundle(device)
        elif args.operation == "logs" and args.follow_seconds:
            follow(device, args.follow_seconds, 2.0)
            return 0
        elif args.operation == "netbird-cancel":
            data = device.call(args.operation, args.job_id)
        elif args.operation == "netbird-view":
            # This receipt means queued, not a fresh page or probe result. Read
            # netbird-status and match its section view.request before using it.
            request = secrets.token_hex(16)
            data = device.call("netbird-view", view_argument(args.section, args.page, request))
        elif args.operation in CONFIG:
            payload, candidate = config_input(args.file)
            if args.operation == "config-apply":
                base = args.expected_revision
                if base is None or not re.fullmatch(r"none|[0-9a-f]{64}", base) or candidate != args.expected_candidate:
                    raise ControlError("config_plan_required", 2)
            else:
                base = device.call("status").get("configRevision") or "none"
                if not isinstance(base, str) or not re.fullmatch(r"none|[0-9a-f]{64}", base):
                    raise ControlError("invalid_reply", 5)
            data = device.config(args.operation, payload, base, candidate)
        else:
            data = device.call(args.operation, args.route)
            if args.operation == "logs":
                data = {**numbers(data, NUMBERS), "events": events(data)}
            elif args.operation == "netbird-status":
                data = {"netbird": data.get("netbird"), **numbers(data, NUMBERS)}
        emit({"schemaVersion": 1, "operation": args.operation, "result": data})
        return 0
    except ControlError as err:
        emit({"schemaVersion": 1, "operation": args.operation, "error": err.code})
        return err.exit_status
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
