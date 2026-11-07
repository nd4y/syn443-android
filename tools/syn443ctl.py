#!/usr/bin/env python3
"""Bounded JSON client for the SYN443 debug ADB control provider."""
import argparse
import json
import re
import subprocess
import sys
import time

URI = "content://io.syn443.control"
METHODS = {
    "status": "status", "logs": "logs", "routes-status": "routes-status",
    "routes-check": "routes-check", "routes-cancel": "routes-cancel",
    "netbird-status": "status", "netbird-diagnose": "netbird-diagnose",
    "vpn-start": "connect", "vpn-stop": "disconnect", "vpn-resume": "resume",
    "resources": "resources", "engine-exits": "engine-exits", "health-workers": "health-workers",
}
OPERATIONS = ("capabilities", "status", "logs", "diagnostic-bundle", "routes-status",
              "routes-check", "routes-cancel", "netbird-status", "netbird-diagnose",
              "vpn-start", "vpn-stop", "vpn-resume")
REJECTED = {"needs_unlock": 4, "command_rejected": 4, "unauthorized": 4}
NUMBERS = ("generation", "networkEpoch", "activationGeneration", "eventSequence")
PHASES = {"Off", "NeedsLogin", "NeedsPermission", "NeedsUnlock", "NeedsAction", "NoNetwork",
          "Portal", "Detecting", "Connecting", "Online", "Degraded", "Recovering", "BlockedByPolicy"}
EVENT_CODES = {
    "awaiting_identity_release", "configuration_invalid", "configuration_or_capability_invalid",
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


def invalid_constant(_):
    raise ValueError("non-finite JSON")


class ControlError(Exception):
    def __init__(self, code, exit_status):
        super().__init__(code)
        self.code, self.exit_status = code, exit_status


class Device:
    def __init__(self, serial, timeout):
        if not re.fullmatch(r"[A-Za-z0-9_.:%\[\]-]{1,128}", serial) or serial.startswith("-"):
            raise ControlError("invalid_serial", 2)
        self.serial, self.timeout = serial, timeout

    def call(self, operation, route=None):
        method = METHODS[operation]
        command = ["adb", "-s", self.serial, "shell", "content", "call", "--uri", URI, "--method", method]
        if route is not None:
            if operation != "routes-check" or not re.fullmatch(r"route-[1-9][0-9]?", route):
                raise ControlError("invalid_route", 2)
            command.extend(["--arg", route])
        try:
            result = subprocess.run(command, capture_output=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as err:
            raise ControlError("adb_timeout", 3) from err
        except OSError as err:
            raise ControlError("adb_unavailable", 3) from err
        if len(result.stdout) > 262_144 or len(result.stderr) > 32_768:
            raise ControlError("reply_too_large", 5)
        output = result.stdout.decode(errors="replace")
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
            data = json.loads(raw, parse_constant=invalid_constant)
        except (ValueError, RecursionError) as err:
            raise ControlError("invalid_reply", 5) from err
        if not isinstance(data, dict):
            raise ControlError("invalid_reply", 5)
        return data


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
    checks = state.get("policyChecks")
    if isinstance(checks, dict) and type(checks.get("current")) is bool:
        safe["policyChecks"] = {"current": checks["current"], **numbers(checks, ("ageMs",))}
    # Do not copy status wholesale: it can include route labels and peer names.
    return {"state": safe, "events": events(state), "collection": "bounded_debug_snapshot"}


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


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise ControlError("invalid_arguments", 2)


def main(argv=None):
    parser = Arguments(description=__doc__)
    parser.add_argument("--serial", required=True, help="explicit adb device serial")
    parser.add_argument("--timeout", type=int, choices=range(1, 61), default=12, metavar="1..60")
    parser.add_argument("operation", choices=OPERATIONS)
    parser.add_argument("--route")
    parser.add_argument("--follow-seconds", type=int, choices=range(0, 301), default=0, metavar="0..300")
    try:
        args = parser.parse_args(argv)
    except ControlError as err:
        emit({"schemaVersion": 1, "operation": None, "error": err.code})
        return err.exit_status
    try:
        if (args.route is not None and args.operation != "routes-check") or (args.follow_seconds and args.operation != "logs"):
            raise ControlError("invalid_arguments", 2)
        device = Device(args.serial, args.timeout)
        if args.operation == "capabilities":
            state = device.call("status")
            data = {"operations": OPERATIONS, "access": "debug_adb_shell",
                    "device": {**numbers(state, NUMBERS), "unlocked": state.get("phase") != "NeedsUnlock"}}
        elif args.operation == "diagnostic-bundle":
            data = bundle(device)
        elif args.operation == "logs" and args.follow_seconds:
            follow(device, args.follow_seconds, 2.0)
            return 0
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
