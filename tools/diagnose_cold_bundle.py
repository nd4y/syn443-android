"""Bounded diagnostics on a disposable API 29 runner, using a hosted APK."""
import os
from pathlib import Path
import tempfile
import traceback
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "candidate-release" / "tools"))

import run_support_bundle_smoke as smoke
from syn443ctl import Device


class ObservedDevice(Device):
    controller = b""
    prior = b""
    history = []

    def call(self, operation, argument=None):
        try:
            value = super().call(operation, argument)
        except Exception as error:
            self.history.append((operation, type(error).__name__))
            raise
        pid = smoke.adb("shell", "pidof", smoke.PACKAGE + ":controller").stdout.strip()
        state = value.get("state")
        known = {"failed", "expired", "cancelled", "busy", "not_found", "open", "collecting", "ready"}
        self.history.append((operation, state if isinstance(state, str) and state in known else "chunk_or_unknown",
            bool(pid), bool(self.prior) and self.prior != pid))
        self.prior = pid
        if operation == "support-bundle-open":
            self.controller = pid
        if operation == "support-bundle-read":
            fields = {"grant", "offset", "data", "nextOffset", "done"}
            state = value.get("state")
            print("read evidence", {
                "state": state if isinstance(state, str) and state in {"failed", "expired", "cancelled", "busy", "not_found"} else "chunk_or_unknown",
                "exact_fields": set(value) == fields,
                "grant_matches": value.get("grant") == argument.split(":")[0],
                "offset_matches": value.get("offset") == int(argument.split(":")[1]),
                "data_chars": len(value["data"]) if isinstance(value.get("data"), str) else None,
                "done_boolean": type(value.get("done")) is bool,
                "same_controller": bool(self.controller) and self.controller == smoke.adb("shell", "pidof", smoke.PACKAGE + ":controller").stdout.strip(),
            }, flush=True)
        return value


if __name__ == "__main__":
    root = Path(os.environ["RUNNER_TEMP"])
    assert smoke.adb("shell", "getprop", "ro.build.version.sdk").stdout.strip() == b"29"
    assert smoke.adb("shell", "getprop", "ro.hardware").stdout.strip() in (b"goldfish", b"ranchu")
    assert smoke.adb("install", "-r", str(root / "bundle-apks/debug/app-debug.apk"), timeout=60).returncode == 0
    smoke.Device = ObservedDevice
    failures = 0
    for index in range(8):
        with tempfile.TemporaryDirectory(dir=root) as directory:
            os.environ["RUNNER_TEMP"] = directory
            ObservedDevice.history.clear()
            try:
                smoke.main()
            except Exception as error:
                failures += 1
                frames = [(Path(frame.filename).name, frame.lineno, frame.name)
                          for frame in traceback.extract_tb(error.__traceback__)]
                print("failed sample", index + 1, type(error).__name__, frames, ObservedDevice.history, flush=True)
                events = smoke.adb("logcat", "-b", "events", "-d", "-t", "300",
                    "-s", "am_kill:I", "am_proc_died:I", "am_proc_start:I").stdout.decode(errors="replace")
                for line in events.splitlines():
                    if smoke.PACKAGE + ":controller" in line:
                        print("controller event", line[:320], flush=True)
    print("samples", 8, "failures", failures, flush=True)
    if failures:
        raise SystemExit(1)
    device = Device(smoke.adb("get-serialno").stdout.decode().strip(), 10)
    sequence = smoke.SupportDeadline(device)
    with device.bundle_connection() as held:
        assert held
        current = smoke.support_collect(sequence)["id"]
        smoke.support_wait(sequence, current)
        grant = sequence.call("support-bundle-open", current)["grant"]
    assert smoke.adb("shell", "am", "force-stop", smoke.PACKAGE).returncode == 0
    assert sequence.call("support-bundle-read", grant + ":0") == {"state": "not_found"}
    assert sequence.call("support-bundle-status", current) == {"state": "not_found", "id": current}
    smoke.no_engine()
    print("Old grant denied after actual provider process termination", flush=True)
