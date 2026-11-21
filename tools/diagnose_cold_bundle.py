"""Bounded diagnostics on a disposable API 29 runner, using a hosted APK."""
import os
from pathlib import Path
import tempfile

import run_support_bundle_smoke as smoke
from syn443ctl import Device


class ObservedDevice(Device):
    controller = b""

    def call(self, operation, argument=None):
        value = super().call(operation, argument)
        if operation == "support-bundle-open":
            self.controller = smoke.adb("shell", "pidof", smoke.PACKAGE + ":controller").stdout.strip()
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
            try:
                smoke.main()
            except Exception as error:
                failures += 1
                print("failed sample", index + 1, type(error).__name__, flush=True)
    print("samples", 8, "failures", failures, flush=True)
    if failures:
        raise SystemExit(1)
