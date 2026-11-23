"""Exercise owner consent on the normal release, before creating the CI fixture identity."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from emulator_policy_ui import tap, tree
from run_vpn_process_faults import adb
from syn443ctl import ControlError, Device

PACKAGE = "io.syn443.android"


def press(label):
    width, height = map(int, re.findall(r"(\d+)x(\d+)", adb("shell", "wm", "size").decode())[-1])
    for _ in range(9):
        for node in tree().iter("node"):
            if node.get("package") == PACKAGE and label in (node.get("text"), node.get("content-desc")):
                bounds = [int(v) for v in re.findall(r"\d+", node.get("bounds", ""))]
                if len(bounds) == 4 and bounds[2] > bounds[0] and bounds[3] > bounds[1]:
                    tap(node)
                    return
        adb("shell", "input", "swipe", str(width // 2), str(height * 4 // 5),
            str(width // 2), str(height // 3), "330")
        time.sleep(.25)
    raise AssertionError("Release diagnostics control did not appear")


def denied(client):
    for method, arg in (("status", None), ("overlay-status", "netbird"), ("routes-status", None), ("auth-status", None)):
        try:
            client.call(method, arg)
        except ControlError as err:
            assert err.code == "local_consent_required", err.code
        else:
            raise AssertionError("Unconsented release read succeeded")


def await_grant(client, enabled):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            result = client.call("status")
            if enabled:
                return result
        except ControlError as err:
            if err.code != "local_consent_required":
                raise
            if not enabled:
                return
        time.sleep(.15)
    raise AssertionError("Release did not acknowledge the local consent change")


def run():
    assert os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("SYN443_CI_AVD") == "syn443-ci"
    assert adb("emu", "avd", "name").splitlines() == [b"syn443-ci", b"OK"]
    assert adb("shell", "getprop", "ro.hardware").strip() in {b"ranchu", b"goldfish"}
    assert adb("shell", "getprop", "ro.build.version.sdk").strip() == b"35"
    assert not adb("shell", "pm", "list", "packages", "--user", "0", PACKAGE).strip()
    serial = subprocess.check_output(["adb", "-e", "get-serialno"], text=True, timeout=12).strip()
    assert re.fullmatch("emulator-[0-9]+", serial)
    client = Device(serial, 12, local_read=True)
    unsigned = Path(os.environ["RUNNER_TEMP"]) / "syn443-release-input" / "app-release-unsigned.apk"
    signing = Path(os.environ["ANDROID_HOME"]) / "build-tools/36.0.0/apksigner"
    with tempfile.TemporaryDirectory() as directory:
        signed = Path(directory) / "ci-release.apk"
        subprocess.run([str(signing), "sign", "--ks", str(Path.home() / ".android/debug.keystore"),
                        "--ks-key-alias", "androiddebugkey", "--ks-pass", "pass:android",
                        "--out", str(signed), str(unsigned)], check=True, timeout=90)
        subprocess.run([str(signing), "verify", str(signed)], check=True, timeout=40)
        assert b"Success" in adb("install", str(signed), timeout=120)
        try:
            denied(client)
            adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
            adb("shell", "wm", "dismiss-keyguard")
            adb("shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity")
            press("Диагностический архив")
            press("Разрешить на 15 минут")
            status = await_grant(client, True)
            capabilities = client.call("capabilities")
            assert capabilities["operations"] == ["capabilities", "status", "logs"]
            assert capabilities["optionalOperations"] == ["overlay-status", "routes-status", "auth-status"]
            netbird = client.call("overlay-status", "netbird")
            assert set(netbird) == {"schemaVersion", "provider", "implementation", "configured", "control", "controlTransport"}
            assert netbird["control"] == netbird["controlTransport"] == "unknown"
            command = [sys.executable, str(Path(__file__).with_name("syn443ctl.py")), "--serial", client.serial,
                       "--local-read", "overlay-status", "--provider", "netbird"]
            projection = json.loads(subprocess.check_output(command, timeout=20))
            assert projection["result"] == netbird
            route_command = command[:command.index("overlay-status")] + ["routes-status"]
            login_command = command[:command.index("overlay-status")] + ["auth-status"]
            login = client.call("auth-status")
            assert set(login) <= {"schemaVersion", "phase", "reason", "busy", "canReauthenticate"}
            assert login["phase"] in {"SIGNED_OUT", "unknown"} and login["schemaVersion"] == 1
            assert json.loads(subprocess.check_output(login_command, timeout=20))["result"] == login
            route_health = client.call("routes-status")
            assert json.loads(subprocess.check_output(route_command, timeout=20))["result"] == route_health
            assert all(row["state"] == "off" for row in route_health["routes"])
            for reserved in ("tailscale", "zerotier"):
                assert client.call("overlay-status", reserved) == {"schemaVersion":1,"provider":reserved,"implementation":"not_implemented"}
            assert (PACKAGE + ":engine").encode() not in adb("shell", "ps", "-A", "-o", "NAME").splitlines()
            assert status["desiredOn"] is False and type(status["generation"]) is int
            assert isinstance(client.call("logs")["events"], list)
            assert b"ok=false" in adb("shell", "content", "call", "--uri", "content://io.syn443.operator.read", "--method", "connect")
            press("Отозвать доступ")
            await_grant(client, False)
            denied(client)
            press("Разрешить на 15 минут")
            assert await_grant(client, True)["schemaVersion"] == 1
            adb("shell", "am", "force-stop", PACKAGE)
            adb("shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity")
            denied(client)
        finally:
            assert b"Success" in adb("uninstall", PACKAGE, timeout=30)
    print("ordinaryReleaseLocalOperatorGrantAndProcessRestart: passed", flush=True)
    print("ordinaryReleasePassiveOverlayWithoutNativeOwner: passed", flush=True)
    print("ordinaryReleasePassiveRouteHealthWithoutNativeOwner: passed", flush=True)
    print("releaseAdbLoginStatusUsesConsentAndReturnsOnlyCurrentPublicFields: passed", flush=True)


if __name__ == "__main__":
    run()
