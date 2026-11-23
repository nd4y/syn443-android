"""Describe the Android release build passed to an independent signer."""

import argparse
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from build_manifest import AAR, apk_record, describe, native_members

ANDROID = "{http://schemas.android.com/apk/res/android}"
PACKAGE = "io.syn443.android"
APK = Path("app/build/outputs/apk/release/app-release-unsigned.apk")


def inspect_manifest(xml, metadata):
    manifest = ET.fromstring(xml)
    if manifest.tag != "manifest" or manifest.get("package") != PACKAGE:
        raise ValueError("unexpected application")
    if (manifest.get(ANDROID + "versionCode") != str(metadata["versionCode"]) or
            manifest.get(ANDROID + "versionName") != metadata["versionName"]):
        raise ValueError("manifest and APK output metadata disagree")
    sdk, = manifest.findall("uses-sdk")
    minimum = int(sdk.attrib[ANDROID + "minSdkVersion"])
    target = int(sdk.attrib[ANDROID + "targetSdkVersion"])
    if minimum != 29 or target < 37:
        raise ValueError("unexpected release SDK")
    app, = manifest.findall("application")
    if (app.get(ANDROID + "allowBackup") != "false" or
            any(app.get(ANDROID + flag, "false") != "false"
                for flag in ("debuggable", "testOnly", "usesCleartextTraffic")) or
            manifest.findall("instrumentation")):
        raise ValueError("debug, backup or cleartext application flags")

    def name(element):
        raw = element.get(ANDROID + "name", "")
        return PACKAGE + raw if raw.startswith(".") else raw

    control, = [item for item in app.findall("provider") if name(item) == PACKAGE + ".vpn.ControlProvider"]
    if control.get(ANDROID + "exported") != "false" or control.get(ANDROID + "authorities") != "io.syn443.control":
        raise ValueError("release control provider must be private")
    diagnostic, = [item for item in app.findall("provider") if name(item) == PACKAGE + ".vpn.OperatorReadProvider"]
    expected = {"authorities": "io.syn443.operator.read", "permission": "android.permission.DUMP",
                "exported": "true", "process": ":controller", "grantUriPermissions": "false"}
    if (any(diagnostic.get(ANDROID + key) != value for key, value in expected.items()) or
            any(diagnostic.get(ANDROID + key) is not None for key in ("readPermission", "writePermission")) or
            diagnostic.findall("path-permission") or diagnostic.findall("grant-uri-permission")):
        raise ValueError("unexpected release operator read boundary")
    vpn, = [item for item in app.findall("service") if name(item) == PACKAGE + ".vpn.TunnelService"]
    if vpn.get(ANDROID + "permission") != "android.permission.BIND_VPN_SERVICE":
        raise ValueError("VPN service missing the system permission")
    if (any(name(item) == PACKAGE + ".HostProbeService" for item in app.findall("service")) or
            any("io.syn443.chat.fixture" in item.get(ANDROID + "authorities", "").split(";")
                for item in app.findall("provider"))):
        raise ValueError("debug fixture in release package")
    return {"minSdk": minimum, "targetSdk": target}


def inventory(root, manifest, commit):
    if not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("invalid source revision")
    apk = apk_record(root, APK, PACKAGE)
    sdk = inspect_manifest(manifest, apk)
    libraries = native_members(root / APK, "lib")
    if libraries != native_members(root / AAR, "jni"):
        raise ValueError("release APK differs from the verified native engine artifact")
    return {"schemaVersion": 1, "kind": "unsigned-release-input", "sourceCommit": commit,
            "apk": {**apk, **sdk, "file": APK.name}, "nativeLibraries": libraries,
            "engineLock": describe(root / "native/engine-lock.json"),
            "contractLock": describe(root / "contracts/lock.json")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("source_commit")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    record = inventory(Path.cwd(), args.manifest.read_bytes(), args.source_commit)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
