"""Record the exact CI source and delivery inputs without exporting host data."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

APK_ROOT = Path("app/build/outputs/apk")
APKS = (
    (APK_ROOT / "debug/app-debug.apk", "io.syn443.android"),
    (APK_ROOT / "androidTest/debug/app-debug-androidTest.apk", "io.syn443.android.test"),
)
AAR = Path("native/build/engine.aar")
INPUTS = (
    Path("native/engine-lock.json"), Path("native/bridge/go.mod"),
    Path("native/bridge/go.sum"), Path("gradle/wrapper/gradle-wrapper.properties"),
    Path("contracts/lock.json"),
)
ABIS = ("arm64-v8a", "x86_64")


def describe(path):
    with path.open("rb") as content:
        size = path.stat().st_size
        if size <= 0:
            raise ValueError("Empty manifest input")
        return {"bytes": size, "sha256": hashlib.file_digest(content, "sha256").hexdigest()}


def native_members(path, prefix):
    result = {}
    with zipfile.ZipFile(path) as archive:
        for abi in ABIS:
            name = f"{prefix}/{abi}/libgojni.so"
            entries = [entry for entry in archive.infolist() if entry.filename == name]
            if len(entries) != 1 or not 0 < entries[0].file_size <= 128 * 1024 * 1024:
                raise ValueError("Missing, duplicate or unbounded primary native library")
            with archive.open(entries[0]) as content:
                result[abi] = hashlib.file_digest(content, "sha256").hexdigest()
    return result


def apk_record(root, relative, application):
    path = root / relative
    metadata = json.loads(path.with_name("output-metadata.json").read_text(encoding="utf-8"))
    elements = metadata.get("elements", [])
    if (metadata.get("applicationId") != application or len(elements) != 1 or
            elements[0].get("outputFile") != relative.name):
        raise ValueError("APK output metadata does not describe the expected package")
    item = elements[0]
    is_test = application == "io.syn443.android.test"
    version = item.get("versionCode")
    if type(version) is not int or not (0 if is_test else 1) <= version <= 2_100_000_000:
        raise ValueError("Invalid APK version code")
    name = item.get("versionName")
    if not (is_test and name in ("", None)) and (
            not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", name)):
        raise ValueError("Invalid APK version name")
    return {**describe(path), "package": application, "versionCode": version, "versionName": name}


def build_record(root, source, run, attempt):
    if not re.fullmatch(r"[0-9a-f]{40}", source) or not 1 <= run <= 2**53 - 1 or not 1 <= attempt <= 1000:
        raise ValueError("Invalid CI provenance inputs")
    git = ["git", "-C", str(root)]
    actual = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    if actual != source:
        raise ValueError("Checkout does not match the requested source commit")
    changes = subprocess.check_output([*git, "status", "--porcelain", "--untracked-files=all"]).splitlines()
    if any(change != b"?? dependency-inventory.txt" for change in changes):
        raise ValueError("Unexpected tracked or untracked source changes")

    aars = {AAR.as_posix(): describe(root / AAR)}
    apks = {path.as_posix(): apk_record(root, path, application) for path, application in APKS}
    dependencies = Path("dependency-inventory.txt")
    return {
        "schemaVersion": 1,
        "sourceCommit": source,
        "actionsRun": run,
        "actionsAttempt": attempt,
        "artifacts": {**apks, **aars, dependencies.as_posix(): describe(root / dependencies)},
        "sourceInputs": {path.as_posix(): describe(root / path) for path in INPUTS},
        "nativeLibraries": {
            "engineAar": native_members(root / AAR, "jni"),
            "debugApk": native_members(root / APKS[0][0], "lib"),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("run", type=int)
    parser.add_argument("attempt", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    record = build_record(root, args.source, args.run, args.attempt)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
