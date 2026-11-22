"""Bind the higher-version debug APK to the original APK and its CI receipt."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from build_manifest import APKS, describe, native_members
from verify_signed_apk import signer_digest


def inspect_pair(base, candidate, manifest, root):
    source = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if (manifest["sourceCommit"] != source or manifest["actionsRun"] != int(os.environ["GITHUB_RUN_ID"])
            or not 1 <= manifest["actionsAttempt"] <= int(os.environ["GITHUB_RUN_ATTEMPT"])):
        raise ValueError("Base manifest belongs to another build")
    record = manifest["artifacts"][APKS[0][0].as_posix()]
    if describe(base) != {key: record[key] for key in ("bytes", "sha256")}:
        raise ValueError("Base APK differs from its CI receipt")
    sdk = Path(os.environ["ANDROID_HOME"]) / "build-tools/36.0.0/apksigner"
    signer = signer_digest(sdk, base)
    if signer != signer_digest(sdk, candidate):
        raise ValueError("Candidate signer differs from base")
    def field(path, name):
        return subprocess.check_output(["apkanalyzer", "manifest", name, str(path)], text=True, timeout=120).strip()
    if any(field(path, "application-id") != record["package"] for path in (base, candidate)):
        raise ValueError("Unexpected package")
    previous = int(field(base, "version-code"))
    following = int(field(candidate, "version-code"))
    if previous != record["versionCode"] or following != previous + 1:
        raise ValueError("Expected a single real version increment")
    if native_members(candidate, "lib") != manifest["nativeLibraries"]["debugApk"]:
        raise ValueError("Embedded engine differs from base")
    return {"sourceCommit": source, "actionsRun": manifest["actionsRun"], "actionsAttempt": manifest["actionsAttempt"],
            "previous": previous, "following": following, "baseSha256": record["sha256"],
            "candidate": describe(candidate), "signerSha256": signer}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("record", "verify"))
    for argument in ("base", "candidate", "manifest", "receipt"):
        parser.add_argument(argument, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    receipt = inspect_pair(args.base, args.candidate, json.loads(args.manifest.read_bytes()), root)
    if args.mode == "record":
        args.receipt.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    elif receipt != json.loads(args.receipt.read_bytes()):
        raise ValueError("Upgrade fixture differs from build receipt")


if __name__ == "__main__":
    main()
