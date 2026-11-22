"""Exercise an independent APK signer on the normal release in an isolated Actions directory."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

from exercise_release_delivery import exercise_delivery
from verify_signed_apk import require_alignment, verify


def run(command):
    # OpenSSL and SDK diagnostics must never publish a temporary key or identity.
    result = subprocess.run(command, capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"{Path(command[0]).name} failed in signing fixture")


def exercise(unsigned, inventory, apksigner, release_tool):
    record = json.loads(inventory.read_bytes())
    if record["kind"] != "unsigned-release-input":
        raise ValueError("expected the checked normal release input")
    expected = record["apk"]["sha256"]
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        pem, cert, key, der = [work / name for name in ("test.pem", "test.crt", "test.pk8", "test.der")]
        run(["openssl", "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
             "-subj", "/CN=Synthetic fixture", "-keyout", str(pem), "-out", str(cert)])
        run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem), "-outform", "DER", "-out", str(key)])
        run(["openssl", "x509", "-in", str(cert), "-outform", "DER", "-out", str(der)])
        pin = hashlib.sha256(der.read_bytes()).hexdigest()

        def sign(source, target):
            run([str(apksigner), "sign", "--key", str(key), "--cert", str(cert),
                 "--v1-signing-enabled", "false", "--v2-signing-enabled", "true",
                 "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
                 "--out", str(target), str(source)])

        def rejected(candidate, digest, signer, reason):
            try:
                verify(unsigned, candidate, digest, signer, apksigner)
            except ValueError as error:
                if str(error) == reason:
                    return
                raise
            raise AssertionError("unexpectedly accepted a signing fixture")

        signed = work / "normal.apk"
        sign(unsigned, signed)
        receipt = verify(unsigned, signed, expected, pin, apksigner)
        with signed.open("rb") as candidate:
            if receipt["signed"] != {"bytes": signed.stat().st_size, "sha256": hashlib.file_digest(candidate, "sha256").hexdigest()}:
                raise ValueError("signed release inventory mismatch")
        if receipt["signed"]["sha256"] == expected:
            raise ValueError("signed and unsigned release digests must differ")
        def changed(value):
            return ("1" if value[0] == "0" else "0") + value[1:]
        rejected(signed, changed(expected), pin, "unsigned APK digest mismatch")
        rejected(signed, expected, changed(pin), "release signer mismatch")
        rejected(unsigned, expected, pin, "APK signature rejected by Android SDK")
        different = work / "different.apk"
        shutil.copyfile(unsigned, different)
        with zipfile.ZipFile(different, "a") as archive:
            archive.writestr("assets/synthetic-extra", b"fixture")
        signed_different = work / "different-signed.apk"
        sign(different, signed_different)
        rejected(signed_different, expected, pin, "APK entry list changed")
        # The layout check uses ZIP offsets, independently of ELF contents or the signing key.
        unaligned = work / "unaligned-fixture.zip"
        with zipfile.ZipFile(unaligned, "w") as archive:
            archive.writestr("lib/arm64-v8a/libfixture.so", b"synthetic layout fixture")
        try:
            require_alignment(apksigner, unaligned)
        except ValueError as error:
            if str(error) != "APK ZIP alignment check failed":
                raise
        else:
            raise AssertionError("SDK accepted an unaligned native library")
        delivery = exercise_delivery(release_tool, work, inventory, signed, signed_different, receipt)
    return {"schemaVersion": 1, "sourceCommit": record["sourceCommit"], "versionCode": record["apk"]["versionCode"],
            "kind": "synthetic-signing-acceptance", "passed": ["signed-release", "modified-input-digest",
            "wrong-certificate", "unsigned-apk", "different-payload-with-valid-signature",
            "signed-apk-alignment", "unaligned-native-library", *delivery]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unsigned", type=Path)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("apksigner", type=Path)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--release-tool", required=True, type=Path)
    args = parser.parse_args()
    result = exercise(args.unsigned, args.inventory, args.apksigner, args.release_tool)
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Signed release identity, content and 16 KiB archive alignment verified")
