"""Verify a signed release APK against independent input and signer digests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

MAX_APK = 256 * 1024 * 1024
DIGEST = re.compile(r"[a-f0-9]{64}")
CERT_LINE = re.compile(r"Signer #(\d+) certificate SHA-256 digest: ([a-fA-F0-9]{64})")


def snapshot(source, destination):
    digest = hashlib.sha256()
    total = 0
    with source.open("rb") as reader, destination.open("xb") as writer:
        while chunk := reader.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_APK:
                raise ValueError("APK too large")
            digest.update(chunk)
            writer.write(chunk)
    if total == 0:
        raise ValueError("empty APK")
    return {"sha256": digest.hexdigest(), "bytes": total}


def signer_digest(apksigner, path):
    result = subprocess.run([str(apksigner), "verify", "--min-sdk-version", "29", "--verbose",
                             "--print-certs", str(path)], capture_output=True, timeout=120)
    if result.returncode:
        raise ValueError("APK signature rejected by Android SDK")
    lines = result.stdout.decode("utf-8", errors="strict").splitlines()
    certs = [match.groups() for line in lines if (match := CERT_LINE.fullmatch(line))]
    if len(certs) != 1 or certs[0][0] != "1" or not any(
            line in lines for line in ("Verified using v2 scheme (APK Signature Scheme v2): true",
                                       "Verified using v3 scheme (APK Signature Scheme v3): true")):
        raise ValueError("expected one release signer using the APK signing block")
    return certs[0][1].lower()


def require_alignment(apksigner, apk):
    # Use the same SDK build-tools installation for both checks.
    zipalign = Path(apksigner).with_name("zipalign.exe" if os.name == "nt" else "zipalign")
    result = subprocess.run([str(zipalign), "-c", "-P", "16", "4", str(apk)],
                            capture_output=True, timeout=120)
    if result.returncode:
        raise ValueError("APK ZIP alignment check failed")


def entries(archive):
    info = archive.infolist()
    files = {item.filename: item for item in info}
    if len(files) != len(info) or "AndroidManifest.xml" not in files or "classes.dex" not in files:
        raise ValueError("malformed APK entry list")
    return files


def compare_payloads(original, candidate):
    with zipfile.ZipFile(original) as before, zipfile.ZipFile(candidate) as after:
        expected, received = entries(before), entries(after)
        if expected.keys() != received.keys():
            raise ValueError("APK entry list changed")
        for name, reference in expected.items():
            other = received[name]
            if (reference.file_size, reference.compress_type) != (other.file_size, other.compress_type):
                raise ValueError("APK entry metadata changed")
            with before.open(reference) as left, after.open(other) as right:
                if hashlib.file_digest(left, "sha256").digest() != hashlib.file_digest(right, "sha256").digest():
                    raise ValueError("APK entry contents changed")


def verify(unsigned, signed, expected_input, expected_signer, apksigner):
    if not all(DIGEST.fullmatch(text) for text in (expected_input, expected_signer)):
        raise ValueError("expected two lowercase SHA-256 digests")
    with tempfile.TemporaryDirectory() as directory:
        unsigned_copy = Path(directory) / "input.apk"
        signed_copy = Path(directory) / "candidate.apk"
        source = snapshot(unsigned, unsigned_copy)
        if source["sha256"] != expected_input:
            raise ValueError("unsigned APK digest mismatch")
        result = snapshot(signed, signed_copy)
        if signer_digest(apksigner, signed_copy) != expected_signer:
            raise ValueError("release signer mismatch")
        compare_payloads(unsigned_copy, signed_copy)
        require_alignment(apksigner, signed_copy)
    return {"schemaVersion": 1, "kind": "verified-apk-signing", "unsigned": source,
            "signed": result, "signerCertificateSha256": expected_signer}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsigned", type=Path, required=True)
    parser.add_argument("--signed", type=Path, required=True)
    parser.add_argument("--unsigned-sha256", required=True)
    parser.add_argument("--signer-sha256", required=True)
    parser.add_argument("--apksigner", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.unsigned, args.signed, args.unsigned_sha256, args.signer_sha256,
                            args.apksigner), sort_keys=True))
