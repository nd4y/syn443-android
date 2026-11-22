"""Exercise the operator's offline release tool with the SDK-verified Android APK."""

import base64
import hashlib
import json
import os
import subprocess
import time


def private_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
        out.write(json.dumps(value, separators=(",", ":")).encode())


def recipient(label):
    return base64.urlsafe_b64encode(hashlib.sha256(label).digest()).rstrip(b"=").decode("ascii")


def exercise_delivery(tool, directory, inventory, signed, other_signed, signing_receipt):
    # Both keys are disposable. This P-256 metadata key is independent of the SDK's APK signer.
    key = directory / "release-key.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-out", key], capture_output=True, check=True, timeout=30)
    key.chmod(0o600)
    spki = subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"],
                          capture_output=True, check=True, timeout=30).stdout
    signer_variable = "SYN443_APK_RELEASE_KEY_FILE"
    public_env = {k: v for k, v in os.environ.items() if k != signer_variable}
    signing_env = {**public_env, signer_variable: str(key)}
    record = json.loads(inventory.read_bytes())
    candidate = record["apk"]["versionCode"]
    scope = {"serviceId": "test-service", "deviceId": recipient(b"test device one"),
             "channel": "pilot", "signerCertificateSha256": signing_receipt["signerCertificateSha256"]}
    expected = {"anchor": {"id": "test-releases", "epoch": 1, "spki": base64.b64encode(spki).decode("ascii")},
                "scope": scope, "floor": {},
                "installed": {"versionCode": candidate - 1, "sdk": 35, "abis": ["arm64-v8a"],
                              "requiredEngineCapabilities": ["tun.v1"], "evaluator": "local-v1", "schema": "policy-v1"}}
    trust_file, receipt_file = directory / "installed.json", directory / "signing.json"
    private_json(trust_file, expected)
    private_json(receipt_file, signing_receipt)
    now = int(time.time())
    offer = {"inventorySha256": hashlib.sha256(inventory.read_bytes()).hexdigest(),
             "receiptSha256": hashlib.sha256(receipt_file.read_bytes()).hexdigest(),
             "securityEpoch": 1, "revocationFloor": 0, "issuedAt": now, "notBefore": now, "expires": now + 900,
             "compatibility": {"minimumInstalledVersionCode": candidate - 1,
                               "engineCapabilities": ["tun.v1"], "evaluators": ["local-v1"], "schemas": ["policy-v1"]}}

    def issue(revision):
        proposal = directory / f"offer-{revision}.json"
        private_json(proposal, {**offer, "revision": revision})
        result = subprocess.run([tool, "sign", trust_file, proposal, inventory, receipt_file, signed],
                                env=signing_env, capture_output=True, timeout=120, check=True)
        envelope = directory / f"issued-{revision}.jws"
        envelope.write_bytes(result.stdout)
        return envelope

    def check(trust, envelope, apk, accepted):
        result = subprocess.run([tool, "verify", trust, envelope, apk],
                                env=public_env, capture_output=True, timeout=120)
        if accepted and result.returncode == 0:
            return json.loads(result.stdout)
        if not accepted and result.returncode == 1 and not result.stdout:
            return None
        raise ValueError("unexpected signed APK delivery result")

    original, newer = issue(1), issue(2)
    key.unlink()
    first = check(trust_file, original, signed, True)
    later = check(trust_file, newer, signed, True)
    if first["revision"] != 1 or later["revision"] != 2 or first["scope"] != scope or later["scope"] != scope:
        raise ValueError("unexpected verified subject or revision")
    previous = directory / "accepted.json"
    private_json(previous, {**expected, "floor": later})
    if check(previous, newer, signed, True) != later:
        raise ValueError("repeating identical release changed the accepted floor")
    check(previous, original, signed, False)
    foreign = directory / "other-device.json"
    private_json(foreign, {**expected, "scope": {**scope, "deviceId": recipient(b"test device two")}})
    check(foreign, newer, signed, False)
    check(trust_file, newer, other_signed, False)
    subprocess.run(["./gradlew", ":core:identity:verifyReleaseDelivery", "--quiet"],
                   env={**public_env, "SYN443_RELEASE_FIXTURE_DIR": str(directory)},
                   check=True, timeout=240)
    return ["kotlin-verified-signed-apk", "addressed-release", "unchanged-release-retry", "stale-release-revision",
            "foreign-release-device", "other-apk-with-same-signer"]
