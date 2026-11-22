"""Create a disposable profiled test APK and an addressed public release offer in CI.

Private keys remain in temporary directories on the build runner. The ordinary
debug APK, upgrade APK, and unsigned release input are already sealed by CI.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from build_manifest import describe, native_members
from check_installation_profile import check_profile
from policy_fixture import Publisher, b64
from verify_signed_apk import signer_digest


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def main(directory, manifest_path):
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    manifest = json.loads(manifest_path.read_bytes())
    pair = json.loads((directory / "upgrade.json").read_bytes())
    candidate = directory / "new-debug.apk"
    assert describe(candidate) == pair["candidate"] and pair["sourceCommit"] == manifest["sourceCommit"]
    device = b64(hashlib.sha256(("syn443/installer-ci/" + str(pair["actionsRun"])).encode("ascii")).digest())
    now = int(time.time()) - 10
    with contextlib.ExitStack() as stack:
        bootstrap, policies, releases = [stack.enter_context(contextlib.closing(Publisher())) for _ in range(3)]
        def signed(key, kid, kind, value):
            return key.signed_document({"alg":"ES256", "kid":kid, "typ":kind}, value)
        service = "emulator"
        descriptor = {"schemaVersion":1, "audience":"syn443-client-bootstrap", "rootEpoch":1,
                      "revision":1, "serviceId":service, "issuer":"https://id.example.invalid/realms/test",
                      "clientId":"test", "apiOrigin":"https://control.example.invalid",
                      "roots":{"policy-ci":policies.spki}, "issuedAt":now, "notBefore":now, "expires":now+86400}
        release_id = "ci-releases"
        profile = b64(canonical({"schemaVersion":3, "anchor":{"id":"ci-install","epoch":1,"spki":bootstrap.spki},
                        "service":signed(bootstrap,"ci-install","syn443-bootstrap+jws",descriptor),
                        "releaseAuthority":{"serviceId":service, "channel":"ci", "anchor":{
                            "id":release_id, "epoch":1, "spki":releases.spki}}}))
        check_profile(profile)
        subprocess.run(["./gradlew", ":app:assembleDebug"], env={**os.environ, "SYN443_INSTALLATION_PROFILE":profile},
                       check=True, timeout=600)
        profiled=directory / "installer-base.apk"
        shutil.copyfile("app/build/outputs/apk/debug/app-debug.apk", profiled)
        signer=Path(os.environ["ANDROID_HOME"]) / "build-tools/36.0.0/apksigner"
        assert signer_digest(signer,profiled)==pair["signerSha256"]
        expected_libs=manifest["nativeLibraries"]["debugApk"]
        assert native_members(profiled,"lib")==expected_libs and native_members(candidate,"lib")==expected_libs
        def field(file, name):
            return subprocess.check_output(["apkanalyzer","manifest",name,str(file)],text=True,timeout=90).strip()
        assert field(profiled,"application-id")=="io.syn443.android" and int(field(profiled,"version-code"))==pair["previous"]
        locks=manifest["sourceInputs"]
        offer={"schemaVersion":1,"audience":"syn443-device-release","scope":{
                   "serviceId":service,"deviceId":device,"channel":"ci","signerCertificateSha256":pair["signerSha256"]},
               "rootEpoch":1,"securityEpoch":1,"revision":1,"revocationFloor":0,"issuedAt":now,"notBefore":now,
               "expires":now+86400, "apk":{"package":"io.syn443.android","versionCode":pair["following"],
                   "minSdk":int(field(candidate,"min-sdk")),"targetSdk":int(field(candidate,"target-sdk")),
                   "nativeLibraries":expected_libs, **pair["candidate"],"sourceCommit":pair["sourceCommit"],
                   "engineLockSha256":locks["native/engine-lock.json"]["sha256"],
                   "contractLockSha256":locks["contracts/lock.json"]["sha256"]},
               "compatibility":{"minimumInstalledVersionCode":pair["previous"],
                   "engineCapabilities":["engine-config.v1","policy.keybound.v2","tun.lease.v1"],
                   "evaluators":["m1-local-v1"],"schemas":["policy-v2"]}}
        (directory/"syn443-update.txt").write_text(signed(releases,release_id,"syn443-apk-release+jws",offer), encoding="ascii")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
