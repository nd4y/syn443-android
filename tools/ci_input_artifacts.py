"""Read the immutable archives emitted by this workflow's producer job."""
import os
from pathlib import Path
import re
import sys
import tempfile

from build_manifest import APKS, APK_ROOT
from protected_upgrade_inputs import MANIFEST, PACKAGES, api, read_members

ENGINE = "embedded-native-engine"
UPGRADE = "syn443-version-upgrade-fixture"
MIB = 1024 * 1024


def validate_artifact(artifact, artifact_id, name, run, source):
    provenance = artifact.get("workflow_run") or {}
    if (artifact.get("id") != artifact_id or artifact.get("name") != name
            or artifact.get("expired") is not False or provenance.get("id") != run
            or provenance.get("head_sha") != source
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest") or "")):
        raise ValueError("Artifact does not belong to the requested workflow input")


def fetch(name, id_var, members, limit):
    value = os.environ[id_var]
    if not re.fullmatch(r"[1-9][0-9]{0,18}", value):
        raise ValueError("Missing immutable artifact ID for " + name)
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid GitHub repository")
    artifact = api("actions/artifacts/" + value, repository)
    validate_artifact(artifact, int(value), name, int(os.environ["GITHUB_RUN_ID"]), os.environ["SOURCE_COMMIT"])
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as scratch:
        for _, destination, _ in members:
            destination.parent.mkdir(parents=True, exist_ok=True)
        read_members(Path(scratch), artifact, members, limit, repository)
    print(f"Verified {name} artifact {value}", flush=True)


def main(stage):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("This command consumes GitHub Actions job outputs")
    root = Path(__file__).resolve().parents[1]
    temp = Path(os.environ["RUNNER_TEMP"])
    if stage == "native":
        fetch(ENGINE, "ENGINE_ARTIFACT_ID", [("engine.aar", root / "native/build/engine.aar", 128 * MIB)], 128 * MIB)
    elif stage == "emulator":
        fetch(MANIFEST, "MANIFEST_ARTIFACT_ID", [("build-manifest.json", temp / "build-manifest.json", 65536)], MIB)
        apks = [(p.relative_to(APK_ROOT).as_posix(), root / p, 256 * MIB) for p, _ in APKS]
        for path, _ in APKS:
            metadata = path.with_name("output-metadata.json")
            apks.append((metadata.relative_to(APK_ROOT).as_posix(), root / metadata, 1048576))
        fetch(PACKAGES, "APK_ARTIFACT_ID", apks, 512 * MIB)
        fixture = temp / "upgrade-fixture"
        fetch(UPGRADE, "UPGRADE_ARTIFACT_ID", [("new-debug.apk", fixture / "new-debug.apk", 256 * MIB),
                                                ("upgrade.json", fixture / "upgrade.json", 65536)], 512 * MIB)
    else:
        raise ValueError("Unknown build stage")


if __name__ == "__main__":
    main(sys.argv[1])
