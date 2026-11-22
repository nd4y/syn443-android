"""Verify and prepare two archived protected-build APKs for a disposable emulator."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from build_manifest import APKS, describe
from exercise_signed_apk import run
from verify_signed_apk import signer_digest


REPOSITORY = "nd4y/syn443-android"
MANIFEST = "syn443-build-manifest"
PACKAGES = "syn443-prototype-debug-apks"


def api(endpoint):
    return json.loads(subprocess.check_output(["gh", "api", f"repos/{REPOSITORY}/{endpoint}"], timeout=60))


def version(commit):
    gradle = subprocess.check_output(["git", "show", commit + ":app/build.gradle.kts"], text=True)
    values = re.findall(r"^\s*versionCode\s*=\s*(\d+)\s*$", gradle, re.MULTILINE)
    if len(values) != 1:
        raise ValueError("Ambiguous Android version in protected source")
    return int(values[0])


def select_runs(runs, main_history, candidate_id, previous_id):
    # First-parent history excludes feature-only revisions even if they were
    # built on a branch that happened to be called main.
    order = {commit: i for i, commit in enumerate(main_history)}
    known = [r for r in runs if r.get("event") == "push" and r.get("head_branch") == "main"
             and r.get("conclusion") == "success" and r.get("head_sha") in order
             and r.get("path") == ".github/workflows/ci.yml"
             and r.get("head_repository", {}).get("full_name") == REPOSITORY]
    known.sort(key=lambda r: (order[r["head_sha"]], -r["id"]))
    current = next((r for r in known if candidate_id is None or r["id"] == candidate_id), None)
    if current is None:
        raise ValueError("A successful protected candidate run is required")
    current_version = version(current["head_sha"])
    previous = next((r for r in known if order[r["head_sha"]] > order[current["head_sha"]]
                     and (previous_id is None or r["id"] == previous_id)
                     and version(r["head_sha"]) < current_version), None)
    if previous is None:
        raise ValueError("No protected ancestor with a lower Android version in the available inputs")
    return previous, current


def read_members(directory, artifact, members, size_limit):
    if artifact["expired"] or not 0 < artifact["size_in_bytes"] <= size_limit:
        raise ValueError("Required Actions artifact has expired or exceeds its size limit")
    archive = directory / "download.zip"
    with archive.open("wb") as stream:
        subprocess.run(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip"],
                       stdout=stream, check=True, timeout=420)
    with archive.open("rb") as stream:
        if (archive.stat().st_size != artifact["size_in_bytes"] or
                "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() != artifact["digest"]):
            raise ValueError("Downloaded archive differs from its GitHub artifact digest")
    with zipfile.ZipFile(archive) as z:
        for name, output, limit in members:
            matches = [info for info in z.infolist() if info.filename == name]
            if len(matches) != 1 or not 0 < matches[0].file_size <= limit:
                raise ValueError("Missing, duplicate, or oversized Actions artifact member")
            with z.open(matches[0]) as src, output.open("xb") as dest:
                shutil.copyfileobj(src, dest)
    archive.unlink()


def collect(work, item, include_driver):
    run_id, commit = item["id"], item["head_sha"]
    work.mkdir()
    artifacts = api(f"actions/runs/{run_id}/artifacts?per_page=100")["artifacts"]
    def artifact(name):
        matches = [a for a in artifacts if a["name"] == name and not a["expired"]]
        if len(matches) != 1:
            raise ValueError(f"Expected one retained {name} for run {run_id}")
        return matches[0]
    manifest_archive, apk_archive = artifact(MANIFEST), artifact(PACKAGES)
    read_members(work, manifest_archive, [("build-manifest.json", work / "manifest.json", 65536)], 1048576)
    manifest = json.loads((work / "manifest.json").read_bytes())
    if (manifest["schemaVersion"] != 1 or manifest["actionsRun"] != run_id or
            not 1 <= manifest["actionsAttempt"] <= item["run_attempt"] or manifest["sourceCommit"] != commit):
        raise ValueError("Manifest has different provenance")
    selected = APKS if include_driver else APKS[:1]
    paths = [(p.relative_to("app/build/outputs/apk").as_posix(), work / p.name, 268435456) for p, _ in selected]
    read_members(work, apk_archive, paths, 536870912)
    for (path, package), (_, apk, _) in zip(selected, paths, strict=True):
        entry = manifest["artifacts"][path.as_posix()]
        if describe(apk) != {k: entry[k] for k in ("sha256", "bytes")} or entry["package"] != package:
            raise ValueError("APK payload differs from its build manifest")
    app = manifest["artifacts"][APKS[0][0].as_posix()]
    if app["versionCode"] != version(commit):
        raise ValueError("Build manifest and protected source disagree about the installed version")
    return {"run": run_id, "source": commit, "version": app["versionCode"], "sha256": app["sha256"],
            "manifestArchiveDigest": manifest_archive["digest"], "apkArchiveDigest": apk_archive["digest"]}


def run_number(name):
    value = os.environ.get(name, "")
    if not value:
        return None
    if not re.fullmatch(r"[1-9][0-9]{0,15}", value):
        raise ValueError("Invalid Actions run number")
    return int(value)


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ValueError("Disposable project CI only")
    work = Path(os.environ["RUNNER_TEMP"]) / "historical-upgrade"
    work.mkdir(mode=0o700)
    recent = api("actions/workflows/ci.yml/runs?event=push&branch=main&status=success&per_page=100")["workflow_runs"]
    candidate_id, previous_id = run_number("CANDIDATE_RUN"), run_number("PREVIOUS_RUN")
    for number in (candidate_id, previous_id):
        if number and not any(r["id"] == number for r in recent):
            recent.append(api(f"actions/runs/{number}"))
    history = subprocess.check_output(["git", "rev-list", "--first-parent", "origin/main"], text=True).splitlines()
    old_run, new_run = select_runs(recent, history, candidate_id, previous_id)
    old = collect(work / "previous", old_run, True)
    new = collect(work / "candidate", new_run, False)
    sdk = Path(os.environ["ANDROID_HOME"]) / "build-tools/36.0.0/apksigner"
    pairs = [(work / "previous/app-debug.apk", work / "previous.apk"),
             (work / "previous/app-debug-androidTest.apk", work / "driver.apk"),
             (work / "candidate/app-debug.apk", work / "new-debug.apk")]
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        keydir = Path(tmp)
        pem, cert, key = [keydir / n for n in ("test.pem", "test.crt", "test.pk8")]
        run(["openssl", "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
             "-subj", "/CN=Emulator", "-keyout", str(pem), "-out", str(cert)])
        run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem), "-outform", "DER", "-out", str(key)])
        original_signers = [signer_digest(sdk, src) for src, _ in pairs]
        if original_signers[0] != original_signers[1]:
            raise ValueError("Old application and enrollment driver have different signers")
        for src, dest in pairs:
            run([str(sdk), "sign", "--key", str(key), "--cert", str(cert), "--out", str(dest), str(src)])
        if len({signer_digest(sdk, dest) for _, dest in pairs}) != 1:
            raise ValueError("The three packages must share a disposable signer")
    public = {"previousBuild": old, "candidateBuild": new, "previous": old["version"], "following": new["version"]}
    (work / "upgrade.json").write_text(json.dumps(public, indent=2) + "\n")


if __name__ == "__main__":
    main()
