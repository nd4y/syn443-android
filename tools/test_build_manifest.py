import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from build_manifest import AAR, ABIS, APKS, INPUTS, apk_record, build_record, native_members


class BuildManifestTest(unittest.TestCase):
    def test_records_exact_files_and_primary_native_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, package in APKS:
                path = root / relative
                path.parent.mkdir(parents=True)
                with zipfile.ZipFile(path, "w") as apk:
                    for abi in ABIS:
                        apk.writestr(f"lib/{abi}/libgojni.so", abi.encode())
                version = 0 if package.endswith(".test") else 64
                path.with_name("output-metadata.json").write_text(json.dumps({
                    "applicationId": package, "elements": [
                        {"versionCode": version, "versionName": "0.1.0" if version else "", "outputFile": path.name}
                    ],
                }), encoding="utf-8")
            aar = root / AAR
            aar.parent.mkdir(parents=True)
            with zipfile.ZipFile(aar, "w") as archive:
                for abi in ABIS:
                    archive.writestr(f"jni/{abi}/libgojni.so", abi.encode() + b"-aar")
            for relative in (*INPUTS, Path("dependency-inventory.txt")):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic", encoding="utf-8")
            source = "a" * 40
            with patch("build_manifest.subprocess.check_output", side_effect=[source + "\n", b"?? dependency-inventory.txt\n"]):
                record = build_record(root, source, 123, 2)
            self.assertEqual(record["sourceCommit"], source)
            self.assertEqual((record["actionsRun"], record["actionsAttempt"]), (123, 2))
            self.assertEqual(len(record["artifacts"]), 4)
            self.assertEqual(record["artifacts"][APKS[1][0].as_posix()]["versionCode"], 0)
            for path in (*INPUTS, AAR, APKS[0][0], APKS[1][0]):
                expected = hashlib.sha256((root / path).read_bytes()).hexdigest()
                actual = (record["artifacts"] | record["sourceInputs"])[path.as_posix()]["sha256"]
                self.assertEqual(actual, expected)
            self.assertNotEqual(record["nativeLibraries"]["engineAar"], record["nativeLibraries"]["debugApk"])
            self.assertNotIn(str(root), json.dumps(record))
            with self.assertRaises(ValueError):
                apk_record(root, APKS[0][0], "io.syn443.wrong")

    def test_dirty_wrong_or_unidentified_source_is_rejected(self):
        for responses in (["b" * 40 + "\n"], ["a" * 40 + "\n", b"M  tracked.txt"], ["a" * 40 + "\n", b"?? injected.kt"]):
            with patch("build_manifest.subprocess.check_output", side_effect=responses):
                with self.assertRaises(ValueError):
                    build_record(Path("."), "a" * 40, 123, 1)
        with self.assertRaises(ValueError):
            build_record(Path("."), "unresolved", 123, 1)

    def test_missing_native_member_does_not_publish_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.aar"
            with zipfile.ZipFile(path, "w") as aar:
                aar.writestr("jni/arm64-v8a/libgojni.so", "sample")
            with self.assertRaises(ValueError):
                native_members(path, "jni")
