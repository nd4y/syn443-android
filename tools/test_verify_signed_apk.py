from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

from verify_signed_apk import compare_payloads, require_alignment, signer_digest, verify
from unittest.mock import patch
from subprocess import CompletedProcess


class SignedApkTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def apk(self, name, entries):
        path = self.root / name
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as archive:
                for member, body in entries:
                    archive.writestr(member, body)
        return path

    def test_entry_verification_rejects_modified_bytes_missing_extra_and_duplicate_members(self):
        base = [("AndroidManifest.xml", b"fixture"), ("classes.dex", b"sample")]
        original = self.apk("input.apk", base)
        compare_payloads(original, self.apk("same.apk", base))
        for modified in ([base[0], ("classes.dex", b"tamper")], base[:-1], base + [("more", b"data")], base + base[:1]):
            with self.subTest(entries=len(modified)), self.assertRaises(ValueError):
                compare_payloads(original, self.apk("candidate.apk", modified))

    def test_sdk_must_verify_one_pinned_certificate_using_the_apk_signing_block(self):
        value = "ab" * 32
        cert = f"Signer #1 certificate SHA-256 digest: {value}"
        scheme = "Verified using v2 scheme (APK Signature Scheme v2): true"
        cases = [(0, [scheme, cert], True), (1, [scheme, cert], False),
                 (0, [cert], False), (0, [scheme, cert, cert.replace("#1", "#2")], False),
                 (0, [scheme, cert.replace("#1", "#2")], False)]
        for code, lines, valid in cases:
            result = CompletedProcess([], code, "\n".join(lines).encode(), b"")
            with self.subTest(code=code, lines=len(lines)), patch("verify_signed_apk.subprocess.run", return_value=result):
                if valid:
                    self.assertEqual(value, signer_digest("apksigner", self.root))
                else:
                    with self.assertRaises(ValueError):
                        signer_digest("apksigner", self.root)

    def test_sdk_checks_the_final_snapshot_in_read_only_mode(self):
        import os
        signer = self.root / ("apksigner.bat" if os.name == "nt" else "apksigner")
        aligner = self.root / ("zipalign.exe" if os.name == "nt" else "zipalign")
        candidate = self.root / "candidate.apk"
        for code in (0, 1):
            with self.subTest(code=code), patch("verify_signed_apk.subprocess.run",
                    return_value=CompletedProcess([], code, b"", b"")) as run:
                if code:
                    with self.assertRaisesRegex(ValueError, "ZIP alignment"):
                        require_alignment(signer, candidate)
                else:
                    require_alignment(signer, candidate)
                run.assert_called_once_with([str(aligner), "-c", "-P", "16", "4", str(candidate)],
                                            capture_output=True, timeout=120)

    def test_invalid_expectations_are_rejected_before_file_access(self):
        missing = self.root / "missing"
        with self.assertRaisesRegex(ValueError, "two lowercase"):
            verify(missing, missing, "ab" * 32, "invalid", missing)
