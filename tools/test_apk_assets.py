from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile
from check_apk_assets import TEST_SUFFIX_LIST, check, expected_assets


class ApkAssetsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, value in [('app/src/main/assets/licenses/fixture.txt', b'synthetic license'),
                            ('contracts/v1/decision-vectors.json', b'{"cases":[]}'),
                            ('app/src/androidTest/assets/chat-fixture.mp4', b'synthetic fixture')]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)

    def apk(self, values, name='app-debug.apk'):
        path = self.root / name
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w') as archive:
                for name, value in values:
                    archive.writestr(name, value)
        return path

    def test_runtime_assets_and_license_bytes_are_preserved(self):
        check(self.apk(list(expected_assets(self.root).items())), self.root)

    def test_instrumentation_requires_exact_pinned_suffix_data_and_runtime_rejects_it(self):
        synthetic = b'public suffix test data'
        expected = [('assets/chat-fixture.mp4', b'synthetic fixture'), (TEST_SUFFIX_LIST, synthetic)]
        test_name = 'app-debug-androidTest.apk'
        with patch('check_apk_assets.TEST_SUFFIX_SHA256', hashlib.sha256(synthetic).hexdigest()):
            check(self.apk(expected, test_name), self.root)
            for invalid in (expected[:1], expected + expected[1:],
                            [expected[0], (TEST_SUFFIX_LIST, b'changed')],
                            [expected[0], ('assets/foreign.list', synthetic)]):
                with self.assertRaises(AssertionError):
                    check(self.apk(invalid, test_name), self.root)
            with self.assertRaises(AssertionError):
                check(self.apk(list(expected_assets(self.root).items()) + expected[1:]), self.root)

    def test_extra_missing_altered_and_duplicate_assets_are_rejected(self):
        values = list(expected_assets(self.root).items())
        for variant in [values + [('assets/test-only-contract.json', b'{}')], values[:-1],
                        values + values[:1], [(n, b'changed') for n, _ in values]]:
            with self.assertRaises(AssertionError):
                check(self.apk(variant), self.root)

    def test_instrumentation_cannot_silently_bundle_runtime_assets(self):
        with self.assertRaises(AssertionError):
            check(self.apk(list(expected_assets(self.root).items()), 'app-debug-androidTest.apk'), self.root)

    def test_instrumentation_fixture_cannot_be_replaced_or_extended(self):
        suffix = b'synthetic suffix list'
        with patch('check_apk_assets.TEST_SUFFIX_SHA256', hashlib.sha256(suffix).hexdigest()):
            for values in [[], [('assets/chat-fixture.mp4', b'changed')],
                           [('assets/chat-fixture.mp4', b'synthetic fixture'), ('assets/private.mp4', b'not allowed')]]:
                with self.assertRaises(AssertionError):
                    check(self.apk(values + [(TEST_SUFFIX_LIST, suffix)], 'app-debug-androidTest.apk'), self.root)
