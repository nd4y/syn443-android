from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile
from check_apk_assets import check, expected_assets


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
        check(self.apk([('assets/chat-fixture.mp4', b'synthetic fixture')], 'app-debug-androidTest.apk'), self.root)

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
        for values in [[], [('assets/chat-fixture.mp4', b'changed')],
                       [('assets/chat-fixture.mp4', b'synthetic fixture'), ('assets/private.mp4', b'not allowed')]]:
            with self.assertRaises(AssertionError):
                check(self.apk(values, 'app-debug-androidTest.apk'), self.root)
