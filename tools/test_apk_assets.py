from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile
from check_apk_assets import CHAT_VIDEO_FIXTURES, TEST_SUFFIX_LIST, check, expected_assets


class ApkAssetsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.clips = [('assets/' + name, name.encode()) for name in CHAT_VIDEO_FIXTURES]
        self.sing_box = '1' * 40
        self.netbird = '2' * 40
        lock = {'sources': {'sing-box': {'revision': self.sing_box}, 'netbird': {'revision': self.netbird}}}
        (self.root / 'native').mkdir()
        (self.root / 'native/engine-lock.json').write_text(json.dumps(lock), encoding='utf-8')
        for name, value in [('app/src/main/assets/licenses/fixture.txt', b'synthetic license'),
                            ('contracts/v1/decision-vectors.json', b'{"cases":[]}')] + [
                                ('app/src/androidTest/' + name, data) for name, data in self.clips]:
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

    def test_engine_build_metadata_cannot_be_substituted(self):
        name = 'assets/engine-builds.json'
        values = expected_assets(self.root)
        builds = json.loads(values[name])
        self.assertEqual(builds, {'schemaVersion': 1, 'singBoxRevision': self.sing_box, 'netBirdRevision': self.netbird})
        builds['netBirdRevision'] = '3' * 40
        values[name] = json.dumps(builds, separators=(',', ':')).encode()
        with self.assertRaises(AssertionError):
            check(self.apk(values.items()), self.root)

    def test_instrumentation_requires_exact_pinned_suffix_data_and_runtime_rejects_it(self):
        synthetic = b'public suffix test data'
        expected = self.clips + [(TEST_SUFFIX_LIST, synthetic)]
        test_name = 'app-debug-androidTest.apk'
        with patch('check_apk_assets.TEST_SUFFIX_SHA256', hashlib.sha256(synthetic).hexdigest()):
            check(self.apk(expected, test_name), self.root)
            for invalid in (self.clips, expected + expected[-1:],
                            self.clips + [(TEST_SUFFIX_LIST, b'changed')],
                            self.clips + [('assets/foreign.list', synthetic)]):
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

    def test_release_compiler_profiles_must_match_and_cannot_enter_debug_apks(self):
        files = [('binary_art_profile', 'baseline.prof', b'pro\x00010\x00synthetic'),
                 ('binary_art_profile_metadata', 'baseline.profm', b'prm\x00002\x00synthetic')]
        members = []
        for artifact, name, data in files:
            file = self.root / 'app/build/intermediates' / artifact / 'release/compileReleaseArtProfile' / name
            file.parent.mkdir(parents=True)
            file.write_bytes(data)
            members.append(('assets/dexopt/' + name, data))
        normal = list(expected_assets(self.root).items())
        release_name = 'app-release-unsigned.apk'
        check(self.apk(normal + members, release_name), self.root)
        for entries in (normal, normal + members[:1], normal + members + [members[0]],
                        normal + [members[0], (members[1][0], members[1][1] + b'changed')]):
            with self.assertRaises(AssertionError):
                check(self.apk(entries, release_name), self.root)
        with self.assertRaises(AssertionError):
            check(self.apk(normal + members), self.root)
        file.write_bytes(b'unknown-format')
        with self.assertRaises(AssertionError):
            check(self.apk(normal + members, release_name), self.root)

    def test_instrumentation_cannot_silently_bundle_runtime_assets(self):
        with self.assertRaises(AssertionError):
            check(self.apk(list(expected_assets(self.root).items()), 'app-debug-androidTest.apk'), self.root)

    def test_instrumentation_fixture_cannot_be_replaced_or_extended(self):
        suffix = b'synthetic suffix list'
        with patch('check_apk_assets.TEST_SUFFIX_SHA256', hashlib.sha256(suffix).hexdigest()):
            for values in [self.clips[1:], self.clips + [('assets/private.mp4', b'extra')]] + [
                    [(name, b'changed' if name == changed else value) for name, value in self.clips]
                    for changed, _ in self.clips]:
                with self.assertRaises(AssertionError):
                    check(self.apk(values + [(TEST_SUFFIX_LIST, suffix)], 'app-debug-androidTest.apk'), self.root)
