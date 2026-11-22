"""Admit only explicit runtime assets and original license files into the APK."""
from pathlib import Path
import hashlib
import sys
import zipfile

# OkHttp Android 5.5.1, verified against the published AAR and the matching
# Square tag, okhttp/src/androidMain/assets/PublicSuffixDatabase.list.
CHAT_VIDEO_FIXTURES = ('chat-fixture.mp4', 'chat-square.mp4', 'chat-rotated.mp4')
TEST_SUFFIX_LIST = 'assets/PublicSuffixDatabase.list'
TEST_SUFFIX_SHA256 = 'c75ab827afd7ffff59a51b14729c25dbfc3b45237eb40ccf02bec7b7d44304a4'


def expected_assets(root):
    base = root / 'app/src/main/assets'
    result = {'assets/' + str(p.relative_to(base)).replace('\\', '/'): p.read_bytes()
              for p in base.rglob('*') if p.is_file()}
    result['assets/decision-vectors.json'] = (root / 'contracts/v1/decision-vectors.json').read_bytes()
    return result


def release_art_profiles(root):
    # AGP 9.4.1 CompileArtProfileTask publishes these two independent outputs.
    # Use the compiler outputs as the source of truth for the packaged bytes.
    profiles = {}
    for artifact, filename, magic in (
        ('binary_art_profile', 'baseline.prof', b'pro\0'),
        ('binary_art_profile_metadata', 'baseline.profm', b'prm\0'),
    ):
        path = root / 'app/build/intermediates' / artifact / 'release/compileReleaseArtProfile' / filename
        assert path.is_file() and 8 < path.stat().st_size <= 1_572_864, 'Invalid release ART profile size'
        data = path.read_bytes()
        assert data.startswith(magic) and data[4:7].isdigit() and data[7] == 0, 'Invalid release ART profile header'
        profiles['assets/dexopt/' + filename] = data
    return profiles


def check(path, root):
    instrumented = path.name.endswith('-androidTest.apk')
    if instrumented:
        # Generated from the public testsrc/sine recipe on this build worker.
        # Compare the generated media with the exact bytes in the test APK.
        expected = {}
        for name in CHAT_VIDEO_FIXTURES:
            fixture = root / 'app/src/androidTest/assets' / name
            assert fixture.is_file() and 0 < fixture.stat().st_size < 25 * 1024 * 1024
            expected['assets/' + name] = fixture.read_bytes()
    else:
        expected = expected_assets(root)
        if path.name == 'app-release-unsigned.apk':
            expected.update(release_art_profiles(root))
    with zipfile.ZipFile(path) as archive:
        names = [i.filename for i in archive.infolist() if i.filename.startswith('assets/')]
        assert len(names) == len(set(names)), 'Duplicate APK asset'
        required = set(expected) | ({TEST_SUFFIX_LIST} if instrumented else set())
        assert set(names) == required, 'APK runtime asset allowlist mismatch'
        if instrumented:
            assert hashlib.sha256(archive.read(TEST_SUFFIX_LIST)).hexdigest() == TEST_SUFFIX_SHA256, 'Incorrect OkHttp test asset'
        assert all(archive.read(name) == value for name, value in expected.items()), 'APK asset differs from source'


if __name__ == '__main__':
    root = Path(__file__).resolve().parent.parent
    paths = [Path(p) for p in sys.argv[1:]] or list((root / 'app/build/outputs/apk').rglob('*.apk'))
    assert paths, 'No APK assets checked'
    for path in paths:
        check(path, root)
    print('APK runtime assets and original license contents verified')
