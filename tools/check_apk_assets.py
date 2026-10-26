"""Admit only explicit runtime assets and original license files into the APK."""
from pathlib import Path
import sys
import zipfile


def expected_assets(root):
    base = root / 'app/src/main/assets'
    result = {'assets/' + str(p.relative_to(base)).replace('\\', '/'): p.read_bytes()
              for p in base.rglob('*') if p.is_file()}
    result['assets/decision-vectors.json'] = (root / 'contracts/v1/decision-vectors.json').read_bytes()
    return result


def check(path, root):
    expected = {} if path.name.endswith('-androidTest.apk') else expected_assets(root)
    with zipfile.ZipFile(path) as archive:
        names = [i.filename for i in archive.infolist() if i.filename.startswith('assets/')]
        assert len(names) == len(set(names)), 'Duplicate APK asset'
        assert set(names) == set(expected), 'APK runtime asset allowlist mismatch'
        assert all(archive.read(name) == value for name, value in expected.items()), 'APK asset differs from source'


if __name__ == '__main__':
    root = Path(__file__).resolve().parent.parent
    paths = [Path(p) for p in sys.argv[1:]] or list((root / 'app/build/outputs/apk').rglob('*.apk'))
    assert paths, 'No APK assets checked'
    for path in paths:
        check(path, root)
    print('APK runtime assets and original license contents verified')
