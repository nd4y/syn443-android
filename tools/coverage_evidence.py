"""Check required report classes independently of JaCoCo rule-name matching."""
import xml.etree.ElementTree as ET

IDENTITY_CLASSES = {'io.syn443.identity.' + name for name in (
    'Identity', 'Bootstrap', 'Pending', 'BoundedHttp', 'BoundedHttpKt', 'BoundedHttp.Scope',
    'AuthProtocol', 'IdentityScope', 'TrustedTime', 'TrustedTime.Companion',
    'IdentityOperation', 'IdentityOperation.Companion',
    'LoginRecovery', 'LoginIntent', 'RegistrationTombstone')}


def verify_classes(path, required):
    found = set()
    for row in ET.parse(path).getroot().iter('class'):
        name = row.get('name', '').replace('/', '.').replace('$', '.')
        if name not in required:
            continue
        assert name not in found, 'Duplicate required coverage class'
        found.add(name)
        lines = [c for c in row.findall('counter') if c.get('type') == 'LINE']
        assert len(lines) == 1, 'Missing required class line counter'
        covered, missed = (int(lines[0].get(k)) for k in ('covered', 'missed'))
        assert covered >= 0 and missed >= 0 and covered + missed > 0, 'Invalid class line counts'
        assert covered * 10 >= (covered + missed) * 9, 'Required class line coverage below90%: ' + name
    assert found == required, 'Missing required coverage classes'
