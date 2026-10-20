"""Publish test outcomes through an allowlist, never raw device/system logs."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
CLASS = re.compile(r"io\.syn443\.[A-Za-z0-9_.$]+")
METHOD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def sanitize(doc):
    result = ET.Element('testsuite', name='SYN443 synthetic Android tests')
    counts = {'tests': 0, 'failures': 0, 'errors': 0, 'skipped': 0}
    seen = set()
    for case in doc.iter('testcase'):
        classname, name = case.get('classname', ''), case.get('name', '')
        if not CLASS.fullmatch(classname) or not METHOD.fullmatch(name):
            raise ValueError('Unexpected test identity; public evidence refused')
        identity = (classname, name)
        if identity in seen:
            raise ValueError('Duplicate test case')
        seen.add(identity)
        public = ET.SubElement(result, 'testcase', classname=classname, name=name)
        counts['tests'] += 1
        for tag, counter in (('failure', 'failures'), ('error', 'errors'), ('skipped', 'skipped')):
            if case.find(tag) is not None:
                ET.SubElement(public, tag, message='Details retained in Actions job log')
                counts[counter] += 1
    if not counts['tests']:
        raise ValueError('No actual test case evidence')
    result.attrib.update({key: str(value) for key, value in counts.items()})
    return result


def main():
    files = sorted((ROOT / 'app/build/outputs/androidTest-results').rglob('TEST-*.xml'))
    if not files:
        raise SystemExit('No Android JUnit reports')
    combined = ET.Element('testsuites')
    for file in files:
        combined.append(ET.parse(file).getroot())
    public = sanitize(combined)
    out = ROOT / 'public-evidence/emulator'
    out.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(public).write(out / 'tests.xml', encoding='utf-8', xml_declaration=True)
    print('Public Android evidence: ' + public.attrib['tests'] + ' allowlisted test outcomes')


if __name__ == '__main__':
    main()
