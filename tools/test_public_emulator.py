import unittest
import xml.etree.ElementTree as ET
from collect_public_emulator import sanitize


class PublicEmulatorTest(unittest.TestCase):
    def test_allowlist_removes_payloads_and_system_metadata(self):
        doc = ET.Element('testsuite', hostname='sensitive-host', name='sensitive-suite')
        props = ET.SubElement(doc, 'properties')
        ET.SubElement(props, 'property', name='secret', value='sensitive-value')
        case = ET.SubElement(doc, 'testcase', classname='io.syn443.ExampleTest', name='probe',
                             device='sensitive-device', time='sensitive-time')
        ET.SubElement(case, 'failure', message='sensitive-message').text = 'sensitive-stack'
        ET.SubElement(case, 'system-out').text = 'sensitive-output'
        result = sanitize(doc)
        self.assertNotIn('sensitive', ET.tostring(result).decode())
        self.assertEqual(result.attrib['tests'], '1')
        self.assertEqual(result.attrib['failures'], '1')
        self.assertEqual(result.find('testcase').attrib, {'classname': 'io.syn443.ExampleTest', 'name': 'probe'})

    def test_pass_error_skip_counts_are_preserved(self):
        doc = ET.Element('testsuite')
        for name, tag in (('passes', None), ('errors', 'error'), ('skips', 'skipped')):
            case = ET.SubElement(doc, 'testcase', classname='io.syn443.ExampleTest', name=name)
            if tag:
                ET.SubElement(case, tag)
        result = sanitize(doc)
        self.assertEqual({key: result.get(key) for key in ('tests', 'failures', 'errors', 'skipped')},
                         {'tests': '3', 'failures': '0', 'errors': '1', 'skipped': '1'})

    def test_missing_invalid_or_duplicate_cases_are_rejected(self):
        with self.assertRaises(ValueError):
            sanitize(ET.Element('testsuite'))
        for classname, name in (('foreign.Test', 'probe'), ('io.syn443.Test', 'unsafe/value')):
            doc = ET.Element('testsuite')
            ET.SubElement(doc, 'testcase', classname=classname, name=name)
            with self.assertRaises(ValueError):
                sanitize(doc)
        doc = ET.Element('testsuite')
        for _ in range(2):
            ET.SubElement(doc, 'testcase', classname='io.syn443.Test', name='probe')
        with self.assertRaises(ValueError):
            sanitize(doc)
