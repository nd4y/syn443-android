from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
from run_vpn_competing import finalize_evidence


class CompetingCleanupEvidenceTest(unittest.TestCase):
    def fixture(self,failed=False):
        suite=ET.Element('testsuite')
        case=ET.SubElement(suite,'testcase',name='synthetic-ownership-case')
        if failed:ET.SubElement(case,'failure',message='original').text='Original failed scenario'
        return suite,case

    def test_original_failed_case_survives_cleanup_errors_and_all_resources_are_attempted(self):
        calls=[]
        def fail():calls.append('failure');raise RuntimeError('not exported')
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'nested/result.xml';suite,case=self.fixture(True)
            finalize_evidence(suite,case,out,[('stop',fail),('shutdown',lambda:calls.append('shutdown')),('close',lambda:calls.append('close'))])
            self.assertEqual(['failure','shutdown','close'],calls)
            failures=list(ET.parse(out).getroot().iter('failure'))
            self.assertEqual(1,len(failures));self.assertEqual('original',failures[0].get('message'))
            self.assertEqual('Original failed scenario',failures[0].text)

    def test_cleanup_failure_turns_an_otherwise_successful_case_into_failure(self):
        def fail():raise OSError('not exported')
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'result.xml';suite,case=self.fixture()
            with self.assertRaisesRegex(AssertionError,'cleanup failed'):
                finalize_evidence(suite,case,out,[('reverse-remove',fail)])
            failure=next(ET.parse(out).getroot().iter('failure'))
            self.assertEqual('fixture_cleanup_failed',failure.get('message'))
            self.assertEqual('reverse-remove:OSError',failure.text)

    def test_successful_cleanup_does_not_invent_a_failure_or_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'result.xml';suite,case=self.fixture()
            finalize_evidence(suite,case,out,[('close',lambda:None)])
            result=ET.parse(out).getroot()
            self.assertEqual(1,len(list(result.iter('testcase'))))
            self.assertFalse(list(result.iter('failure'))+list(result.iter('skipped')))


if __name__=='__main__':unittest.main()
