from pathlib import Path
import tempfile
import unittest
from coverage_evidence import verify_classes


class CoverageEvidenceTest(unittest.TestCase):
    def report(self, text):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'report.xml'
        path.write_text(text, encoding='utf-8')
        return path

    def test_nested_vm_names_and_exact_ninety_percent_boundary(self):
        path = self.report('<report><class name="io/syn443/Fixture$Scope">'
                           '<counter type="LINE" covered="9" missed="1"/></class></report>')
        verify_classes(path, {'io.syn443.Fixture.Scope'})

    def test_absent_class_or_counter_cannot_silently_pass(self):
        for text in ['<report/>', '<report><class name="io/syn443/Fixture$Scope"/></report>',
                     '<report><class name="other"><counter type="LINE" covered="100" missed="0"/></class></report>']:
            with self.assertRaises(AssertionError):
                verify_classes(self.report(text), {'io.syn443.Fixture.Scope'})

    def test_low_empty_negative_and_duplicate_class_counts_fail(self):
        row = '<class name="io/syn443/Fixture$Scope"><counter type="LINE" covered="{}" missed="{}"/></class>'
        for contents in [row.format(8, 1), row.format(0, 0), row.format(-1, 0), row.format(9, 1) * 2]:
            with self.assertRaises(AssertionError):
                verify_classes(self.report('<report>' + contents + '</report>'), {'io.syn443.Fixture.Scope'})
