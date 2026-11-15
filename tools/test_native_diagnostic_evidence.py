import json
import unittest
from check_native_diagnostic_evidence import REQUIRED, verify


class NativeDiagnosticEvidenceTest(unittest.TestCase):
    def rows(self, names=REQUIRED, terminal='pass', package='io.syn443/engine-netbird'):
        return [json.dumps({'Action': action, 'Package': package, 'Test': name}) for name in sorted(names) for action in ('run', terminal)]

    def test_requires_all_real_start_and_pass_records(self):
        self.assertEqual(5, verify(self.rows()))

    def test_missing_skipped_failed_or_foreign_package_is_not_acceptance(self):
        for rows in [self.rows(sorted(REQUIRED)[:-1]), self.rows(terminal='skip'), self.rows(terminal='fail'), self.rows(package='other')]:
            with self.assertRaises(AssertionError):
                verify(rows)

    def test_duplicate_or_pass_without_start_cannot_forge_a_gate(self):
        rows = self.rows()
        for altered in [rows + rows[:2], rows[1:]]:
            with self.assertRaises(AssertionError):
                verify(altered)

    def test_malformed_metadata_is_rejected_instead_of_counted(self):
        for malformed in ['[]', '{}', json.dumps({'Action': 'pass', 'Package': 'io.syn443/engine-netbird', 'Test': []})]:
            with self.assertRaises(AssertionError):
                verify([malformed])
