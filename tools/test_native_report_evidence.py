import json
from pathlib import Path
import unittest

from check_native_report_evidence import MODULE, BRIDGE, MODULE_ROOTS, BRIDGE_ROOTS, source_bindings, verify


class NativeReportEvidenceTest(unittest.TestCase):
    def sources(self):
        root = Path(__file__).resolve().parent.parent
        return [(root / name).read_text(encoding='utf-8') for name in (
            'native/engine-netbird/report_view_test.go', 'native/bridge/netbird_view_test.go')]

    def rows(self):
        rows = []
        for package, roots in ((MODULE, MODULE_ROOTS), (BRIDGE, BRIDGE_ROOTS)):
            rows.append({'Action': 'start', 'Package': package})
            for name in sorted(roots):
                rows.extend({'Action': action, 'Package': package, 'Test': name} for action in ('run', 'pass'))
            rows.append({'Action': 'pass', 'Package': package})
        return rows

    def verify(self, rows):
        return verify([json.dumps(row) for row in rows], *self.sources())

    def test_actual_roots_are_source_bound_and_both_packages_complete(self):
        self.assertEqual({MODULE: 8, BRIDGE: 2}, self.verify(self.rows()))
        module, bridge = self.sources()
        with self.assertRaises(AssertionError):
            source_bindings(module.replace(next(iter(MODULE_ROOTS)), 'TestSubstituted'), bridge)

    def test_missing_failed_skipped_duplicate_and_foreign_outcomes_are_rejected(self):
        for action in ('fail', 'skip'):
            rows = self.rows()
            rows[2]['Action'] = action
            with self.assertRaises(AssertionError): self.verify(rows)
        for mutate in ('missing', 'duplicate', 'foreign', 'before-start', 'no-completion'):
            rows = self.rows()
            if mutate == 'missing': del rows[1:3]
            elif mutate == 'duplicate': rows[3:3] = rows[1:3]
            elif mutate == 'foreign': rows[1]['Package'] = BRIDGE
            elif mutate == 'before-start': rows[0], rows[1] = rows[1], rows[0]
            else: rows.pop()
            with self.assertRaises(AssertionError): self.verify(rows)

    def test_unrelated_failure_late_event_and_malformed_metadata_cannot_hide(self):
        for inserted in ({'Action': 'fail', 'Package': MODULE, 'Test': 'TestExisting'},
                         {'Action': 'pass', 'Package': MODULE, 'Test': []},
                         {'Action': 'output', 'Package': MODULE, 'ImportPath': BRIDGE}):
            rows = self.rows()
            rows.insert(1, inserted)
            with self.assertRaises(AssertionError): self.verify(rows)
        with self.assertRaises(AssertionError): self.verify(self.rows() + [{'Action': 'output', 'Package': MODULE}])
        for raw in ('[]', '{"Action":"start","Action":"pass","Package":"io.syn443/engine-netbird"}', '{}'):
            with self.assertRaises((AssertionError, ValueError)):
                verify([raw], *self.sources())
