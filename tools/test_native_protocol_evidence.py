import json
from pathlib import Path
import unittest
from check_native_protocol_evidence import (BRIDGE, FAILURES, FIXTURE_ROOT, NEGATIVE_ROOT, POSITIVE_ROOT, ROOTS,
                                            POSITIVE_TRANSPORTS, XHTTP_TRANSPORTS,
                                            required_cases, source_bindings, verify)


class NativeProtocolEvidenceTest(unittest.TestCase):
    def source(self):
        def table(values):
            return ','.join(json.dumps(value) for value in values)
        return ('package bridge\nimport "testing"\n'
                'func ' + POSITIVE_ROOT + '(t *testing.T) {\n'
                'for _, transport := range []string{' + table(POSITIVE_TRANSPORTS) + '} {\n'
                't.Run(transport, func(t *testing.T) {})\n}}\n'
                'func ' + NEGATIVE_ROOT + '(t *testing.T) {\n'
                'for _, transport := range []string{' + table(XHTTP_TRANSPORTS) + '} {\n'
                'for _, failure := range []string{' + table(FAILURES) + '} {\n'
                't.Run(transport+"/"+failure, func(t *testing.T) {})\n}}}\n')

    def helper_source(self):
        return 'package bridge\nimport "testing"\nfunc ' + FIXTURE_ROOT + '(t *testing.T) {}\n'

    def event(self, action, test=None, **fields):
        row = {'Action': action, 'Package': BRIDGE}
        if test is not None:
            row['Test'] = test
        row.update(fields)
        return json.dumps(row)

    def rows(self):
        rows = [self.event('start')]
        required = required_cases()
        for root in ROOTS:
            rows.append(self.event('run', root))
            for leaf in sorted(name for name in required if name.startswith(root + '/')):
                rows.extend([self.event('run', leaf), self.event('pass', leaf)])
            rows.append(self.event('pass', root))
        rows.append(self.event('pass'))
        return rows

    def test_requires_thirty_protocol_and_one_fixture_ordered_passes_and_package_completion(self):
        self.assertEqual(31, verify(self.rows(), self.source(), self.helper_source()))
        self.assertEqual(31, len(required_cases()))
        # Actual Go registration emits the standalone fixture before the two
        # protocol roots. It must not require itself as an already-running parent.
        rows = self.rows()
        fixture_first = rows[:1] + [self.event('run', FIXTURE_ROOT), self.event('pass', FIXTURE_ROOT)]
        fixture_first += [row for row in rows[1:] if json.loads(row).get('Test') != FIXTURE_ROOT]
        self.assertEqual(31, verify(fixture_first, self.source(), self.helper_source()))
        # Unrelated package output does not substitute for bridge evidence.
        rows = [json.dumps({'Action': 'output', 'Package': 'example.invalid/other', 'Output': 'synthetic'})] + self.rows()
        self.assertEqual(31, verify(rows, self.source(), self.helper_source()))
        for fields in ({'Package': BRIDGE}, {'ImportPath': BRIDGE}, {'Package': BRIDGE, 'ImportPath': BRIDGE}):
            build = json.dumps({'Action': 'build-output', 'Output': 'synthetic compile metadata', **fields})
            self.assertEqual(31, verify([build] + self.rows(), self.source(), self.helper_source()))
        rows = self.rows()
        rows.insert(1, self.event('run', 'TestOtherBridge'))
        rows.insert(2, self.event('pause', 'TestOtherBridge'))
        rows.insert(3, self.event('cont', 'TestOtherBridge'))
        rows.insert(4, self.event('pass', 'TestOtherBridge'))
        self.assertEqual(31, verify(rows, self.source(), self.helper_source()))

    def test_each_missing_parent_leaf_or_package_completion_is_rejected(self):
        rows = self.rows()
        for omitted in required_cases():
            reduced = [row for row in rows if json.loads(row).get('Test') != omitted]
            with self.assertRaises(AssertionError):
                verify(reduced, self.source(), self.helper_source())
        with self.assertRaises(AssertionError):
            verify(rows[:-1], self.source(), self.helper_source())

    def test_duplicate_out_of_order_parent_early_and_late_records_fail_closed(self):
        rows = self.rows()
        leaf = POSITIVE_ROOT + '/tls'
        run = rows.index(self.event('run', leaf))
        passed = rows.index(self.event('pass', leaf))
        reordered = rows.copy()
        reordered[run], reordered[passed] = reordered[passed], reordered[run]
        early = rows.copy()
        early.remove(self.event('pass', POSITIVE_ROOT))
        early.insert(2, self.event('pass', POSITIVE_ROOT))
        before_parent = rows.copy()
        before_parent.remove(self.event('run', leaf))
        before_parent.insert(1, self.event('run', leaf))
        invalid = [rows[1:], rows[1:] + rows[:1], rows + [self.event('pass')], rows + [self.event('output', Output='late')],
                   rows[:passed] + [rows[run]] + rows[passed:], reordered, early, before_parent,
                   [self.event('pass', leaf)] + rows, rows[1:2] + [self.event('start')] + rows[2:]]
        for changed in invalid:
            with self.assertRaises(AssertionError):
                verify(changed, self.source(), self.helper_source())
        for early in (self.event('run', POSITIVE_ROOT), self.event('output'), self.event('pass')):
            with self.assertRaisesRegex(AssertionError, 'before package start'):
                verify([early] + rows, self.source(), self.helper_source())

    def test_any_bridge_failure_skip_error_or_import_path_build_failure_is_rejected(self):
        for action in ('fail', 'skip', 'error', 'build-fail'):
            for test in (None, 'TestUnrelatedBridge', POSITIVE_ROOT + '/tls', FIXTURE_ROOT):
                changed = self.rows()
                changed.insert(1, self.event(action, test))
                with self.assertRaises(AssertionError):
                    verify(changed, self.source(), self.helper_source())
            for package in (None, 'example.invalid/other'):
                failure = {'Action': action, 'ImportPath': BRIDGE}
                if package is not None:
                    failure['Package'] = package
                with self.assertRaises(AssertionError):
                    verify([json.dumps(failure)] + self.rows(), self.source(), self.helper_source())
        for changed in (self.rows()[:-1] + [self.event('output', Error='synthetic')],
                        self.rows()[:-1] + [self.event('pass', 'TestUnstartedBridge'), self.event('pass')]):
            with self.assertRaises(AssertionError):
                verify(changed, self.source(), self.helper_source())
        for changed in ([self.event('build-output', POSITIVE_ROOT)] + self.rows(),
                        self.rows()[:1] + [self.event('build-output')] + self.rows()[1:],
                        self.rows() + [json.dumps({'Action': 'build-output', 'ImportPath': BRIDGE})]):
            with self.assertRaises(AssertionError):
                verify(changed, self.source(), self.helper_source())

    def test_wrong_package_unknown_intermediate_or_renamed_outcome_never_satisfies_matrix(self):
        rows = self.rows()
        for index in (0, len(rows) - 1):
            changed = rows.copy()
            row = json.loads(changed[index])
            del row['Package']
            row['ImportPath'] = BRIDGE
            changed[index] = json.dumps(row)
            with self.assertRaises(AssertionError):
                verify(changed, self.source(), self.helper_source())
        for name in required_cases():
            changed = [self.event(json.loads(row)['Action'], name, Package='example.invalid/foreign')
                       if json.loads(row).get('Test') == name else row for row in rows]
            with self.assertRaises(AssertionError):
                verify(changed, self.source(), self.helper_source())
        for name in (NEGATIVE_ROOT + '/xhttp-auto', NEGATIVE_ROOT + '/xhttp-auto/future', POSITIVE_ROOT + '/future'):
            with self.assertRaises(AssertionError):
                verify([self.event('run', name)] + rows, self.source(), self.helper_source())
        renamed = [row.replace('/xhttp-h3', '/xhttp-h3-renamed') for row in rows]
        with self.assertRaises(AssertionError):
            verify(renamed, self.source(), self.helper_source())

    def test_malformed_duplicate_null_types_and_unknown_bridge_actions_are_rejected(self):
        malformed = ['[]', '{}', '{', 'null', '{"Action":"output","Action":"pass","Package":"' + BRIDGE + '"}',
                     json.dumps({'Action': 'output', 'Package': BRIDGE, 'Test': None}),
                     json.dumps({'Action': [], 'Package': BRIDGE}),
                     json.dumps({'Action': 'output', 'Package': BRIDGE, 'ImportPath': 1}),
                     '{"Action":"output","Package":"' + BRIDGE + '","Elapsed":NaN}',
                     self.event('future-action'), self.event('run'), self.event('cont', 'TestUnstarted'),
                     self.event('output', 'TestUnstarted')]
        for row in malformed:
            with self.assertRaises(AssertionError):
                verify([row] + self.rows(), self.source(), self.helper_source())

    def test_literal_source_tables_name_bindings_and_comment_boundaries_cannot_drift(self):
        source = self.source()
        changed = [source.replace('"tls",', '', 1), source.replace('"xhttp-auto"', '"future"'),
                   source.replace('"refused"', '"uuid"'), source.replace('"uuid"', 'unknownVariable'),
                   source.replace('transport+"/"+failure', 'failure+"/"+transport'),
                   source.replace('t.Run(transport,', 't.Run("fixed",'),
                   source.replace('t.Run(transport+"/"+failure,', 't.Run(transport, func(t *testing.T) {});t.Run(transport+"/"+failure,'),
                   source + source, source + '/*', source + '"unterminated',
                   source.replace('[]string', 'tableType', 1)]
        for raw in changed:
            with self.assertRaises(AssertionError):
                source_bindings(raw, self.helper_source())
        for helper in ('', self.helper_source().replace(FIXTURE_ROOT, 'TestRenamedFixture'),
                       self.helper_source() + self.helper_source(),
                       self.helper_source().replace('*testing.T', '*unknown.Type')):
            with self.assertRaises(AssertionError):
                source_bindings(source, helper)
        decorated = '// fake t.Run(transport, ignored)\n' + source + '\n/* fake func ' + POSITIVE_ROOT + '(t *testing.T) {} */\n'
        decorated += 'var quoted = `func ' + NEGATIVE_ROOT + '(t *testing.T) { t.Run(fake) }`\n'
        decorated += 'var escaped = "\\\"/* t.Run(fake) */\\\""\nvar brace = \'{\'\n'
        self.assertEqual(required_cases(), source_bindings(decorated, self.helper_source()))

    def test_actual_repo_source_and_both_existing_stream_gates_keep_exact_inventory(self):
        root = Path(__file__).resolve().parent.parent
        actual = (root / 'native/bridge/vless_ssh_wire_test.go').read_text(encoding='utf-8')
        actual_helper = (root / 'native/bridge/proxy_wire_test.go').read_text(encoding='utf-8')
        self.assertEqual(required_cases(), source_bindings(actual, actual_helper))
        self.assertEqual(31, verify(self.rows(), actual, actual_helper))
        build = (root / 'native/build_engine.sh').read_text(encoding='utf-8')
        for stream in ('native-tests.jsonl', 'native-race-tests.jsonl'):
            previous = 'python3 "$root/tools/check_native_diagnostic_evidence.py" "$work/' + stream + '" --path-candidates'
            gate = 'python3 "$root/tools/check_native_protocol_evidence.py" "$work/' + stream + '"'
            self.assertEqual(1, build.count(previous))
            self.assertEqual(1, build.count(gate))
            self.assertIn(previous + '\n' + ('    ' if 'race' in stream else '') + gate, build)
