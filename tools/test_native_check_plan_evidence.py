import json
from pathlib import Path
import unittest

from check_native_check_plan_evidence import (BRIDGE, CATEGORIES, FIXTURE_NAME,
                                             ROOTS, RUNTIME_ROOTS, SUBCASES,
                                             fixture_cases, source_bindings, verify)


class NativeCheckPlanEvidenceTest(unittest.TestCase):
    def fixture(self):
        result = {'schemaVersion': 1}
        for _root, _field, key, count, fields in CATEGORIES:
            result[key] = []
            for index in range(count):
                row = {'name': 'case-' + str(index)}
                if 'profile' in fields:
                    row['profile'] = {}
                if 'sha256' in fields:
                    row['sha256'] = '0' * 64
                if 'raw' in fields:
                    row['raw'] = '{}'
                if 'checks' in fields:
                    row['checks'] = []
                if 'results' in fields:
                    row.update(results={'a': 'TRUE'}, expected='TRUE', visited=['a'], leafStates={'a': 'TRUE'})
                result[key].append(row)
        return json.dumps(result)

    def source(self):
        result = 'package bridge\nimport "testing"\nvar fixture = "testdata/' + FIXTURE_NAME + '"\n'
        for root, field, _key, _count, _fields in CATEGORIES:
            result += ('func ' + root + '(t *testing.T) { for _, tc := range readCheckPlanShared(t).' + field +
                       ' { t.Run(tc.Name, func(t *testing.T) {}) } }\n')
        return result

    def runtime(self):
        result = 'package bridge\nimport "testing"\n'
        for root in RUNTIME_ROOTS:
            result += 'func ' + root + '(t *testing.T) {'
            if root in SUBCASES:
                variable, values = SUBCASES[root]
                result += ('for _, ' + variable + ' := range []string{' + ','.join(json.dumps(value) for value in values) +
                           '} {t.Run(' + variable + ',func(t *testing.T){})}')
            result += '}\n'
        return result

    def event(self, action, test=None, **extra):
        row = {'Action': action, 'Package': BRIDGE}
        if test is not None:
            row['Test'] = test
        row.update(extra)
        return json.dumps(row)

    def rows(self, fixture=None):
        fixture = self.fixture() if fixture is None else fixture
        required = fixture_cases(fixture, fixture)
        result = [self.event('start')]
        for root in ROOTS:
            result.append(self.event('run', root))
            for leaf in sorted(name for name in required if name.startswith(root + '/')):
                result.extend((self.event('run', leaf), self.event('pass', leaf)))
            result.append(self.event('pass', root))
        result.append(self.event('pass'))
        return result

    def check(self, rows, source=None, runtime=None, fixture=None, copied=None):
        fixture = self.fixture() if fixture is None else fixture
        return verify(rows, self.source() if source is None else source,
                      self.runtime() if runtime is None else runtime, fixture, fixture if copied is None else copied)

    def test_requires_all_public_vector_leaves_runtime_boundaries_and_package_completion(self):
        self.assertEqual(128, self.check(self.rows()))
        for metadata in ({'Package': BRIDGE}, {'ImportPath': BRIDGE}, {'Package': BRIDGE, 'ImportPath': BRIDGE}):
            self.assertEqual(128, self.check([json.dumps({'Action': 'build-output', **metadata})] + self.rows()))
        rows = self.rows()
        rows[1:1] = [self.event('run', 'TestUnrelated'), self.event('pause', 'TestUnrelated'),
                     self.event('cont', 'TestUnrelated'), self.event('pass', 'TestUnrelated')]
        self.assertEqual(128, self.check(rows))
        reverse = [self.event('start')]
        required = fixture_cases(self.fixture(), self.fixture())
        for root in reversed(ROOTS):
            reverse.append(self.event('run', root))
            for leaf in sorted(name for name in required if name.startswith(root + '/')):
                reverse += [self.event('run', leaf), self.event('pass', leaf)]
            reverse.append(self.event('pass', root))
        self.assertEqual(128, self.check(reverse + [self.event('pass')]))

    def test_missing_any_vector_runtime_subcase_root_or_start_never_passes(self):
        rows = self.rows()
        for missing in fixture_cases(self.fixture(), self.fixture()):
            with self.assertRaises(AssertionError):
                self.check([row for row in rows if json.loads(row).get('Test') != missing])
        for changed in (rows[1:], rows[:-1], rows[1:] + rows[:1]):
            with self.assertRaises(AssertionError):
                self.check(changed)

    def test_duplicate_parent_early_reordered_and_late_events_are_rejected(self):
        rows = self.rows()
        root = CATEGORIES[0][0]
        leaf = root + '/case-0'
        run, passed = rows.index(self.event('run', leaf)), rows.index(self.event('pass', leaf))
        reordered = rows.copy()
        reordered[run], reordered[passed] = reordered[passed], reordered[run]
        early = rows.copy()
        early.remove(self.event('pass', root))
        early.insert(2, self.event('pass', root))
        before = rows.copy()
        before.remove(self.event('run', leaf))
        before.insert(1, self.event('run', leaf))
        for changed in (reordered, early, before, rows[:passed] + [rows[run]] + rows[passed:],
                        rows + [self.event('pass')], rows + [self.event('output')]):
            with self.assertRaises(AssertionError):
                self.check(changed)

    def test_all_bridge_fail_skip_error_and_build_failure_outcomes_remain_fatal(self):
        for action in ('fail', 'skip', 'error', 'build-fail'):
            for test in (None, 'TestUnrelatedBridge', ROOTS[0], ROOTS[0] + '/case-0'):
                with self.assertRaises(AssertionError):
                    self.check(self.rows()[:1] + [self.event(action, test)] + self.rows()[1:])
            with self.assertRaises(AssertionError):
                self.check([json.dumps({'Action': action, 'ImportPath': BRIDGE})] + self.rows())
        for extra in (self.event('output', Error='synthetic'), self.event('build-output'),
                      self.event('future-action'), self.event('pass', 'TestUnstarted')):
            with self.assertRaises(AssertionError):
                self.check(self.rows()[:1] + [extra] + self.rows()[1:])

    def test_foreign_renamed_unknown_and_malformed_events_cannot_substitute_evidence(self):
        rows = self.rows()
        for name in fixture_cases(self.fixture(), self.fixture()):
            foreign = [json.dumps({**json.loads(row), 'Package': 'example.invalid/foreign'})
                       if json.loads(row).get('Test') == name else row for row in rows]
            with self.assertRaises(AssertionError):
                self.check(foreign)
        malformed = ['null', '[]', '{}', '{', '{"Action":"run","Action":"pass","Package":"' + BRIDGE + '"}',
                     json.dumps({'Action': 'output', 'Package': BRIDGE, 'Test': None}),
                     '{"Action":"output","Package":"' + BRIDGE + '","Elapsed":NaN}',
                     self.event('run', ROOTS[0] + '/unknown'), self.event('output', 'TestUnstarted')]
        for row in malformed:
            with self.assertRaises(AssertionError):
                self.check([row] + rows)

    def test_source_categories_literal_boundaries_names_and_root_inventory_are_bound(self):
        source, runtime, raw = self.source(), self.runtime(), self.fixture()
        for changed in (source.replace('.ValidCases', '.InvalidCases', 1), source.replace('tc.Name', '"renamed"', 1),
                        source.replace('t.Run(tc.Name,', 't.Run("extra",func(t *testing.T){});t.Run(tc.Name,', 1),
                        source.replace('readCheckPlanShared(t)', 'forgedCases(t)', 1), source + source,
                        source.replace(FIXTURE_NAME, 'foreign.json'), source + '/*'):
            with self.assertRaises(AssertionError):
                source_bindings(changed, runtime, raw, raw)
        for changed in (runtime.replace('"before-first"', '"unknown"'), runtime.replace('t.Run(phase,', 't.Run("fixed",'),
                        runtime.replace(RUNTIME_ROOTS[0], 'TestRenamed'), runtime + runtime,
                        runtime + '\nfunc TestCheckPlanV2Unexpected(t *testing.T) {}'):
            with self.assertRaises(AssertionError):
                source_bindings(source, changed, raw, raw)
        decorated = '// fake func TestCheckPlanV2Unexpected(t *testing.T) {}\n' + source
        decorated += '\nvar quoted = `func TestCheckPlanV2Unexpected(t *testing.T) {}`\n'
        self.assertEqual(128, len(source_bindings(decorated, runtime, raw, raw)))

    def test_exact_fixture_copy_closed_categories_names_counts_and_hash_metadata_are_required(self):
        raw = self.fixture()
        with self.assertRaises(AssertionError):
            fixture_cases(raw, raw + ' ')
        for change in ('missing', 'duplicate', 'rename', 'foreign', 'hash', 'version', 'case', 'unknown-field'):
            data = json.loads(raw)
            if change == 'missing':
                data['truthCases'].pop()
            elif change == 'duplicate':
                data['invalidCases'][1]['name'] = data['invalidCases'][0]['name']
            elif change == 'rename':
                data['validCases'][0]['name'] = 'renamed/hidden'
            elif change == 'foreign':
                data['extra'] = []
            elif change == 'hash':
                data['validCases'][0]['sha256'] = 'not-a-hash'
            elif change == 'version':
                data['schemaVersion'] = True
            elif change == 'case':
                data['ValidCases'] = data.pop('validCases')
            else:
                data['legacyCases'][0]['authority'] = True
            changed = json.dumps(data)
            with self.assertRaises(AssertionError):
                fixture_cases(changed, changed)
        for changed in ('null', raw[:-1] + ',"schemaVersion":1}', raw[:-1] + ',"schemaVersion":NaN}'):
            with self.assertRaises(AssertionError):
                fixture_cases(changed, changed)

    def test_actual_repo_source_public_fixture_and_both_stream_gates_keep_existing_evidence(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / 'native/bridge/route_check_profile_test.go').read_text(encoding='utf-8')
        runtime = (root / 'native/bridge/route_check_profile_runtime_test.go').read_text(encoding='utf-8')
        fixture = (root / 'contracts/v1' / FIXTURE_NAME).read_text(encoding='utf-8')
        self.assertEqual(128, len(source_bindings(source, runtime, fixture, fixture)))
        self.assertEqual(128, verify(self.rows(fixture), source, runtime, fixture, fixture))
        build = (root / 'native/build_engine.sh').read_text(encoding='utf-8')
        self.assertIn('cp "$root/contracts/v1/' + FIXTURE_NAME + '" "$work/bridge/testdata/' + FIXTURE_NAME + '"', build)
        for stream in ('native-tests.jsonl', 'native-race-tests.jsonl'):
            previous = 'python3 "$root/tools/check_native_protocol_evidence.py" "$work/' + stream + '"'
            gate = 'python3 "$root/tools/check_native_check_plan_evidence.py" "$work/' + stream + '"'
            self.assertEqual(1, build.count(gate))
            self.assertLess(build.index(previous), build.index(gate))
            self.assertEqual(1, build.count('python3 "$root/tools/check_native_diagnostic_evidence.py" "$work/' + stream + '" --path-candidates'))
        workflow = (root / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.assertIn("unittest discover -s tools -p 'test_*.py'", workflow)


if __name__ == '__main__':
    unittest.main()
