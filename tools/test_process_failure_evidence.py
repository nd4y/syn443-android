from pathlib import Path
import ast
import json
import unittest

from process_failure_evidence import (
    COUNTERS, MAX_COUNT, MAX_REPORT_BYTES, FailureEvidence, controller_snapshot,
    fixture_snapshot, native_snapshot, reverse_snapshot,
)


def fixture(role='ingress', **changes):
    value = dict(role=role, allowed=True, threadAlive=True, progress=2, accepted=4,
                 active=1, handled=2, errors=1, connectHeaders=3,
                 requestHeaders=2, rejected=1)
    value.update(changes)
    return value


class ProcessFailureEvidenceTest(unittest.TestCase):
    def test_current_ready_is_explicit_and_never_claims_owned_tun(self):
        observed = controller_snapshot(dict(
            phase='Recovering', reason='tcp_timeout', desiredOn=True, generation=28,
            resumeRequired=False, attempt=7, heavyWallMs=[100, 200],
            engineStateKnown=True, engineActive=True,
            ownedTun=True, address='private-marker', configuration='private-marker',
        ))
        self.assertTrue(observed['available'])
        self.assertEqual(('Recovering', 'tcp_timeout', 7, 2),
                         (observed['phase'], observed['reason'], observed['attempt'], observed['heavyStarts']))
        self.assertTrue(observed['ready'])
        self.assertIsNone(observed['ownedTun'])
        self.assertNotIn('private-marker', json.dumps(observed))
        self.assertFalse(controller_snapshot(dict(engineStateKnown=True, engineActive=False))['ready'])

    def test_missing_wrong_types_and_nonfinite_values_never_become_false_zero_or_ready(self):
        for index, value in enumerate((None, [], {}, dict(
                phase='private-marker', reason='private-marker', desiredOn=1,
                generation=True, resumeRequired='false', attempt=31,
                heavyWallMs=[True], engineStateKnown='true', engineActive=1), dict(
                generation=MAX_COUNT + 1, attempt=float('nan'), heavyWallMs=[1] * 4,
                engineStateKnown=False, engineActive=True))):
            with self.subTest(case=index):
                observed = controller_snapshot(value)
                self.assertIsNone(observed['ready'])
                self.assertIsNone(observed['engineActive'])
                self.assertIsNone(observed['ownedTun'])
                self.assertIsNone(observed['attempt'])
                self.assertIsNone(observed['generation'])
                self.assertIsNone(observed['heavyStarts'])
                self.assertNotIn('private-marker', json.dumps(observed, allow_nan=False))
        self.assertFalse(controller_snapshot(None)['available'])
        self.assertTrue(controller_snapshot({})['available'])
        wrong = controller_snapshot(dict(desiredOn=1, resumeRequired='false'))
        self.assertIsNone(wrong['desiredOn'])
        self.assertIsNone(wrong['resumeRequired'])

    def test_native_comparison_is_known_relative_only_and_never_serializes_pid(self):
        self.assertEqual('same_pid', native_snapshot('12345', '12345')['relation'])
        self.assertEqual('different_pid', native_snapshot('12346', '12345')['relation'])
        self.assertEqual(dict(known=True, present=False, relation='absent'), native_snapshot('', '12345'))
        self.assertEqual(dict(known=True, present=True, relation='unknown'), native_snapshot('12345', None))
        for index, value in enumerate((None, True, 12345, '0', '-1', '12 13', '1' * 11, 'private-marker')):
            with self.subTest(case=index):
                self.assertEqual(dict(known=False, present=None, relation='unknown'), native_snapshot(value, '12345'))
        evidence = FailureEvidence('12345')
        evidence.native('12346')
        evidence.sample(1, fixture(), fixture('egress'))
        raw = json.dumps(evidence.report())
        self.assertNotIn('12345', raw)
        self.assertNotIn('12346', raw)

    def test_fixture_counts_are_coherent_bounded_role_bound_and_owned(self):
        original = fixture(address='private-marker')
        observed = fixture_snapshot(original, 'ingress')
        self.assertTrue(observed['available'])
        self.assertEqual((4, 1, 2, 1), tuple(observed[key] for key in ('accepted', 'active', 'handled', 'errors')))
        original['accepted'] = 99
        self.assertEqual(4, observed['accepted'])
        self.assertNotIn('address', observed)
        invalid = [None, {}, fixture('egress'), fixture(accepted=3),
                   fixture(connectHeaders=5), fixture(requestHeaders=4),
                   fixture(progress=4), fixture(rejected=5)]
        invalid += [fixture(**{key: value}) for key in COUNTERS
                    for value in (-1, True, 1.0, MAX_COUNT + 1, None)]
        for index, value in enumerate(invalid):
            with self.subTest(case=index):
                rejected = fixture_snapshot(value, 'ingress')
                self.assertFalse(rejected['available'])
                self.assertTrue(all(rejected[key] is None for key in COUNTERS))
                self.assertIsNone(rejected['threadAlive'])
        self.assertFalse(fixture_snapshot(fixture('egress', progress=3), 'egress')['available'])
        unknown = fixture_snapshot(fixture(allowed=1, threadAlive='true'), 'ingress')
        self.assertIsNone(unknown['allowed'])
        self.assertIsNone(unknown['threadAlive'])
        empty = fixture('egress', allowed=False, threadAlive=False, **dict.fromkeys(COUNTERS, 0))
        known_empty = fixture_snapshot(empty, 'egress')
        self.assertTrue(known_empty['available'])
        self.assertFalse(known_empty['allowed'])
        self.assertFalse(known_empty['threadAlive'])
        self.assertTrue(all(known_empty[key] == 0 for key in COUNTERS))
        maximum = dict(empty, accepted=MAX_COUNT, handled=MAX_COUNT)
        self.assertEqual(MAX_COUNT, fixture_snapshot(maximum, 'egress')['handled'])
        with self.assertRaises(ValueError):
            fixture_snapshot(fixture(), 'private-marker')

    def test_reverse_mapping_is_exact_bounded_configuration_evidence_not_liveness(self):
        owned = b'emulator-fixture tcp:23456 tcp:23456\n'
        self.assertEqual(dict(known=True, ownedMappingPresent=True), reverse_snapshot(owned, 23456))
        self.assertEqual(dict(known=True, ownedMappingPresent=False), reverse_snapshot(b'', 23456))
        self.assertEqual(dict(known=True, ownedMappingPresent=False), reverse_snapshot(
            b'emulator-fixture tcp:23456 tcp:23457\n', 23456))
        self.assertEqual(dict(known=True, ownedMappingPresent=True), reverse_snapshot(
            b'emulator-fixture tcp:23457 tcp:23457\n' + owned, 23456))
        for index, (raw, port) in enumerate((
                (owned * 2, 23456), (b'wrong-columns', 23456), (b'\xff', 23456),
                (b'\x00', 23456), (b'\x7f', 23456), (b'\n' * 65, 23456),
                (b' ' * 16385, 23456), (owned.decode(), 23456),
                (owned, True), (owned, 0), (owned, 65536))):
            with self.subTest(case=index):
                self.assertEqual(dict(known=False, ownedMappingPresent=None), reverse_snapshot(raw, port))

    def test_ring_is_eight_changed_polls_with_owned_copies_and_unknown_missing_reads(self):
        evidence = FailureEvidence('12345')
        for index in range(12):
            evidence.begin_poll()
            evidence.status(dict(phase='Recovering', reason='tcp_timeout', attempt=index))
            evidence.native('12346')
            evidence.sample(index, fixture(), fixture('egress'))
        observed = evidence.report()
        self.assertEqual(8, len(observed['transitions']))
        self.assertEqual(list(range(4, 12)), [row['elapsedMs'] for row in observed['transitions']])
        evidence.sample(99, fixture(), fixture('egress'))
        self.assertEqual(observed['transitions'], evidence.report()['transitions'])
        self.assertEqual(99, evidence.report()['lastSampleElapsedMs'])
        observed['transitions'][0]['observation']['controller']['reason'] = 'private-marker'
        self.assertNotIn('private-marker', json.dumps(evidence.report()))
        evidence.begin_poll()
        evidence.sample(MAX_COUNT + 1, fixture(), fixture('egress'))
        last = evidence.report()['transitions'][-1]
        self.assertIsNone(last['elapsedMs'])
        self.assertFalse(last['observation']['controller']['available'])
        self.assertFalse(last['observation']['native']['known'])

    def test_report_has_closed_fields_and_never_copies_external_nested_payloads(self):
        evidence = FailureEvidence('private-marker')
        for index in range(12):
            evidence.begin_poll()
            evidence.status(dict(phase='Recovering', reason='tcp_timeout', attempt=index,
                                 raw='private-marker', engineStateKnown=True, engineActive=True))
            evidence.sample(index, fixture(), fixture('egress'))
        report = evidence.report(dict(known=True, ownedMappingPresent=True, raw='private-marker'))
        self.assertEqual({'version', 'transitions', 'lastSampleElapsedMs', 'reverse',
                          'ownedTunAvailable', 'ownerBindingAvailable'}, set(report))
        self.assertEqual({'known', 'ownedMappingPresent'}, set(report['reverse']))
        self.assertFalse(report['ownedTunAvailable'])
        self.assertFalse(report['ownerBindingAvailable'])
        raw = json.dumps(report, separators=(',', ':'), allow_nan=False).encode()
        self.assertLessEqual(len(raw), MAX_REPORT_BYTES)
        self.assertNotIn(b'private-marker', raw)
        self.assertEqual(dict(known=False, ownedMappingPresent=None),
                         evidence.report(dict(known=1, ownedMappingPresent=True))['reverse'])

    def test_driver_records_before_cleanup_without_diagnostic_poll_transport_or_wait_changes(self):
        tree = ast.parse(Path(__file__).with_name('run_vpn_process_faults.py').read_text(encoding='utf-8'))
        wait = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'await_condition')
        self.assertEqual([110], [node.value for node in wait.args.defaults])
        calls = [node for node in ast.walk(wait) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Name) and node.func.id in ('adb', 'call', 'pid') for node in calls))
        self.assertEqual(1, sum(isinstance(node.func, ast.Attribute) and node.func.attr == 'sleep' for node in calls))
        observer = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ProcessObservation')
        sample = next(node for node in observer.body if isinstance(node, ast.FunctionDef) and node.name == 'sample')
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                             node.func.id in ('adb', 'call', 'pid') for node in ast.walk(sample)))
        capture = next(node for node in observer.body if isinstance(node, ast.FunctionDef) and node.name == 'capture_failure')
        commands = [node for node in ast.walk(capture) if isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Name) and node.func.id in ('adb', 'call', 'pid')]
        self.assertEqual(3, len(commands))
        self.assertTrue(all(any(kw.arg == 'timeout' and isinstance(kw.value, ast.Constant) and kw.value.value == 2
                                for kw in node.keywords) for node in commands))
        self.assertEqual({'status', ':engine', 'reverse'}, {node.args[0].value for node in commands})
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        capture_calls = [node for node in ast.walk(main) if isinstance(node, ast.Call) and
                         isinstance(node.func, ast.Attribute) and node.func.attr == 'capture_failure']
        self.assertEqual(1, len(capture_calls))
        cleanup = next(node for node in main.body if isinstance(node, ast.Try)).finalbody
        self.assertTrue(cleanup)
        self.assertLess(capture_calls[0].lineno, cleanup[0].lineno)
        self.assertEqual(2, sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
                                isinstance(node.func.value, ast.Name) and node.func.value.id == 'threading' and
                                node.func.attr == 'Thread' for node in ast.walk(main)))


if __name__ == '__main__':
    unittest.main()
