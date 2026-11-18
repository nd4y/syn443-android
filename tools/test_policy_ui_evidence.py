"""Evidence-only helper tests; no emulator, transport or recovery is used."""
import itertools
import subprocess
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

import emulator_policy_ui as ui


UNKNOWN = {'category': 'unknown', 'correlated': False}
COUNTS = {'focus_before', 'focus_after', 'recent_anr', 'process_start', 'active_anr', 'matching_process'}
COMMANDS = (
    ('shell', 'getprop', 'ro.hardware'),
    ('shell', 'date', '+%s'),
    ('shell', 'dumpsys', 'window', 'displays'),
    ('shell', 'logcat', '-d', '-b', 'events', '-v', 'epoch', '-t', '2048', 'am_anr:I', 'am_proc_start:I', "'*:S'"),
    ('shell', 'dumpsys', 'activity', '-a', 'processes'),
    ('shell', 'dumpsys', 'window', 'displays'),
    ('shell', 'date', '+%s'),
)


def observations(name=b'com.android.systemui'):
    focus = b'mCurrentFocus=Window{abc123 u0 Application Not Responding: ' + name + b'}\n'
    events = (
        b'1699999900.000 660 700 I am_proc_start: [0,2468,10034,' + name + b',service,synthetic]\n'
        b'1699999998.123 660 700 I am_anr: [0,2468,' + name + b',0,private-detail]\n'
    )
    processes = (
        b'ACTIVITY MANAGER RUNNING PROCESSES (dumpsys activity processes)\n All known processes:\n'
        b'  *PERS* UID 10034 ProcessRecord{def456 2468:' + name + b'/u0a34}\n'
        b'    user #0 uid=10034 gids={3003}\n'
        b'    pid=2468\n'
        b'    mCrashing=false null mNotResponding=true [com.android.server.am.AppNotRespondingDialog@fed123] bad=false\n'
    )
    return [focus, focus, events, processes, 1700000000, 1700000002]


def node(parent, **values):
    return ET.SubElement(parent, 'node', {key.replace('_', '-'): value for key, value in values.items()})


def owned_row():
    root = ET.Element('hierarchy')
    row = node(root, package='com.android.settings', bounds='[0,0][400,80]')
    node(row, package='com.android.settings', resource_id='android:id/title', text='SYN443', bounds='[20,20][180,50]')
    gear = node(row, package='com.android.settings', resource_id='com.android.settings:id/settings_button',
                content_desc='Settings for SYN443', bounds='[320,10][380,70]')
    return root, gear


class PolicyUiEvidenceTest(unittest.TestCase):
    def assert_evidence(self, value, stage, reason, correlated=False):
        self.assertEqual(set(value), {'stage', 'reason', 'trust', 'counts'})
        self.assertEqual(value['stage'], stage)
        self.assertEqual(value['reason'], reason)
        self.assertEqual(value['trust'], 'correlated' if correlated else 'unverified')
        self.assertEqual(set(value['counts']), COUNTS)
        self.assertTrue(all(count is None or type(count) is int and 0 <= count <= 2 for count in value['counts'].values()))
        for raw in ('private-detail', 'private.owner.fixture', 'abc123', 'def456', 'fed123', '2468', '10034', 'com.android.systemui'):
            self.assertNotIn(raw, repr(value))

    def test_launch_status_is_bounded_classified_and_never_echoes_output(self):
        for raw, expected in (
            (b'Starting: Intent { private-detail }\nStatus: ok\nActivity: private.owner.fixture\n', 'ok'),
            (b'Status: ok\r\nActivity: private-detail\r\n', 'ok'),
            (b'Status: timeout\nWaitTime: 10000\n', 'timeout'),
            (b'Error type 3\nError: private-detail\n', 'error'),
            (b'Exception occurred while executing private-detail\n', 'error'),
            (b'Status: ok\nError: private-detail\n', 'ambiguous'),
            (b'Status: ok\nStatus: timeout\n', 'ambiguous'),
            (b'Status: private-detail\n', 'unrecognized'),
            (b'', 'unrecognized'),
            (None, 'unavailable'),
            ('Status: ok', 'unavailable'),
            (b'\xffprivate-detail', 'malformed'),
            (b'x' * 16385, 'oversized'),
        ):
            with self.subTest(kind=expected):
                result = ui.launch_status(raw)
                self.assertEqual(result, {'kind': expected})
                self.assertNotIn('private-detail', repr(result))
                self.assertNotIn('private.owner.fixture', repr(result))
        # The byte limit applies before decoding, even to a recognizable prefix.
        prefix = b'Status: ok\n'
        self.assertEqual(ui.launch_status(prefix + b'x' * (16384 - len(prefix))), {'kind': 'ok'})
        self.assertEqual(ui.launch_status(prefix + b'x' * (16385 - len(prefix))), {'kind': 'oversized'})

    def test_detail_preserves_legacy_owner_result_and_exact_known_binding(self):
        values = observations()
        expected = {'category': 'system_ui', 'correlated': True}
        self.assertEqual(ui.correlated_anr_owner(*values), expected)
        evidence = {'stale': 'private-detail'}
        self.assertEqual(ui.correlated_anr_owner(*values, evidence=evidence), expected)
        self.assert_evidence(evidence, 'complete', 'known_owner', True)
        self.assertEqual(evidence['counts'], {key: 1 for key in COUNTS})
        # A process name that is perfectly correlated but not on the fixed map
        # is still unknown, and is never emitted as an invented category.
        self.assertEqual(ui.correlated_anr_owner(*observations(b'private.owner.fixture'), evidence=evidence), UNKNOWN)
        self.assert_evidence(evidence, 'owner', 'unmapped_owner')
        self.assertNotIn('stale', evidence)
        self.assertEqual(ui.correlated_anr_owner(*values, evidence=None), expected)

    def test_correlation_failure_stages_are_finite_bounded_and_unverified(self):
        base = observations()
        cases = []
        def changed(index, raw, stage, reason):
            values = base.copy()
            values[index] = raw
            cases.append((values, stage, reason))
        changed(0, None, 'input', 'unavailable')
        changed(2, b'x' * 1048577, 'input', 'oversized')
        changed(0, b'', 'focus', 'missing')
        changed(1, base[1] * 20, 'focus', 'ambiguous')
        changed(0, b'mCurrentFocus=null\n', 'focus', 'malformed')
        changed(1, base[1].replace(b'abc123', b'abc124'), 'focus', 'changed')
        changed(4, True, 'clock', 'malformed')
        changed(5, base[4] - 1, 'clock', 'malformed')
        changed(2, b'private-detail am_anr: [malformed]\n', 'events', 'malformed')
        changed(2, b'', 'events', 'missing')
        changed(2, base[2].replace(b'1699999998.123', b'1699999800.123'), 'events', 'stale_or_future')
        changed(2, base[2].replace(b'1699999998.123', b'1700000003.000'), 'events', 'stale_or_future')
        changed(2, base[2] + base[2].splitlines(keepends=True)[1], 'events', 'ambiguous')
        changed(2, base[2] + b'x' * 16385 + b'\n', 'events', 'oversized')
        changed(2, base[2].replace(b'com.android.systemui,0,', b'com.android.settings,0,'), 'focus', 'identity_mismatch')
        changed(2, base[2].splitlines(keepends=True)[1], 'process_start', 'missing')
        changed(2, base[2] + base[2].splitlines(keepends=True)[0], 'process_start', 'ambiguous')
        changed(2, base[2].replace(b'1699999900.000', b'1699999999.000'), 'process_start', 'identity_mismatch')
        changed(2, base[2].replace(b',10034,', b',110034,'), 'process_start', 'identity_mismatch')
        changed(3, b'ACTIVITY MANAGER LAST ANR\nprivate-detail', 'process', 'missing')
        changed(3, base[3] + b' *APP* UID malformed private-detail\n', 'process', 'malformed')
        changed(3, base[3].replace(b'mNotResponding=true', b'mNotResponding=false'), 'process', 'missing')
        changed(3, base[3] + b' mNotResponding=true\n', 'process', 'ambiguous')
        changed(3, base[3].replace(b'pid=2468', b'pid=2469'), 'process', 'identity_mismatch')
        for values, stage, reason in cases:
            with self.subTest(stage=stage, reason=reason):
                evidence = {'previous': 'private-detail'}
                self.assertEqual(ui.correlated_anr_owner(*values, evidence=evidence), UNKNOWN)
                self.assert_evidence(evidence, stage, reason)
                self.assertEqual(ui.correlated_anr_owner(*values), UNKNOWN)

    def test_transport_evidence_retains_constant_commands_and_existing_deadline(self):
        values = observations()
        replies = (b'ranchu\n', b'1700000000\n', values[0], values[2], values[3], values[1], b'1700000002\n')
        calls = []
        def observe(*args, **kwargs):
            index = len(calls)
            self.assertEqual(args, COMMANDS[index])
            self.assertEqual(kwargs, {'timeout': 2})
            calls.append(args)
            return replies[index]
        evidence = {}
        with patch.object(ui, 'adb', side_effect=observe), patch.object(ui.time, 'monotonic', return_value=0), patch.object(ui, 'tap') as tap:
            self.assertEqual(ui.anr_owner_diagnostic(evidence=evidence), {'category': 'system_ui', 'correlated': True})
            tap.assert_not_called()
        self.assertEqual(calls, list(COMMANDS))
        self.assert_evidence(evidence, 'complete', 'known_owner', True)
        for error, reason in (
            (subprocess.TimeoutExpired('private-detail', 2), 'timeout'),
            (subprocess.CalledProcessError(1, ['private-detail'], output=b'private-detail'), 'transport_error'),
            (OSError('private-detail'), 'transport_error'),
        ):
            with patch.object(ui, 'adb', side_effect=error) as adb, patch.object(ui.time, 'monotonic', return_value=0):
                self.assertEqual(ui.anr_owner_diagnostic(evidence=evidence), UNKNOWN)
                adb.assert_called_once_with(*COMMANDS[0], timeout=2)
            self.assert_evidence(evidence, 'hardware', reason)
        with patch.object(ui, 'adb', return_value=b'goldfish') as adb, patch.object(ui.time, 'monotonic', side_effect=[0, 1, 9]):
            self.assertEqual(ui.anr_owner_diagnostic(evidence=evidence), UNKNOWN)
            adb.assert_called_once_with(*COMMANDS[0], timeout=2)
        self.assert_evidence(evidence, 'clock', 'timeout')
        for first, stage, reason in ((b'physical-phone', 'hardware', 'not_emulator'), (b'x' * 1048577, 'hardware', 'oversized'), (None, 'hardware', 'unavailable')):
            with patch.object(ui, 'adb', return_value=first) as adb, patch.object(ui.time, 'monotonic', return_value=0):
                self.assertEqual(ui.anr_owner_diagnostic(evidence=evidence), UNKNOWN)
                self.assertEqual(adb.call_count, 1)
            self.assert_evidence(evidence, stage, reason)
        with patch.object(ui, 'adb', side_effect=[b'ranchu', b'private-detail']) as adb, patch.object(ui.time, 'monotonic', return_value=0):
            self.assertEqual(ui.anr_owner_diagnostic(evidence=evidence), UNKNOWN)
            self.assertEqual([call.args for call in adb.call_args_list], list(COMMANDS[:2]))
        self.assert_evidence(evidence, 'clock', 'malformed')

    def test_navigation_failure_never_reuses_details_or_recovers_unknown_owner(self):
        blocked = ET.Element('hierarchy')
        node(blocked, package='android', resource_id='android:id/aerr_close')
        for fill_evidence in (True, False):
            calls = []
            def adb(*args, **kwargs):
                calls.append(args)
                if args[-1] == 'ro.hardware': return b'ranchu'
                if args[-1] == 'size': return b'1080x1920'
                if 'resolve-activity' in args: return b'com.android.settings/.Settings$VpnSettingsActivity'
                if args[1:3] == ('am', 'start'): return b'Status: timeout\nActivity: private-detail\n'
                if args[1:3] == ('dumpsys', 'window'): return b'mCurrentFocus=Window{abc123 u0 Application Not Responding: private.owner.fixture}\n'
                return b''
            def diagnostic(*, evidence=None):
                if fill_evidence:
                    ui._owner_evidence(evidence, 'complete', 'known_owner', correlated=True)
                    return {'category': 'system_ui', 'correlated': True}
                # A legacy-compatible substitute does not fill the collector.
                return UNKNOWN.copy()
            with patch.object(ui, 'adb', side_effect=adb), patch.object(ui, 'tree', return_value=blocked), patch.object(ui, 'tap') as tap, patch.object(ui, 'anr_owner_diagnostic', side_effect=diagnostic) as observed, patch.object(ui.time, 'sleep'), patch.object(ui.time, 'monotonic', side_effect=itertools.count()), patch('builtins.print') as output:
                with self.assertRaisesRegex(AssertionError, 'Owned VPN settings entry unavailable'):
                    ui.open_policy()
                tap.assert_not_called()
                self.assertEqual(observed.call_count, 1)
                output.assert_called_once()
            message = output.call_args.args[0]
            self.assertIn("'launchStatus': [{'kind': 'timeout'}]", message)
            self.assertIn("'focusedSettingsANR': False", message)
            self.assertIn("'stage': 'complete'" if fill_evidence else "'stage': 'input'", message)
            self.assertIn("'trust': 'correlated'" if fill_evidence else "'trust': 'unverified'", message)
            if not fill_evidence:
                self.assertIn("'reason': 'not_observed'", message)
                self.assertNotIn("'stage': 'complete'", message)
            for raw in ('private-detail', 'private.owner.fixture', 'abc123'):
                self.assertNotIn(raw, message)
            self.assertEqual(sum(args[1:3] == ('am', 'start') for args in calls), 1)
            self.assertFalse(any(any(part in args for part in ('logcat', 'force-stop', 'kill', 'sh', 'text')) for args in calls))
            self.assertEqual([args for args in calls if args[1:3] == ('input', 'keyevent')], [('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')])

    def test_successful_owned_navigation_has_no_new_diagnostic_or_action(self):
        root, gear = owned_row()
        calls = []
        def adb(*args, **kwargs):
            calls.append(args)
            if args[-1] == 'ro.hardware': return b'ranchu'
            if args[-1] == 'size': return b'1080x1920'
            if 'resolve-activity' in args: return b'com.android.settings/.Settings$VpnSettingsActivity'
            if args[1:3] == ('am', 'start'): return b'Status: ok\nActivity: private-detail\n'
            return b''
        with patch.object(ui, 'adb', side_effect=adb), patch.object(ui, 'tree', return_value=root), patch.object(ui, 'tap') as tap, patch.object(ui, 'anr_owner_diagnostic') as diagnostic:
            ui.open_policy()
            tap.assert_called_once_with(gear)
            diagnostic.assert_not_called()
        self.assertEqual(len(calls), 6)
        self.assertFalse(any('dumpsys' in args or 'logcat' in args for args in calls))
        with patch.object(ui, 'adb', return_value=b'physical-phone') as physical, patch.object(ui, 'tree') as tree:
            with self.assertRaises(AssertionError): ui.open_policy()
            physical.assert_called_once_with('shell', 'getprop', 'ro.hardware')
            tree.assert_not_called()
        with patch.object(ui, 'adb', side_effect=adb), patch.object(ui, 'tree', return_value=root), patch.object(ui, 'pin_keys', return_value={'1': object()}), patch.object(ui, 'tap') as tap:
            with self.assertRaisesRegex(AssertionError, 'Protected emulator keyguard'): ui.open_policy()
            tap.assert_not_called()


if __name__ == '__main__':
    unittest.main()
