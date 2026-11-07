import unittest
from unittest.mock import patch
from run_vpn_fatal import native_crash_matches, await_native_crash, scoped_libc_abort_matches
from run_vpn_process_faults import ControlUnavailable, pid


class NativeCrashEvidenceTest(unittest.TestCase):
    def test_overlapping_processes_are_neither_absent_nor_a_unique_owner(self):
        with patch('run_vpn_process_faults.adb', side_effect=[b'42 99\n', b'99\n', b'\n']):
            with self.assertRaises(ControlUnavailable):
                pid(':engine')
            self.assertEqual('99', pid(':engine'))
            self.assertEqual('', pid(':engine'))

    def test_unexpected_process_output_still_fails_closed(self):
        for output in (b'error: device offline', b'42 42', b'0'):
            with patch('run_vpn_process_faults.adb', return_value=output):
                with self.assertRaisesRegex(AssertionError, 'Unexpected process identity format'):
                    pid(':engine')

    def test_api29_libc_record_requires_its_real_owner_and_exact_signal(self):
        raw=(b'11-07 13:58:41.558  42  99 F libc    : Fatal signal 6 (SIGABRT), '
             b'code -6 (SI_TKILL) in tid 99 (native-engine), pid 42 (.android:engine)\n')
        self.assertTrue(scoped_libc_abort_matches(raw,'42'))
        self.assertFalse(scoped_libc_abort_matches(raw,'99'))
        self.assertFalse(scoped_libc_abort_matches(raw.replace(b'pid 42',b'pid 21'),'42'))
        self.assertFalse(scoped_libc_abort_matches(raw.replace(b'F libc',b'I libc'),'42'))
        self.assertFalse(scoped_libc_abort_matches(raw.replace(b'SIGABRT',b'SIGSEGV'),'42'))

    def test_exact_owner_and_abort_signal_are_required(self):
        raw=b'DEBUG: pid: 42, tid: 42 >>> synthetic <<<\nDEBUG: signal 6 (SIGABRT)\n'
        self.assertTrue(native_crash_matches(raw,'42'))
        self.assertFalse(native_crash_matches(raw,'4'))
        self.assertFalse(native_crash_matches(raw.replace(b'SIGABRT',b'SIGSEGV'),'42'))
        self.assertFalse(native_crash_matches(raw.replace(b'signal 6',b'signal 11'),'42'))

    def test_another_owner_signal_cannot_complete_the_record(self):
        raw=b'pid: 42, tid: 42\nno signal yet\npid: 99, tid: 99\nsignal 6 (SIGABRT)\n'
        self.assertFalse(native_crash_matches(raw,'42'))
        self.assertTrue(native_crash_matches(raw,'99'))
        with self.assertRaises(AssertionError):native_crash_matches(b'x'*(2*1024*1024+1),'42')

    def test_delayed_publication_is_polled_without_accepting_absence(self):
        replies=iter([b'',b'pid: 42, tid: 42\n',b'pid: 42, tid: 42\nsignal 6 (SIGABRT)\n'])
        def wait(predicate,budget):
            self.assertEqual(30,budget)
            self.assertFalse(predicate());self.assertFalse(predicate());self.assertTrue(predicate())
        await_native_crash('42',lambda:next(replies),wait)

    def test_missing_crash_evidence_still_fails(self):
        def wait(predicate,budget):
            self.assertFalse(predicate())
            raise AssertionError('exit evidence deadline')
        with self.assertRaisesRegex(AssertionError,'exit evidence deadline'):
            await_native_crash('42',lambda:b'',wait)
