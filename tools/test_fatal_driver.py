import unittest
from unittest.mock import patch
from run_vpn_process_faults import ControlUnavailable, await_condition, pid
from run_vpn_fatal import native_crash_matches, await_native_crash, scoped_libc_abort_matches


class ProcessObservationTest(unittest.TestCase):
    @patch("run_vpn_process_faults.adb", side_effect=[b"42 57\n", b"57\n", b""])
    @patch("run_vpn_process_faults.time.sleep")
    def test_overlap_cannot_prove_exit_until_a_single_owner_is_observed(self, sleep, adb):
        await_condition(lambda: pid(":engine") == "57", timeout=5)
        self.assertEqual(2, adb.call_count)
        sleep.assert_called_once_with(1)
        self.assertEqual("", pid(":engine"))

    @patch("run_vpn_process_faults.adb", side_effect=[b"42 57", b"pidof: permission denied"])
    def test_multi_owner_and_malformed_samples_never_report_off(self, adb):
        with self.assertRaises(ControlUnavailable):
            pid(":engine")
        with self.assertRaisesRegex(AssertionError, "Unexpected process identity"):
            pid(":engine")


class NativeCrashEvidenceTest(unittest.TestCase):
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
