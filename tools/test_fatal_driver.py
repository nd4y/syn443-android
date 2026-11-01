import unittest
from run_vpn_fatal import native_crash_matches, await_native_crash


class NativeCrashEvidenceTest(unittest.TestCase):
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
