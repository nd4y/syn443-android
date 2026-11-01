import unittest
from unittest.mock import patch
from run_route_lifecycle import resume_blocked


class ForegroundResumeBoundaryTest(unittest.TestCase):
    before={'configRevision':'synthetic','generation':7}
    def check(self,changes=None,native=''):
        snapshot=dict(self.before,engineActive=False,desiredOn=True,resumeRequired=False)
        snapshot.update(changes or {})
        with patch('run_route_lifecycle.call',return_value=snapshot),patch('run_route_lifecycle.pid',return_value=native):
            return resume_blocked(self.before)
    def test_drawn_activity_without_foreground_callback_is_not_completion(self):
        self.assertFalse(self.check())
    def test_explicit_resume_gate_completes_without_connect(self):
        self.assertTrue(self.check({'resumeRequired':True}))
    def test_native_owner_during_wait_is_an_immediate_failure(self):
        for changes,native in [({},'123'),({'engineActive':True},'')]:
            with self.subTest(changes=changes,native=native),self.assertRaisesRegex(AssertionError,'native owner'):
                self.check(changes,native)
    def test_config_generation_or_desired_intent_cannot_drift_during_wait(self):
        for changes in [{'configRevision':'other'},{'generation':8},{'desiredOn':False}]:
            with self.subTest(changes=changes),self.assertRaises(AssertionError):self.check(changes)


if __name__=='__main__':unittest.main()
