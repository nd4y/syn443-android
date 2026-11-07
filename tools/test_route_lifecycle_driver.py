import unittest
from unittest.mock import patch
from run_route_lifecycle import direct_boot_diagnostics, locked_boot_boundary, resume_blocked


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
            with self.subTest(changes=changes,native=native),self.assertRaisesRegex(AssertionError,'native owner|engine checkpoint'):
                self.check(changes,native)
    def test_config_generation_or_desired_intent_cannot_drift_during_wait(self):
        for changes in [{'configRevision':'other'},{'generation':8},{'desiredOn':False}]:
            with self.subTest(changes=changes),self.assertRaises(AssertionError):self.check(changes)


class LockedBootBoundaryTest(unittest.TestCase):
    def test_only_locked_redacted_state_completes_the_gate(self):
        locked={'phase':'NeedsUnlock','engineActive':False,'desiredOn':None,'desiredOnKnown':False}
        with patch('run_route_lifecycle.pid',return_value=''),patch('run_route_lifecycle.call',return_value=locked) as state:
            self.assertTrue(locked_boot_boundary())
            state.return_value={**locked,'phase':'Off'}
            self.assertFalse(locked_boot_boundary())
            state.return_value={**locked,'desiredOn':True}
            with self.assertRaisesRegex(AssertionError,'Credential intent'):locked_boot_boundary()

    def test_native_owner_fails_before_polling_unavailable_provider(self):
        with patch('run_route_lifecycle.pid',return_value='123'),patch('run_route_lifecycle.call') as state:
            with self.assertRaisesRegex(AssertionError,'Unexpected native owner'):locked_boot_boundary()
            state.assert_not_called()

    def test_diagnostics_classify_without_returning_provider_or_package_text(self):
        with patch('run_route_lifecycle.adb',side_effect=[
            b'RUNNING_LOCKED',b'package:synthetic-private-location',b'123',b'No content provider found: synthetic-detail']):
            self.assertEqual({'user0State':'RUNNING_LOCKED','packagePresent':True,'controllerPresent':True,'control':'missing'},direct_boot_diagnostics())


if __name__=='__main__':unittest.main()
