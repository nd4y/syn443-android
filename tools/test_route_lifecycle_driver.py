import subprocess
import unittest
from unittest.mock import patch
from run_route_lifecycle import direct_boot_diagnostics, locked_boot_boundary, off_after_reboot, resume_blocked, completed_route_batch
from run_vpn_process_faults import ControlUnavailable, await_condition, vpn_stopped


class ForegroundResumeBoundaryTest(unittest.TestCase):
    before={'configRevision':'synthetic','generation':7}
    def check(self,changes=None,native=''):
        snapshot=dict(self.before,engineActive=False,engineStateKnown=True,desiredOn=True,resumeRequired=False)
        snapshot.update(changes or {})
        with patch('run_route_lifecycle.call',return_value=snapshot),patch('run_route_lifecycle.pid',return_value=native):
            return resume_blocked(self.before)
    def test_drawn_activity_without_foreground_callback_is_not_completion(self):
        self.assertFalse(self.check())
    def test_explicit_resume_gate_completes_without_connect(self):
        self.assertTrue(self.check({'resumeRequired':True}))
    def test_unresolved_engine_does_not_complete_the_resume_boundary(self):
        for resume in (False, True):
            self.assertFalse(self.check({'engineActive':None,'engineStateKnown':False,'resumeRequired':resume}))
    def test_native_owner_during_wait_is_an_immediate_failure(self):
        for changes,native in [({},'123'),({'engineActive':True},'')]:
            with self.subTest(changes=changes,native=native),self.assertRaisesRegex(AssertionError,'native owner|engine checkpoint'):
                self.check(changes,native)
    def test_config_generation_or_desired_intent_cannot_drift_during_wait(self):
        for changes in [{'configRevision':'other'},{'generation':8},{'desiredOn':False}]:
            with self.subTest(changes=changes),self.assertRaises(AssertionError):self.check(changes)


class RebootWithOffIntentTest(unittest.TestCase):
    before = {'generation': 4, 'configRevision': 'fixture', 'heavyWallMs': [123]}
    off = {**before, 'phase': 'Off', 'desiredOn': False, 'engineStateKnown': True, 'engineActive': False}

    def test_missing_provider_locked_user_and_unknown_engine_wait_for_explicit_off(self):
        locked = {'phase': 'NeedsUnlock', 'desiredOnKnown': False, 'desiredOn': None, 'engineActive': False}
        replies = [ControlUnavailable('starting'), subprocess.TimeoutExpired('status', 5),
                   locked, {**self.off, 'engineActive': None, 'engineStateKnown': False}, self.off]
        with (patch('run_route_lifecycle.pid', return_value='') as pid,
              patch('run_route_lifecycle.call', side_effect=replies) as call,
              patch('run_vpn_process_faults.time.sleep')):
            await_condition(lambda: off_after_reboot(self.before), 5)
            self.assertEqual(len(replies), pid.call_count)
            self.assertEqual(len(replies), call.call_count)
            self.assertTrue(all(args.args == ('status',) for args in call.call_args_list))

    def test_observed_native_process_fails_before_any_provider_query(self):
        for result in ('123', ControlUnavailable('multiple native PIDs')):
            with (self.subTest(result=result), patch('run_route_lifecycle.pid', side_effect=[result]),
                  patch('run_route_lifecycle.call') as call):
                with self.assertRaises(AssertionError):
                    off_after_reboot(self.before)
                call.assert_not_called()

    def test_unsafe_or_changed_checkpoint_is_an_immediate_failure(self):
        for change in ({'desiredOn': True}, {'generation': 5}, {'configRevision': 'changed'},
                       {'heavyWallMs': []}, {'engineActive': True}, {'phase': 'Online'},
                       {'desiredOnKnown': False, 'phase': 'NeedsUnlock', 'desiredOn': True}):
            with (self.subTest(change=change), patch('run_route_lifecycle.pid', return_value=''),
                  patch('run_route_lifecycle.call', return_value={**self.off, **change}),
                  self.assertRaises(AssertionError)):
                off_after_reboot(self.before)


class SettledStopTest(unittest.TestCase):
    def test_requires_known_inactive_status_and_no_native_process(self):
        off = dict(phase='Off', desiredOn=False, engineActive=False, engineStateKnown=True)
        with (
            patch('run_vpn_process_faults.pid', return_value='') as pid,
            patch('run_vpn_process_faults.call', return_value=off) as call,
        ):
            self.assertTrue(vpn_stopped())
            for change in (dict(engineActive=None, engineStateKnown=False), dict(engineActive=True),
                           dict(desiredOn=True), dict(phase='Recovering')):
                with self.subTest(change=change):
                    call.return_value = {**off, **change}
                    self.assertFalse(vpn_stopped())
            call.reset_mock()
            pid.return_value = '123'
            self.assertFalse(vpn_stopped())
            call.assert_not_called()


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


class RouteBatchCompletionTest(unittest.TestCase):
    def report(self):
        return {'running':False,'requiredReady':True,'routes':[
            {'id':'route-1','state':'working','ageMs':1,'measuredPath':['route-1']},
            {'id':'route-2','state':'failed','ageMs':1,'measuredPath':['route-2']},
            {'id':'route-3','state':'working','ageMs':1,'measuredPath':['route-3','route-1']}]}
    def check(self,report):
        with patch('run_route_lifecycle.call',return_value=report):return completed_route_batch()
    def test_online_with_the_selector_still_checking_is_not_a_complete_batch(self):
        value=self.report();value['running']=True;value['routes'][2].update(state='checking',ageMs=None,measuredPath=[])
        self.assertFalse(self.check(value))
    def test_actual_complete_membership_freshness_and_selected_path_pass(self):
        self.assertTrue(self.check(self.report()))
    def test_wrong_completed_outcome_fails_without_waiting_for_a_replacement_batch(self):
        value=self.report();value['routes'][0]['state']='failed'
        with self.assertRaisesRegex(AssertionError,'unexpected outcome'):self.check(value)
    def test_wrong_path_or_missing_duplicate_foreign_membership_never_pass(self):
        value=self.report();value['routes'][2]['measuredPath']=['route-3','route-2']
        with self.assertRaisesRegex(AssertionError,'actual selected outbound'):self.check(value)
        for rows in ([],self.report()['routes'][:2],[self.report()['routes'][0]]*3):
            with self.subTest(rows=len(rows)),self.assertRaisesRegex(AssertionError,'membership'):
                self.check(dict(self.report(),routes=rows))
    def test_inflight_and_unfinished_evidence_cannot_be_called_success(self):
        self.assertFalse(self.check(dict(self.report(),running=True)))
        for state in ('checking','unknown','unavailable'):
            value=self.report();value['routes'][2]['state']=state;self.assertFalse(self.check(value))
    def test_stale_missing_negative_or_coerced_age_fails(self):
        for age in (None,True,-1,35_001,'1'):
            value=self.report();value['routes'][0]['ageMs']=age
            with self.subTest(age=age),self.assertRaisesRegex(AssertionError,'missing or stale'):self.check(value)
    def test_missing_required_completion_proof_never_pass(self):
        for change in ({'running':None},{'requiredReady':False},{'requiredReady':None}):
            with self.subTest(change=change),self.assertRaisesRegex(AssertionError,'completion proof'):
                self.check(dict(self.report(),**change))


if __name__=='__main__':unittest.main()
