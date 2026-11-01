import copy
import unittest
from unittest.mock import patch
from run_enrolled_vpn import stopped_rollback_recovered


class StoppedControllerRecoveryTest(unittest.TestCase):
    state={'desiredOn':False,'generation':7,'engineActive':False,
           'policy':{'phase':'rolled_back','activeRevision':1}}

    def test_missing_controller_is_recreated_by_the_first_status_request(self):
        live=False
        def request(method):
            nonlocal live
            live=True
            return copy.deepcopy(self.state) if method=='status' else {'busy':False}
        def process(suffix):
            self.assertTrue(live,'PID was checked before requesting provider recreation')
            return 'new-controller' if suffix==':controller' else ''
        with patch('run_enrolled_vpn.call',side_effect=request),patch('run_enrolled_vpn.pid',side_effect=process):
            self.assertTrue(stopped_rollback_recovered('old-controller',7))

    def test_changed_stop_intent_or_new_native_owner_fails_immediately(self):
        for changes,engine in [({'desiredOn':True},''),({'generation':8},''),({},'unexpected-engine')]:
            state=copy.deepcopy(self.state);state.update(changes)
            with patch('run_enrolled_vpn.call',return_value=state),patch('run_enrolled_vpn.pid',return_value=engine):
                with self.assertRaises(AssertionError):stopped_rollback_recovered('old-controller',7)

    def test_uncommitted_or_unknown_runtime_state_cannot_complete_recovery(self):
        for changes in [{'engineActive':None},{'policy':{'phase':'applying'}},{'policy':{'phase':'committed','activeRevision':2}}]:
            state=copy.deepcopy(self.state);state.update(changes)
            def request(method):return state if method=='status' else {'busy':False}
            with patch('run_enrolled_vpn.call',side_effect=request),patch('run_enrolled_vpn.pid',side_effect=lambda suffix:'new-controller' if suffix==':controller' else ''):
                self.assertFalse(stopped_rollback_recovered('old-controller',7))
