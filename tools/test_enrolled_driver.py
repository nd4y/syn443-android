import copy
import os
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from run_enrolled_vpn import stopped_rollback_recovered, failure_summary, logout, committed_online, enrolled_management_outage, prepare_emulator_wifi, operator_mode_candidates
from run_vpn_process_faults import ControlUnavailable


class SignedPolicyReadinessTest(unittest.TestCase):
    def test_operator_mode_signed_profiles_are_distinct_and_only_last_candidate_is_on_wifi(self):
        base = {'type': 'http', 'tag': 'original', 'server': '127.0.0.1', 'server_port': 14001}
        graph, catalogue, selected = operator_mode_candidates(base, 14002)
        choices, = graph['templates'][0]['slots']
        self.assertEqual(21, len(choices))
        self.assertEqual(set(choices), set(catalogue))
        self.assertEqual(21, len({(p['server'], p['server_port']) for p in catalogue.values()}))
        self.assertEqual([selected], [h['id'] for h in graph['hops'] if 'WIFI' in h['entryModes']])
        self.assertEqual(choices[-1], selected)
        self.assertEqual(dict(base, tag=selected, server_port=14002), catalogue[selected])
        self.assertEqual(14001, base['server_port'])

    def test_wifi_reassociation_requires_disposable_emulator_and_new_app_uid_observation(self):
        def fixture(states, scan):
            observations = iter(states)
            def respond(*args, **kwargs):
                if args == ("emu","avd","name"): return b"syn443-ci\nOK"
                if args == ("shell","getprop","ro.hardware"): return b"ranchu"
                if args == ("shell","getprop","ro.build.version.sdk"): return b"35"
                if args[:3] == ("shell","am","instrument"):
                    return b"INSTRUMENTATION_RESULT: wifiEligibility="+next(observations)+b"\nINSTRUMENTATION_CODE: -1"
                if args == ("shell","cmd","wifi","list-scan-results"): return scan
                return b""
            with patch.dict(os.environ, {"GITHUB_ACTIONS":"true","SYN443_CI_AVD":"syn443-ci"}), patch("run_enrolled_vpn.adb",side_effect=respond) as adb, patch("run_enrolled_vpn.time.sleep"):
                prepare_emulator_wifi()
            return [c.args for c in adb.call_args_list]
        no_change = fixture([b"eligible"], b"")
        self.assertFalse(any("svc" in c or "cmd" in c for c in no_change))
        recovered = fixture([b"missing",b"unvalidated",b"eligible"], b"AndroidWifi")
        self.assertIn(("shell","cmd","wifi","connect-network","AndroidWifi","open"), recovered)
        self.assertFalse(any("connect-network" in c for c in fixture([b"unvalidated",b"eligible"], b"unrelated")))
        with patch.dict(os.environ, {"GITHUB_ACTIONS":"false"}), patch("run_enrolled_vpn.adb") as adb:
            with self.assertRaises(AssertionError): prepare_emulator_wifi()
            adb.assert_not_called()

    def test_online_during_publication_is_incomplete_until_the_engine_and_revision_match(self):
        online = {'phase': 'Online', 'engineActive': True}
        for partial in (None, {}, {'phase': 'committed'}, {'phase': 'committed', 'activeRevision': 1},
                        {'phase': 'preparing', 'activeRevision': 2}):
            self.assertFalse(committed_online(dict(online, policy=partial), 2))
        ready = dict(online, policy={'phase': 'committed', 'activeRevision': 2})
        self.assertTrue(committed_online(ready, 2))
        self.assertFalse(committed_online(dict(ready, engineActive=False), 2))


class FreshInstallReadinessTest(unittest.TestCase):
    def test_startup_polls_only_reads_and_uses_one_final_signed_out_snapshot(self):
        with patch('run_vpn_process_faults.time.sleep'), patch('run_enrolled_vpn.vpn_stopped', return_value=True), patch('run_enrolled_vpn.call') as invoke:
            invoke.side_effect = [ControlUnavailable(), {'phase': 'SIGNED_OUT'}, {},
                                  {'phase': 'SIGNED_OUT', 'busy': True}, {'phase': 'SIGNED_OUT', 'busy': False}]
            logout(fresh_install=True)
        self.assertEqual([args.args[0] for args in invoke.call_args_list],
                         ['auth-status', 'auth-status', 'auth-cancel', 'auth-status', 'auth-status'])

    def test_lost_cancel_acknowledgement_is_never_replayed(self):
        with patch('run_enrolled_vpn.call') as invoke:
            invoke.side_effect = [{'phase': 'SIGNED_OUT'}, ControlUnavailable()]
            with self.assertRaises(ControlUnavailable):
                logout(fresh_install=True)
        self.assertEqual([args.args[0] for args in invoke.call_args_list], ['auth-status', 'auth-cancel'])


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

    def test_management_outage_requires_a_disposable_emulator_before_touching_a_port(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), patch('run_enrolled_vpn.adb') as adb:
            with self.assertRaises(ValueError):
                enrolled_management_outage(None, None, 0)
            adb.assert_not_called()

    def test_management_port_is_restored_if_the_app_does_not_observe_a_refusal(self):
        from unittest.mock import call
        port = 'tcp:10001'
        fixture = SimpleNamespace(server=SimpleNamespace(server_port=10001), telemetry_enabled=True,
                                  issuer='https://127.0.0.1:10001/realms/test', origin='https://127.0.0.1:10001',
                                  sessions={'key': {'deviceId': 'device'}}, registrations=1)
        proxy = SimpleNamespace(server_address=('127.0.0.1', 10002))
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'SYN443_CI_AVD': 'syn443-ci'}))
            adb = stack.enter_context(patch('run_enrolled_vpn.adb', side_effect=[
                b"syn443-ci\nOK", b"emulator tcp:10001 tcp:10001", b"", b"emulator tcp:10002 tcp:10002", b""]))
            stack.enter_context(patch('run_enrolled_vpn.exchange_through_proxy'))
            stack.enter_context(patch('run_enrolled_vpn.pid', return_value='original'))
            control = stack.enter_context(patch('run_enrolled_vpn.call'))
            stack.enter_context(patch('run_enrolled_vpn.committed_online', return_value=True))
            stack.enter_context(patch('run_enrolled_vpn.subprocess.run',
                                      return_value=SimpleNamespace(returncode=0, stdout=b'', stderr=b'')))
            with self.assertRaises(AssertionError):
                enrolled_management_outage(fixture, proxy, 1)
            self.assertEqual([call('reverse', '--remove', port), call('reverse', '--list'),
                              call('reverse', port, port)], adb.call_args_list[-3:])
            self.assertEqual([call('status')], control.call_args_list)

    def test_failure_diagnostics_never_copy_untrusted_or_private_fields(self):
        import json
        state=copy.deepcopy(self.state)
        state.update(token='synthetic-secret',netbird={'peers':['private-fixture']},error='synthetic-secret')
        state['policy'].update(phase='synthetic-secret',activeRevision='synthetic-secret',target='synthetic-secret')
        with patch('run_enrolled_vpn.call',side_effect=lambda method:state if method=='status' else {'busy':False,'token':'synthetic-secret'}),patch('run_enrolled_vpn.pid',return_value=''):
            result=failure_summary()
        self.assertEqual('unknown',result['policy']['phase'])
        self.assertNotIn('activeRevision',result['policy'])
        self.assertNotIn('synthetic-secret',json.dumps(result))
        self.assertNotIn('private-fixture',json.dumps(result))
