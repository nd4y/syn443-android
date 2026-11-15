import os
import subprocess
import unittest
from unittest.mock import patch
from prepare_emulator_art import prepare, framework_booted

BOOTED = b'mProcessesReady=true mSystemReady=true mBooted=true mBooting=false'


class FrameworkHeapTest(unittest.TestCase):
    def exercise(self, *, overrides=None, environment=None, stop_lost=False, start_lost=False,
                 stop_stuck=False, same_pid=False, ready=True, root=True, ready_after=0):
        calls = []
        time = [0]
        state = ['running']
        values = {
            ('get-serialno',): b'emulator-5554', ('emu', 'avd', 'name'): b'syn443-ci\r\nOK\r\n',
            ('shell', 'getprop', 'ro.hardware'): b'ranchu',
            ('shell', 'getprop', 'ro.build.version.sdk'): b'29',
            ('shell', 'getprop', 'ro.debuggable'): b'1',
            ('shell', 'getprop', 'dalvik.vm.heapsize'): b'512m',
            ('shell', 'getprop', 'dalvik.vm.heapgrowthlimit'): b'512m',
            ('shell', 'pm', 'list', 'packages', '--user', '0', 'io.syn443.android'): b'',
            ('shell', 'id', '-u'): b'0' if root else b'2000',
            ('root',): b'restarting adbd as root', ('wait-for-device',): b'',
            ('shell', 'service', 'check', 'package'): b'Service package: found' if ready else b'Service package: not found',
            ('shell', 'dumpsys', 'activity', '-a', 'processes'): BOOTED,
            ('shell', 'pm', 'list', 'packages', '--user', '0', 'android'): b'package:android',
        }
        values.update(overrides or {})

        def adb(*args, **kwargs):
            calls.append(args)
            if args == ('shell', 'dumpsys', 'activity', '-a', 'processes') and time[0] < ready_after:
                return BOOTED.replace(b'mBooted=true', b'mBooted=false')
            if args in values:
                return values[args]
            if args == ('shell', 'stop'):
                state[0] = 'running' if stop_stuck else 'stopped'
                if stop_lost:
                    raise subprocess.TimeoutExpired('adb', 1)
                return b''
            if args == ('shell', 'start'):
                state[0] = 'new'
                if start_lost:
                    raise subprocess.TimeoutExpired('adb', 1)
                return b''
            if args == ('shell', 'pidof', 'system_server'):
                if state[0] == 'stopped':
                    raise subprocess.CalledProcessError(1, 'adb')
                return b'123' if state[0] == 'running' or same_pid else b'456'
            raise AssertionError(args)

        env = {'GITHUB_ACTIONS': 'true', 'SYN443_CI_AVD': 'syn443-ci'}
        env.update(environment or {})
        try:
            with patch.dict(os.environ, env):
                prepare(adb, clock=lambda: time[0], sleep=lambda t: time.__setitem__(0, time[0]+t), budget=4)
        finally:
            self.calls = calls
            self.assertLessEqual(calls.count(('shell', 'stop')), 1)
            self.assertLessEqual(calls.count(('shell', 'start')), 1)
        return calls

    def test_owned_api29_restarts_once_and_requires_a_new_framework(self):
        for lost_stop, lost_start in ((False, False), (True, False), (False, True), (True, True)):
            calls = self.exercise(stop_lost=lost_stop, start_lost=lost_start)
            self.assertEqual(1, calls.count(('shell', 'stop')))
            self.assertEqual(1, calls.count(('shell', 'start')))

    def test_other_supported_api_does_not_restart_or_root(self):
        for api in (b'35', b'37'):
            calls = self.exercise(overrides={('shell', 'getprop', 'ro.build.version.sdk'): api})
            self.assertNotIn(('root',), calls)
            self.assertNotIn(('shell', 'stop'), calls)

    def test_owner_serial_image_heap_and_installed_application_fences(self):
        for overrides in (
            {('get-serialno',): b'phone'}, {('emu', 'avd', 'name'): b'other\nOK'},
            {('shell', 'getprop', 'ro.hardware'): b'qcom'},
            {('shell', 'getprop', 'ro.debuggable'): b'0'},
            {('shell', 'getprop', 'dalvik.vm.heapgrowthlimit'): b'16m'},
            {('shell', 'pm', 'list', 'packages', '--user', '0', 'io.syn443.android'): b'package:io.syn443.android'},
            {('shell', 'pm', 'list', 'packages', '--user', '0', 'io.syn443.android'): b'package:io.syn443.android.test'},
        ):
            with self.assertRaises(AssertionError):
                self.exercise(overrides=overrides)
            self.assertNotIn(('root',), self.calls)
            self.assertNotIn(('shell', 'stop'), self.calls)
        for env in ({'GITHUB_ACTIONS': 'false'}, {'SYN443_CI_AVD': 'other'}):
            with self.assertRaises(AssertionError):
                self.exercise(environment=env)
            self.assertFalse(self.calls)

    def test_root_failure_never_stops_framework(self):
        with self.assertRaisesRegex(AssertionError, 'root unavailable'):
            self.exercise(root=False)
        self.assertNotIn(('shell', 'stop'), self.calls)

    def test_deadlines_restore_once_and_never_accept_old_or_unready_process(self):
        for args in (dict(stop_stuck=True), dict(same_pid=True), dict(ready=False)):
            with self.assertRaisesRegex(AssertionError, 'deadline|did not stop'):
                self.exercise(**args)
            self.assertEqual(1, self.calls.count(('shell', 'start')))

    def test_package_binder_does_not_outrun_full_system_startup(self):
        calls = self.exercise(ready_after=2)
        self.assertGreaterEqual(calls.count(('shell', 'dumpsys', 'activity', '-a', 'processes')), 3)
        for raw in (b'', BOOTED.replace(b'mSystemReady=true', b'mSystemReady=false'),
                    BOOTED.replace(b'mProcessesReady=true', b'mProcessesReady=false'),
                    BOOTED.replace(b'mBooted=true', b'mBooted=false'),
                    BOOTED.replace(b'mBooting=false', b'mBooting=true'), BOOTED+b' mBooted=false'):
            self.assertFalse(framework_booted(raw))
            with self.assertRaisesRegex(AssertionError, 'deadline'):
                self.exercise(overrides={('shell', 'dumpsys', 'activity', '-a', 'processes'): raw})
        self.assertTrue(framework_booted(BOOTED))
        with self.assertRaisesRegex(AssertionError, 'Unbounded'):
            framework_booted(b'x'*1_048_577)


if __name__ == '__main__':
    unittest.main()
