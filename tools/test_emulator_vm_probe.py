import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import emulator_vm_probe as probe

BOOTED = b'mProcessesReady=true mSystemReady=true mBooted=true mBooting=false'
ENV = {'GITHUB_ACTIONS': 'true', 'SYN443_CI_AVD': 'syn443-ci'}


def wire(maximum=256*1024*1024, **changes):
    return {'schemaVersion': 1, 'maxBytes': maximum, 'totalBytes': min(maximum, 8*1024*1024),
            'freeBytes': 1024, 'pid': 4242, 'uptimeMs': 1000, **changes}


def broadcast(value):
    return ('Broadcasting: Intent { act='+probe.ACTION+' cmp='+probe.COMPONENT+' }\n'
            'Broadcast completed: result=0, data="'+json.dumps(value, separators=(',', ':'))+'"\n').encode('ascii')


class Fixture:
    def __init__(self, overrides=None):
        self.now = 0
        self.stage = 0
        self.calls = []
        self.installed = True
        self.measured = False
        self.bad_health = False
        self.stale_boot = False
        self.lost_reboot = False
        self.ready_after = 0
        self.boot_delay = 0
        self.maximum = 256*1024*1024
        self.overrides = overrides or {}
        self.context = (b'emulator-5554', (1234, 'owned-start-time'))
        self.checkpoint = (b'package:/data/app/synthetic/base.apk', b'a'*64, b'10001')

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def engines(self, _):
        return [self.context[1]]

    def adb(self, *args, **_):
        self.calls.append(args)
        if args in self.overrides:
            return self.overrides[args]
        identity = {
            ('get-serialno',): b'emulator-5554', ('emu', 'avd', 'name'): b'syn443-ci\r\nOK\r\n',
            ('shell', 'getprop', 'ro.kernel.qemu'): b'1', ('shell', 'getprop', 'ro.hardware'): b'ranchu',
            ('shell', 'getprop', 'ro.debuggable'): b'1', ('shell', 'getprop', 'ro.build.version.sdk'): b'29',
            ('shell', 'getprop', 'debug.syn443.vm_seed'): b'',
            ('shell', 'id', '-u'): b'2000', ('shell', 'getprop', 'sys.boot_completed'): b'1',
            ('shell', 'pm', 'list', 'packages', '--user', '0', 'io.syn443.android'): b'',
            ('shell', 'service', 'check', 'package'): b'Service package: found',
            ('shell', 'pm', 'path', '--user', '0', probe.PACKAGE): self.checkpoint[0],
            ('shell', 'pm', 'list', 'packages', '-U', '--user', '0', probe.PACKAGE): b'package:'+probe.PACKAGE.encode()+b' uid:10001',
            ('shell', 'sha256sum', '/data/app/synthetic/base.apk'): b'a'*64+b'  /data/app/synthetic/base.apk',
            ('shell', 'dumpsys', 'package', probe.PACKAGE): b'pkgFlags=[ DEBUGGABLE HAS_CODE ]',
            # Good properties are available but must never substitute for VM evidence.
            ('shell', 'getprop', 'dalvik.vm.heapsize'): b'512m',
            ('shell', 'getprop', 'dalvik.vm.heapgrowthlimit'): b'512m',
        }
        if args in identity:
            return identity[args]
        if args == ('shell', 'pm', 'list', 'packages', '--user', '0', probe.PACKAGE):
            return b'package:'+probe.PACKAGE.encode() if self.installed else b''
        if args == ('shell', 'cat', '/proc/sys/kernel/random/boot_id'):
            ordinal = 0 if self.stale_boot else self.stage
            return ('00000000-0000-0000-0000-'+format(ordinal+1, '012x')).encode()
        if args == ('shell', 'settings', 'get', 'global', 'boot_count'):
            assert self.now >= self.ready_after, 'Settings read before AMS readiness'
            return str(7+self.stage).encode()
        if args == ('shell', 'dumpsys', 'activity', '-a', 'processes'):
            return BOOTED if self.now >= self.ready_after else BOOTED.replace(b'mBooted=true', b'mBooted=false')
        if args == ('shell', 'pidof', 'system_server'):
            return str(1200+self.stage+(1 if self.bad_health and self.measured and self.now >= 2 else 0)).encode()
        if args == ('shell', 'pidof', probe.PACKAGE):
            if not self.measured:
                raise subprocess.CalledProcessError(1, 'fixture-pidof')
            return b'4242'
        if args == ('shell', 'am', 'broadcast', '--user', '0', '-a', probe.ACTION, '-n', probe.COMPONENT, '-f', '0x10000020'):
            self.measured = True
            return broadcast(wire(self.maximum))
        if args == ('reboot',):
            self.stage += 1
            self.measured = False
            self.ready_after = self.now+self.boot_delay
            if self.lost_reboot:
                raise subprocess.CalledProcessError(1, 'fixture-reboot')
            return b''
        raise AssertionError(args)

    def capture(self, captures, stage=0, previous=None, **options):
        return probe.stage_capture(self.adb, self.context, self.checkpoint, stage, captures, previous=previous,
            clock=self.clock, sleep=self.sleep, engines=self.engines, **options)


class CapturedVmProbeTest(unittest.TestCase):
    def test_failure_operation_codes_are_closed_labels_without_arguments_or_outputs(self):
        cases = [(('root',), 'root'), (('unroot',), 'unroot'), (('wait-for-device',), 'wait_for_device'),
            (('shell', 'am', 'broadcast', 'synthetic-foreign-value'), 'probe_broadcast'),
            (('shell', 'pidof', probe.PACKAGE), 'probe_pid'), (('shell', 'pidof', 'system_server'), 'system_pid'),
            (('install', 'synthetic-foreign-value'), 'install'), (('shell', 'getprop', 'synthetic-foreign-value'), 'property'),
            (('shell', 'stop'), 'framework_stop'), (('shell', 'start'), 'framework_start'),
            (('shell', 'settings', 'get', 'global', 'boot_count'), 'boot_counter'),
            (('shell', 'pm', 'synthetic-foreign-value'), 'package_inventory'),
            (('synthetic-foreign-value',), 'other')]
        for args, expected in cases:
            self.assertEqual(expected, probe.operation_code(args))
            self.assertNotIn('synthetic-foreign-value', probe.operation_code(args))

    def failure(self, reason, action):
        with self.assertRaises(probe.ProbeError) as caught:
            action()
        self.assertEqual(reason, caught.exception.reason)
        self.assertEqual(reason, str(caught.exception))

    def test_reply_requires_one_bounded_exact_numeric_schema_and_rejects_duplicates(self):
        self.assertEqual(wire(), probe.broadcast_result(broadcast(wire())))
        malformed = [b'', b'x'*2049, broadcast(wire(pid=True)), broadcast(wire(maxBytes=0)),
            broadcast(wire(maxBytes=probe.MAX_HEAP+1)), broadcast(wire(totalBytes=-1)), broadcast(wire(freeBytes=9*1024*1024)),
            broadcast(wire(uptimeMs=probe.MAX_TIME+1)), broadcast(wire(extra='synthetic-foreign-data')),
            broadcast(wire()).replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'),
            broadcast(wire()).replace(b'"schemaVersion":1', b'"schemaVersion":1.0'),
            broadcast(wire()).replace(b'"schemaVersion":1', b'"schemaVersion":NaN'),
            broadcast(wire()).replace(b'result=0', b'result=1'), broadcast(wire())*2,
            broadcast(wire()).replace(probe.COMPONENT.encode(), b'io.foreign/.Receiver'),
            broadcast(wire()).replace(probe.ACTION.encode(), b'io.foreign.MEASURE'),
            broadcast(wire())+b'arbitrary diagnostic text\n', broadcast(wire()).replace(b'4242', b'\xff')]
        for raw in malformed:
            with self.subTest(bytes=len(raw)):
                self.failure('reply', lambda: probe.broadcast_result(raw))

    def test_environment_identity_and_production_guards_run_before_any_mutation(self):
        fixture = Fixture()
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'false', 'SYN443_CI_AVD': 'syn443-ci'}):
            self.failure('environment', lambda: probe.guard(fixture.adb, probe=False, engines=fixture.engines))
        self.assertEqual([], fixture.calls)
        substitutions = [({('get-serialno',): b'phone'}, 'identity'),
            ({('emu', 'avd', 'name'): b'other\nOK'}, 'identity'),
            ({('shell', 'getprop', 'ro.kernel.qemu'): b'0'}, 'identity'),
            ({('shell', 'getprop', 'ro.hardware'): b'qcom'}, 'identity'),
            ({('shell', 'getprop', 'ro.debuggable'): b'0'}, 'identity'),
            ({('shell', 'getprop', 'ro.build.version.sdk'): b'35'}, 'identity'),
            ({('shell', 'id', '-u'): b'0'}, 'identity'),
            ({('shell', 'pm', 'list', 'packages', '--user', '0', 'io.syn443.android'): b'package:io.syn443.android'}, 'production_app')]
        with patch.dict('os.environ', ENV):
            fresh = Fixture();fresh.installed = False
            self.assertEqual(fresh.context, probe.guard(fresh.adb, probe=False, engines=fresh.engines))
            for changes, reason in substitutions:
                f = Fixture(changes)
                self.failure(reason, lambda: probe.guard(f.adb, probe=False, engines=f.engines))
                self.assertFalse(any(call[0] in ('reboot', 'install', 'root', 'unroot') or call[:3] == ('shell', 'am', 'broadcast') for call in f.calls))
            f = Fixture()
            self.failure('probe_package', lambda: probe.guard(f.adb, probe=False, engines=f.engines))
            self.failure('identity', lambda: probe.guard(f.adb, probe=True, engines=lambda _: []))

    def test_three_actual_stage_functions_require_new_boots_preserved_fixture_and_no_command_replay(self):
        f = Fixture();f.lost_reboot = True;f.boot_delay = 2;captures = [];previous = None
        with patch.dict('os.environ', ENV):
            for stage in range(3):
                previous = f.capture(captures, stage, previous)
        self.assertEqual(3, len(captures));self.assertEqual(2, f.calls.count(('reboot',)))
        self.assertEqual(3, sum(call[:3] == ('shell', 'am', 'broadcast') for call in f.calls))
        self.assertTrue(all(row['frameworkContinuous'] and row['healthWindowMs'] >= 30000 for row in captures))
        self.assertTrue(all(not row['seedSentinelLoaded'] for row in captures))
        self.assertEqual('PASS', probe.public_result('a'*40, captures, 'none', no_production_app=True)['verdict'])
        self.assertFalse(any(call in (('root',), ('unroot',), ('shell', 'stop'), ('shell', 'start')) for call in f.calls))

    def test_sixteen_mib_actual_capture_stays_failure_despite_good_properties_and_two_reboots(self):
        f = Fixture({('shell', 'getprop', 'debug.syn443.vm_seed'): b'v1'})
        f.maximum = 16*1024*1024;captures = [];previous = None
        with patch.dict('os.environ', ENV):
            for stage in range(3):
                previous = f.capture(captures, stage, previous)
        result = probe.public_result('a'*40, captures, 'none', no_production_app=True)
        self.assertEqual('FAIL', result['verdict']);self.assertEqual('captured_heap', result['reason'])
        self.assertEqual([16*1024*1024]*3, [row['snapshot']['maxBytes'] for row in result['captures']])
        self.assertTrue(all(row['seedSentinelLoaded'] for row in result['captures']))
        self.assertFalse(any('dalvik.vm.' in ' '.join(call) for call in f.calls))
        self.assertEqual(2, f.calls.count(('reboot',)))

    def test_stale_boot_or_changed_framework_cannot_borrow_readiness_or_trigger_repair(self):
        f = Fixture();captures = []
        with patch.dict('os.environ', ENV):
            previous = f.capture(captures)
            f.stale_boot = True
            self.failure('boot_deadline', lambda: f.capture(captures, 1, previous, budget=4, health=1))
        self.assertEqual(1, f.calls.count(('reboot',)));self.assertEqual(1, len(captures))
        broken = Fixture();broken.bad_health = True;partial = []
        with patch.dict('os.environ', ENV):
            self.failure('framework', lambda: broken.capture(partial))
        self.assertEqual(1, len(partial));self.assertFalse(partial[0]['frameworkContinuous'])
        self.assertEqual('FAIL', probe.public_result('a'*40, partial, 'framework', no_production_app=True)['verdict'])
        self.assertFalse(any(call[0] in ('reboot', 'root', 'unroot') or call in (('shell', 'stop'), ('shell', 'start')) for call in broken.calls))

    def test_real_ams_readiness_package_debug_and_snapshot_pid_are_mandatory(self):
        delayed = Fixture();delayed.ready_after = 2;captures = []
        with patch.dict('os.environ', ENV):
            delayed.capture(captures)
        self.assertGreaterEqual(delayed.now, 32)
        for changes, reason in [({('shell', 'pidof', probe.PACKAGE): b'999'}, 'probe_package'),
            ({('shell', 'getprop', 'debug.syn443.vm_seed'): b'x'*65}, 'identity'),
            ({('shell', 'dumpsys', 'package', probe.PACKAGE): b'pkgFlags=[ HAS_CODE ]'}, 'probe_package'),
            ({('shell', 'pm', 'list', 'packages', '-U', '--user', '0', probe.PACKAGE): b'package:io.syn443.emulatorheap.test uid:10001'}, 'probe_package'),
            ({('shell', 'sha256sum', '/data/app/synthetic/base.apk'): b'b'*64+b'  /data/app/synthetic/base.apk'}, 'preservation')]:
            f = Fixture(changes)
            with patch.dict('os.environ', ENV):
                self.failure(reason, lambda: f.capture([]))
        wrong = Fixture()
        original = wrong.adb
        def adb(*args, **options):
            result = original(*args, **options)
            return broadcast(wire(pid=888)) if args[:3] == ('shell', 'am', 'broadcast') else result
        with patch.dict('os.environ', ENV):
            self.failure('reply', lambda: probe.stage_capture(adb, wrong.context, wrong.checkpoint, 0, [],
                clock=wrong.clock, sleep=wrong.sleep, engines=wrong.engines))

    def test_actual_capacity_survives_probe_exit_after_reply_without_becoming_a_success(self):
        f = Fixture(); f.maximum = 16*1024*1024; captures = []
        original = f.adb
        def adb(*args, **options):
            if args == ('shell', 'pidof', probe.PACKAGE) and f.measured:
                raise subprocess.CalledProcessError(1, 'fixture-exited-after-reply')
            return original(*args, **options)
        with patch.dict('os.environ', ENV), self.assertRaises(subprocess.CalledProcessError):
            probe.stage_capture(adb, f.context, f.checkpoint, 0, captures,
                clock=f.clock, sleep=f.sleep, engines=f.engines)
        self.assertEqual(1, len(captures))
        self.assertEqual(16*1024*1024, captures[0]['snapshot']['maxBytes'])
        self.assertFalse(captures[0]['heapAdequate'])
        self.assertFalse(captures[0]['frameworkContinuous'])
        self.assertEqual('FAIL', probe.public_result('a'*40, captures, 'adb', no_production_app=True)['verdict'])

    def test_public_artifact_is_closed_numeric_metadata_and_cannot_relabel_partial_failure(self):
        f = Fixture();captures = [];previous = None
        with patch.dict('os.environ', ENV):
            for stage in range(3):
                previous = f.capture(captures, stage, previous)
        good = probe.public_result('a'*40, captures, 'none', no_production_app=True)
        self.assertEqual('FAIL', probe.public_result('a'*40, captures, 'none')['verdict'])
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'metadata.json'
            with patch.object(probe, 'OUTPUT', target):
                target.write_text(json.dumps(good), encoding='utf-8')
                self.assertEqual(good, probe.check_artifact())
                bad = []
                for field, value in [('verdict', 'FAIL'), ('diagnosticOnly', False), ('rawBootId', 'foreign'), ('schemaVersion', True)]:
                    item = copy.deepcopy(good);item[field] = value;bad.append(item)
                item = copy.deepcopy(good);item['captures'][0]['snapshot']['endpoint'] = 'synthetic-private-value';bad.append(item)
                item = copy.deepcopy(good);item['captures'][0]['stage'] = False;bad.append(item)
                item = copy.deepcopy(good);item['captures'][0]['seedSentinelLoaded'] = 'v1';bad.append(item)
                item = copy.deepcopy(good);item['captures'][0]['frameworkContinuous'] = False;bad.append(item)
                for item in bad:
                    target.write_text(json.dumps(item), encoding='utf-8')
                    self.failure('artifact' if 'endpoint' not in item['captures'][0]['snapshot'] else 'reply', probe.check_artifact)
                target.write_text(json.dumps(good).replace('"schemaVersion": 1', '"schemaVersion": 1,"schemaVersion": 1', 1), encoding='utf-8')
                self.failure('artifact', probe.check_artifact)
                target.write_bytes(b'x'*8193)
                self.failure('artifact', probe.check_artifact)


if __name__ == '__main__':
    unittest.main()
