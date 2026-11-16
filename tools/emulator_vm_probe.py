"""CI-only captured probe-VM capacity across real reboots, never a heap fix.

Only a fresh owned API29 AVD is admitted. Original prepareART runs before ANY
fixture install. After installation there is no framework restart, root, host
relaunch, property write, repair or command replay. This measures the forked
probe VM, not system_server's heap; its PID/AMS continuity is a separate witness.
API29 DUMP permission excludes ordinary app senders, not privileged platform/root.
The host additionally requires an actual UID2000 shell for every stage.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from emulator_boot import owned_engines
from prepare_emulator_art import framework_booted, prepare

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = 'io.syn443.emulatorheap'
COMPONENT = PACKAGE + '/.VmProbeReceiver'
ACTION = PACKAGE + '.MEASURE'
APK = ROOT / 'ci-vm-probe/build/outputs/apk/debug/ci-vm-probe-debug.apk'
OUTPUT = ROOT / 'public-evidence/avd-vm-capture.json'
MIN_HEAP = 64 * 1024 * 1024
MAX_HEAP = 2 * 1024 * 1024 * 1024
MAX_TIME = 9_007_199_254_740_991
SNAPSHOT_KEYS = {'schemaVersion', 'maxBytes', 'totalBytes', 'freeBytes', 'pid', 'uptimeMs'}
CAPTURE_KEYS = {'stage', 'snapshot', 'heapAdequate', 'bootIdChanged', 'bootCountAdvanced',
                'sameApkAndUid', 'systemServerPid', 'frameworkContinuous', 'healthWindowMs', 'seedSentinelLoaded'}
REASONS = {'none', 'environment', 'identity', 'production_app', 'probe_package', 'reply',
           'framework', 'boot_deadline', 'preservation', 'adb', 'artifact', 'captured_heap'}


class ProbeError(Exception):
    def __init__(self, reason):
        assert reason in REASONS and reason != 'none'
        self.reason = reason
        super().__init__(reason)


def need(value, reason):
    if not value:
        raise ProbeError(reason)


def number(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def snapshot(value):
    need(type(value) is dict and set(value) == SNAPSHOT_KEYS, 'reply')
    need(value['schemaVersion'] == 1 and type(value['schemaVersion']) is int, 'reply')
    need(number(value['maxBytes'], 1, MAX_HEAP), 'reply')
    need(number(value['totalBytes'], 0, value['maxBytes']), 'reply')
    need(number(value['freeBytes'], 0, value['totalBytes']), 'reply')
    need(number(value['pid'], 1, 2**31 - 1) and number(value['uptimeMs'], 0, MAX_TIME), 'reply')
    return dict(value)


def broadcast_result(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 2048, 'reply')
    try:
        text = raw.decode('ascii')
        lines = [line for line in text.splitlines() if line.strip()]
        completed = [line for line in lines if line.startswith('Broadcast completed:')]
        need(len(lines) == 2 and len(completed) == 1 and lines[1] == completed[0], 'reply')
        need(lines[0].startswith('Broadcasting: Intent { ') and 'act='+ACTION in lines[0] and 'cmp='+COMPONENT in lines[0], 'reply')
        match = re.fullmatch(r'Broadcast completed: result=0, data="(\{[^\r\n]{1,512}\})"', completed[0])
        need(match is not None, 'reply')

        def pairs(rows):
            result = {}
            for key, value in rows:
                need(key not in result, 'reply')
                result[key] = value
            return result

        def invalid(_):
            raise ProbeError('reply')

        return snapshot(json.loads(match[1], object_pairs_hook=pairs, parse_constant=invalid, parse_float=invalid))
    except ProbeError:
        raise
    except (UnicodeError, ValueError, TypeError):
        raise ProbeError('reply') from None


def guard(adb, *, probe, engines=owned_engines):
    # No ADB command may run when this is not the explicit disposable CI job.
    need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('SYN443_CI_AVD') == 'syn443-ci', 'environment')
    serial = adb('get-serialno').strip()
    need(re.fullmatch(rb'emulator-[0-9]+', serial) is not None, 'identity')
    need(adb('emu', 'avd', 'name').splitlines() == [b'syn443-ci', b'OK'], 'identity')
    need(adb('shell', 'getprop', 'ro.kernel.qemu').strip() == b'1', 'identity')
    need(adb('shell', 'getprop', 'ro.hardware').strip() in (b'ranchu', b'goldfish'), 'identity')
    need(adb('shell', 'getprop', 'ro.debuggable').strip() == b'1', 'identity')
    need(adb('shell', 'getprop', 'ro.build.version.sdk').strip() == b'29', 'identity')
    need(adb('shell', 'id', '-u').strip() == b'2000', 'identity')
    need(not adb('shell', 'pm', 'list', 'packages', '--user', '0', 'io.syn443.android').strip(), 'production_app')
    current = engines('syn443-ci')
    need(len(current) == 1, 'identity')
    if not probe:
        need(not adb('shell', 'pm', 'list', 'packages', '--user', '0', PACKAGE).strip(), 'probe_package')
    return serial, current[0]


def package(adb):
    path = adb('shell', 'pm', 'path', '--user', '0', PACKAGE).strip()
    need(re.fullmatch(rb'package:/data/app/[A-Za-z0-9_./+=~-]+/base\.apk', path) is not None, 'probe_package')
    uid = adb('shell', 'pm', 'list', 'packages', '-U', '--user', '0', PACKAGE).strip()
    match = re.fullmatch(rb'package:io\.syn443\.emulatorheap uid:([1-9][0-9]{0,8})', uid)
    need(match is not None and 10000 <= int(match[1]) < 100000, 'probe_package')
    digest = adb('shell', 'sha256sum', path[8:].decode('ascii')).split()
    need(len(digest) == 2 and re.fullmatch(rb'[a-f0-9]{64}', digest[0]) is not None and digest[1] == path[8:], 'probe_package')
    flags = adb('shell', 'dumpsys', 'package', PACKAGE)
    need(len(flags) <= 262144 and re.search(rb'\bpkgFlags=\[[^\]\r\n]*\bDEBUGGABLE\b[^\]\r\n]*\]', flags) is not None, 'probe_package')
    return path, digest[0], match[1]


def boot_id(adb):
    value = adb('shell', 'cat', '/proc/sys/kernel/random/boot_id').strip()
    need(re.fullmatch(rb'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value) is not None, 'identity')
    return value


def boot_count(adb):
    raw = adb('shell', 'settings', 'get', 'global', 'boot_count').strip()
    need(re.fullmatch(rb'[0-9]{1,9}', raw) is not None, 'identity')
    return int(raw)


def process(adb, name, *, absent=False):
    try:
        raw = adb('shell', 'pidof', name).strip()
    except subprocess.CalledProcessError as error:
        if absent and error.returncode == 1:
            return None
        raise
    if absent and not raw:
        return None
    need(re.fullmatch(rb'[1-9][0-9]{0,9}', raw) is not None and int(raw) <= 2**31 - 1, 'framework')
    return int(raw)


def ready(adb):
    if adb('shell', 'getprop', 'sys.boot_completed').strip() != b'1':
        return None
    first = process(adb, 'system_server')
    if b': found' not in adb('shell', 'service', 'check', 'package'):
        return None
    activity = adb('shell', 'dumpsys', 'activity', '-a', 'processes')
    need(isinstance(activity, bytes) and len(activity) <= 1048576, 'framework')
    if not framework_booted(activity):
        return None
    need(process(adb, 'system_server') == first, 'framework')
    return first


def stage_capture(adb, context, checkpoint, stage, captures, *, previous=None,
                  clock=time.monotonic, sleep=time.sleep, engines=owned_engines, budget=150, health=30):
    """One deadline, one reboot, one measurement; no repair or hidden retry."""
    need(type(stage) is int and stage in (0, 1, 2) and 0 < health <= 30 and health < budget <= 150, 'environment')
    need(len(captures) == stage, 'artifact')
    need((stage == 0) == (previous is None), 'environment')
    deadline = clock() + budget

    def call(*args, **_):
        remaining = deadline - clock()
        need(remaining > 0, 'boot_deadline')
        return adb(*args, timeout=min(5, remaining))

    if stage:
        need(previous is not None, 'environment')
        try:
            call('reboot')
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass  # Lost acknowledgement does not authorize a second reboot.
    while clock() < deadline:
        need(engines('syn443-ci') == [context[1]], 'identity')
        try:
            current_boot = boot_id(call)
            if previous is not None and current_boot == previous[0]:
                sleep(min(1, max(0, deadline-clock())))
                continue
            server = ready(call)
            if server is None:
                sleep(min(1, max(0, deadline-clock())))
                continue
            # Settings may be unavailable while adbd/proc already answer. Only
            # ask its boot counter after the full framework readiness witness.
            current_count = boot_count(call)
            if previous is not None and current_count <= previous[1]:
                sleep(min(1, max(0, deadline-clock())))
                continue
            need(guard(call, probe=True, engines=engines) == context, 'identity')
            need(package(call) == checkpoint, 'preservation')
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            sleep(min(1, max(0, deadline-clock())))
    else:
        raise ProbeError('boot_deadline')
    # No prior probe process can be borrowed as a fresh post-boot fork witness.
    need(process(call, PACKAGE, absent=True) is None, 'probe_package')
    marker = call('shell', 'getprop', 'debug.syn443.vm_seed').strip()
    need(len(marker) <= 64 and all(value < 128 for value in marker), 'identity')
    # Optional experiment metadata only; this cannot establish captured capacity.
    seed_loaded = marker == b'v1'
    raw = call('shell', 'am', 'broadcast', '--user', '0', '-a', ACTION, '-n', COMPONENT, '-f', '0x10000020')
    measured = broadcast_result(raw)
    record = {'stage': stage, 'snapshot': measured, 'heapAdequate': measured['maxBytes'] >= MIN_HEAP,
              'bootIdChanged': stage > 0, 'bootCountAdvanced': stage > 0, 'sameApkAndUid': True,
              'systemServerPid': server, 'frameworkContinuous': False, 'healthWindowMs': 0,
              'seedSentinelLoaded': seed_loaded}
    captures.append(record)
    # A receiver can return actual capacity and die immediately afterwards.
    # Preserve that bounded observation; a missing live PID still fails the run.
    need(process(call, PACKAGE) == measured['pid'], 'reply')
    started = clock()
    while True:
        need(engines('syn443-ci') == [context[1]] and boot_id(call) == current_boot, 'identity')
        need(process(call, 'system_server') == server and ready(call) == server, 'framework')
        record['healthWindowMs'] = min(150000, max(0, int((clock()-started)*1000)))
        if clock()-started >= health:
            break
        sleep(min(1, max(0, deadline-clock())))
    need(package(call) == checkpoint and guard(call, probe=True, engines=engines) == context, 'preservation')
    need(clock() < deadline, 'boot_deadline')
    record['frameworkContinuous'] = True
    return current_boot, current_count


def public_result(source, captures, reason, *, no_production_app=False):
    need(re.fullmatch(r'[a-f0-9]{40}', source) is not None and reason in REASONS and len(captures) <= 3, 'artifact')
    safe = []
    for index, value in enumerate(captures):
        need(type(value) is dict and set(value) == CAPTURE_KEYS and number(value['stage'], index, index), 'artifact')
        copy = dict(value)
        copy['snapshot'] = snapshot(value['snapshot'])
        for field in ('heapAdequate', 'bootIdChanged', 'bootCountAdvanced', 'sameApkAndUid', 'frameworkContinuous', 'seedSentinelLoaded'):
            need(type(value[field]) is bool, 'artifact')
        need(value['heapAdequate'] == (value['snapshot']['maxBytes'] >= MIN_HEAP), 'artifact')
        need(value['bootIdChanged'] == (index > 0) and value['bootCountAdvanced'] == (index > 0), 'artifact')
        need(number(value['systemServerPid'], 1, 2**31-1) and number(value['healthWindowMs'], 0, 150000), 'artifact')
        safe.append(copy)
    need(type(no_production_app) is bool, 'artifact')
    complete = no_production_app and len(safe) == 3 and all(row['heapAdequate'] and row['frameworkContinuous'] and row['sameApkAndUid']
                                     and row['healthWindowMs'] >= 30000 for row in safe)
    if reason == 'none' and not complete:
        reason = 'captured_heap'
    return {'schemaVersion': 1, 'sourceCommit': source, 'diagnosticOnly': True, 'api': 29,
            'noProductionApp': no_production_app, 'hostFrameworkRestartAfterInstall': False,
            'verdict': 'PASS' if complete and reason == 'none' else 'FAIL', 'reason': reason, 'captures': safe}


def check_artifact():
    need(OUTPUT.is_file() and not OUTPUT.is_symlink() and 0 < OUTPUT.stat().st_size <= 8192, 'artifact')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'artifact')
            value[key] = item
        return value
    def invalid(_):
        raise ProbeError('artifact')
    document = json.loads(OUTPUT.read_text(encoding='utf-8'), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(document) is dict and set(document) == {'schemaVersion', 'sourceCommit', 'diagnosticOnly', 'api',
        'noProductionApp', 'hostFrameworkRestartAfterInstall', 'verdict', 'reason', 'captures'}, 'artifact')
    expected = public_result(document['sourceCommit'], document['captures'], document['reason'],
                             no_production_app=document['noProductionApp'])
    need(type(document['schemaVersion']) is int and type(document['api']) is int and
         type(document['diagnosticOnly']) is bool and type(document['hostFrameworkRestartAfterInstall']) is bool and document == expected, 'artifact')
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--source')
    mode.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        try:
            checked = check_artifact()
            print(json.dumps({'schemaValid': True, 'verdict': checked['verdict']}))
            return 0
        except Exception:
            print(json.dumps({'schemaValid': False}))
            return 1
    captures, reason, no_production_app = [], 'none', False
    last_failure = {'operation': 'none', 'kind': 'none'}
    try:
        need(re.fullmatch(r'[a-f0-9]{40}', args.source) is not None, 'artifact')
        need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('SYN443_CI_AVD') == 'syn443-ci', 'environment')
        binary = shutil.which('adb')
        need(binary is not None, 'adb')
        selected = subprocess.check_output([binary, '-e', 'get-serialno'], timeout=5).strip().decode('ascii')
        need(re.fullmatch(r'emulator-[0-9]+', selected) is not None, 'identity')

        def adb(*items, timeout=5):
            prefix = tuple(items[:3])
            operation = 'probe_broadcast' if prefix == ('shell', 'am', 'broadcast') else (
                'probe_pid' if tuple(items) == ('shell', 'pidof', PACKAGE) else (
                'system_pid' if tuple(items) == ('shell', 'pidof', 'system_server') else (
                'reboot' if tuple(items) == ('reboot',) else 'guard_or_framework')))
            try:
                reply = subprocess.run([binary, '-s', selected, *items], capture_output=True, timeout=timeout)
                if reply.returncode:
                    last_failure.update(operation=operation, kind='nonzero_exit')
                    raise subprocess.CalledProcessError(reply.returncode, 'owned-adb')
                return reply.stdout
            except subprocess.TimeoutExpired:
                last_failure.update(operation=operation, kind='timeout')
                raise

        context = guard(adb, probe=False)
        no_production_app = True
        need(APK.is_file() and not APK.is_symlink() and 0 < APK.stat().st_size <= 16*1024*1024 and not OUTPUT.exists(), 'artifact')
        apk_digest = hashlib.sha256(APK.read_bytes()).hexdigest().encode('ascii')
        try:
            prepare(adb)  # Existing fresh/uninstalled guard stays unchanged.
        except AssertionError:
            raise ProbeError('framework') from None
        need(guard(adb, probe=False) == context, 'identity')
        need(b'Success' in adb('install', '--no-incremental', str(APK), timeout=60), 'probe_package')
        checkpoint = package(adb)
        need(checkpoint[1] == apk_digest, 'probe_package')
        previous = None
        for stage in range(3):
            previous = stage_capture(adb, context, checkpoint, stage, captures, previous=previous)
    except ProbeError as error:
        reason = error.reason
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, UnicodeError):
        reason = 'adb'
        print(json.dumps({'failedOperation': last_failure['operation'], 'failureKind': last_failure['kind'],
                          'completedCaptures': len(captures)}))
    except Exception:
        reason = 'artifact'
    result = public_result(args.source, captures, reason, no_production_app=no_production_app and reason != 'production_app')
    OUTPUT.parent.mkdir(exist_ok=True)
    with OUTPUT.open('x', encoding='utf-8') as output:
        json.dump(result, output, sort_keys=True, separators=(',', ':'))
        output.write('\n')
    print(json.dumps({'diagnosticOnly': True, 'verdict': result['verdict'], 'reason': result['reason'], 'captures': len(captures)}))
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
