"""Run the already scanned APK pair on the disposable Actions emulator."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

from build_manifest import APKS, apk_record
from collect_public_emulator import CLASS, METHOD


def verify_apks(root, manifest, source, run, attempt):
    if (manifest.get('schemaVersion') != 1 or manifest.get('sourceCommit') != source
            or manifest.get('actionsRun') != run or not 1 <= manifest.get('actionsAttempt', 0) <= attempt):
        raise ValueError('APK manifest belongs to another workflow build')
    for path, package in APKS:
        if apk_record(root, path, package) != manifest['artifacts'].get(path.as_posix()):
            raise ValueError('Downloaded APK differs from its build manifest')


class InstrumentationInterrupted(ValueError):
    pass


def interruption(reporter_line, completed, total, active):
    """Describe a runner stop using only bounded counts and a checked-in test identity."""
    reason = {
        None: 'deadline',
        'INSTRUMENTATION_RESULT: shortMsg=Process crashed.': 'process_crashed',
        'INSTRUMENTATION_RESULT: shortMsg=Process crashed': 'process_crashed',
    }.get(reporter_line, 'runner_stopped')
    summary = f'Android instrumentation {reason}; completed={completed}/{total or 0}'
    if active is not None:
        classname, method = active
        # Never reflect arbitrary status text into the public job log.
        test_root = Path(__file__).resolve().parents[1] / 'app/src/androidTest/kotlin'
        if len(classname) <= 200 and len(method) <= 200:
            source = test_root.joinpath(*classname.split('.')).with_suffix('.kt')
            if source.is_file() and re.search(r'@Test\s+fun\s+' + re.escape(method) + r'\s*\(', source.read_text(encoding='utf-8')):
                summary += f'; active={classname}.{method}'
    return InstrumentationInterrupted(summary)


VPN_LIFECYCLE_CLASS = 'io.syn443.android.VpnLifecycleTest'
VPN_PHASES = {'Off', 'NoNetwork', 'Online', 'Starting', 'Connecting', 'Recovering', 'Degraded',
              'NeedsAction', 'NeedsPermission', 'NeedsLogin', 'NeedsUnlock', 'BlockedByPolicy'}
VPN_REASONS = {'network_unavailable', 'network_changed', 'network_capabilities_changed', 'captive_portal',
               'dns_resolution_failed', 'tls_failed', 'transport_failed', 'transport_eof', 'required_https_ok',
               'native_start_failed', 'native_release_timeout', 'policy_gate_pending', 'health_check_timeout'}


def vpn_lifecycle_snapshot(stack_head):
    match = re.match(
        r'java\.lang\.AssertionError: VPN lifecycle deadline exceeded: phase=([^,\r\n]{0,48}), '
        r'reason=([^,\r\n]{0,64}), wifi=(true|false|unknown), ',
        stack_head,
    )
    if match is None:
        return None
    phase, reason, wifi = match.groups()
    return (phase if phase in VPN_PHASES else 'unknown',
            reason if reason in VPN_REASONS else 'other',
            wifi)


def parse_run(output, *, timed_out=False):
    """Require a matching start and finish for each AndroidJUnitRunner result."""
    fields = {}
    cases = {}
    active = None
    source_lines = {}
    failure_categories = {}
    vpn_snapshots = {}
    reading_stack = False
    total = None
    finished = False
    for line in output.splitlines():
        if line.startswith(('INSTRUMENTATION_FAILED:', 'INSTRUMENTATION_ABORTED:', 'INSTRUMENTATION_RESULT: shortMsg=')):
            raise interruption(line, len(cases), total, active)
        if line.startswith('INSTRUMENTATION_CODE:'):
            if finished or line != 'INSTRUMENTATION_CODE: -1' or fields or active or len(cases) != total:
                raise ValueError('Instrumentation terminated abnormally or with missing outcomes')
            finished = True
        elif line.startswith('INSTRUMENTATION_STATUS: '):
            key, _, value = line.removeprefix('INSTRUMENTATION_STATUS: ').partition('=')
            reading_stack = key == 'stack' and active is not None
            if reading_stack:
                # Retain a fixed category only. The message and arbitrary class names
                # can contain application or user data.
                exception = value.partition(':')[0]
                category = {
                    'androidx.compose.ui.test.ComposeTimeoutException': 'compose_timeout',
                    'java.lang.AssertionError': 'assertion',
                    'java.lang.IllegalStateException': 'invalid_state',
                    'junit.framework.AssertionFailedError': 'assertion',
                    'org.junit.ComparisonFailure': 'assertion',
                }.get(exception)
                if category:
                    failure_categories[active] = category
                if active[0] == VPN_LIFECYCLE_CLASS:
                    snapshot = vpn_lifecycle_snapshot(value)
                    if snapshot is not None:
                        vpn_snapshots[active] = snapshot
            if key in ('class', 'test', 'id', 'current', 'numtests'):
                if finished or key in fields:
                    raise ValueError('Repeated or late instrumentation field')
                fields[key] = value
        elif line.startswith('INSTRUMENTATION_STATUS_CODE: '):
            reading_stack = False
            if finished or set(fields) != {'class', 'test', 'id', 'current', 'numtests'}:
                raise ValueError('Incomplete instrumentation status')
            identity = fields['class'], fields['test']
            if fields['id'] != 'AndroidJUnitRunner' or not CLASS.fullmatch(identity[0]) or not METHOD.fullmatch(identity[1]):
                raise ValueError('Unknown instrumentation identity')
            count, position = int(fields['numtests']), int(fields['current'])
            if not 1 <= count <= 10000 or (total is not None and total != count) or position != len(cases) + 1 or position > count:
                raise ValueError('Invalid instrumentation test sequence')
            total = count
            code = int(line.split(': ', 1)[1])
            if code == 1 and active is None and identity not in cases:
                active = identity
            elif code in (0, -1, -2, -3, -4) and active == identity:
                cases[identity] = code
                active = None
            else:
                raise ValueError('Unpaired instrumentation outcome')
            fields.clear()
        elif reading_stack and active not in source_lines:
            classname, test = active
            simple_class = classname.rsplit('.', 1)[-1]
            # Kotlin may put the assertion in a generated lambda frame. Only match the
            # current public test, its own filename and a bounded source line number.
            owner = re.escape(classname)
            method = re.escape(test)
            callable_name = rf"(?:\.{method}(?:\x24lambda[-\x24][0-9]+)*|\x24{method}(?:\x24[0-9]+)+\.invoke)"
            frame = re.fullmatch(rf"\s*at {owner}{callable_name}\({re.escape(simple_class)}\.kt:([1-9][0-9]{{0,3}})\)\s*", line)
            if frame:
                source_lines[active] = int(frame[1])
    if timed_out:
        raise interruption(None, len(cases), total, active)
    if not finished or not cases:
        raise ValueError('Missing instrumentation completion')
    suite = ET.Element('testsuite', name='Packaged Android instrumentation', tests=str(len(cases)))
    for (classname, method), code in cases.items():
        case = ET.SubElement(suite, 'testcase', classname=classname, name=method)
        if code:
            tag = {-1: 'error', -2: 'failure', -3: 'skipped', -4: 'skipped'}[code]
            ET.SubElement(case, tag, message='AndroidJUnitRunner status ' + str(code))
            print(f'{tag}: {classname}.{method}')
            if (classname, method) in failure_categories:
                print(f'Test failure category: {failure_categories[classname, method]}')
            if (classname, method) in source_lines:
                print(f'Test source line: {source_lines[classname, method]}')
            if (classname, method) in vpn_snapshots:
                phase, reason, wifi = vpn_snapshots[classname, method]
                print(f'VPN lifecycle snapshot: phase={phase}, reason={reason}, wifi={wifi}')
    return suite


def deadline_failure(raw):
    # adb can stop halfway through a status line. Only parse complete reporter
    # events; neither malformed data nor a final status can make a timeout pass.
    if raw and len(raw) <= 8 * 1024 * 1024:
        prefix = raw.rpartition(b'\n')[0].decode('utf-8', errors='replace')
        try:
            parse_run(prefix, timed_out=True)
        except InstrumentationInterrupted as ended:
            return ended
        except (ValueError, OverflowError):
            pass
    return interruption(None, 0, None, None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step', choices=('verify', 'run'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((Path(os.environ['RUNNER_TEMP']) / 'build-manifest.json').read_bytes())
    commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    verify_apks(root, manifest, commit, int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT']))
    if args.step == 'verify':
        return
    adb = ['adb', '-e']
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('SYN443_CI_AVD') != 'syn443-ci'
            or not re.fullmatch(rb'emulator-[0-9]+', subprocess.check_output([*adb, 'get-serialno']).strip())
            or subprocess.check_output([*adb, 'emu', 'avd', 'name']).splitlines() != [b'syn443-ci', b'OK']):
        raise ValueError('The test runner requires the disposable CI emulator')
    command = [*adb, 'shell', 'am', 'instrument', '-w', '-r', '-e', 'listener',
               'io.syn443.android.NetBirdTestProgress,io.syn443.android.DiagnosticBundleTestProgress',
               'io.syn443.android.test/io.syn443.android.EnrollmentDriver']
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, timeout=1200)
    except subprocess.TimeoutExpired as exc:
        raise deadline_failure(exc.stdout) from None
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError('Instrumentation result exceeded its output limit')
    suite = parse_run(result.stdout.decode('utf-8', errors='replace'))
    path = root / 'app/build/outputs/androidTest-results/connected/TEST-packaged.xml'
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(path, encoding='utf-8', xml_declaration=True)
    if any(suite.find('.//' + tag) is not None for tag in ('failure', 'error', 'skipped')):
        raise SystemExit('Packaged instrumentation had unsuccessful tests')


if __name__ == '__main__':
    main()
