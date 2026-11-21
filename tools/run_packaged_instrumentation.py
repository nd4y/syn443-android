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


def parse_run(output):
    """Require a matching start and finish for each AndroidJUnitRunner result."""
    fields = {}
    cases = {}
    active = None
    total = None
    finished = False
    for line in output.splitlines():
        if line.startswith(('INSTRUMENTATION_FAILED:', 'INSTRUMENTATION_ABORTED:', 'INSTRUMENTATION_RESULT: shortMsg=')):
            raise ValueError('Android reported an instrumentation failure')
        if line.startswith('INSTRUMENTATION_CODE:'):
            if finished or line != 'INSTRUMENTATION_CODE: -1' or fields or active or len(cases) != total:
                raise ValueError('Instrumentation terminated abnormally or with missing outcomes')
            finished = True
        elif line.startswith('INSTRUMENTATION_STATUS: '):
            key, _, value = line.removeprefix('INSTRUMENTATION_STATUS: ').partition('=')
            if key in ('class', 'test', 'id', 'current', 'numtests'):
                if finished or key in fields:
                    raise ValueError('Repeated or late instrumentation field')
                fields[key] = value
        elif line.startswith('INSTRUMENTATION_STATUS_CODE: '):
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
    if not finished or not cases:
        raise ValueError('Missing instrumentation completion')
    suite = ET.Element('testsuite', name='Packaged Android instrumentation', tests=str(len(cases)))
    for (classname, method), code in cases.items():
        case = ET.SubElement(suite, 'testcase', classname=classname, name=method)
        if code:
            tag = {-1: 'error', -2: 'failure', -3: 'skipped', -4: 'skipped'}[code]
            ET.SubElement(case, tag, message='AndroidJUnitRunner status ' + str(code))
            print(f'{tag}: {classname}.{method}')
    return suite


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
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE, timeout=1200)
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
