"""Exercise the system camera prompt on a fresh, disposable Actions emulator."""
import re
import subprocess
import time
import xml.etree.ElementTree as ET

from emulator_policy_ui import anr_owner_diagnostic, tap, tree
from run_vpn_process_faults import PACKAGE, ROOT, adb


def require_initial_camera_denied():
    # PackageManager reads the installed permission without starting or stopping
    # the target process immediately before its first visible Activity.
    user = adb('shell', 'am', 'get-current-user').strip()
    assert re.fullmatch(rb'[0-9]{1,5}', user), 'Unknown emulator user'
    result = adb('shell', 'dumpsys', 'package', 'check-permission',
                 'android.permission.CAMERA', PACKAGE, user.decode('ascii')).strip()
    assert result == b'-1', 'Expected PackageManager to report camera permission denied'


PERMISSION_OWNERS = {'com.android.permissioncontroller', 'com.google.android.permissioncontroller',
                     'com.android.packageinstaller'}


def camera_state(report):
    rows = re.findall(rb'(?m)^[ \t]*android[.]permission[.]CAMERA: granted=(true|false)(?:, flags=\[([^\]\r\n]*)\])?[ \t]*\r?$', report)
    if len(rows) != 1:
        raise AssertionError('Expected one installed camera permission record')
    granted, flags = rows[0]
    return granted == b'true', b'USER_SET' in {value.strip() for value in flags.split(b'|')}


def installed_camera_state():
    report = adb('shell', 'dumpsys', 'package', PACKAGE)
    permission = b'android.permission.CAMERA'
    if re.search(rb'(?m)^\s*android[.]permission[.]CAMERA:', report):
        return camera_state(report)
    # A fresh installation can list CAMERA only among requested permissions.
    # Verify the target package and its actual denied grant before treating a
    # missing runtime row as undecided. Only an explicit USER_SET row can pass denial.
    name = re.escape(PACKAGE.encode('ascii'))
    assert re.search(rb'(?m)^\s*Package \[' + name + rb'\] \(', report), 'No target package record'
    assert re.search(rb'(?m)^[ \t]*' + re.escape(permission) + rb'[ \t]*\r?$', report), 'Camera request absent'
    require_initial_camera_denied()
    return False, False


def camera_deny_target(nodes):
    prompts = [node for node in nodes if node.get('package') in PERMISSION_OWNERS
               and node.get('resource-id', '').endswith(':id/permission_message')]
    if len(prompts) != 1:
        return None
    text = prompts[0].get('text', '').casefold()
    if 'syn443' not in text or not any(word in text for word in ('camera', 'pictures', 'video')):
        return None
    candidates = [node for node in nodes if node.get('package') == prompts[0].get('package')
                  and node.get('enabled') == 'true' and node.get('clickable') == 'true'
                  and node.get('resource-id', '').endswith(':id/permission_deny_button')]
    return candidates[0] if len(candidates) == 1 else None


ERROR_CONTROLS = {'aerr_close', 'aerr_wait', 'aerr_report'}
CRASH_PROCESSES = {
    b'io.syn443.android': 'syn443_app',
    b'io.syn443.android:controller': 'syn443_controller',
    b'io.syn443.android:engine': 'syn443_engine',
    **{name.encode('ascii'): 'permission_controller' for name in PERMISSION_OWNERS},
    b'com.android.systemui': 'system_ui',
    b'com.android.settings': 'settings',
}
CRASH_EVENT = re.compile(
    rb'([0-9]{9,12})[.][0-9]{3,6}\s+[0-9]+\s+[0-9]+\s+I\s+am_crash\s*:\s*'
    rb'\[[0-9]{1,5},[0-9]{1,10},([A-Za-z0-9_.:]{1,160}),[^\r\n]*\]'
)


def recent_crash_event_categories(report, now):
    # These observations are adjacent in time only. They do not bind the
    # dialog to one of the events or reveal the process name or error text.
    if len(report) > 1_048_576:
        return ['oversized']
    categories = set()
    for line in report.splitlines():
        if b'am_crash' not in line:
            continue
        match = CRASH_EVENT.fullmatch(line.strip())
        if match is None:
            categories.add('unrecognized')
            continue
        if now - 120 <= int(match[1]) <= now:
            categories.add(CRASH_PROCESSES.get(match[2], 'other'))
    return sorted(categories)


def observe_recent_crash_events():
    try:
        clock = adb('shell', 'date', '+%s', timeout=2).strip()
        if not re.fullmatch(rb'[0-9]{9,12}', clock):
            return ['unavailable']
        report = adb('shell', 'logcat', '-d', '-b', 'events', '-v', 'epoch', '-t', '2048',
                     'am_crash:I', "'*:S'", timeout=3)
        return recent_crash_event_categories(report, int(clock))
    except (OSError, subprocess.SubprocessError):
        return ['unavailable']


def fail_on_error_dialog(nodes, stage):
    controls = sorted({node.get('resource-id', '').rsplit('/', 1)[-1] for node in nodes} & ERROR_CONTROLS)
    if not controls:
        return
    anr_evidence = {}
    owner = anr_owner_diagnostic(evidence=anr_evidence)
    print('Camera test system dialog: ' + repr({
        'stage': stage, 'controls': controls, 'visibleOwner': visible_owner(nodes),
        'anrOwner': owner, 'anrEvidence': anr_evidence,
        'recentCrashEvents': observe_recent_crash_events(),
    }), flush=True)
    raise AssertionError('The disposable emulator displayed an application crash or ANR')


def deny_camera():
    deadline = time.monotonic() + 45
    stable = None
    attempts = 0
    last_tap = 0.0
    observed = set()
    while time.monotonic() < deadline:
        nodes = list(tree().iter('node'))
        fail_on_error_dialog(nodes, 'deny permission')
        granted, user_set = installed_camera_state()
        assert not granted, 'Camera was granted during the denial scenario'
        target = camera_deny_target(nodes)
        observed.add((visible_owner(nodes), target is not None, user_set))
        if user_set and attempts > 0:
            return
        bounds = target.get('bounds') if target is not None else None
        now = time.monotonic()
        if not user_set and bounds and bounds == stable and attempts < 3 and now - last_tap >= 2:
            tap(target)
            attempts += 1
            last_tap = now
            stable = None
        else:
            stable = bounds
        time.sleep(.3)
    raise AssertionError(f'Camera denial was not acknowledged; taps={attempts}, observations={sorted(observed)}')


def visible_owner(nodes):
    packages = {n.get('package') for n in nodes}
    if PACKAGE in packages:
        return 'enrollment'
    if packages & {'com.google.android.permissioncontroller','com.android.permissioncontroller','com.android.packageinstaller'}:
        return 'permission'
    if packages & {'com.android.launcher3','com.google.android.apps.nexuslauncher'}:
        return 'launcher'
    if 'com.android.systemui' in packages:
        return 'system_ui'
    return 'other'


def start_enrollment():
    start = adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.EnrollmentActivity',
                '-f', '0x10008000')
    assert re.search(rb'(?m)^Status: ok\s*$', start), 'The enrollment Activity did not start'


def find_node(predicate, stage, reveal=False, recover_initial_focus=False):
    deadline = time.monotonic() + 45
    observed = set()
    retry_after = time.monotonic() + 8
    while time.monotonic() < deadline:
        nodes = list(tree().iter('node'))
        fail_on_error_dialog(nodes, stage)
        matches = [node for node in nodes if node.get('enabled') == 'true' and predicate(node)]
        if len(matches) == 1:
            return matches[0]
        owned = [node for node in nodes if node.get('package') == PACKAGE]
        owner = visible_owner(nodes)
        observed.add((owner, len(matches)))
        if recover_initial_focus and not owned and owner in ('other', 'launcher', 'system_ui') and time.monotonic() >= retry_after:
            # Package replacement may leave the launcher or another task over the
            # first Activity. Recover only before opening the system permission dialog.
            recover_initial_focus = False
            adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
            adb('shell', 'wm', 'dismiss-keyguard')
            start_enrollment()
            continue
        panes = [node for node in owned if node.get('scrollable') == 'true']
        if reveal and not matches and len(panes) == 1:
            bounds = [int(value) for value in re.findall(r'\d+', panes[0].get('bounds', ''))]
            if len(bounds) == 4:
                left, top, right, bottom = bounds
                x = str((left + right) // 2)
                adb('shell','input','swipe',x,str((top + 3*bottom)//4),x,str((3*top + bottom)//4),'250')
        time.sleep(.3)
    raise AssertionError(f'Camera permission stage {stage} lacked a unique visible control; observed {sorted(observed)}')


def main():
    assert adb('shell', 'getprop', 'ro.hardware').strip() in (b'ranchu', b'goldfish')
    def require_denied():
        report = adb('shell', 'am', 'instrument', '-w', '-e', 'observeCameraPermission', 'true',
                     PACKAGE + '.test/io.syn443.android.EnrollmentDriver')
        assert re.findall(rb'(?m)^INSTRUMENTATION_RESULT: cameraPermission=(\w+)\s*$', report) == [b'denied']
        assert re.findall(rb'(?m)^INSTRUMENTATION_CODE: (-?\d+)\s*$', report) == [b'-1']
    require_initial_camera_denied()
    assert installed_camera_state() == (False, False), 'Camera must start without a user decision'
    adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
    adb('shell', 'wm', 'dismiss-keyguard')
    start_enrollment()
    try:
        def label(text):
            return lambda n: n.get('package') == PACKAGE and n.get('text') == text
        tap(find_node(label('Сканировать QR'), 'open scanner', reveal=True, recover_initial_focus=True))
        deny_camera()
        find_node(label('QR из фото'), 'image alternative')
        find_node(lambda n: n.get('package') == PACKAGE and n.get('class') == 'android.widget.EditText', 'paste alternative')
        assert b'EnrollmentActivity' in adb('shell', 'dumpsys', 'activity', 'top')
    finally:
        adb('shell', 'input', 'keyevent', 'KEYCODE_BACK')
    require_denied()
    suite = ET.Element('testsuite', name='InvitationCameraPermission', tests='1', failures='0')
    ET.SubElement(suite, 'testcase', classname='io.syn443.android.InvitationCameraPermission', name='systemDenialReturnsToEnrollmentWithImageAndPaste')
    path = ROOT / 'app/build/outputs/androidTest-results/external/TEST-invitation-camera-permission.xml'
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(path, encoding='utf-8', xml_declaration=True)


if __name__ == '__main__':
    main()
