"""Exercise the system camera prompt on a fresh, disposable Actions emulator."""
import re
import time
import xml.etree.ElementTree as ET

from emulator_policy_ui import tap, tree
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


def deny_camera():
    deadline = time.monotonic() + 45
    stable = None
    attempts = 0
    last_tap = 0.0
    observed = set()
    while time.monotonic() < deadline:
        nodes = list(tree().iter('node'))
        granted, user_set = camera_state(adb('shell', 'dumpsys', 'package', PACKAGE))
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


def find_node(predicate, stage, reveal=False):
    deadline = time.monotonic() + 45
    observed = set()
    while time.monotonic() < deadline:
        nodes = list(tree().iter('node'))
        matches = [node for node in nodes if node.get('enabled') == 'true' and predicate(node)]
        if len(matches) == 1:
            return matches[0]
        owned = [node for node in nodes if node.get('package') == PACKAGE]
        observed.add((visible_owner(nodes), len(matches)))
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
    assert camera_state(adb('shell', 'dumpsys', 'package', PACKAGE)) == (False, False), 'Camera must start without a user decision'
    adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
    adb('shell', 'wm', 'dismiss-keyguard')
    start = adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.EnrollmentActivity')
    assert re.search(rb'(?m)^Status: ok\s*$', start), 'The enrollment Activity did not start'
    try:
        def label(text):
            return lambda n: n.get('package') == PACKAGE and n.get('text') == text
        tap(find_node(label('Сканировать QR'), 'open scanner', reveal=True))
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
