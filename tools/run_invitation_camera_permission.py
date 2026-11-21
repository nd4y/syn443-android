"""Exercise the system camera prompt on a fresh, disposable Actions emulator."""
import re
import time
import xml.etree.ElementTree as ET

from emulator_policy_ui import tap, tree
from run_vpn_process_faults import PACKAGE, ROOT, adb


def find_node(predicate, stage, reveal=False):
    deadline = time.monotonic() + 45
    observed = set()
    while time.monotonic() < deadline:
        nodes = list(tree().iter('node'))
        matches = [node for node in nodes if node.get('enabled') == 'true' and predicate(node)]
        if len(matches) == 1:
            return matches[0]
        owned = [node for node in nodes if node.get('package') == PACKAGE]
        observed.add(('enrollment' if owned else 'system', len(matches)))
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
    require_denied()
    adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
    adb('shell', 'wm', 'dismiss-keyguard')
    # The read-only instrumentation above uses the target app process. Start
    # from a new Activity process after the OS has finished tearing it down.
    start = adb('shell', 'am', 'start', '-S', '-W', '-n', PACKAGE + '/.EnrollmentActivity')
    assert re.search(rb'(?m)^Status: ok\s*$', start), 'The enrollment Activity did not start'
    try:
        def label(text):
            return lambda n: n.get('package') == PACKAGE and n.get('text') == text
        tap(find_node(label('Сканировать QR'), 'open scanner', reveal=True))
        prompt = find_node(lambda n: n.get('package') in ('com.android.permissioncontroller', 'com.google.android.permissioncontroller', 'com.android.packageinstaller')
                           and n.get('resource-id', '').endswith(':id/permission_deny_button'), 'system deny')
        tap(prompt)
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
