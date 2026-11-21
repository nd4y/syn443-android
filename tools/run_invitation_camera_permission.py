"""Exercise the system camera prompt on a fresh, disposable Actions emulator."""
import re
import time
import xml.etree.ElementTree as ET

from emulator_policy_ui import tap, tree
from run_vpn_process_faults import PACKAGE, ROOT, adb


def find_node(predicate):
    deadline = time.monotonic() + 32
    while time.monotonic() < deadline:
        matches = [node for node in tree().iter('node') if node.get('enabled') == 'true' and predicate(node)]
        if len(matches) == 1:
            return matches[0]
        time.sleep(.3)
    raise AssertionError('Expected one visible control in the camera permission flow')


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
    adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.EnrollmentActivity')
    try:
        def label(text):
            return lambda n: n.get('package') == PACKAGE and n.get('text') == text
        tap(find_node(label('Сканировать QR')))
        prompt = find_node(lambda n: n.get('package') in ('com.android.permissioncontroller', 'com.google.android.permissioncontroller', 'com.android.packageinstaller')
                           and n.get('resource-id', '').endswith(':id/permission_deny_button'))
        tap(prompt)
        find_node(label('QR из фото'))
        find_node(lambda n: n.get('package') == PACKAGE and n.get('class') == 'android.widget.EditText')
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
