import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

import run_invitation_camera_permission as camera


class CameraPermissionTest(unittest.TestCase):
    def test_preflight_queries_current_user_without_launching_target_instrumentation(self):
        with patch.object(camera, 'adb', side_effect=[b'10\n', b'-1\n']) as adb:
            camera.require_initial_camera_denied()
        self.assertEqual([c.args for c in adb.call_args_list], [
            ('shell', 'am', 'get-current-user'),
            ('shell', 'dumpsys', 'package', 'check-permission', 'android.permission.CAMERA', camera.PACKAGE, '10'),
        ])
        for replies in ([b'0', b'0'], [b'0', b'unknown'], [b'not-a-user']):
            with self.subTest(replies=replies), patch.object(camera, 'adb', side_effect=replies), self.assertRaises(AssertionError):
                camera.require_initial_camera_denied()

    def test_missing_runtime_row_requires_installed_request_and_current_denied_grant(self):
        fresh = b'  Package [io.syn443.android] (abc):\n    requested permissions:\n      android.permission.CAMERA\n'
        with patch.object(camera, 'adb', side_effect=[fresh,b'0',b'-1']):
            self.assertEqual((False,False),camera.installed_camera_state())
        for bad in (fresh.replace(b'io.syn443.android', b'example.other'),
                    fresh.replace(b'android.permission.CAMERA', b'android.permission.INTERNET'),
                    fresh+b'      android.permission.CAMERA: granted=unknown\n'):
            with patch.object(camera, 'adb', return_value=bad), self.assertRaises(AssertionError):
                camera.installed_camera_state()
        with patch.object(camera, 'adb', side_effect=[fresh,b'0',b'0']), self.assertRaises(AssertionError):
            camera.installed_camera_state()

    def test_denial_must_be_an_explicit_android_decision(self):
        self.assertEqual((False, False), camera.camera_state(b'  android.permission.CAMERA: granted=false\r\n'))
        prefix = b'android.permission.CAMERA: granted=false, flags=['
        self.assertEqual((False, False), camera.camera_state(prefix + b' USER_SENSITIVE_WHEN_DENIED]'))
        self.assertEqual((False, True), camera.camera_state(prefix + b' USER_SET|USER_SENSITIVE_WHEN_DENIED]'))
        self.assertEqual((True, True), camera.camera_state(prefix.replace(b'false', b'true') + b' USER_SET]'))
        with self.assertRaises(AssertionError):
            camera.camera_state(prefix + b']\n' + prefix + b']')

    def test_only_the_visible_syn443_camera_request_may_be_denied(self):
        owner = 'com.android.permissioncontroller'
        def node(name, text=''):
            return ET.Element('node', {'package': owner, 'enabled': 'true', 'clickable': 'true',
                                       'resource-id': owner + ':id/' + name, 'text': text, 'bounds': '[10,10][50,50]'})
        message = node('permission_message', 'Allow SYN443 to take pictures and record video?')
        button = node('permission_deny_button')
        self.assertIs(button, camera.camera_deny_target([message, button]))
        for nodes in ([button], [message, button, button], [node('permission_message', 'Allow SYN443 to send notifications?'), button],
                      [node('permission_message', 'Allow a different app to use your camera?'), button]):
            self.assertIsNone(camera.camera_deny_target(nodes))

    def test_screen_diagnostic_uses_only_fixed_categories(self):
        for package, label in [(camera.PACKAGE,'enrollment'),('com.android.systemui','system_ui'),
                               ('com.android.launcher3','launcher'),('com.android.permissioncontroller','permission'),
                               ('private.example','other')]:
            self.assertEqual(label, camera.visible_owner([ET.Element('node', package=package)]))
