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

    def test_screen_diagnostic_uses_only_fixed_categories(self):
        for package, label in [(camera.PACKAGE,'enrollment'),('com.android.systemui','system_ui'),
                               ('com.android.launcher3','launcher'),('com.android.permissioncontroller','permission'),
                               ('private.example','other')]:
            self.assertEqual(label, camera.visible_owner([ET.Element('node', package=package)]))
