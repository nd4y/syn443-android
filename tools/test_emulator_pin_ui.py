import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch
from emulator_policy_ui import pin_keys, unlock_test_pin


class EmulatorPinUiTest(unittest.TestCase):
    def keypad(self,package='com.android.systemui',count=10):
        root=ET.Element('hierarchy')
        for digit in range(count):
            parent=ET.SubElement(root,'node',package=package,clickable='true',bounds='[1,1][20,20]')
            ET.SubElement(parent,'node',package=package,text=str(digit),clickable='false',attrib={'resource-id':package+':id/key'+str(digit)})
        return root
    def test_complete_system_pin_keypad_uses_clickable_parent(self):
        keys=pin_keys(self.keypad());self.assertEqual(set('0123456789'),set(keys))
        self.assertTrue(all(n.get('clickable')=='true' for n in keys.values()))
    def test_other_app_and_incomplete_bouncer_are_not_pin_targets(self):
        self.assertEqual({},pin_keys(self.keypad('example.other')))
        self.assertEqual({},pin_keys(self.keypad(count=5)))
    def test_physical_hardware_cannot_receive_synthetic_pin_input(self):
        with patch('emulator_policy_ui.adb',return_value=b'qcom') as adb:
            with self.assertRaises(AssertionError):unlock_test_pin()
            adb.assert_called_once_with('shell','getprop','ro.hardware')
    def test_late_keyguard_gets_wake_swipe_but_digits_only_once(self):
        def reply(*args,**kwargs):
            if args==('shell','getprop','ro.hardware'):return b'ranchu'
            if args==('shell','wm','size'):return b'Physical size: 1080x2400'
            return b''
        with patch('emulator_policy_ui.adb',side_effect=reply) as adb,patch('emulator_policy_ui.tree',side_effect=[ET.Element('hierarchy'),self.keypad()]),patch('emulator_policy_ui.tap') as tap,patch('emulator_policy_ui.time.sleep'):
            unlock_test_pin()
            self.assertEqual(2,sum(c.args==('shell','input','keyevent','KEYCODE_WAKEUP') for c in adb.call_args_list))
            self.assertEqual(4,tap.call_count)


if __name__=='__main__':unittest.main()
