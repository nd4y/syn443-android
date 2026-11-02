import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch
import emulator_policy_ui as ui

def node(parent,**values):return ET.SubElement(parent,'node',{k.replace('_','-'):v for k,v in values.items()})

class OwnedVpnSettingsTest(unittest.TestCase):
    def row(self,package='com.android.settings',description='Settings for SYN443',offset=0):
        root=ET.Element('hierarchy');row=node(root,package=package,bounds=f'[0,{offset}][400,{offset+80}]')
        node(row,package=package,resource_id='android:id/title',text='SYN443',bounds=f'[20,{offset+20}][180,{offset+50}]')
        gear=node(row,package=package,resource_id='com.android.settings:id/settings_button',content_desc=description,bounds=f'[320,{offset+10}][380,{offset+70}]')
        return root,gear
    def test_owned_row_accepts_description_or_standard_gear_id(self):
        for description in ['Settings for SYN443','Settings','']:
            root,gear=self.row(description=description);self.assertIs(ui.profile_settings(root),gear)
    def test_foreign_package_description_and_sibling_row_are_rejected(self):
        root,_=self.row(package='com.android.systemui');self.assertIsNone(ui.profile_settings(root))
        root,_=self.row(description='Settings for another VPN');self.assertIsNone(ui.profile_settings(root))
        root,gear=self.row();gear.set('bounds','[320,110][380,170]');self.assertIsNone(ui.profile_settings(root))
        root,_=self.row();next(root.iter('node')).find('node').set('text','Another VPN');self.assertIsNone(ui.profile_settings(root))
    def test_two_line_title_and_gear_need_not_overlap_inside_the_owned_row(self):
        root,gear=self.row(description='Settings');gear.set('bounds','[320,51][380,79]')
        self.assertIs(ui.profile_settings(root),gear)
    def test_ascending_to_a_foreign_sibling_row_cannot_borrow_its_gear(self):
        root,gear=self.row();root.find('node').remove(gear)
        other,_=self.row(offset=90);other.find('node').find('node').set('text','Another VPN')
        root.append(other.find('node'));self.assertIsNone(ui.profile_settings(root))
    def test_navigation_wakes_only_disposable_emulator_and_resets_settings_task(self):
        root,gear=self.row();calls=[]
        def adb(*args,**kwargs):
            calls.append(args)
            if args[-1]=='ro.hardware':return b'ranchu\n'
            if args[-1]=='size':return b'Physical size: 1080x1920\n'
            return b''
        with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',return_value=root),patch.object(ui,'tap')as tap:
            ui.open_policy();tap.assert_called_once_with(gear)
        self.assertIn(('shell','am','start','-W','-a','android.settings.VPN_SETTINGS','-p','com.android.settings','-f','0x10008000'),calls)
        with patch.object(ui,'adb',return_value=b'physical-phone'),patch.object(ui,'tree')as tree:
            with self.assertRaises(AssertionError):ui.open_policy()
            tree.assert_not_called()
    def test_protected_bouncer_is_never_filled_by_policy_navigation(self):
        root,_=self.row()
        def adb(*args,**kwargs):return b'ranchu' if args[-1]=='ro.hardware' else b'1080x1920' if args[-1]=='size' else b''
        with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',return_value=root),patch.object(ui,'pin_keys',return_value={'1':object()}),patch.object(ui,'tap')as tap:
            with self.assertRaisesRegex(AssertionError,'Protected emulator keyguard'):ui.open_policy()
            tap.assert_not_called()

    def test_framework_resolver_is_never_tapped_or_treated_as_owned_settings(self):
        root=ET.Element('hierarchy')
        node(root,package='android',resource_id='android:id/title',text='SYN443',bounds='[0,0][100,100]')
        node(root,package='android',resource_id='android:id/button1',text='Always',bounds='[0,100][100,200]')
        self.assertIsNone(ui.profile_settings(root))

if __name__=='__main__':unittest.main()
