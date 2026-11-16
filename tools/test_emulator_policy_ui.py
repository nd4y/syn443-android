import unittest
import itertools
import subprocess
import xml.etree.ElementTree as ET
from unittest.mock import patch
import emulator_policy_ui as ui

def node(parent,**values):return ET.SubElement(parent,'node',{k.replace('_','-'):v for k,v in values.items()})

class OwnedVpnSettingsTest(unittest.TestCase):
    def test_hierarchy_waits_for_a_fresh_file_before_any_pin_input(self):
        calls=[];reads=0
        def adb(*args,**kwargs):
            nonlocal reads
            calls.append(args)
            if args[-1]=='ro.hardware':return b'ranchu'
            if args[1]=='cat':
                reads+=1
                if reads==1:raise subprocess.CalledProcessError(1,['adb','cat'])
                return b'<hierarchy><node package="com.android.systemui"/></hierarchy>'
            return b''
        with patch.object(ui,'adb',side_effect=adb),patch.object(ui.time,'sleep'):
            self.assertEqual(ui.tree().tag,'hierarchy')
        self.assertEqual(reads,2)
        self.assertEqual(sum(args[1:3]==('rm','-f') for args in calls),4)
        self.assertFalse(any('input' in args for args in calls))

    def test_hierarchy_retries_are_bounded_and_do_not_accept_invalid_roots(self):
        for raw in (b'not xml',b'<previous-screen/>'):
            calls=[]
            def adb(*args,**kwargs):
                calls.append(args)
                return b'ranchu' if args[-1]=='ro.hardware' else raw if args[1]=='cat' else b''
            with patch.object(ui,'adb',side_effect=adb),patch.object(ui.time,'sleep'):
                with self.assertRaisesRegex(AssertionError,'observation budget'):ui.tree()
            self.assertEqual(sum(args[1]=='cat' for args in calls),3)
            self.assertFalse(any('input' in args for args in calls))

    def test_hierarchy_refuses_physical_devices_before_writing_fixture_files(self):
        with patch.object(ui,'adb',return_value=b'physical-device')as adb:
            with self.assertRaises(AssertionError):ui.tree()
        adb.assert_called_once_with('shell','getprop','ro.hardware')

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
            if args[1:3]==('cmd','package'):return b'com.android.settings/.Settings$VpnSettingsActivity\n'
            return b''
        with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',return_value=root),patch.object(ui,'tap')as tap:
            ui.open_policy();tap.assert_called_once_with(gear)
        self.assertIn(('shell','am','start','-S','-W','-n',"'com.android.settings/.Settings$VpnSettingsActivity'",'-f','0x10008000'),calls)
        with patch.object(ui,'adb',return_value=b'physical-phone'),patch.object(ui,'tree')as tree:
            with self.assertRaises(AssertionError):ui.open_policy()
            tree.assert_not_called()
    def test_only_focused_settings_anr_is_recognized(self):
        owned=b'  mCurrentFocus=Window{123a u0 Application Not Responding: com.android.settings}' + bytes([10])
        self.assertTrue(ui.focused_settings_anr(owned))
        for foreign in (
            owned.replace(b'com.android.settings', b'io.syn443.android'),
            owned.replace(b'com.android.settings', b'com.android.settings.other'),
            owned.replace(b'mCurrentFocus', b'mPreviousFocus'),
        ):
            self.assertFalse(ui.focused_settings_anr(foreign))

    def test_absent_oversized_and_ambiguous_display_focus_is_not_authority(self):
        owned=b'  mCurrentFocus=Window{123a u0 Application Not Responding: com.android.settings}\n'
        for raw in (b'WINDOW MANAGER WINDOWS\nWindow{123a u0 Application Not Responding: com.android.settings}',
                    b'mCurrentFocus=null\n',owned+owned,owned+b'mCurrentFocus=null\n',owned+b'x'*1_048_576):
            self.assertFalse(ui.focused_settings_anr(raw))

    def test_focus_snapshot_classifies_only_fixed_categories_without_window_data(self):
        owned=b'  mCurrentFocus=Window{123a u0 Application Not Responding: com.android.settings}\n'
        for raw,count,category in (
            (owned,1,'settings_anr'),
            (owned.replace(b'com.android.settings',b'io.syn443.android'),1,'app_anr'),
            (owned.replace(b'com.android.settings',b'io.syn443.android:controller'),1,'app_anr'),
            (owned.replace(b'com.android.settings',b'io.syn443.android:engine'),1,'app_anr'),
            (owned.replace(b'com.android.settings',b'com.android.settings.other'),1,'foreign_anr'),
            (owned.replace(b'com.android.settings',b'io.syn443.android.other'),1,'foreign_anr'),
            (owned.replace(b'com.android.settings',b'private-label-fixture'),1,'foreign_anr'),
            (b'mCurrentFocus=null\n',1,'null'),
            (owned+b'mCurrentFocus=null\n',2,'ambiguous'),
            (owned+owned,2,'ambiguous'),
            (owned.replace(b'mCurrentFocus',b'mPreviousFocus'),0,'unrecognized'),
            (b'mCurrentFocus=Window{123a u0 private-label-fixture}\n',1,'unrecognized'),
            (b'',0,'unrecognized'),
        ):
            snapshot=ui.classified_focus_snapshot(raw)
            self.assertEqual(snapshot,{'focusCount':count,'category':category})
            self.assertNotIn('private-label-fixture',repr(snapshot))
            self.assertNotIn('123a',repr(snapshot))
            self.assertNotIn('com.android.settings',repr(snapshot))
            self.assertNotIn('io.syn443.android',repr(snapshot))
            self.assertEqual(ui.focused_settings_anr(raw),category=='settings_anr')

    def test_focus_snapshot_refuses_oversized_or_unobserved_input_without_parsing(self):
        for raw in (b'x'*1_048_577,None,'private-label-fixture'):
            with patch.object(ui.re,'findall')as scan:
                self.assertEqual(ui.classified_focus_snapshot(raw),{'focusCount':None,'category':'unrecognized'})
                scan.assert_not_called()

    def test_unknown_anr_failure_prints_only_classified_focus_and_preserves_guards(self):
        blocked=ET.Element('hierarchy');node(blocked,package='android',resource_id='android:id/aerr_close')
        launches=[]
        def adb(*args,**kwargs):
            if args[-1]=='ro.hardware':return b'ranchu'
            if args[-1]=='size':return b'1080x1920'
            if 'resolve-activity' in args:return b'com.android.settings/.Settings$VpnSettingsActivity'
            if args[1:3]==('dumpsys','window'):
                return b'mCurrentFocus=Window{123a u0 Application Not Responding: private-label-fixture}\n'
            if args[1:3]==('am','start'):launches.append(args)
            return b''
        with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',return_value=blocked),patch.object(ui,'tap')as tap,patch.object(ui.time,'sleep'),patch.object(ui.time,'monotonic',side_effect=itertools.count()),patch('builtins.print')as output:
            with self.assertRaisesRegex(AssertionError,'Owned VPN settings entry unavailable'):ui.open_policy()
            tap.assert_not_called()
            output.assert_called_once()
        self.assertEqual(len(launches),1)
        message=output.call_args.args[0]
        self.assertIn("'focusedSettingsANR': False",message)
        self.assertIn("'focusSnapshot': {'focusCount': 1, 'category': 'foreign_anr'}",message)
        self.assertNotIn('private-label-fixture',message)
        self.assertNotIn('123a',message)

    def test_owned_settings_anr_reopens_activity_without_tapping_dialog(self):
        blocked=ET.Element('hierarchy')
        node(blocked, package='android', resource_id='android:id/aerr_close')
        settings,gear=self.row()
        launches=[];focus_commands=[]

        def adb(*args, **kwargs):
            if args[-1]=='ro.hardware':return b'ranchu'
            if args[-1]=='size':return b'1080x1920'
            if 'resolve-activity' in args:return b'com.android.settings/.Settings$VpnSettingsActivity'
            if args[1:3]==('dumpsys','window'):
                focus_commands.append(args)
                return b'  mCurrentFocus=Window{123a u0 Application Not Responding: com.android.settings}' if args[-1]=='displays' else b'WINDOW MANAGER WINDOWS'
            if args[1:3]==('am','start'):launches.append(args)
            return b''

        with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',side_effect=[blocked,settings]),patch.object(ui,'tap') as tap:
            ui.open_policy()
            tap.assert_called_once_with(gear)
        self.assertEqual(len(launches),2)
        self.assertEqual(launches[0],launches[1])
        self.assertEqual(focus_commands,[('shell','dumpsys','window','displays')])

    def test_foreign_and_unknown_anr_never_restart_settings_or_tap_a_dialog(self):
        blocked=ET.Element('hierarchy');node(blocked,package='android',resource_id='android:id/aerr_close')
        for focus in (b'mCurrentFocus=null',b'mCurrentFocus=Window{123a u0 Application Not Responding: io.syn443.android}'):
            launches=[]
            def adb(*args,**kwargs):
                if args[-1]=='ro.hardware':return b'ranchu'
                if args[-1]=='size':return b'1080x1920'
                if 'resolve-activity' in args:return b'com.android.settings/.Settings$VpnSettingsActivity'
                if args[1:3]==('dumpsys','window'):return focus
                if args[1:3]==('am','start'):launches.append(args)
                return b''
            with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',return_value=blocked),patch.object(ui,'tap')as tap,patch.object(ui.time,'sleep'),patch.object(ui.time,'monotonic',side_effect=itertools.count()):
                with self.assertRaisesRegex(AssertionError,'Owned VPN settings entry unavailable'):ui.open_policy()
                tap.assert_not_called()
            self.assertEqual(len(launches),1)

    def test_protected_bouncer_is_never_filled_by_policy_navigation(self):
        root,_=self.row()
        def adb(*args,**kwargs):return b'ranchu' if args[-1]=='ro.hardware' else b'1080x1920' if args[-1]=='size' else b'com.android.settings/.Settings$VpnSettingsActivity' if args[1:3]==('cmd','package') else b''
        with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',return_value=root),patch.object(ui,'pin_keys',return_value={'1':object()}),patch.object(ui,'tap')as tap:
            with self.assertRaisesRegex(AssertionError,'Protected emulator keyguard'):ui.open_policy()
            tap.assert_not_called()

    def test_framework_resolver_is_never_tapped_or_treated_as_owned_settings(self):
        root=ET.Element('hierarchy')
        node(root,package='android',resource_id='android:id/title',text='SYN443',bounds='[0,0][100,100]')
        node(root,package='android',resource_id='android:id/button1',text='Always',bounds='[0,100][100,200]')
        self.assertIsNone(ui.profile_settings(root))
    def test_component_resolution_rejects_foreign_classes_and_shell_text(self):
        for value in [b'android/com.android.internal.app.ResolverActivity',b'com.android.settings/com.example.VpnSettingsActivity',b'com.android.settings/.Settings$VpnSettingsActivity;id',b'com.android.settings/.Settings$VpnSettingsActivity\nandroid/Resolver']:
            self.assertIsNone(ui.settings_component(value))
        self.assertIsNone(ui.settings_component(b'x'*8193))
    def test_query_can_select_only_one_named_vpn_activity_from_owned_handlers(self):
        owned=b'com.android.settings/.Settings$VpnSettingsActivity'
        self.assertEqual(owned.decode(),ui.settings_component(b'priority=0\n'+owned))
        self.assertEqual(owned.decode(),ui.settings_component(b'com.android.settings/.GenericSettings\n'+owned))
        self.assertIsNone(ui.settings_component(b'com.android.settings/.One\ncom.android.settings/.Two'))
    def test_ambiguous_framework_resolution_uses_owned_query_before_launch(self):
        root,gear=self.row();calls=[]
        def adb(*args,**kwargs):
            calls.append(args)
            if args[-1]=='ro.hardware':return b'goldfish'
            if args[-1]=='size':return b'1080x1920'
            if 'resolve-activity' in args:return b'android/com.android.internal.app.ResolverActivity'
            if 'query-activities' in args:return b'com.android.settings/.Settings$VpnSettingsActivity'
            return b''
        with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',return_value=root),patch.object(ui,'tap')as tap:
            ui.open_policy();tap.assert_called_once_with(gear)
        self.assertTrue(any('query-activities' in x for x in calls))

if __name__=='__main__':unittest.main()
