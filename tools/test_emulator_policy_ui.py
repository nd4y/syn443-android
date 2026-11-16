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

class AnrOwnerDiagnosticTest(unittest.TestCase):
    def observations(self,name=b'com.android.systemui',uid=10034,pid=2468,user=0):
        focus=b'mCurrentFocus=Window{abc123 u'+str(user).encode()+b' Application Not Responding: '+name+b'}\n'
        events=(b'1699999900.000  660  700 I am_proc_start: ['+str(user).encode()+b','+str(pid).encode()+b','+str(uid).encode()+b','+name+b',service,synthetic]\n'
                b'1699999998.123  660  700 I am_anr: ['+str(user).encode()+b','+str(pid).encode()+b','+name+b',0,private-detail]\n')
        app_id=uid%100_000
        descriptor=str(uid) if uid<10_000 else f'u{user}{"a" if app_id>=10_000 else "s"}{app_id-10_000 if app_id>=10_000 else app_id}'
        processes=(b'ACTIVITY MANAGER RUNNING PROCESSES (dumpsys activity processes)\n All known processes:\n'
                   b'  *PERS* UID '+str(uid).encode()+b' ProcessRecord{def456 '+str(pid).encode()+b':'+name+b'/'+descriptor.encode()+b'}\n'
                   b'    user #'+str(user).encode()+b' uid='+str(uid).encode()+b' gids={3003}\n'
                   b'    pid='+str(pid).encode()+b'\n'
                   b'    mCrashing=false null mNotResponding=true [com.android.server.am.AppNotRespondingDialog@fed123] bad=false\n')
        return focus,focus,events,processes,1700000000,1700000002

    def unknown(self,observations):
        result=ui.correlated_anr_owner(*observations)
        self.assertEqual(result,{'category':'unknown','correlated':False})
        for private in ('private-detail','2468','10034','abc123','def456','fed123'):
            self.assertNotIn(private,repr(result))

    def test_known_owner_needs_exact_recent_event_uid_pid_process_and_active_dialog(self):
        cases={b'com.android.settings':'settings',b'com.android.systemui':'system_ui',
               b'com.android.launcher3':'launcher',b'com.google.android.apps.nexuslauncher':'launcher',
               b'com.android.permissioncontroller':'permission_controller',b'com.google.android.permissioncontroller':'permission_controller',
               b'com.google.android.gms':'google_services',b'com.android.vending':'play_store',
               b'io.syn443.android':'syn443_app',b'io.syn443.android:controller':'syn443_controller',b'io.syn443.android:engine':'syn443_engine'}
        for name,category in cases.items():
            with self.subTest(category=category,name=name):
                self.assertEqual(ui.correlated_anr_owner(*self.observations(name)),{'category':category,'correlated':True})
        # The event's first field is user ID; target UID comes from the start
        # event and must agree with both forms in the current ProcessRecord.
        for uid,user in ((1000,0),(110034,1)):
            self.assertEqual(ui.correlated_anr_owner(*self.observations(uid=uid,user=user)),{'category':'system_ui','correlated':True})

    def test_foreign_lookalikes_and_unknown_labels_remain_redacted_unknown(self):
        for name in (b'com.android.settings.other',b'io.syn443.android.other',b'private-label-fixture',b'SYN443'):
            values=self.observations(name)
            self.unknown(values)
            self.assertNotIn(name.decode(),repr(ui.correlated_anr_owner(*values)))

    def test_stale_future_and_multiple_recent_events_cannot_become_current_owner(self):
        values=list(self.observations())
        for events in (
            values[2].replace(b'1699999998.123',b'1699999870.123'),
            values[2].replace(b'1699999998.123',b'1700000003.000'),
            values[2]+values[2].splitlines(keepends=True)[1],
            values[2]+values[2].splitlines(keepends=True)[1].replace(b'com.android.systemui',b'com.android.settings'),
        ):
            changed=values.copy();changed[2]=events;self.unknown(changed)
        for started,finished in ((1700000003,1700000002),(1699999980,1700000002),(True,1700000002)):
            changed=values.copy();changed[4:]=started,finished;self.unknown(changed)

    def test_absent_start_reused_pid_and_user_uid_mismatch_are_not_owner_proof(self):
        values=list(self.observations())
        start,anr=values[2].splitlines(keepends=True)
        for events in (anr,start+start+anr,
                       start+anr+start.replace(b'1699999900.000',b'1700000001.000'),
                       values[2].replace(b',10034,',b',110034,'),
                       values[2].replace(b'[0,2468,10034',b'[1,2468,10034'),
                       values[2].replace(b'1699999900.000',b'1699999998.123'),
                       start.replace(b'com.android.systemui',b'com.android.settings')+anr):
            changed=values.copy();changed[2]=events;self.unknown(changed)

    def test_focus_must_be_single_exact_and_stable_through_observation(self):
        values=list(self.observations())
        for focus in (b'mCurrentFocus=null\n',values[0]+values[0],
                      values[0].replace(b'abc123',b'abc124'),
                      values[0].replace(b'com.android.systemui',b'com.android.settings'),
                      values[0].replace(b'u0 ',b'u1 '),
                      values[0].replace(b'mCurrentFocus',b'mPreviousFocus')):
            changed=values.copy();changed[1]=focus;self.unknown(changed)

    def test_current_process_requires_same_identity_single_active_anr_and_dialog(self):
        values=list(self.observations())
        for processes in (
            values[3].replace(b'UID 10034',b'UID 10035'),
            values[3].replace(b'uid=10034',b'uid=10035'),
            values[3].replace(b'2468:',b'2469:'),
            values[3].replace(b'pid=2468',b'pid=2469'),
            values[3].replace(b'/u0a34}',b'/u0a35}'),
            values[3].replace(b'user #0 uid=',b'user #1 uid='),
            values[3].replace(b'uid=10034 gids=',b'uid=10034 ISOLATED uid=99000 gids='),
            values[3].replace(b'mNotResponding=true',b'mNotResponding=false'),
            values[3].replace(b'mCrashing=false',b'mCrashing=true'),
            values[3].replace(b'[com.android.server.am.AppNotRespondingDialog@fed123]',b'null'),
            values[3]+b'    mCrashing=false null mNotResponding=true null bad=false\n',
            values[3]+values[3][values[3].index(b'  *PERS*'):],
            values[3].replace(b'ProcessRecord{def456',b'PreviousRecord{def456'),
        ):
            changed=values.copy();changed[3]=processes;self.unknown(changed)
        # A historical lastanr task snapshot is not a live process ownership
        # record, even if its text happens to mention the matching process.
        changed=values.copy();changed[3]=b'ACTIVITY MANAGER LAST ANR (dumpsys activity lastanr)\n'+values[3][values[3].index(b' All known'):]
        self.unknown(changed)

    def test_malformed_unbounded_and_injected_log_data_fail_without_echo(self):
        values=list(self.observations())
        other_starts=b''.join(b'1699999900.000 660 700 I am_proc_start: [0,'+str(3000+i).encode()+b',10035,synthetic.process,service,synthetic]\n' for i in range(254))
        boundary=values.copy();boundary[2]=other_starts+values[2]
        self.assertEqual(ui.correlated_anr_owner(*boundary),{'category':'system_ui','correlated':True})
        boundary[2]=b'1699999900.000 660 700 I am_proc_start: [0,3999,10035,synthetic.process,service,synthetic]\n'+boundary[2]
        self.unknown(boundary)
        for index in range(4):
            for raw in (None,'private-label-fixture',b'x'*1_048_577):
                changed=values.copy();changed[index]=raw;self.unknown(changed)
        for events in (values[2].replace(b' I am_anr:',b' E am_anr:'),
                       values[2].replace(b',2468,com.android.systemui',b',0,com.android.systemui'),
                       values[2].replace(b',10034,',b',9999999999,'),
                       values[2].replace(b'com.android.systemui',b'com.android.systemui;touch /synthetic'),
                       values[2]+b'1700000001.000 660 700 I am_anr: [malformed]\n',
                       values[2]+b'x'*16_385+b'\n'):
            changed=values.copy();changed[2]=events;self.unknown(changed)

    def diagnostic_adb(self,calls,values=None):
        values=self.observations() if values is None else values
        def observe(*args,**kwargs):
            calls.append((args,kwargs));self.assertGreater(kwargs['timeout'],0);self.assertLessEqual(kwargs['timeout'],2)
            if args==('shell','getprop','ro.hardware'):return b'ranchu\n'
            if args==('shell','date','+%s'):return b'1700000002\n'
            if args==('shell','dumpsys','window','displays'):return values[0]
            if args==('shell','logcat','-d','-b','events','-v','epoch','-t','256','am_anr:I','am_proc_start:I',"'*:S'"):return values[2]
            if args==('shell','dumpsys','activity','-a','processes'):return values[3]
            self.fail('Unexpected diagnostic command')
        return observe

    def test_diagnostic_reads_only_constant_commands_with_bounded_timeouts(self):
        calls=[]
        with patch.object(ui,'adb',side_effect=self.diagnostic_adb(calls)),patch.object(ui.time,'monotonic',return_value=0),patch.object(ui,'tap')as tap:
            self.assertEqual(ui.anr_owner_diagnostic(),{'category':'system_ui','correlated':True})
            tap.assert_not_called()
        self.assertEqual(len(calls),7)
        self.assertFalse(any(any(value in args for value in ('am','input','kill','force-stop','sh','rm')) for args,_ in calls))
        self.assertFalse(any(b'com.android.systemui'.decode() in repr(args) for args,_ in calls))

    def test_diagnostic_refuses_physical_device_and_exhausted_budget_without_actions(self):
        with patch.object(ui,'adb',return_value=b'physical-phone')as adb:
            self.assertEqual(ui.anr_owner_diagnostic(),{'category':'unknown','correlated':False})
        self.assertEqual(adb.call_count,1)
        self.assertEqual(adb.call_args.args,('shell','getprop','ro.hardware'))
        with patch.object(ui,'adb',return_value=b'goldfish')as adb,patch.object(ui.time,'monotonic',side_effect=[0,1,9]):
            self.assertEqual(ui.anr_owner_diagnostic(),{'category':'unknown','correlated':False})
        self.assertEqual(adb.call_count,1)

    def test_diagnostic_observation_failure_and_bad_clock_cannot_mask_original_failure(self):
        for error in (subprocess.TimeoutExpired('synthetic',2),subprocess.CalledProcessError(1,['synthetic'],output=b'private-detail'),OSError('private-detail')):
            with patch.object(ui,'adb',side_effect=error),patch('builtins.print')as output:
                self.assertEqual(ui.anr_owner_diagnostic(),{'category':'unknown','correlated':False})
                output.assert_not_called()
        calls=[];observe=self.diagnostic_adb(calls)
        def bad_clock(*args,**kwargs):return b'private-detail' if args==('shell','date','+%s') else observe(*args,**kwargs)
        with patch.object(ui,'adb',side_effect=bad_clock):
            self.assertEqual(ui.anr_owner_diagnostic(),{'category':'unknown','correlated':False})
        self.assertEqual(len(calls),1)

    def test_failure_branch_reports_correlated_owner_but_never_recovers_foreign_anr(self):
        blocked=ET.Element('hierarchy');node(blocked,package='android',resource_id='android:id/aerr_close')
        calls=[];values=self.observations();diagnostic=self.diagnostic_adb(calls,values);launches=[]
        def adb(*args,**kwargs):
            if args[-1]=='size':return b'1080x1920'
            if 'resolve-activity' in args:return b'com.android.settings/.Settings$VpnSettingsActivity'
            if args[1:3]==('am','start'):launches.append(args);return b''
            if args[1:3]==('input','keyevent') or args[1:3]==('input','swipe'):return b''
            if args==('shell','dumpsys','window','displays') and kwargs.get('timeout')==5:return values[0]
            # The preexisting navigation reads do not set a timeout for getprop.
            return diagnostic(*args,**({'timeout':2}|kwargs))
        with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',return_value=blocked),patch.object(ui,'tap')as tap,patch.object(ui.time,'sleep'),patch.object(ui.time,'monotonic',side_effect=itertools.count()),patch('builtins.print')as output:
            with self.assertRaisesRegex(AssertionError,'Owned VPN settings entry unavailable'):ui.open_policy()
            tap.assert_not_called();output.assert_called_once()
        self.assertEqual(len(launches),1)
        message=output.call_args.args[0]
        self.assertIn("'anrOwner': {'category': 'system_ui', 'correlated': True}",message)
        self.assertIn("'focusedSettingsANR': False",message)
        for private in ('com.android.systemui','private-detail','abc123','def456','fed123','2468','10034'):
            self.assertNotIn(private,message)

    def test_successful_navigation_does_not_read_anr_logs(self):
        root,gear=OwnedVpnSettingsTest().row()
        def adb(*args,**kwargs):
            if args[-1]=='ro.hardware':return b'ranchu'
            if args[-1]=='size':return b'1080x1920'
            if 'resolve-activity' in args:return b'com.android.settings/.Settings$VpnSettingsActivity'
            return b''
        with patch.object(ui,'adb',side_effect=adb),patch.object(ui,'tree',return_value=root),patch.object(ui,'tap')as tap,patch.object(ui,'anr_owner_diagnostic')as diagnostic:
            ui.open_policy();tap.assert_called_once_with(gear);diagnostic.assert_not_called()


if __name__=='__main__':unittest.main()
