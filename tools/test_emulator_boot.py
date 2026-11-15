import os
import subprocess
import unittest
from unittest.mock import patch
from emulator_boot import reboot_preserved, launch_preserved, installed_checkpoint, CheckpointUnavailable


class EmulatorBootTest(unittest.TestCase):
    def exercise(self,exited=False,advances=True,alive=True,marker_changed=False,apk_changed=False,uid_changed=False):
        now=[0];calls=[];launches=[]
        def adb(*args,**kwargs):
            calls.append(args)
            if args==('shell','getprop','ro.hardware'):return b'ranchu'
            if args==('get-serialno',):return b'emulator-5554'
            if args==('shell','am','get-current-user'):return b'0'
            if args==('shell','pm','path','--user','0','io.syn443.android'):return b'package:/data/app/fixture/base.apk'
            if args==('shell','sha256sum','/data/app/fixture/base.apk'):
                return (b'b' if apk_changed and now[0] else b'a')*64+b'  /data/app/fixture/base.apk'
            if args==('shell','pm','list','packages','-U','--user','0','io.syn443.android'):
                return b'package:io.syn443.android uid:'+ (b'10002' if uid_changed and now[0] else b'10001')
            marker='/data/local/tmp/syn443-boot-proof-'+'a'*32
            if args==('shell','cat',marker):return (b'b' if marker_changed and now[0] else b'a')*32
            if args==('shell','rm','-f',marker):return b''
            if args==('shell','sh','-c',"'umask 077 && set -C && printf %s "+'a'*32+' > '+marker+" && sync'"):return b''
            if args==('reboot',):
                now[0]+=1;raise subprocess.CalledProcessError(1,'adb')
            if args==('shell','getprop','sys.boot_completed'):
                if not alive:raise subprocess.CalledProcessError(1,'adb')
                return b'1'
            if args==('shell','settings','get','global','boot_count'):
                return b'8' if now[0] and advances else b'7'
            raise AssertionError(args)
        def engines(avd):return [] if exited and now[0] else [(123,'456')]
        def launch(avd,serial):
            launches.append((avd,serial))
            return type('Process',(),{'poll':lambda self:None})()
        with patch.dict(os.environ,{'SYN443_CI_AVD':'syn443-ci'}):
            try:reboot_preserved(adb,clock=lambda:now[0],sleep=lambda t:now.__setitem__(0,now[0]+t),engines=engines,launch=launch,budget=4,nonce='a'*32)
            finally:
                self.assertEqual(1,calls.count(('reboot',)))
                self.assertLessEqual(len(launches),1)
        return launches
    def test_healthy_vm_requires_advanced_boot_counter(self):
        self.assertEqual([],self.exercise())
        with self.assertRaisesRegex(AssertionError,'deadline'):self.exercise(advances=False)
    def test_exited_vm_is_relaunched_once_without_replaying_reboot(self):
        self.assertEqual([('syn443-ci','emulator-5554')],self.exercise(exited=True))
    def test_live_but_unreachable_vm_is_not_replaced_or_given_more_time(self):
        with self.assertRaisesRegex(AssertionError,'recovery=False'):self.exercise(alive=False)
    def test_failed_relaunch_still_fails_without_restarting_the_test(self):
        with self.assertRaisesRegex(AssertionError,'recovery=True'):self.exercise(exited=True,alive=False)
    def test_advanced_boot_counter_cannot_hide_reset_userdata_or_replaced_apk_uid(self):
        for changed in ({'marker_changed':True},{'apk_changed':True},{'uid_changed':True}):
            with self.subTest(changed=changed),self.assertRaisesRegex(AssertionError,'userdata marker|APK or UID'):
                self.exercise(exited=True,**changed)
    def test_checkpoint_selects_exact_main_package_and_never_test_uid_or_duplicate(self):
        prefix=[b'package:/data/app/fixture/base.apk',b'a'*64+b'  /data/app/fixture/base.apk']
        with self.subTest('exact main'),patch('builtins.print'):
            values=prefix+[b'package:io.syn443.android.test uid:10002\npackage:io.syn443.android uid:10001']
            result=installed_checkpoint(lambda *args,**kwargs:values.pop(0))
            self.assertEqual('10001',result[2])
        for uid,error in [(b'package:io.syn443.android.test uid:10002',CheckpointUnavailable),
                          (b'package:io.syn443.android uid:10001\npackage:io.syn443.android uid:10001',AssertionError)]:
            values=prefix+[uid]
            with self.subTest(uid=uid),self.assertRaises(error):
                installed_checkpoint(lambda *args,**kwargs:values.pop(0))
    def test_relaunch_rejects_wipe_and_alternate_userdata(self):
        for extra in ('-wipe-data','-data /tmp/other.img','-avd other','-snapshot clean'):
            with patch.dict(os.environ,{'SYN443_CI_EMULATOR_OPTIONS':'-no-window -no-snapshot '+extra}),patch('emulator_boot.subprocess.Popen') as spawn:
                with self.assertRaises(AssertionError):launch_preserved('syn443-ci','emulator-5554')
                spawn.assert_not_called()


if __name__=='__main__':unittest.main()
