import os
import subprocess
import unittest
from unittest.mock import patch
from emulator_boot import reboot_preserved, launch_preserved


class EmulatorBootTest(unittest.TestCase):
    def exercise(self,exited=False,advances=True,alive=True):
        now=[0];calls=[];launches=[]
        def adb(*args,**kwargs):
            calls.append(args)
            if args==('shell','getprop','ro.hardware'):return b'ranchu'
            if args==('get-serialno',):return b'emulator-5554'
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
            try:reboot_preserved(adb,clock=lambda:now[0],sleep=lambda t:now.__setitem__(0,now[0]+t),engines=engines,launch=launch,budget=4)
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
    def test_relaunch_rejects_wipe_and_alternate_userdata(self):
        for extra in ('-wipe-data','-data /tmp/other.img','-avd other','-snapshot clean'):
            with patch.dict(os.environ,{'SYN443_CI_EMULATOR_OPTIONS':'-no-window -no-snapshot '+extra}),patch('emulator_boot.subprocess.Popen') as spawn:
                with self.assertRaises(AssertionError):launch_preserved('syn443-ci','emulator-5554')
                spawn.assert_not_called()


if __name__=='__main__':unittest.main()
