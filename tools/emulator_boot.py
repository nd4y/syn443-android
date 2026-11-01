"""Bounded real emulator reboot; recover only an exited host VM, preserving userdata."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import time


def owned_engines(avd):
    """Read identities only. Never kill or adopt another AVD's host process."""
    result=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():continue
        try:
            args=(entry/'cmdline').read_bytes()[:8192].split(b'\0')
            if not args or not Path(os.fsdecode(args[0])).name.startswith('qemu-system-'):continue
            words=[os.fsdecode(a) for a in args if a]
            if not any(words[i:i+2]==['-avd',avd] for i in range(len(words)-1)):continue
            stat=(entry/'stat').read_text().rsplit(')',1)[1].split()
            if stat[0] not in ('Z','X'):result.append((int(entry.name),stat[19]))
        except (OSError,ValueError,IndexError):continue
    return result


def launch_preserved(avd,serial):
    assert re.fullmatch(r'emulator-[0-9]+',serial)
    assert avd=='syn443-ci'
    options=shlex.split(os.environ['SYN443_CI_EMULATOR_OPTIONS'])
    assert '-no-snapshot' in options and '-no-window' in options
    singles={'-no-snapshot','-no-window','-noaudio','-no-boot-anim','-no-metrics','-show-kernel'}
    pairs={'-gpu':{'software'},'-feature':{'-Vulkan'}}
    i=0
    while i<len(options):
        if options[i] in singles:i+=1;continue
        assert options[i] in pairs and i+1<len(options) and options[i+1] in pairs[options[i]]
        i+=2
    sdk=Path(os.environ.get('ANDROID_HOME') or os.environ['ANDROID_SDK_ROOT'])
    binary=sdk/'emulator/emulator';assert binary.is_file()
    log=Path(os.environ['RUNNER_TEMP'])/'syn443-preserved-emulator.log'
    # This is the same disposable CI AVD on the same port, never a clean fixture.
    # No userdata/config/credential files are changed by this host recovery.
    with log.open('ab') as output:
        return subprocess.Popen([str(binary),'-avd',avd,'-port',serial.split('-')[1],*options],
                                stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)


def reboot_preserved(adb,*,clock=time.monotonic,sleep=time.sleep,engines=owned_engines,launch=launch_preserved,budget=150):
    assert 0<budget<=150
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish')
    avd=os.environ.get('SYN443_CI_AVD','syn443-ci');assert avd=='syn443-ci'
    serial=adb('get-serialno').decode().strip();assert re.fullmatch(r'emulator-[0-9]+',serial)
    initial=engines(avd);assert len(initial)==1,'Expected exactly one owned host VM before reboot'
    count=adb('shell','settings','get','global','boot_count').strip();assert count.isdigit()
    deadline=clock()+budget;recovered=False;process=None
    # Reboot is issued once. A lost acknowledgement must never replay it.
    try:adb('reboot',timeout=min(10,budget))
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired):pass
    while clock()<deadline:
        current=engines(avd)
        if not recovered and not current:
            sleep(min(1,max(0,deadline-clock()))) # Allow an exited VM's file descriptors/locks to drain.
            assert not engines(avd),'Another host VM appeared during recovery'
            print('Owned emulator exited during reboot; cold-starting same preserved AVD once',flush=True)
            process=launch(avd,serial);recovered=True
        elif not recovered:
            assert current==initial,'Host VM identity changed outside this test'
        try:
            if clock()>=deadline:break
            if adb('shell','getprop','sys.boot_completed',timeout=min(5,deadline-clock())).strip()==b'1':
                if clock()>=deadline:break
                after=adb('shell','settings','get','global','boot_count',timeout=min(5,deadline-clock())).strip()
                if after.isdigit() and int(after)>int(count):
                    print('Real reboot complete; boot counter advanced; preserved-VM recovery='+str(recovered),flush=True)
                    return
        except (subprocess.CalledProcessError,subprocess.TimeoutExpired):pass
        sleep(min(1,max(0,deadline-clock())))
    state='unknown' if process is None else str(process.poll())
    raise AssertionError('Real reboot deadline exceeded; host recovery='+str(recovered)+' launcher='+state)
