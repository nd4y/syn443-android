"""Restart only a fresh, owned API29 CI framework after heap properties settle.

ART captures heap flags when the VM starts. A property read cannot establish
the heap of an already running zygote/system_server. No device or userdata reset.
"""
import os
import re
import subprocess
import time
from check_emulator_heap import check


def prepare(adb, *, clock=time.monotonic, sleep=time.sleep, budget=120):
    assert 0 < budget <= 120
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('SYN443_CI_AVD') == 'syn443-ci'
    serial = adb('get-serialno').strip()
    assert re.fullmatch(rb'emulator-[0-9]+', serial)
    assert adb('emu', 'avd', 'name').splitlines() == [b'syn443-ci', b'OK']
    assert adb('shell', 'getprop', 'ro.hardware').strip() in (b'ranchu', b'goldfish')
    check(adb)
    sdk = adb('shell', 'getprop', 'ro.build.version.sdk').strip()
    assert sdk in (b'29', b'35', b'37'), 'Unexpected CI matrix API'
    if sdk != b'29':
        print('Framework heap preparation is unnecessary on this API', flush=True)
        return
    assert adb('shell', 'getprop', 'ro.debuggable').strip() == b'1'
    # Never restart a previously installed test or a configured application.
    for package in ('io.syn443.android', 'io.syn443.android.test'):
        assert not adb('shell', 'pm', 'path', package).strip(), 'Expected an uninstalled fresh fixture'
    initial = adb('shell', 'pidof', 'system_server').strip()
    assert re.fullmatch(rb'[1-9][0-9]*', initial), 'Expected one system_server'
    deadline = clock() + budget

    def call(*args):
        remaining = deadline - clock()
        assert remaining > 0, 'Framework preparation deadline exceeded'
        return adb(*args, timeout=min(10, remaining))

    call('root')
    call('wait-for-device')
    assert call('shell', 'id', '-u').strip() == b'0', 'Owned AVD root unavailable'
    # Repeat identity checks after restarting adbd, before any framework command.
    assert call('get-serialno').strip() == serial
    assert call('emu', 'avd', 'name').splitlines() == [b'syn443-ci', b'OK']
    check(adb)
    stopped = False
    try:
        # Each transition is dispatched once, including a lost acknowledgement.
        stopped = True
        try:
            call('shell', 'stop')
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        while True:
            try:
                running = call('shell', 'pidof', 'system_server').strip()
            except subprocess.CalledProcessError:
                running = b''
            if not running:
                break
            assert clock() < deadline, 'Old system_server did not stop'
            sleep(min(1, max(0, deadline-clock())))
    finally:
        if stopped:
            # Restore the owned framework even if the stop observation failed.
            try:
                adb('shell', 'start', timeout=10)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
    while clock() < deadline:
        try:
            current = call('shell', 'pidof', 'system_server').strip()
            ready = call('shell', 'service', 'check', 'package')
            if re.fullmatch(rb'[1-9][0-9]*', current) and current != initial and b': found' in ready:
                check(adb)
                print('Owned API29 framework restarted once; new system_server verified; userdata preserved', flush=True)
                return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        sleep(min(1, max(0, deadline-clock())))
    raise AssertionError('Framework preparation deadline exceeded')


if __name__ == '__main__':
    serial = subprocess.check_output(['adb', '-e', 'get-serialno'], timeout=10).decode().strip()
    assert re.fullmatch(r'emulator-[0-9]+', serial)
    prepare(lambda *args, timeout=15: subprocess.check_output(['adb', '-s', serial, *args], timeout=timeout))
