"""Reject an obsolete tiny-heap disposable AVD before running any app tests."""
import os
import re
import subprocess


def megabytes(raw):
    value = raw.decode('ascii').strip()
    match = re.fullmatch(r'([1-9][0-9]{0,8})([kKmMgG])', value)
    assert match is not None, 'Invalid emulator heap property'
    size = int(match[1])
    return size / 1024 if match[2].lower() == 'k' else size * 1024 if match[2].lower() == 'g' else size


def check(adb):
    assert os.environ.get('SYN443_CI_AVD') == 'syn443-ci'
    assert re.fullmatch(rb'emulator-[0-9]+\s*', adb('get-serialno'))
    assert adb('shell', 'getprop', 'ro.hardware').strip() in (b'ranchu', b'goldfish')
    maximum = megabytes(adb('shell', 'getprop', 'dalvik.vm.heapsize'))
    raw_growth = adb('shell', 'getprop', 'dalvik.vm.heapgrowthlimit').strip()
    growth = megabytes(raw_growth) if raw_growth else maximum
    assert 128 <= maximum <= 2048 and 64 <= growth <= maximum, 'Disposable AVD Java heap is not representative of supported Android devices'
    print(f'Disposable AVD heap verified: maximum={maximum:g}MiB, growth={growth:g}MiB')


if __name__ == '__main__':
    check(lambda *args: subprocess.check_output(['adb', *args], timeout=15))
