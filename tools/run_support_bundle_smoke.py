"""Actual local bundle protocol, on a fresh disposable emulator only."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from syn443ctl import Device, SupportDeadline, support_collect, support_wait, support_export

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = 'io.syn443.android'


def adb(*arguments, timeout=10):
    result = subprocess.run(['adb', '-e', *arguments], capture_output=True, timeout=timeout, check=False)
    assert len(result.stdout) <= 65_536 and len(result.stderr) <= 8192, 'bounded_emulator_reply_required'
    return result


def no_backup_names():
    result = adb('shell', 'run-as', PACKAGE, 'ls', '-1', 'no_backup')
    if result.returncode:
        assert b'No such file or directory' in result.stdout + result.stderr, 'private_inventory_unavailable'
        return set()
    names = result.stdout.decode('utf-8').splitlines()
    assert len(names) <= 64 and all(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', name) for name in names), 'private_inventory_invalid'
    return set(names)


def no_engine():
    result = adb('shell', 'pidof', PACKAGE + ':engine')
    assert result.returncode in (0, 1) and not result.stdout.strip(), 'unexpected_engine_owner'


def main():
    hardware = adb('shell', 'getprop', 'ro.hardware')
    assert hardware.returncode == 0 and hardware.stdout.decode().strip() in {'ranchu', 'goldfish'}, 'disposable_emulator_required'
    serial = adb('get-serialno')
    assert serial.returncode == 0 and re.fullmatch(r'emulator-[0-9]+', serial.stdout.decode().strip()), 'disposable_serial_required'
    report = Path(os.environ['RUNNER_TEMP']) / 'syn443-support-protocol-result.xml'
    assert not report.exists(), 'old_protocol_result_must_not_be_reused'
    suite = ET.Element('testsuite', name='SYN443 offline bundle protocol', tests='1', failures='0')
    case = ET.SubElement(suite, 'testcase', classname='io.syn443.android.SupportBundleProtocolTest',
                         name='freshProviderCollectExportAndCancelNeverInitializesVpnOrIdentity')
    passed = False
    try:
        before = no_backup_names()
        assert not before.intersection({'vpn-intent.json', 'vpn-config.enc'}), 'fresh_app_required'
        no_engine()
        device = Device(serial.stdout.decode().strip(), 10)
        with device.bundle_connection() as connected:
            assert connected, 'active_shell_connection_required'
            sequence = SupportDeadline(device)
            receipt = support_collect(sequence)
            bundle_id = receipt['id']
            ready = support_wait(sequence, bundle_id)
            assert ready['manifest']['complete'] is False
            # Ask Android to reclaim eligible background processes in this disposable fixture.
            owner = adb('shell', 'pidof', PACKAGE + ':controller').stdout.strip()
            assert owner.isdigit() and adb('shell', 'am', 'kill', PACKAGE).returncode == 0
            with tempfile.TemporaryDirectory(prefix='syn443-bundle-protocol-') as directory:
                output = Path(directory) / 'bundle.zip'
                result = support_export(sequence, bundle_id, output, ready)
                assert result['exported'] is True and result['bytes'] == output.stat().st_size
                assert result['complete'] is False
                # This is synthetic emulator data, never a real-device export.
                subprocess.run(['python3', str(ROOT / 'tools/check_public_data.py'), str(output)], check=True)
            assert adb('shell', 'pidof', PACKAGE + ':controller').stdout.strip() == owner
            cancelled = sequence.call('support-bundle-cancel', bundle_id)
            assert cancelled == {'state': 'cancelled', 'id': bundle_id}
            assert sequence.call('support-bundle-status', bundle_id) == cancelled
            denied = sequence.call('support-bundle-open', bundle_id)
            assert denied == cancelled, 'cancelled_export_grant_created'
        after = no_backup_names()
        assert before <= after and after - before <= {'support-bundles'}, 'diagnostics_initialized_identity_or_vpn'
        no_engine()
        print(case.get('name') + ': passed', flush=True)
        passed = True
    finally:
        if not passed:
            suite.set('failures', '1')
            ET.SubElement(case, 'failure', message='Offline bundle protocol did not complete every required check')
        # Gradle owns and may clear its result directories. Preserve this actual
        # earlier result outside them; the harness publishes it after Gradle.
        with report.open('xb') as stream:
            ET.ElementTree(suite).write(stream, encoding='utf-8', xml_declaration=True)


if __name__ == '__main__':
    main()
