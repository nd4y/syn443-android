"""Emulator-only callback injection: ownership drain must outlive onRevoke.

This exercises the real native/TUN owner, not actual system permission removal.
Actual Android Settings revocation remains a physical acceptance gate.
"""
import base64
import json
import threading
import time
import xml.etree.ElementTree as ET
from run_vpn_process_faults import ROOT, PACKAGE, Proxy, Server, adb, call, pid, await_condition


def main():
    assert adb('shell', 'getprop', 'ro.hardware').decode().strip() in ('ranchu', 'goldfish'), 'Emulator only'
    suite = ET.Element('testsuite', name='SYN443 native revocation drain')
    out = ROOT / 'app/build/outputs/androidTest-results/external/TEST-vpn-revocation.xml'
    proxy = Server(('127.0.0.1', 0), Proxy)
    port = str(proxy.server_address[1])
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    case = ET.SubElement(suite, 'testcase', classname='io.syn443.android.NativeRevocationTest',
                         name='revocationDrainsNativeBeforeFinalOffAndSurvivesControllerDeath')
    try:
        call('disconnect'); await_condition(lambda: not pid(':engine') and not call('status')['engineActive'], 30)
        call('policy-test-reset'); call('test-reset')
        adb('reverse', 'tcp:' + port, 'tcp:' + port)
        config = {'outbounds': [{'type': 'http', 'tag': 'test-proxy', 'server': '127.0.0.1', 'server_port': int(port)}],
                  'route': {'final': 'test-proxy'}}
        call('import', base64.b64encode(json.dumps(config).encode()).decode())
        call('test-health', 'synthetic-http'); call('connect')
        await_condition(lambda: call('status')['phase'] == 'Online' and proxy.progress > 0)
        before = call('status'); original = pid(':engine'); assert original
        call('fault-revoke')
        await_condition(lambda: not pid(':engine') and not call('status')['desiredOn'] and
                        not call('status')['engineActive'] and call('status')['phase'] == 'Off', 20)
        stopped = call('status'); assert stopped['generation'] > before['generation']
        assert any(e['code'] == 'vpn_permission_revoked' for e in stopped['events'])
        time.sleep(5)
        assert not pid(':engine') and not call('status')['desiredOn'] and not call('status')['engineActive']
        controller = pid(':controller'); assert controller
        # Use the existing debug-only self-termination hook: run-as signal
        # delivery is not supported on every Android SELinux policy.
        call('fault-controller')
        await_condition(lambda: pid(':controller') != controller, 20)
        await_condition(lambda: call('status')['phase'] == 'Off' and not call('status')['engineActive'] and
                        call('status')['generation'] == stopped['generation'], 20)
        assert not pid(':engine')
        progress = proxy.progress
        call('connect')
        await_condition(lambda: call('status')['phase'] == 'Online' and pid(':engine') != original and proxy.progress > progress)
        assert call('status')['generation'] > stopped['generation']
        print(case.get('name') + ': passed', flush=True)
        case = ET.SubElement(suite, 'testcase', classname='io.syn443.android.NativeRevocationTest',
                             name='revocationDrainPreservesNewerConnectAndRetiresFrozenOldOwner')
        frozen = pid(':engine'); assert frozen
        call('fault-hang'); call('fault-revoke')
        await_condition(lambda: not call('status')['desiredOn'], 10)
        revoked_generation = call('status')['generation']
        call('connect'); resumed_generation = call('status')['generation']
        assert resumed_generation > revoked_generation
        progress = proxy.progress
        await_condition(lambda: call('status')['phase'] == 'Online' and pid(':engine') != frozen and proxy.progress > progress)
        resumed = call('status')
        assert resumed['desiredOn'] and resumed['engineActive'] and resumed['generation'] == resumed_generation
        print(case.get('name') + ': passed', flush=True)
    except Exception as error:
        ET.SubElement(case, 'failure', message=type(error).__name__).text = str(error)
        raise
    finally:
        try:
            call('disconnect'); await_condition(lambda: not pid(':engine') and not call('status')['engineActive'], 30)
        finally:
            adb('reverse', '--remove', 'tcp:' + port)
            proxy.shutdown(); proxy.server_close()
            out.parent.mkdir(parents=True, exist_ok=True)
            ET.ElementTree(suite).write(out, encoding='utf-8', xml_declaration=True)


if __name__ == '__main__':
    main()
