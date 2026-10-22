"""Disposable emulator: managed delivery, activation, rollback and lease gates.

HTTPS policy probes use the existing visibly synthetic HTTP harness only on an
emulator. TLS implementation/physical HTTPS acceptance is a separate gate.
"""
import base64
import copy
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from policy_fixture import Publisher
from run_vpn_process_faults import ROOT, PACKAGE, Proxy, Server, adb, call, pid, await_condition

class Delivery(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        p = self.server.publisher
        allowed = (self.path == '/v1/device/policy' and
                   hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + p.bearer) and
                   self.headers.get('X-SYN443-Device') == p.device and self.server.available)
        body = self.server.envelope.encode() if allowed else b'unavailable'
        self.send_response(200 if allowed else 503)
        self.send_header('Cache-Control', 'no-store'); self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)

def private_input(raw, method):
    data = raw.encode()
    adb('shell', 'run-as', PACKAGE, 'touch', 'no_backup/operator-policy.json')
    adb('shell', 'run-as', PACKAGE, 'chmod', '600', 'no_backup/operator-policy.json')
    subprocess.run(['adb', '-e', 'shell', '-T', 'run-as', PACKAGE, 'dd',
                    'of=no_backup/operator-policy.json'], input=data, capture_output=True, check=True, timeout=20)
    return call(method)

def stage(envelope):
    return private_input(envelope, 'policy-stage-file')

def main():
    assert adb('shell', 'getprop', 'ro.hardware').decode().strip() in ('ranchu', 'goldfish'), 'Emulator only'
    suite = ET.Element('testsuite', name='SYN443 managed activation')
    out = ROOT / 'app/build/outputs/androidTest-results/external/TEST-policy.xml'
    proxy = Server(('127.0.0.1', 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    delivery = ThreadingHTTPServer(('127.0.0.1', 0), Delivery)
    delivery.daemon_threads = True
    threading.Thread(target=delivery.serve_forever, daemon=True).start()
    ports = [proxy.server_address[1], delivery.server_address[1]]
    publisher = None
    config = {'outbounds': [{'type': 'http', 'tag': 'test-proxy', 'server': '127.0.0.1', 'server_port': ports[0]}],
              'route': {'final': 'test-proxy'}}
    def stop():
        call('disconnect'); await_condition(lambda: not pid(':engine') and not call('status').get('engineActive'), 30)
    def setup(ttl=600):
        nonlocal publisher
        stop(); call('policy-test-reset'); call('test-reset')
        if publisher:
            publisher.close()
        publisher = Publisher(); delivery.publisher = publisher; delivery.available = True
        delivery.envelope = publisher.sign(config, ttl=ttl)
        proxy.allowed = True
        call('import', base64.b64encode(json.dumps(config, separators=(',', ':')).encode()).decode())
        call('test-health', 'synthetic-http'); call('connect')
        await_condition(lambda: call('status').get('phase') == 'Online')
        private_input(json.dumps(publisher.binding(ports[1])), 'policy-bind-file')
        await_condition(lambda: call('status').get('policy', {}).get('phase') == 'committed' and call('status')['policy'].get('activeRevision') == 1)
    scenarios = ['signedPolicyBootstrapsCurrentConfig', 'invalidPolicyAndImportCannotReplaceActive',
                 'failedNativeCandidateRollsBackAndCannotReplay', 'requiredRegressionRollsBack',
                 'baselineOutageCanCommitDegraded', 'stopFencesPendingPolicy',
                 'controllerDeathDuringApplyRollsBackOffline', 'expiredLeaseBlocksWithoutDirectFallback',
                 'offlineControlPlaneRetainsAuthorizedPath', 'signedManagementReleasePreservesLocalState']
    try:
        for port in ports:
            adb('reverse', 'tcp:'+str(port), 'tcp:'+str(port))
        for name in scenarios:
            case = ET.SubElement(suite, 'testcase', classname='io.syn443.android.ManagedPolicy', name=name)
            try:
                setup(ttl=45 if name.startswith('expired') else 600)
                original = pid(':engine'); active = call('status')['policy']['activeRevision']
                if name.startswith('signed'):
                    if name.startswith('signedManagement'):
                        stage(publisher.sign(config, revision=2, operation='release'))
                        await_condition(lambda: not call('status')['policy']['managed'] and call('status')['policy']['phase'] == 'released')
                        assert pid(':engine') == original and call('status')['desiredOn']
                    else:
                        assert active == 1 and call('status')['policy']['lastKnownGoodRevision'] == 1
                elif name.startswith('invalid'):
                    recipient = publisher.device
                    try:
                        publisher.device = 'other-device-example'
                        wrong_recipient = publisher.sign(config, revision=2)
                    finally:
                        publisher.device = recipient
                    for bad in [delivery.envelope[:-2], wrong_recipient]:
                        try:
                            stage(bad)
                        except AssertionError:
                            pass
                        else:
                            raise AssertionError('Invalid policy accepted')
                    try:
                        call('import', base64.b64encode(json.dumps(config).encode()).decode())
                    except AssertionError:
                        pass
                    else:
                        raise AssertionError('Managed import bypass')
                    assert call('status')['policy']['activeRevision'] == active and pid(':engine') == original
                elif name.startswith('failedNative'):
                    bad = copy.deepcopy(config); bad['outbounds'][0]['server_port'] = -1
                    candidate = publisher.sign(bad, revision=2); stage(candidate)
                    await_condition(lambda: call('status')['policy']['phase'] == 'rolled_back' and call('status').get('phase') == 'Online', 110)
                    restored = pid(':engine'); assert call('status')['policy']['activeRevision'] == 1
                    for replay in [candidate, publisher.sign(bad, revision=3)]:
                        try:
                            stage(replay)
                        except AssertionError:
                            pass
                        else:
                            raise AssertionError('Failed snapshot retried')
                    time.sleep(3); assert pid(':engine') == restored
                elif name.startswith('requiredRegression'):
                    stage(publisher.sign(config, revision=2))
                    await_condition(lambda: call('status')['policy']['phase'] == 'applying')
                    proxy.allowed = False
                    await_condition(lambda: call('status')['policy']['phase'] == 'rolled_back', 65)
                    proxy.allowed = True
                    await_condition(lambda: call('status').get('phase') == 'Online')
                    assert call('status')['policy']['activeRevision'] == 1
                elif name.startswith('baselineOutage'):
                    proxy.allowed = False; stage(publisher.sign(config, revision=2, degraded=True))
                    await_condition(lambda: call('status')['policy']['phase'] == 'degraded', 65)
                    assert call('status')['policy']['activeRevision'] == 2 and call('status')['policy']['lastKnownGoodRevision'] == 1
                elif name.startswith('stopFences'):
                    stage(publisher.sign(config, revision=2)); stop()
                    snapshot = call('status')['policy']['activeRevision']; time.sleep(12)
                    assert not call('status')['desiredOn'] and not pid(':engine') and call('status')['policy']['activeRevision'] == snapshot
                elif name.startswith('controllerDeath'):
                    stage(publisher.sign(config, revision=2)); await_condition(lambda: call('status')['policy']['phase'] == 'applying')
                    delivery.available = False; call('fault-controller')
                    await_condition(lambda: call('status')['policy']['phase'] == 'rolled_back' and call('status').get('phase') == 'Online', 110)
                    assert call('status')['policy']['activeRevision'] == 1
                elif name.startswith('expired'):
                    delivery.available = False
                    await_condition(lambda: call('status').get('phase') == 'BlockedByPolicy' and not pid(':engine'), 75)
                    progress = proxy.progress; time.sleep(4)
                    assert call('status')['desiredOn'] and proxy.progress == progress
                else:
                    delivery.available = False; call('policy-refresh'); progress = proxy.progress
                    await_condition(lambda: proxy.progress > progress)
                    assert pid(':engine') == original and call('status')['policy']['activeRevision'] == 1
                print(name + ': passed', flush=True)
            except Exception:
                ET.SubElement(case, 'failure', message='Managed policy scenario failed; see bounded job output')
                raise
    finally:
        try:
            stop(); call('policy-test-reset'); call('test-health', 'production-https')
        finally:
            if publisher:
                publisher.close()
            for port in ports:
                adb('reverse', '--remove', 'tcp:'+str(port))
            proxy.shutdown(); proxy.server_close(); delivery.shutdown(); delivery.server_close()
            out.parent.mkdir(parents=True, exist_ok=True); ET.ElementTree(suite).write(out, encoding='utf-8', xml_declaration=True)

if __name__ == '__main__':
    main()
