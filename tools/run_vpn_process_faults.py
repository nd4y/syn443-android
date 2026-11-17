"""Disposable-emulator only: the driver/proxy survives death of the app's UI.

No external Internet target, user credentials or device-specific configuration.
"""
import base64
import json
from pathlib import Path
import re
import socketserver
import socket
import selectors
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from process_failure_evidence import FailureEvidence, MAX_COUNT, reverse_snapshot

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = 'io.syn443.android'
URI = 'content://io.syn443.control'
ACTIVE_OBSERVATION = None


def adb(*args, timeout=30):
    return subprocess.check_output(['adb', '-e', *args], stderr=subprocess.STDOUT, timeout=timeout)


class ControlUnavailable(RuntimeError):
    """An emulator observation may be unavailable while Android replaces a process."""


def call(method, arg=None, *, timeout=30):
    args = ['shell', 'content', 'call', '--uri', URI, '--method', method]
    if arg is not None:
        args += ['--arg', arg]
    raw = adb(*args, timeout=timeout).decode()
    if 'ok=false' in raw:
        raise AssertionError('Control command rejected: ' + method)
    result = re.search(r'json=(\{.*\})\}\]', raw)
    if 'ok=true' not in raw or result is None:
        raise ControlUnavailable('Control provider has not returned a response')
    value = json.loads(result[1])
    if method == 'status' and ACTIVE_OBSERVATION is not None:
        ACTIVE_OBSERVATION.evidence.status(value)
    return value


def pid(suffix, *, timeout=30):
    raw = adb('shell', 'sh', '-c', "'pidof " + PACKAGE + suffix + " || true'", timeout=timeout).strip()
    if not raw:
        if suffix == ':engine' and ACTIVE_OBSERVATION is not None:
            ACTIVE_OBSERVATION.evidence.native('')
        return ''
    matches = raw.split()
    if not all(re.fullmatch(rb'[1-9][0-9]{0,9}', item) for item in matches):
        raise AssertionError('Unexpected process identity')
    if len(matches) != 1:
        # pidof lists all matches. A poll must wait for exactly one owner.
        raise ControlUnavailable('Multiple matching emulator process IDs')
    value = matches[0].decode()
    if suffix == ':engine' and ACTIVE_OBSERVATION is not None:
        ACTIVE_OBSERVATION.evidence.native(value)
    return value


def vpn_stopped():
    """A missing process is insufficient until the controller settles Off."""
    if pid(':engine'):
        return False
    state = call('status')
    return (state.get('phase') == 'Off' and state.get('desiredOn') is False and
            state.get('engineStateKnown') is True and state.get('engineActive') is False)


def await_condition(predicate, timeout=110):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if ACTIVE_OBSERVATION is not None:
            ACTIVE_OBSERVATION.evidence.begin_poll()
        try:
            if predicate():
                return
        except ControlUnavailable:
            # Poll only. Never replay a Connect/Stop/fault command after an
            # ambiguous acknowledgement; the deadline and final assertions stay.
            pass
        finally:
            if ACTIVE_OBSERVATION is not None:
                # Reuse only observations made by the unchanged predicate.
                # No extra transport, probe or polling worker is introduced.
                ACTIVE_OBSERVATION.sample()
        time.sleep(1)
    raise AssertionError('Process recovery deadline exceeded')


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.handler_started()
        completed = False
        try:
            self.handle_request()
            completed = True
        finally:
            self.server.handler_finished(completed)

    def handle_request(self):
        if not self.server.allowed:
            self.server.count('rejected')
            return
        self.request.settimeout(15)
        stream = self.request.makefile('rb')
        first = stream.readline(4096)
        target = self.server.ingress_target
        expected = ('CONNECT 127.0.0.1:' + str(target) + ' ').encode() if target else b'CONNECT 203.0.113.10:80 '
        if not first.startswith(expected):
            self.server.count('rejected')
            return
        self.headers(stream)
        self.server.count('connectHeaders')
        self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        if target:
            with self.server.progress_lock:
                self.server.progress += 1
            with socket.create_connection(('127.0.0.1', target), timeout=5) as upstream:
                with selectors.DefaultSelector() as selector:
                    selector.register(self.request, selectors.EVENT_READ, upstream)
                    selector.register(upstream, selectors.EVENT_READ, self.request)
                    end, total = time.monotonic() + 20, 0
                    while time.monotonic() < end and total < 4 * 1024 * 1024:
                        events = selector.select(1)
                        for key, _ in events:
                            data = key.fileobj.recv(16384)
                            if not data:
                                return
                            key.data.sendall(data)
                            total += len(data)
            return
        if not stream.readline(4096).startswith(b'GET /generate_204 '):
            self.server.count('rejected')
            return
        self.headers(stream)
        self.server.count('requestHeaders')
        self.request.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        with self.server.progress_lock:
            self.server.progress += 1

    @staticmethod
    def headers(stream):
        for _ in range(64):
            if stream.readline(4096) in (b'', b'\r\n'):
                return
        raise AssertionError('Synthetic headers exceeded bound')


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, address, handler, evidence_role):
        self.progress = 0
        self.progress_lock = threading.RLock()
        self.allowed = True
        self.ingress_target = None
        self.evidence_role = evidence_role
        self.counts = dict.fromkeys(('accepted', 'active', 'handled', 'errors',
                                    'connectHeaders', 'requestHeaders', 'rejected'), 0)
        super().__init__(address, handler)

    def count(self, name):
        with self.progress_lock:
            self.counts[name] = min(MAX_COUNT, self.counts[name] + 1)

    def get_request(self):
        request = super().get_request()
        self.count('accepted')
        return request

    def handler_started(self):
        self.count('active')

    def handler_finished(self, completed):
        with self.progress_lock:
            self.counts['active'] = max(0, self.counts['active'] - 1)
            if completed:
                self.counts['handled'] = min(MAX_COUNT, self.counts['handled'] + 1)

    def handle_error(self, request, client_address):
        # Retain the actual failure count without socketserver's raw address,
        # exception message or stack dump. Request cleanup remains its owner.
        self.count('errors')

    def evidence_snapshot(self, thread_alive):
        with self.progress_lock:
            return dict(self.counts, role=self.evidence_role, allowed=self.allowed,
                        progress=min(MAX_COUNT, self.progress), threadAlive=thread_alive)


class ProcessObservation:
    def __init__(self, native, ingress, egress, ingress_thread, egress_thread):
        self.evidence = FailureEvidence(native)
        self.started = time.monotonic()
        self.ingress, self.egress = ingress, egress
        self.ingress_thread, self.egress_thread = ingress_thread, egress_thread

    def sample(self):
        self.evidence.sample(int((time.monotonic() - self.started) * 1000),
                             self.ingress.evidence_snapshot(self.ingress_thread.is_alive()),
                             self.egress.evidence_snapshot(self.egress_thread.is_alive()))

    def capture_failure(self, port):
        # Capture before disconnect/reverse removal/server shutdown. These reads
        # are diagnostic only and cannot replay a fault or extend its PASS wait.
        self.evidence.begin_poll()
        snapshot, reverse = None, None
        try:
            snapshot = call('status', timeout=2)
        except Exception:
            pass  # Unavailable remains explicit; never synthesize zero/Off.
        try:
            pid(':engine', timeout=2)
        except Exception:
            pass
        try:
            reverse = reverse_snapshot(adb('reverse', '--list', timeout=2), int(port))
        except Exception:
            pass
        self.sample()
        print('Process failure evidence: ' + json.dumps(self.evidence.report(reverse),
                                                       separators=(',', ':'), allow_nan=False), flush=True)
        return snapshot if type(snapshot) is dict else {}


def main():
    global ACTIVE_OBSERVATION
    hardware = adb('shell', 'getprop', 'ro.hardware').decode().strip()
    assert hardware in ('ranchu', 'goldfish'), 'Refuse to overwrite a physical device configuration'
    suite = ET.Element('testsuite', name='SYN443 external process recovery')
    out = ROOT / 'app/build/outputs/androidTest-results/external/TEST-vpn-process.xml'
    out.parent.mkdir(parents=True, exist_ok=True)
    proxy = Server(('127.0.0.1', 0), Proxy, 'egress')
    ingress = Server(('127.0.0.1', 0), Proxy, 'ingress')
    ingress.ingress_target = proxy.server_address[1]
    port = str(ingress.server_address[1])
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    ingress_thread = threading.Thread(target=ingress.serve_forever, daemon=True)
    proxy_thread.start()
    ingress_thread.start()
    try:
        adb('reverse', 'tcp:' + port, 'tcp:' + port)
        adb('shell', 'appops', 'set', PACKAGE, 'ACTIVATE_VPN', 'allow')
        adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.MainActivity')
        call('disconnect')
        await_condition(vpn_stopped, timeout=30)
        # Independent emulator suite: do not inherit the preceding lifecycle
        # suite's legitimate restart spending. Never reset within this suite:
        # its controller/native death sequence must exhaust the real limit.
        call('policy-test-reset')
        call('test-reset')
        assert call('status').get('heavyWallMs', []) == []
        case = ET.SubElement(suite, 'testcase', classname='io.syn443.android.ExternalVpnProcessTest',
                             name='missingVpnConsentPreservesIntentWithoutStartingForegroundService')
        try:
            # External driver: changing this app-op kills instrumentation if done inside it.
            adb('shell', 'appops', 'set', PACKAGE, 'ACTIVATE_VPN', 'ignore')
            adb('shell', 'input', 'keyevent', 'KEYCODE_HOME')
            before = call('status')
            call('connect')
            missing = call('status')
            assert missing['desiredOn'] and missing['phase'] == 'NeedsPermission'
            assert missing['reason'] == 'vpn_permission_required' and not pid(':engine')
            assert missing.get('heavyWallMs', []) == before.get('heavyWallMs', [])
            controller = pid(':controller')
            call('resume')
            time.sleep(2)
            assert call('status')['phase'] == 'NeedsPermission' and not pid(':engine')
            assert pid(':controller') == controller
            print(case.get('name') + ': passed', flush=True)
        except Exception as error:
            ET.SubElement(case, 'failure', message=type(error).__name__).text = str(error)
            raise
        finally:
            adb('shell', 'appops', 'set', PACKAGE, 'ACTIVATE_VPN', 'allow')
        adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.MainActivity')
        call('disconnect')
        # Only ingress is forwarded to Android. A direct shortcut to egress
        # cannot pass: there is no Android listener on its host-only port.
        config = {'outbounds': [
            {'type': 'http', 'tag': 'ingress', 'server': '127.0.0.1', 'server_port': int(port)},
            {'type': 'http', 'tag': 'egress', 'server': '127.0.0.1', 'server_port': proxy.server_address[1], 'detour': 'ingress'}],
            'route': {'final': 'egress'}}
        call('import', base64.b64encode(json.dumps(config).encode()).decode())
        call('test-health', 'synthetic-http')
        call('connect')
        await_condition(lambda: call('status').get('phase') == 'Online' and proxy.progress > 0)
        generation = call('status')['generation']
        native = pid(':engine')
        assert native
        for name in ('twoHopTunTrafficCrossesBothProxies', 'ingressFailureRecoversWithoutNativeRestart',
                     'egressFailureRecoversWithoutNativeRestart', 'uiProcessDeathKeepsRealTunTraffic',
                     'forceStopWaitsForForegroundReopenAndPreservesIntent',
                     'controllerDeathRetiresFrozenNativeAndPreservesIntent', 'nativeOwnerRecreationKeepsIntentAndRejectsOldCallbacks',
                     'controllerRestartBudgetSurvivesOwnerDeath'):
            case = ET.SubElement(suite, 'testcase', classname='io.syn443.android.ExternalVpnProcessTest', name=name)
            observation = ProcessObservation(native, ingress, proxy, ingress_thread, proxy_thread)
            ACTIVE_OBSERVATION = observation
            try:
                progress = proxy.progress
                if name.startswith('twoHop'):
                    assert ingress.progress > 0 and proxy.progress > 0
                elif name.startswith(('ingress', 'egress')):
                    failed = ingress if name.startswith('ingress') else proxy
                    try:
                        failed.allowed = False
                        await_condition(lambda: call('status').get('phase') == 'Recovering', timeout=35)
                        assert call('status')['desiredOn'] and pid(':engine') == native
                        progress = proxy.progress
                    finally:
                        failed.allowed = True
                    await_condition(lambda: call('status').get('phase') == 'Online' and proxy.progress > progress)
                    assert pid(':engine') == native
                elif name.startswith('ui'):
                    ui = pid('')
                    assert ui
                    call('fault-ui')
                    await_condition(lambda: proxy.progress > progress)
                    assert pid(':engine') == native
                elif name.startswith('controllerDeath'):
                    call('fault-hang')
                    controller = pid(':controller')
                    assert controller
                    call('fault-controller')
                    await_condition(lambda: pid(':engine') not in ('', native) and
                                    call('status').get('phase') == 'Online' and proxy.progress > progress)
                elif name.startswith('nativeOwnerRecreation'):
                    previous = pid(':engine')
                    call('fault-owner')
                    await_condition(lambda: pid(':engine') not in ('', previous) and call('status').get('phase') == 'Online' and proxy.progress > progress)
                    native = pid(':engine')
                elif name.startswith('forceStop'):
                    previous = pid(':engine')
                    adb('shell', 'am', 'force-stop', PACKAGE)
                    # Reading the provider here could itself unstop the app.
                    time.sleep(2)
                    assert not pid(':engine') and not pid(':controller')
                    adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.MainActivity')
                    time.sleep(2)
                    assert not pid(':engine'), 'Opening UI after Force stop must require explicit Connect'
                    assert call('status').get('resumeRequired'), 'Resume confirmation must survive a later boot'
                    call('connect')
                    generation = call('status')['generation']
                    await_condition(lambda: pid(':engine') not in ('', previous) and
                                    call('status').get('phase') == 'Online' and proxy.progress > progress)
                    native = pid(':engine')
                else:
                    remaining = 3 - len(call('status').get('heavyWallMs', []))
                    assert 0 <= remaining <= 3
                    for _ in range(remaining):
                        previous = pid(':engine')
                        progress = proxy.progress
                        call('fault-hang')
                        controller = pid(':controller')
                        assert controller
                        call('fault-controller')
                        await_condition(lambda: pid(':engine') not in ('', previous) and
                                        call('status').get('phase') == 'Online' and proxy.progress > progress)
                    assert len(call('status')['heavyWallMs']) == 3
                    call('fault-hang')
                    controller = pid(':controller')
                    assert controller
                    call('fault-controller')
                    await_condition(lambda: call('status').get('phase') == 'Recovering' and not pid(':engine') and
                                    call('status').get('nextWallMs', 0) > int(time.time() * 1000) + 300_000)
                    assert len(call('status')['heavyWallMs']) == 3
                assert call('status')['generation'] == generation
                assert call('status')['desiredOn']
                print(name + ': passed', flush=True)
            except Exception:
                snapshot = observation.capture_failure(port)
                print('Recovery failure state: ' + json.dumps({k: snapshot.get(k) for k in
                      ('phase', 'reason', 'desiredOn', 'generation', 'resumeRequired', 'attempt', 'heavyWallMs', 'nextWallMs')}), flush=True)
                ET.SubElement(case, 'failure', message='External process recovery failed; see job log')
                raise
            finally:
                ACTIVE_OBSERVATION = None
    finally:
        try:
            call('disconnect')
            call('test-health', 'production-https')
        finally:
            adb('reverse', '--remove', 'tcp:' + port)
            proxy.shutdown()
            proxy.server_close()
            ingress.shutdown()
            ingress.server_close()
            ET.ElementTree(suite).write(out, encoding='utf-8', xml_declaration=True)


if __name__ == '__main__':
    main()
