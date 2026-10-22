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

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = 'io.syn443.android'
URI = 'content://io.syn443.control'


def adb(*args, timeout=30):
    return subprocess.check_output(['adb', '-e', *args], stderr=subprocess.STDOUT, timeout=timeout)


class ControlUnavailable(RuntimeError):
    """The provider may briefly disappear while its process is being killed."""


def call(method, arg=None):
    args = ['shell', 'content', 'call', '--uri', URI, '--method', method]
    if arg is not None:
        args += ['--arg', arg]
    raw = adb(*args).decode()
    if 'ok=false' in raw:
        raise AssertionError('Control command rejected: ' + method)
    result = re.search(r'json=(\{.*\})\}\]', raw)
    if 'ok=true' not in raw or result is None:
        raise ControlUnavailable('Control provider has not returned a response')
    return json.loads(result[1])


def pid(suffix):
    raw = adb('shell', 'sh', '-c', "'pidof " + PACKAGE + suffix + " || true'").strip()
    if raw and not raw.isdigit():
        raise AssertionError('Unexpected process identity')
    return raw.decode()


def await_condition(predicate, timeout=110):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if predicate():
                return
        except ControlUnavailable:
            # Poll only. Never replay a Connect/Stop/fault command after an
            # ambiguous acknowledgement; the deadline and final assertions stay.
            pass
        time.sleep(1)
    raise AssertionError('Process recovery deadline exceeded')


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        if not self.server.allowed:
            return
        self.request.settimeout(15)
        stream = self.request.makefile('rb')
        first = stream.readline(4096)
        target = self.server.ingress_target
        expected = ('CONNECT 127.0.0.1:' + str(target) + ' ').encode() if target else b'CONNECT 203.0.113.10:80 '
        if not first.startswith(expected):
            return
        self.headers(stream)
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
            return
        self.headers(stream)
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
    progress = 0
    progress_lock = threading.Lock()
    allowed = True
    ingress_target = None


def main():
    hardware = adb('shell', 'getprop', 'ro.hardware').decode().strip()
    assert hardware in ('ranchu', 'goldfish'), 'Refuse to overwrite a physical device configuration'
    suite = ET.Element('testsuite', name='SYN443 external process recovery')
    out = ROOT / 'app/build/outputs/androidTest-results/external/TEST-vpn-process.xml'
    out.parent.mkdir(parents=True, exist_ok=True)
    proxy = Server(('127.0.0.1', 0), Proxy)
    ingress = Server(('127.0.0.1', 0), Proxy)
    ingress.ingress_target = proxy.server_address[1]
    port = str(ingress.server_address[1])
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    threading.Thread(target=ingress.serve_forever, daemon=True).start()
    try:
        adb('reverse', 'tcp:' + port, 'tcp:' + port)
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
                     'controllerDeathRetiresFrozenNativeAndPreservesIntent', 'controllerRestartBudgetSurvivesOwnerDeath'):
            case = ET.SubElement(suite, 'testcase', classname='io.syn443.android.ExternalVpnProcessTest', name=name)
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
                elif name.startswith('forceStop'):
                    previous = pid(':engine')
                    adb('shell', 'am', 'force-stop', PACKAGE)
                    # Reading the provider here could itself unstop the app.
                    time.sleep(2)
                    assert not pid(':engine') and not pid(':controller')
                    adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.MainActivity')
                    time.sleep(2)
                    assert not pid(':engine'), 'Opening UI after Force stop must require explicit Connect'
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
                ET.SubElement(case, 'failure', message='External process recovery failed; see job log')
                raise
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
