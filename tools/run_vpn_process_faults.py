"""Disposable-emulator only: the driver/proxy survives death of the app's UI.

No external Internet target, user credentials or device-specific configuration.
"""
import base64
import json
from pathlib import Path
import re
import socketserver
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = 'io.syn443.android'
URI = 'content://io.syn443.control'


def adb(*args, timeout=30):
    return subprocess.check_output(['adb', '-e', *args], stderr=subprocess.STDOUT, timeout=timeout)


def call(method, arg=None):
    args = ['shell', 'content', 'call', '--uri', URI, '--method', method]
    if arg is not None:
        args += ['--arg', arg]
    raw = adb(*args).decode()
    if 'ok=true' not in raw:
        raise AssertionError('Control command rejected: ' + method)
    return json.loads(re.search(r'json=(\{.*\})\}\]', raw)[1])


def pid(suffix):
    raw = adb('shell', 'sh', '-c', "'pidof " + PACKAGE + suffix + " || true'").strip()
    if raw and not raw.isdigit():
        raise AssertionError('Unexpected process identity')
    return raw.decode()


def await_condition(predicate, timeout=110):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(1)
    raise AssertionError('Process recovery deadline exceeded')


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        stream = self.request.makefile('rb')
        if not stream.readline(4096).startswith(b'CONNECT 203.0.113.10:80 '):
            return
        self.headers(stream)
        self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
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


def main():
    hardware = adb('shell', 'getprop', 'ro.hardware').decode().strip()
    assert hardware in ('ranchu', 'goldfish'), 'Refuse to overwrite a physical device configuration'
    suite = ET.Element('testsuite', name='SYN443 external process recovery')
    out = ROOT / 'app/build/outputs/androidTest-results/external/TEST-vpn-process.xml'
    out.parent.mkdir(parents=True, exist_ok=True)
    proxy = Server(('127.0.0.1', 0), Proxy)
    port = str(proxy.server_address[1])
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    try:
        adb('reverse', 'tcp:' + port, 'tcp:' + port)
        adb('shell', 'appops', 'set', PACKAGE, 'ACTIVATE_VPN', 'allow')
        adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.MainActivity')
        call('disconnect')
        config = {'outbounds': [{'type': 'http', 'tag': 'synthetic', 'server': '127.0.0.1', 'server_port': int(port)}],
                  'route': {'final': 'synthetic'}}
        call('import', base64.b64encode(json.dumps(config).encode()).decode())
        call('test-health', 'synthetic-http')
        call('connect')
        await_condition(lambda: call('status').get('phase') == 'Online' and proxy.progress > 0)
        generation = call('status')['generation']
        native = pid(':engine')
        assert native
        for name in ('uiProcessDeathKeepsRealTunTraffic', 'controllerDeathRetiresFrozenNativeAndPreservesIntent'):
            case = ET.SubElement(suite, 'testcase', classname='io.syn443.android.ExternalVpnProcessTest', name=name)
            try:
                progress = proxy.progress
                if name.startswith('ui'):
                    ui = pid('')
                    assert ui
                    adb('shell', 'run-as', PACKAGE, '/system/bin/kill', '-9', ui)
                    await_condition(lambda: proxy.progress > progress)
                    assert pid(':engine') == native
                else:
                    call('fault-hang')
                    controller = pid(':controller')
                    assert controller
                    adb('shell', 'run-as', PACKAGE, '/system/bin/kill', '-9', controller)
                    await_condition(lambda: pid(':engine') not in ('', native) and
                                    call('status').get('phase') == 'Online' and proxy.progress > progress)
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
            ET.ElementTree(suite).write(out, encoding='utf-8', xml_declaration=True)


if __name__ == '__main__':
    main()
