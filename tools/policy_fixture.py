"""Ephemeral, synthetic ES256 publisher for emulator conformance, OpenSSL only.

No private key or bearer is stored in the repository or emitted into test reports.
"""
import base64
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')

class Publisher:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='syn443-policy-')
        self.key = Path(self.temp.name) / 'ephemeral.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-out', str(self.key)], check=True, capture_output=True)
        public = subprocess.check_output(['openssl', 'pkey', '-in', str(self.key), '-pubout', '-outform', 'DER'])
        self.spki = base64.b64encode(public).decode()
        self.device = 'device-ci-' + secrets.token_hex(8)
        self.bearer = secrets.token_urlsafe(32)

    def close(self):
        self.temp.cleanup()

    def sign(self, config, revision=1, checks=None, degraded=False, ttl=600, floor=0, epoch=0, operation='configure'):
        now = int(time.time() * 1000)
        engine = json.dumps(config, separators=(',', ':'), ensure_ascii=True).encode()
        payload = {'schemaVersion': 1, 'revision': revision, 'securityEpoch': epoch, 'revocationFloor': floor, 'operation': operation,
                   'targetDevice': self.device, 'audience': 'syn443-device', 'issuedAtMs': now - 5000,
                   'notBeforeMs': now - 5000, 'refreshAfterMs': now + min(10000, ttl*500),
                   'offlineUntilMs': now + ttl*1000, 'requiredCapabilities': ['engine-config.v1', 'tun.lease.v1'],
                   'algorithmRevision': 'm1-local-v1', 'engineConfigB64': b64(engine),
                   'contentHash': hashlib.sha256(engine).hexdigest(),
                   'activation': {'timeoutSeconds': 30, 'allowDegraded': degraded,
                                  'checks': checks or [{'id': 'internet', 'type': 'https_204',
                                                       'target': 'https://health.example.org/generate_204',
                                                       'port': 0, 'expected': '', 'required': True}]}}
        header = {'alg': 'ES256', 'kid': 'test-root', 'typ': 'syn443-policy+jws'}
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        content = b64(canonical(header)) + '.' + b64(canonical(payload))
        der = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', str(self.key)], input=content.encode())
        assert der[0] == 0x30 and der[1] == len(der)-2 and der[2] == 2
        rlen = der[3]; r = int.from_bytes(der[4:4+rlen], 'big'); pos = 4+rlen
        assert der[pos] == 2 and pos+2+der[pos+1] == len(der)
        s = int.from_bytes(der[pos+2:], 'big')
        return content + '.' + b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))

    def binding(self, port):
        return {'device': self.device, 'keys': {'test-root': self.spki},
                'url': 'http://127.0.0.1:' + str(port) + '/v1/device/policy',
                'bearer': self.bearer, 'serverTimeMs': int(time.time()*1000)}
