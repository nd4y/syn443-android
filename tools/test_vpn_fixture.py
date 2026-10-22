import socket
import threading
import unittest
from run_vpn_process_faults import Server, Proxy


class VpnFixtureTest(unittest.TestCase):
    def setUp(self):
        self.egress = Server(('127.0.0.1', 0), Proxy)
        self.ingress = Server(('127.0.0.1', 0), Proxy)
        self.ingress.ingress_target = self.egress.server_address[1]
        for server in (self.egress, self.ingress):
            threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True).start()

    def tearDown(self):
        for server in (self.ingress, self.egress):
            server.shutdown()
            server.server_close()

    @staticmethod
    def headers(stream):
        first = stream.readline()
        while stream.readline() not in (b'', b'\r\n'):
            pass
        return first

    def test_two_connect_handshakes_reach_only_the_controlled_egress(self):
        with socket.create_connection(self.ingress.server_address, timeout=2) as client:
            stream = client.makefile('rb')
            client.sendall(('CONNECT 127.0.0.1:' + str(self.egress.server_address[1]) + ' HTTP/1.1\r\n\r\n').encode())
            self.assertIn(b'200', self.headers(stream))
            client.sendall(b'CONNECT 203.0.113.10:80 HTTP/1.1\r\n\r\n')
            self.assertIn(b'200', self.headers(stream))
            client.sendall(b'GET /generate_204 HTTP/1.1\r\n\r\n')
            self.assertIn(b'204', self.headers(stream))
            self.assertGreater(self.ingress.progress, 0)
            self.assertGreater(self.egress.progress, 0)

    def test_foreign_destination_is_not_forwarded(self):
        with socket.create_connection(self.ingress.server_address, timeout=2) as client:
            client.sendall(b'CONNECT example.invalid:443 HTTP/1.1\r\n\r\n')
            self.assertEqual(b'', client.recv(128))
        self.assertEqual(0, self.egress.progress)

    def test_fault_injection_disables_new_connections(self):
        self.ingress.allowed = False
        with socket.create_connection(self.ingress.server_address, timeout=2) as client:
            self.assertEqual(b'', client.recv(128))
        self.assertEqual(0, self.ingress.progress)
