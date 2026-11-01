import unittest
from check_public_data import findings, scan_files
from pathlib import Path
import tempfile, zipfile
import io


class PublicDataTest(unittest.TestCase):
    def test_private_addresses(self):
        for octets in ((10, 2, 3, 4), (192, 168, 5, 6), (172, 16, 2, 3), (100, 106, 1, 2)):
            self.assertIn("private-address", findings(".".join(map(str, octets)).encode()))

    def test_documentation_and_loopback(self):
        self.assertFalse(findings(b"100.64.0.0/10"))
        for address in (b"127.0.0.1", b"0.0.0.0", b"192.0.2.4", b"198.51.100.8", b"203.0.113.9"):
            self.assertFalse(findings(address))

    def test_private_domains_and_paths(self):
        self.assertIn("private-domain", findings(("server." + "local").encode()))
        self.assertIn("personal-path", findings(("C:/" + "Users/person/").encode()))
        self.assertFalse(findings(b"/home/runner/work/syn443"))
        self.assertFalse(findings(b"https://example.invalid/path"))
        self.assertFalse(findings(b"kotlinx.coroutines.internal.MainDispatcherFactory"))

    def test_credential_url(self):
        self.assertIn("credential-url", findings(("https://" + "synthetic:placeholder@" + "example.invalid").encode()))
        self.assertFalse(findings(b"https://example.invalid:443/path"))

    def test_compressed_android_archive_members_are_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            for suffix in ('.apk', '.aar', '.zip'):
                path = Path(directory) / ('synthetic' + suffix)
                with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr('assets/config.txt', 'server.' + 'local')
                self.assertTrue(any(rule == 'private-domain' for _, rule in scan_files([path])))

    def test_elf_symbol_syntax_does_not_hide_real_domains(self):
        symbols = (b'\x7fELF\0type:.eq.' + b'internal/abi.RegArgs\0type:.hash.' + b'internal/profile.functionKey\0'
                   b'time.Time.' + b'Local\0crypto/x509.' + b'local string; crypto/x509.domain string')
        self.assertFalse(findings(symbols))
        self.assertIn('private-domain', findings(symbols + b'\0https://server.' + b'local/path'))
        self.assertIn('private-domain', findings(b'https://time.Time.' + b'Local/path'))

    def test_nested_jar_is_scanned_and_excess_depth_fails_closed(self):
        from check_public_data import scan_payload
        data = b'server.' + b'local'
        for depth in range(4):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('payload', data)
            data = buffer.getvalue()
            rules = {rule for _, rule in scan_payload(data, 'synthetic.aar')}
            self.assertIn('archive-depth-exceeded' if depth == 3 else 'private-domain', rules)

    def test_pinned_sdk_help_and_go_metadata_do_not_hide_real_endpoints(self):
        diagnostic = ("Cumulative sum of memory allocated to the heap by the application." +
                      "internal error: attempted to parse unknown event (please report):")
        helpers = ("link-local (169.254." + "0.0/16, fe80::/10) addresses are anonymized too.\n" +
                   "Internal IPv4 addresses are replaced with addresses starting from " +
                   "198.18." + "0.0 and internal IPv6 addresses with addresses starting from 2001:db8:1::")
        symbols = b'tcp.EndpointState.' + b'internal\0github.com/golang-jwt/jwt/v5.NumericDate.' + b'Local\0'
        elf = b'\x7fELF\0' + diagnostic.encode() + helpers.encode() + symbols
        self.assertFalse(findings(elf))
        # Same-looking user configuration/assets still fail, including when
        # appended to an otherwise reviewed ELF containing public SDK help.
        private_ip = '.'.join(map(str, (100,106,1,2))).encode()
        for domain in (b'application.'+b'internal', b'tcp.EndpointState.'+b'internal', b'v5.NumericDate.'+b'Local'):
            self.assertIn('private-domain', findings(elf+b'\0https://'+domain+b'/path'))
        self.assertIn('private-address', findings(elf+b'\0endpoint='+private_ip))
        self.assertIn('private-address', findings(helpers.encode()))
