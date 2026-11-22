import unittest

from enrollment_fixture import CapabilityHead, canonical, digest


class FixtureCapabilityTest(unittest.TestCase):
    required = ['engine-config.v1', 'policy.keybound.v2', 'tun.lease.v1']

    def test_snapshot_extension_replay_and_isolation(self):
        first = CapabilityHead('fixture-one', self.required)
        other = CapabilityHead('fixture-two', self.required)
        before = first.respond('GET', None)
        self.assertNotEqual(before['authorityHash'], other.respond('GET', None)['authorityHash'])
        self.assertEqual(digest(canonical(sorted(self.required))), before['hash'])
        wanted = sorted(self.required + ['decision.bundle.v1'])
        change = {'requestId': digest(b'fixture-one-operation'), 'previousHash': before['hash'],
                  'capabilities': wanted}
        body = canonical(change)
        accepted = first.respond('POST', body)
        self.assertEqual(accepted, first.respond('POST', body))
        self.assertEqual(accepted['hash'], digest(canonical(wanted)))
        self.assertEqual(accepted['version'], 1)
        self.assertEqual(first.respond('GET', None)['capabilities'], wanted)
        self.assertEqual(other.respond('GET', None)['version'], 0)
        for invalid in (dict(change, requestId=digest(b'outdated')),
                        dict(change, capabilities=self.required),
                        dict(change, requestId=digest(b'remove'), previousHash=accepted['hash'],
                             capabilities=self.required)):
            with self.assertRaises(AssertionError):
                first.respond('POST', canonical(invalid))
        self.assertEqual(len(first.receipts), 1)


if __name__ == '__main__':
    unittest.main()
