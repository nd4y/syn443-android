import base64
import json
import unittest

from check_installation_profile import check_profile


def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def profile(**changes):
    descriptor = {
        "schemaVersion": 1, "audience": "syn443-client-bootstrap", "rootEpoch": 1,
        "revision": 1, "serviceId": "fixture", "issuer": "https://identity.example.invalid/realms/fixture",
        "clientId": "syn443-android", "apiOrigin": "https://api.example.invalid", "roots": {},
        "issuedAt": 1, "notBefore": 1, "expires": 2,
    }
    descriptor.update(changes)
    signature = base64.urlsafe_b64encode(bytes(64)).decode().rstrip("=")
    header = {"alg": "ES256", "kid": "fixture", "typ": "syn443-bootstrap+jws"}
    return encode({"schemaVersion": 1, "anchor": {"id": "fixture", "spki": "", "epoch": 1},
                   "service": ".".join((encode(header), encode(descriptor), signature))})


class InstallationProfileTest(unittest.TestCase):
    def test_public_profile_is_admitted_to_the_runtime_signature_checks(self):
        check_profile(profile(controlPanelOrigin="https://admin.example.invalid"))

    def test_encoded_private_endpoints_and_unknown_fields_are_rejected(self):
        for raw in (profile(apiOrigin="https://host." + "local"), profile(apiOrigin="https://127.0.0.1"),
                    profile(issuer="https://identity.example.invalid/realms/test?token=x"), profile(extra="x"),
                    profile() + "=", "x" * 12001):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                check_profile(raw)
