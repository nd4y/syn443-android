import base64
import json
import unittest

from check_installation_profile import check_profile


def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def signed(kind, kid, payload):
    signature = base64.urlsafe_b64encode(bytes(64)).decode().rstrip("=")
    header = {"alg": "ES256", "kid": kid, "typ": kind}
    return ".".join((encode(header), encode(payload), signature))


def profile(**changes):
    descriptor = {
        "schemaVersion": 1, "audience": "syn443-client-bootstrap", "rootEpoch": 1,
        "revision": 1, "serviceId": "fixture", "issuer": "https://identity.example.invalid/realms/fixture",
        "clientId": "syn443-android", "apiOrigin": "https://api.example.invalid", "roots": {},
        "issuedAt": 1, "notBefore": 1, "expires": 2,
    }
    descriptor.update(changes)
    return encode({"schemaVersion": 1, "anchor": {"id": "fixture", "spki": "", "epoch": 1},
                   "service": signed("syn443-bootstrap+jws", "fixture", descriptor)})


class InstallationProfileTest(unittest.TestCase):
    def test_public_profile_is_admitted_to_the_runtime_signature_checks(self):
        check_profile(profile(controlPanelOrigin="https://admin.example.invalid"))

    def test_administrative_bootstrap_allows_only_public_canonical_endpoints_and_fixed_protocol(self):
        admin = {"issuer": "https://id.example.invalid/realms/mobile", "apiOrigin": "https://control.example.invalid",
                 "clientId": "syn443-control-mobile", "audience": "syn443-control-api", "assuranceAcr": "urn:syn443:loa:2"}
        check_profile(profile(adminBootstrap=admin))
        check_profile(profile(adminBootstrap=dict(admin, issuer="https://id.example.invalid")))
        invalid = [None, {}, {**admin, "extra": "x"}, {k: v for k, v in admin.items() if k != "audience"}]
        for key, values in {
            "clientId": ["syn443-android"], "audience": ["another-api"], "assuranceAcr": ["low"],
            "apiOrigin": [None, "http://control.example.invalid", "https://host." + "local",
                          "https://127.0.0.1", "https://control.example.invalid/private",
                          "https://u@control.example.invalid", "https://control.example.invalid:443",
                          "https://control.example.invalid?x=y", "https://control.example.invalid#x"],
            "issuer": [44, "https://id.example.invalid/realms/../private", "https://id.example.invalid/%2F",
                       "https://id.example.invalid/realms/", "https://id.example.invalid//double"],
        }.items():
            invalid.extend(dict(admin, **{key: v}) for v in values)
        for index, candidate in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(ValueError):
                check_profile(profile(adminBootstrap=candidate))

    def test_encoded_private_endpoints_and_unknown_fields_are_rejected(self):
        for raw in (profile(apiOrigin="https://host." + "local"), profile(apiOrigin="https://127.0.0.1"),
                    profile(issuer="https://identity.example.invalid/realms/test?token=x"), profile(extra="x"),
                    profile() + "=", "x" * 12001):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                check_profile(raw)

    def test_upgrade_checks_both_decoded_signatures_and_rejects_substitution(self):
        raw = profile(rootEpoch=2, revision=2)
        document = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        document.update(schemaVersion=2, anchor={"id": "fixture", "spki": "new-public-key", "epoch": 2})
        kind = "syn443-root-transition+jws"
        transition = {"schemaVersion": 1, "audience": "syn443-root-transition", "from": "prior",
                      "to": "fixture", "spki": "new-public-key", "epoch": 2, "issuedAt": 1,
                      "notBefore": 1, "expires": 2}
        proofs = {"previous": signed(kind, "prior", transition), "next": signed(kind, "fixture", transition)}
        document["upgrade"] = {"previousAnchor": {"id": "prior", "spki": "old-public-key", "epoch": 1},
                               "rotation": proofs}
        check_profile(encode(document))
        for bad in (dict(transition, epoch=3), dict(transition, expires=3),
                    dict(transition, extra="https://host." + "local")):
            with self.assertRaises(ValueError):
                proofs["next"] = signed(kind, "fixture", bad)
                check_profile(encode(document))
