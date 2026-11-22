"""Fail before building if a configured public profile contains nonpublic data."""
import base64
import json
import os
import re
from urllib.parse import urlsplit

from check_public_data import findings


def decode(raw: str, maximum: int) -> bytes:
    if not 1 <= len(raw) <= maximum or not re.fullmatch(r"[A-Za-z0-9_-]+", raw):
        raise ValueError("invalid profile encoding")
    decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != raw:
        raise ValueError("noncanonical profile encoding")
    return decoded


def public_object(raw: bytes) -> dict:
    def unique(pairs):
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError("duplicate profile key")
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or findings(raw) or findings(json.dumps(value, ensure_ascii=False).encode()):
        raise ValueError("unsafe profile data")
    return value


def check_anchor(anchor) -> None:
    if (not isinstance(anchor, dict) or not {"id", "spki", "epoch"} <= set(anchor)
            or set(anchor) - {"id", "spki", "epoch", "lastTransition"} or anchor.get("lastTransition", "") != ""
            or not isinstance(anchor["id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", anchor["id"])
            or not isinstance(anchor["spki"], str) or len(anchor["spki"]) > 344
            or type(anchor["epoch"]) is not int or not 1 <= anchor["epoch"] <= 9_007_199_254_740_991):
        raise ValueError("invalid installation anchor")


def signed_body(document, kind: str, anchor: dict) -> bytes:
    if not isinstance(document, str) or len(document) > 6144 or document.count(".") != 2:
        raise ValueError("invalid signed document")
    header, body, signature = document.split(".")
    fields = public_object(decode(header, 512))
    if (set(fields) != {"alg", "kid", "typ"} or fields["alg"] != "ES256"
            or fields["typ"] != kind or fields["kid"] != anchor["id"]):
        raise ValueError("invalid signature header")
    if len(decode(signature, 128)) != 64:
        raise ValueError("invalid signature")
    return decode(body, 5464)


def check_upgrade(upgrade, anchor: dict) -> None:
    if not isinstance(upgrade, dict) or set(upgrade) != {"previousAnchor", "rotation"}:
        raise ValueError("invalid installation upgrade")
    previous = upgrade["previousAnchor"]
    check_anchor(previous)
    rotation = upgrade["rotation"]
    if (previous["epoch"] + 1 != anchor["epoch"] or previous["id"] == anchor["id"] or previous["spki"] == anchor["spki"]
            or not isinstance(rotation, dict) or set(rotation) != {"previous", "next"}):
        raise ValueError("invalid root pair")
    prior = signed_body(rotation["previous"], "syn443-root-transition+jws", previous)
    successor = signed_body(rotation["next"], "syn443-root-transition+jws", anchor)
    transition = public_object(prior)
    if (prior != successor or set(transition) != {"schemaVersion", "audience", "from", "to", "spki", "epoch", "issuedAt", "notBefore", "expires"}
            or transition["schemaVersion"] != 1 or transition["audience"] != "syn443-root-transition"
            or transition["from"] != previous["id"] or transition["to"] != anchor["id"]
            or transition["spki"] != anchor["spki"] or transition["epoch"] != anchor["epoch"]):
        raise ValueError("invalid root transition")


def administrative_endpoints(value):
    protocol = {"clientId": "syn443-control-mobile", "audience": "syn443-control-api",
                "assuranceAcr": "urn:syn443:loa:2"}
    if (not isinstance(value, dict) or set(value) != set(protocol) | {"issuer", "apiOrigin"}
            or any(value[k] != v for k, v in protocol.items())):
        raise ValueError("unexpected administrative bootstrap")
    for key in ("issuer", "apiOrigin"):
        address = value[key]
        if not isinstance(address, str) or not address.startswith("https://") or len(address) > 2048 or not address.isascii():
            raise ValueError("invalid administrative endpoint")
        parsed = urlsplit(address)
        if (parsed.geturl() != address or (key == "apiOrigin" and parsed.path)
                or (parsed.path and (not parsed.path.startswith("/") or any(
                    segment in (".", "..") or not re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:@-]+", segment)
                    for segment in parsed.path[1:].split("/"))))):
            raise ValueError("invalid administrative endpoint")
    return (value["issuer"], value["apiOrigin"])


def check_release_authority(profile, descriptor):
    release = profile["releaseAuthority"]
    if (not isinstance(release, dict) or set(release) != {"serviceId", "channel", "anchor"}
            or release["serviceId"] != descriptor["serviceId"]
            or any(not isinstance(release[k], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", release[k])
                   for k in ("channel", "serviceId"))):
        raise ValueError("invalid release scope")
    key = release["anchor"]
    check_anchor(key)
    encoded = key["spki"]
    public = base64.b64decode(encoded, validate=True)
    # SubjectPublicKeyInfo for a public, uncompressed P-256 point.
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    if len(public) != len(prefix) + 64 or not public.startswith(prefix) or base64.b64encode(public).decode() != encoded:
        raise ValueError("invalid release public key")
    roots = descriptor["roots"]
    if not isinstance(roots, dict) or key["id"] in roots or encoded in roots.values():
        raise ValueError("release authority overlaps a policy key")
    for other in [profile["anchor"], profile.get("upgrade", {}).get("previousAnchor")]:
        if other and (other["id"] == key["id"] or other["spki"] == encoded):
            raise ValueError("release authority overlaps an installation key")


def check_profile(raw: str) -> None:
    profile = public_object(decode(raw, 12_000))
    version = profile.get("schemaVersion")
    expected = {"schemaVersion", "anchor", "service"}
    if type(version) is not int or version not in (1, 2, 3):
        raise ValueError("invalid installation profile")
    if version == 2 or version == 3 and "upgrade" in profile:
        expected.add("upgrade")
    if version == 3:
        expected.add("releaseAuthority")
    if set(profile) != expected:
        raise ValueError("unexpected installation fields")
    anchor = profile["anchor"]
    check_anchor(anchor)
    if "upgrade" in profile:
        check_upgrade(profile["upgrade"], anchor)
    descriptor = public_object(signed_body(profile["service"], "syn443-bootstrap+jws", anchor))
    required = {"schemaVersion", "audience", "rootEpoch", "revision", "serviceId", "issuer",
                "clientId", "apiOrigin", "roots", "issuedAt", "notBefore", "expires"}
    if not required <= set(descriptor) or set(descriptor) - (required | {"controlPanelOrigin", "adminBootstrap"}):
        raise ValueError("unexpected service descriptor fields")
    if "upgrade" in profile and (not isinstance(descriptor["roots"], dict)
                                 or profile["upgrade"]["previousAnchor"]["spki"] in descriptor["roots"].values()):
        raise ValueError("retired root is not a publication key")
    if version == 3:
        check_release_authority(profile, descriptor)
    endpoints = [descriptor["issuer"], descriptor["apiOrigin"]]
    if descriptor.get("controlPanelOrigin"):
        endpoints.append(descriptor["controlPanelOrigin"])
    if "adminBootstrap" in descriptor:
        endpoints.extend(administrative_endpoints(descriptor["adminBootstrap"]))
    for endpoint in endpoints:
        url = urlsplit(endpoint)
        host = url.hostname or ""
        if (url.scheme != "https" or url.netloc != host or not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*", host)
                or url.query or url.fragment or "?" in endpoint or "#" in endpoint):
            raise ValueError("unsafe profile endpoint")


if __name__ == "__main__":
    configured = os.environ.get("SYN443_INSTALLATION_PROFILE", "")
    if configured:
        try:
            check_profile(configured)
        except (ValueError, TypeError, AttributeError):
            raise SystemExit("Configured installation profile failed public payload validation.")
