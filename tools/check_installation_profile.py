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


def check_profile(raw: str) -> None:
    profile = public_object(decode(raw, 12_000))
    if set(profile) != {"schemaVersion", "anchor", "service"} or type(profile["schemaVersion"]) is not int or profile["schemaVersion"] != 1:
        raise ValueError("invalid installation profile")
    anchor = profile["anchor"]
    if (not isinstance(anchor, dict) or not {"id", "spki", "epoch"} <= set(anchor)
            or set(anchor) - {"id", "spki", "epoch", "lastTransition"} or anchor.get("lastTransition", "")):
        raise ValueError("invalid installation anchor")
    service = profile["service"]
    if not isinstance(service, str) or len(service) > 6144 or service.count(".") != 2:
        raise ValueError("invalid service descriptor")
    header, body, signature = service.split(".")
    fields = public_object(decode(header, 512))
    if (set(fields) != {"alg", "kid", "typ"} or fields["alg"] != "ES256"
            or fields["typ"] != "syn443-bootstrap+jws" or fields["kid"] != anchor["id"]):
        raise ValueError("invalid service signature header")
    if len(decode(signature, 128)) != 64:
        raise ValueError("invalid service signature")
    descriptor = public_object(decode(body, 5464))
    expected = {"schemaVersion", "audience", "rootEpoch", "revision", "serviceId", "issuer",
                "clientId", "apiOrigin", "roots", "issuedAt", "notBefore", "expires"}
    if not expected <= set(descriptor) or set(descriptor) - (expected | {"controlPanelOrigin"}):
        raise ValueError("unexpected service descriptor fields")
    endpoints = [descriptor["issuer"], descriptor["apiOrigin"]]
    if descriptor.get("controlPanelOrigin"):
        endpoints.append(descriptor["controlPanelOrigin"])
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
