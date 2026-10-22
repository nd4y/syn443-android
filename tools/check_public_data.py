"""Conservative privacy gate. Findings contain locations/rule names, never values.

This supplements secret scanning and human review; it cannot prove absence of PII.
Run before committing and before every public artifact upload.
"""
import argparse
import ipaddress
from pathlib import Path
import re
import subprocess
import zipfile
import io

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = {
    "private-domain": re.compile(r"\b(?:[\w-]+\.)+(?:local|lan|internal)(?![\w.-])", re.I),
    "personal-path": re.compile(r"(?:[A-Z]:[\\/](?:Users|SynologyDrive)[\\/]|/home/(?!runner(?:/|\b))[a-z][\w-]+/)", re.I),
    "credential-url": re.compile(r"[a-z][a-z0-9+.-]*://[^\s/\"<>]+:[^\s/\"<>]+@", re.I),
}
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
TEST_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
FORBIDDEN = re.compile(r"(?:^|/)(?:\.env(?:\..*)?|local\.properties|[^/]*\.(?:jks|keystore|pem|key)|(?:bugreport|logcat|backup|diagnostic-bundle)[^/]*)$", re.I)


def findings(data):
    text = data.decode("utf-8", errors="replace")
    if data.startswith(b"\x7fELF"):
        # Reviewed Go symbol/field spellings, not DNS names. Limit normalization
        # to ELF and exact compiler syntax; ordinary domains in ELF still fail.
        text = text.replace("type:.eq." + "internal/", "type:.eq.<go-internal>/")
        text = text.replace("type:.hash." + "internal/", "type:.hash.<go-internal>/")
        text = text.replace("\0time.Time." + "Local\0", "\0<go-time-method>\0")
        text = text.replace("crypto/x509." + "local string; crypto/x509.domain string", "<go-x509-struct-fields>")
        text = text.replace("tcp.EndpointState." + "internal\0", "tcp.EndpointState.<go-method>\0")
        text = text.replace("github.com/golang-jwt/jwt/v5.NumericDate." + "Local\0", "<go-jwt-time-method>\0")
        # Go/linker rodata concatenates independent public diagnostic strings.
        # Match both sentences, never the hostname-like fragment on its own.
        text = text.replace("Cumulative sum of memory allocated to the heap by the application." +
                            "internal error: attempted to parse unknown event (please report):",
                            "<public-runtime-metric-and-parser-diagnostics>")
        # Exact help text from pinned NetBird client/internal/debug/debug.go;
        # these are public allocation/anonymization descriptions, not endpoints.
        text = text.replace("link-local (169.254." + "0.0/16, fe80::/10) addresses are anonymized too.",
                            "<public-netbird-link-local-help>")
        text = text.replace("Internal IPv4 addresses are replaced with addresses starting from " +
                            "198.18." + "0.0 and internal IPv6 addresses with addresses starting from 2001:db8:1::",
                            "<public-netbird-anonymization-help>")
    result = {name for name, pattern in PATTERNS.items() if pattern.search(text)}
    for match in IPV4.finditer(text):
        # The standard shared-address allocation itself is public documentation.
        # Individual addresses in that range remain forbidden.
        if text[match.start():match.end() + 3] == "100.64.0.0/10":
            continue
        try:
            address = ipaddress.ip_address(match[0])
        except ValueError:
            continue
        if (address.is_private or address in ipaddress.ip_network("100.64.0.0/10")) and not (
            address.is_loopback or address.is_unspecified or any(address in net for net in TEST_NETS)
        ):
            result.add("private-address")
    return result


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def scan_history():
    problems = []
    # Every reachable blob, including deleted files and other fetched branches.
    for row in git("rev-list", "--objects", "--all").decode().splitlines():
        oid, _, name = row.partition(" ")
        if git("cat-file", "-t", oid).strip() != b"blob":
            continue
        data = git("cat-file", "blob", oid)
        rules = findings(data)
        if FORBIDDEN.search(name) and name != ".env.example":
            rules.add("private-file")
        if b"\0" in data and name != "gradle/wrapper/gradle-wrapper.jar":
            rules.add("unreviewed-binary")
        problems.extend((oid[:12] + ":" + name, rule) for rule in sorted(rules))
    for email in git("log", "--all", "--format=%ae%n%ce").decode().splitlines():
        if email and email != "noreply@github.com" and not email.endswith("@users.noreply.github.com"):
            problems.append(("commit-metadata", "personal-email"))
    problems.extend(("commit-message", rule) for rule in sorted(findings(git("log", "--all", "--format=%B"))))
    return problems


def scan_payload(data, location, depth=0):
    if zipfile.is_zipfile(io.BytesIO(data)):
        if depth >= 3:
            return [(location, "archive-depth-exceeded")]
        problems = []
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > 4096 or sum(m.file_size for m in members) > 256 * 1024 * 1024:
                return [(location, "archive-budget-exceeded")]
            for member in members:
                problems.extend((location, rule) for rule in sorted(findings(member.filename.encode())))
                if not member.is_dir():
                    problems.extend(scan_payload(archive.read(member), location + ":" + member.filename, depth + 1))
        return problems
    return [(location, rule) for rule in sorted(findings(data))]


def scan_files(paths):
    problems = []
    for path in paths:
        files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        for file in files:
            data = file.read_bytes()
            problems.extend(scan_payload(data, file.name))
    return problems


def scan_staged():
    problems = []
    names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").decode().split("\0")
    for name in filter(None, names):
        data = git("show", ":" + name)
        rules = findings(data)
        if FORBIDDEN.search(name) and name != ".env.example":
            rules.add("private-file")
        if b"\0" in data and name != "gradle/wrapper/gradle-wrapper.jar":
            rules.add("unreviewed-binary")
        problems.extend((name, rule) for rule in sorted(rules))
    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    if not args.history and not args.staged and not args.paths:
        parser.error("select history or files to scan")
    problems = scan_history() if args.history else []
    if args.staged:
        problems += scan_staged()
    problems += scan_files(args.paths)
    for location, rule in problems:
        print(f"Privacy gate: {rule}: {location}")
    if problems:
        raise SystemExit(1)
    print("Public data privacy gate passed (supplemental heuristic, not a confidentiality guarantee)")


if __name__ == "__main__":
    main()
