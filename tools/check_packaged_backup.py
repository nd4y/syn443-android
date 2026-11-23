"""Check the actual Android release manifest and every packaged extraction policy."""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from release_input import ANDROID, PACKAGE

DOMAINS = {"root", "file", "database", "sharedpref", "external",
           "device_root", "device_file", "device_database", "device_sharedpref"}


def rule_paths(manifest, resource_table):
    root = ET.fromstring(manifest)
    app, = root.findall("application")
    if (root.get("package") != PACKAGE or app.get(ANDROID + "allowBackup") != "false"
            or app.get(ANDROID + "fullBackupContent") != "false" or ANDROID + "backupAgent" in app.attrib):
        raise ValueError("packaged application backup flags or agent changed")
    reference = app.get(ANDROID + "dataExtractionRules", "")
    identifier = re.fullmatch(r"@ref/(0x[0-9a-fA-F]{8})", reference)
    symbolic = re.fullmatch(r"@(xml/[a-z0-9_]+)", reference)
    if not identifier and not symbolic:
        raise ValueError("packaged extraction rules missing")

    paths = []
    found = False
    current = False
    for line in resource_table.splitlines():
        row = line.strip()
        if row.startswith(("resource ", "type ", "Package ")):
            current = False
        entry = re.fullmatch(r"resource (0x[0-9a-fA-F]{8}) (xml/[a-z0-9_]+)", row)
        if entry:
            current = entry[1].lower() == identifier[1].lower() if identifier else entry[2] == symbolic[1]
            if current:
                if found:
                    raise ValueError("ambiguous packaged extraction resource")
                found = True
        elif current and row:
            item = re.fullmatch(r"\(([^()]*)\) \(file\) (res/[a-zA-Z0-9_./-]+\.xml) type=XML", row)
            if item is None or ".." in item[2].split("/"):
                raise ValueError("unresolved packaged extraction policy")
            paths.append((item[1], item[2]))
    if not paths or "" not in {config for config, _ in paths} or len({config for config, _ in paths}) != len(paths):
        raise ValueError("missing or ambiguous default extraction policy")
    return sorted({path for _, path in paths})


def verify_rules(xml):
    root = ET.fromstring(xml)
    if root.tag != "data-extraction-rules" or root.attrib or sorted(s.tag for s in root) != ["cloud-backup", "device-transfer"]:
        raise ValueError("unexpected extraction transports")
    for section in root:
        expected = {"disableIfNoEncryptionCapabilities": "true"} if section.tag == "cloud-backup" else {}
        if section.attrib != expected or len(section) != len(DOMAINS):
            raise ValueError("incomplete extraction exclusions")
        excluded = set()
        for entry in section:
            domain = entry.get("domain")
            if (entry.tag != "exclude" or len(entry) or domain not in DOMAINS or
                    entry.attrib != {"domain": domain, "path": "."} or domain in excluded):
                raise ValueError("unexpected extraction rule")
            excluded.add(domain)


def verify(apk, manifest, aapt2, analyzer="apkanalyzer"):
    table = subprocess.check_output([aapt2, "dump", "resources", str(apk)], text=True, timeout=90)
    paths = rule_paths(manifest, table)
    for path in paths:
        xml = subprocess.check_output([analyzer, "resources", "xml", "--file", "/" + path, str(apk)], timeout=45)
        verify_rules(xml)
    return len(paths)


if __name__ == "__main__":
    apk, manifest, aapt2 = sys.argv[1:]
    print("Verified packaged backup rules for", verify(Path(apk), Path(manifest).read_bytes(), aapt2), "resource file(s)")
