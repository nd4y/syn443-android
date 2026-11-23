import copy
import unittest
from pathlib import Path
import xml.etree.ElementTree as ET

from check_packaged_backup import ANDROID, PACKAGE, rule_paths, verify_rules


class PackagedBackupTest(unittest.TestCase):
    def setUp(self):
        self.manifest = ET.Element("manifest", {"package": PACKAGE})
        self.app = ET.SubElement(self.manifest, "application", {
            ANDROID + "allowBackup": "false", ANDROID + "fullBackupContent": "false",
            ANDROID + "dataExtractionRules": "@ref/0x7f0d0000"})
        self.table = """resource 0x7f0d0000 xml/extraction
          () (file) res/4j.xml type=XML
          (v35) (file) res/di.xml type=XML
        resource 0x7f0d0001 xml/other
          () (file) res/zz.xml type=XML"""

    def paths(self, table=None):
        return rule_paths(ET.tostring(self.manifest), self.table if table is None else table)

    def test_numeric_manifest_reference_resolves_every_compiled_variant(self):
        self.assertEqual(["res/4j.xml", "res/di.xml"], self.paths())
        self.app.set(ANDROID + "dataExtractionRules", "@xml/extraction")
        self.assertEqual(["res/4j.xml", "res/di.xml"], self.paths())

    def test_missing_default_ambiguous_id_and_unresolved_alias_are_rejected(self):
        for table in (self.table.replace("()", "(v34)", 1), self.table.replace("(v35)", "()"),
                      self.table.replace("(file) res/di.xml type=XML", "(reference) @0x7f0d0001"),
                      self.table.replace("res/4j.xml", "res/../other.xml"),
                      self.table + "\nresource 0x7f0d0000 xml/duplicate", ""):
            with self.subTest(table=table), self.assertRaises(ValueError):
                self.paths(table)

    def test_manifest_cannot_delegate_backup_or_remove_a_privacy_boundary(self):
        for field, change in (("allowBackup", "true"), ("fullBackupContent", "@xml/open"),
                              ("backupAgent", ".NewAgent"), ("dataExtractionRules", "@null")):
            key = ANDROID + field
            original = dict(self.app.attrib)
            self.app.set(key, change)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.paths()
            self.app.attrib = original

    def test_both_transports_exclude_every_entire_domain(self):
        path = Path(__file__).resolve().parents[1] / "app/src/main/res/xml/data_extraction_rules.xml"
        root = ET.fromstring(path.read_bytes())
        verify_rules(ET.tostring(root))
        for section in range(2):
            for change in ("remove", "repeat", "narrow", "include", "unknown"):
                damaged = copy.deepcopy(root)
                transport = damaged[section]
                if change == "remove":
                    transport.remove(transport[0])
                elif change == "repeat":
                    transport[0].set("domain", transport[1].get("domain"))
                elif change == "narrow":
                    transport[0].set("path", "one-file")
                elif change == "include":
                    transport[0].tag = "include"
                else:
                    transport[0].set("domain", "new-domain")
                with self.subTest(section=section, change=change), self.assertRaises(ValueError):
                    verify_rules(ET.tostring(damaged))
        ET.SubElement(root, "cross-platform-transfer", {"platform": "ios"})
        with self.assertRaises(ValueError):
            verify_rules(ET.tostring(root))
