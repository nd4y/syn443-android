import unittest
import xml.etree.ElementTree as ET

from release_input import ANDROID, PACKAGE, inspect_manifest


class ReleaseInputTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {"versionCode": 17, "versionName": "0.2.1"}
        self.manifest = ET.fromstring("""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="io.syn443.android" android:versionCode="17" android:versionName="0.2.1">
          <uses-sdk android:minSdkVersion="29" android:targetSdkVersion="37"/>
          <application android:allowBackup="false">
            <provider android:name=".vpn.ControlProvider" android:authorities="io.syn443.control" android:exported="false"/>
            <provider android:name=".vpn.OperatorReadProvider" android:authorities="io.syn443.operator.read" android:permission="android.permission.DUMP"
              android:process=":controller" android:grantUriPermissions="false" android:exported="true"/>
            <service android:name=".vpn.TunnelService" android:permission="android.permission.BIND_VPN_SERVICE"/>
          </application></manifest>""")

    def inspect(self):
        return inspect_manifest(ET.tostring(self.manifest), self.metadata)

    def test_inspects_packaged_versions_and_private_control_provider(self):
        self.assertEqual({"minSdk": 29, "targetSdk": 37}, self.inspect())
        self.manifest.find("application/provider").set(ANDROID+"name", PACKAGE+".vpn.ControlProvider")
        self.assertEqual(29, self.inspect()["minSdk"])

    def test_release_shell_diagnostics_cannot_expand_its_manifest_permissions(self):
        provider = self.manifest.findall("application/provider")[1]
        for key, value in (("permission", ""), ("readPermission", "android.permission.INTERNET"),
                           ("writePermission", "android.permission.INTERNET"), ("grantUriPermissions", "true"),
                           ("process", ":engine"), ("authorities", "extra;io.syn443.operator.read")):
            previous = dict(provider.attrib)
            provider.set(ANDROID + key, value)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.inspect()
            provider.attrib.clear()
            provider.attrib.update(previous)
        for name in ("path-permission", "grant-uri-permission"):
            child = ET.SubElement(provider, name)
            with self.assertRaises(ValueError):
                self.inspect()
            provider.remove(child)

    def test_rejects_debug_backup_test_or_cleartext_flags(self):
        app = self.manifest.find("application")
        for name in ("allowBackup", "debuggable", "testOnly", "usesCleartextTraffic"):
            with self.subTest(name=name):
                app.set(ANDROID+name, "true")
                with self.assertRaises(ValueError):
                    self.inspect()
                app.set(ANDROID+name, "false")

    def test_rejects_debug_providers_services_and_instrumentation(self):
        app = self.manifest.find("application")
        for component, attributes in (
                ("service", {"name": ".HostProbeService"}),
                ("provider", {"name": ".Fixture", "authorities": "extra;io.syn443.chat.fixture"})):
            node = ET.SubElement(app, component, {ANDROID+k: v for k,v in attributes.items()})
            with self.assertRaises(ValueError):
                self.inspect()
            app.remove(node)
        ET.SubElement(self.manifest, "instrumentation")
        with self.assertRaises(ValueError):
            self.inspect()

    def test_rejects_mismatched_output_and_weakened_component_boundaries(self):
        changes = [(self.manifest, "versionCode", "18"), (self.manifest, "versionName", "other"),
                   (self.manifest.find("uses-sdk"), "minSdkVersion", "30"),
                   (self.manifest.find("uses-sdk"), "targetSdkVersion", "28"),
                   (self.manifest.find("application/provider"), "exported", "true"),
                   (self.manifest.find("application/service"), "permission", "wrong")]
        for element, key, replacement in changes:
            with self.subTest(key=key):
                name = ANDROID + key
                original = element.attrib[name]
                element.set(name, replacement)
                with self.assertRaises(ValueError):
                    self.inspect()
                element.set(name, original)
