from pathlib import Path
import ast
import re
import tempfile
import unittest
from coverage_evidence import IDENTITY_CLASSES, verify_classes


class CoverageEvidenceTest(unittest.TestCase):
    def report(self, text):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'report.xml'
        path.write_text(text, encoding='utf-8')
        return path

    def test_nested_vm_names_and_exact_ninety_percent_boundary(self):
        path = self.report('<report><class name="io/syn443/Fixture$Scope">'
                           '<counter type="LINE" covered="9" missed="1"/></class></report>')
        verify_classes(path, {'io.syn443.Fixture.Scope'})

    def test_absent_class_or_counter_cannot_silently_pass(self):
        for text in ['<report/>', '<report><class name="io/syn443/Fixture$Scope"/></report>',
                     '<report><class name="other"><counter type="LINE" covered="100" missed="0"/></class></report>']:
            with self.assertRaises(AssertionError):
                verify_classes(self.report(text), {'io.syn443.Fixture.Scope'})

    def test_low_empty_negative_and_duplicate_class_counts_fail(self):
        row = '<class name="io/syn443/Fixture$Scope"><counter type="LINE" covered="{}" missed="{}"/></class>'
        for contents in [row.format(8, 1), row.format(0, 0), row.format(-1, 0), row.format(9, 1) * 2]:
            with self.assertRaises(AssertionError):
                verify_classes(self.report('<report>' + contents + '</report>'), {'io.syn443.Fixture.Scope'})

    def test_service_discovery_classes_require_real_complete_ninety_percent_evidence(self):
        required = {'io.syn443.identity.AdminServiceDiscovery',
                    'io.syn443.identity.AdminServiceDiscovery.Companion', 'io.syn443.identity.AdminServiceManifest'}
        self.assertTrue(required <= IDENTITY_CLASSES)
        names = sorted(required)
        def row(name, covered=9, missed=1):
            vm_name = name.replace('.Companion', '$Companion').replace('io.syn443.identity.', 'io/syn443/identity/')
            return f'<class name="{vm_name}"><counter type="LINE" covered="{covered}" missed="{missed}"/></class>'
        rows = [row(name) for name in names]
        verify_classes(self.report('<report>' + ''.join(rows) + '</report>'), required)
        invalid = [''.join(rows[1:]), ''.join(rows + [rows[0]]),
                   ''.join(row('foreign.' + name) for name in names)]
        invalid += [''.join(row(name, 8, 2) if name == changed else row(name) for name in names) for changed in names]
        for contents in invalid:
            with self.assertRaises(AssertionError):
                verify_classes(self.report('<report>' + contents + '</report>'), required)

    def test_service_refresh_roots_match_eight_jvm_and_six_existing_android_methods(self):
        root = Path(__file__).resolve().parent.parent
        tree = ast.parse((root / 'tools/check_test_evidence.py').read_text(encoding='utf-8'))
        declarations = [node for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'ADMIN_SERVICE_REFRESH_REQUIRED' for target in node.targets)]
        self.assertEqual(1, len(declarations))
        required = ast.literal_eval(declarations[0].value)
        jvm_path = root / 'core/identity/src/test/kotlin/io/syn443/identity/AdminServiceDiscoveryTest.kt'
        methods = set(re.findall(r'@Test\s+fun\s+(\w+)', jvm_path.read_text(encoding='utf-8')))
        self.assertEqual(8, len(methods))
        self.assertEqual({('io.syn443.identity.AdminServiceDiscoveryTest', name) for name in methods}, set(required['identity']))
        self.assertEqual(8, len(required['identity']))
        expected = {
            ('io.syn443.android.BootstrapTrustStoreTest', 'signedAdminDescriptorRefreshAddsRemovesAndRepairsMetadataWithoutChangingDeviceAuthority'),
            ('io.syn443.android.BootstrapTrustStoreTest', 'adminDescriptorRefreshRejectsEveryProjectionChangeBeforeAnyFloorOrCacheWrite'),
            ('io.syn443.android.LoginControllerTest', 'adminDescriptorRefreshUsesOrdinaryContextWithoutMetadataAndRejectsCapturedReauthenticationBinding'),
            ('io.syn443.android.AdminControllerTest', 'missingMetadataWaitsForFreshVerifiedSourceBeforeReservingAnAdminKey'),
            ('io.syn443.android.AdminControllerTest', 'failedInvalidOrAbsentMetadataCannotCreateKeysSessionsOrAutomaticRetries'),
            ('io.syn443.android.AdminControllerTest', 'logoutOrChangedContextDuringMetadataLoadCannotPublishALateAdminOwner'),
        }
        self.assertEqual(expected, set(required['emulator']))
        self.assertEqual(6, len(required['emulator']))
        for class_name, method in expected:
            path = root / 'app/src/androidTest/kotlin/io/syn443/android' / (class_name.rsplit('.', 1)[1] + '.kt')
            self.assertIn(method, set(re.findall(r'@Test\s+fun\s+(\w+)', path.read_text(encoding='utf-8'))))
