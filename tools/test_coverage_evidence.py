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

    def test_layer_editor_classes_keep_complete_independent_ninety_percent_gate(self):
        root = Path(__file__).resolve().parent.parent
        names = {
            'AdminLayerControl', 'AdminLayerAction', 'AdminLayerEdit',
            'AdminLayerRequest', 'AdminLayerExpected', 'AdminLayerProposal', 'AdminLayerReply',
            'AdminLayerInventory', 'AdminLayerDraft', 'AdminLayerDraftSummary', 'AdminLayerDraftList',
            'AdminLayerDiscarded', 'AdminLayerPublishedHead', 'AdminLayerPreview', 'AdminLayerJob',
            'AdminLayerJson', 'AdminLayerJson.Reader', 'AdminLayerJson.Document', 'AdminLayerOwnership',
            'AdminLayerConflict', 'AdminLayerDifference', 'AdminLayerDiff', 'AdminLayerComparison',
            'AdminLayerComparison.Inputs', 'AdminLayerComparison.Row', 'AdminLayerComparison.Companion',
            'AdminLayerProjectionException', 'AdminLayerProjection', 'AdminLayerValues', 'AdminLayerProjector',
        }
        required = {'io.syn443.identity.' + name for name in names}
        self.assertEqual(30, len(required))
        self.assertTrue(required <= IDENTITY_CLASSES)
        gradle = (root / 'core/identity/build.gradle.kts').read_text(encoding='utf-8')
        self.assertTrue(required <= set(re.findall(r'"(io\.syn443\.identity\.[\w.]+)"', gradle)))
        def row(name, covered=9, missed=1):
            suffix = name.removeprefix('io.syn443.identity.').replace('.', '$')
            return f'<class name="io/syn443/identity/{suffix}"><counter type="LINE" covered="{covered}" missed="{missed}"/></class>'
        ordered = sorted(required)
        rows = [row(name) for name in ordered]
        verify_classes(self.report('<report>' + ''.join(rows) + '</report>'), required)
        invalid = [''.join(rows[1:]), ''.join(rows + [rows[0]]),
                   ''.join(row('foreign.' + name) for name in ordered)]
        invalid += [''.join(row(name, 8, 2) if name == changed else row(name) for name in ordered)
                    for changed in ordered]
        for contents in invalid:
            with self.assertRaises(AssertionError):
                verify_classes(self.report('<report>' + contents + '</report>'), required)

    def test_layer_editor_and_comparison_roots_match_source_and_retain_exact_added_outcome_floors(self):
        root = Path(__file__).resolve().parent.parent
        gate_source = (root / 'tools/check_test_evidence.py').read_text(encoding='utf-8')
        tree = ast.parse(gate_source)
        declarations = [node for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'ADMIN_LAYER_EDITOR_REQUIRED'
                            for target in node.targets)]
        self.assertEqual(1, len(declarations))
        editor = ast.literal_eval(declarations[0].value)
        comparison_declarations = [node for node in tree.body if isinstance(node, ast.Assign) and
                                  any(isinstance(target, ast.Name) and target.id == 'ADMIN_LAYER_COMPARISON_REQUIRED'
                                      for target in node.targets)]
        self.assertEqual(1, len(comparison_declarations))
        comparison = ast.literal_eval(comparison_declarations[0].value)
        self.assertEqual({'identity', 'emulator'}, set(editor))
        self.assertEqual({'identity', 'emulator'}, set(comparison))
        required = {}
        for mode, old_count, new_count in [('identity', 43, 14), ('emulator', 44, 21)]:
            self.assertEqual(old_count, len(editor[mode]))
            self.assertEqual(new_count, len(comparison[mode]))
            self.assertFalse(set(editor[mode]) & set(comparison[mode]))
            required[mode] = editor[mode] + comparison[mode]
        expected = {'identity': set(), 'emulator': set()}
        for mode, folder, classes in [
            ('identity', 'core/identity/src/test/kotlin/io/syn443/identity', {
                'AdminLayerControlTest': 23, 'AdminLayerJsonTest': 4,
                'AdminLayerProtocolTest': 7, 'AdminLayerOwnershipTest': 4, 'AdminLayerComparisonTest': 14}),
            ('emulator', 'app/src/androidTest/kotlin/io/syn443/android', {
                'AdminEditorStoreTest': 12, 'AdminEditorWireTest': 5, 'AdminEditorUiTest': 10,
                'AdminEditorCoordinatorTest': 15, 'AdminEditorRouteTest': 4,
                'AdminComparisonUiTest': 7, 'AdminComparisonWireTest': 5, 'AdminComparisonRouteTest': 4}),
        ]:
            package = 'io.syn443.identity.' if mode == 'identity' else 'io.syn443.android.'
            for class_name, count in classes.items():
                methods = re.findall(r'@Test\s+fun\s+(\w+)', (root / folder / (class_name + '.kt')).read_text(encoding='utf-8'))
                self.assertEqual(count, len(methods), class_name)
                self.assertEqual(len(methods), len(set(methods)), class_name)
                expected[mode].update((package + class_name, name) for name in methods)
        expected['identity'].update({
            ('io.syn443.identity.AdminDiscoveryTest', 'typedOperationCancellationPreservesClockButNeverGrantsOrSkipsFreshDiscoveryAdmission'),
            ('io.syn443.identity.AdminIdentityTest', 'initialAuthenticationTimeHonorsBothTrustedWindowEdgesAtExactSecondBoundaries'),
            ('io.syn443.identity.AdminProtocolTest', 'initialIdTokenRejectsMissingMalformedUnsafeAndStaleAuthenticationTimeDespiteFreshIssueTime'),
            ('io.syn443.identity.AdminProtocolTest', 'refreshKeepsOldAuthenticationTimeOptionalWithoutRenewingMfaOrTheOriginalSessionLease'),
            ('io.syn443.identity.AdminProtocolTest', 'catalogReauthenticationRequiresExactBoundedJsonAndNeverRetriesANonceOrWrongCode'),
        })
        expected['emulator'].update({
            ('io.syn443.android.AdminControllerTest', 'catalogFreshAuthenticationChallengeRetiresAdminOwnerWithoutRetryOrDeviceVpnChanges'),
            ('io.syn443.android.AdminControllerTest', 'mailboxLeaseExpiryBeforeDispatchRejectsLateHttpWithoutLazyPollingOrReleasingBlockedOwner'),
            ('io.syn443.android.AdminLoginBrowserTest', 'fixedMaximumAuthenticationAgeRejectsMissingChangedAndDuplicateBrowserParameters'),
        })
        for mode, count, floor, folder in [
            ('identity', 57, 249, 'core/identity/src/test/kotlin/io/syn443/identity'),
            ('emulator', 65, 427, 'app/src/androidTest/kotlin/io/syn443/android'),
        ]:
            self.assertEqual(count, len(required[mode]))
            self.assertEqual(expected[mode], set(required[mode]))
            self.assertRegex(gate_source, rf'(?:if|elif) mode=="{mode}":\n(?:    [^\n]*\n)*?    minimum={floor}\n')
            for class_name, method in expected[mode]:
                path = root / folder / (class_name.rsplit('.', 1)[1] + '.kt')
                self.assertIn(method, set(re.findall(r'@Test\s+fun\s+(\w+)', path.read_text(encoding='utf-8'))))

    def test_operation_reconciliation_classes_keep_complete_independent_ninety_percent_gate(self):
        root = Path(__file__).resolve().parent.parent
        names = {'AdminOperationRequest', 'AdminOperationJob', 'AdminOperationReceipt', 'AdminOperationReconcile',
                 'AdminOperationIntent', 'AdminOperationOutcome', 'AdminOperationJobState'}
        required = {'io.syn443.identity.' + name for name in names}
        self.assertEqual(7, len(required))
        self.assertTrue(required <= IDENTITY_CLASSES)
        gradle = (root / 'core/identity/build.gradle.kts').read_text(encoding='utf-8')
        self.assertTrue(required <= set(re.findall(r'"(io\.syn443\.identity\.[\w.]+)"', gradle)))
        def row(name, covered=9, missed=1):
            vm_name = name.replace('io.syn443.identity.', 'io/syn443/identity/')
            return f'<class name="{vm_name}"><counter type="LINE" covered="{covered}" missed="{missed}"/></class>'
        ordered = sorted(required)
        rows = [row(name) for name in ordered]
        verify_classes(self.report('<report>' + ''.join(rows) + '</report>'), required)
        invalid = [''.join(rows[1:]), ''.join(rows + [rows[0]]),
                   ''.join(row('foreign.' + name) for name in ordered)]
        invalid += [''.join(row(name, 8, 2) if name == changed else row(name) for name in ordered)
                    for changed in ordered]
        for contents in invalid:
            with self.assertRaises(AssertionError):
                verify_classes(self.report('<report>' + contents + '</report>'), required)

    def test_operation_reconciliation_roots_match_all_source_classes_and_add_to_existing_floors(self):
        root = Path(__file__).resolve().parent.parent
        gate_source = (root / 'tools/check_test_evidence.py').read_text(encoding='utf-8')
        tree = ast.parse(gate_source)
        def declaration(name):
            matches = [node for node in tree.body if isinstance(node, ast.Assign) and
                       any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
            self.assertEqual(1, len(matches), name)
            return ast.literal_eval(matches[0].value)
        required = declaration('ADMIN_OPERATION_RECONCILE_REQUIRED')
        self.assertEqual({'identity', 'emulator'}, set(required))
        old_editor = declaration('ADMIN_LAYER_EDITOR_REQUIRED')
        old_comparison = declaration('ADMIN_LAYER_COMPARISON_REQUIRED')
        for mode, count, floor, folder, classes in [
            ('identity', 49, 249, 'core/identity/src/test/kotlin/io/syn443/identity', {
                'AdminOperationReconcileTest': 18, 'AdminOperationProtocolTest': 7, 'AdminOperationHttpTest': 3,
                'AdminOperationVersionTest': 6, 'AdminOperationGoConformanceTest': 6, 'AdminEditorAuthorityTest': 6,
                'BoundedHttpCancellationRaceTest': 3}),
            ('emulator', 29, 427, 'app/src/androidTest/kotlin/io/syn443/android', {
                'AdminPublishDispatchDeadlineTest': 3, 'AdminOperationCoordinatorTest': 10, 'AdminOperationUiTest': 5,
                'AdminOperationWireTest': 3, 'AdminOperationRouteTest': 3, 'AdminEditorOwnerMigrationTest': 5}),
        ]:
            expected = set()
            package = 'io.syn443.identity.' if mode == 'identity' else 'io.syn443.android.'
            for class_name, expected_count in classes.items():
                methods = re.findall(r'@Test\s+fun\s+(\w+)', (root / folder / (class_name + '.kt')).read_text(encoding='utf-8'))
                self.assertEqual(expected_count, len(methods), class_name)
                self.assertEqual(len(methods), len(set(methods)), class_name)
                expected.update((package + class_name, name) for name in methods)
            self.assertEqual(count, len(required[mode]))
            self.assertEqual(count, len(set(required[mode])))
            self.assertEqual(expected, set(required[mode]))
            self.assertFalse(set(required[mode]) & set(old_editor[mode]))
            self.assertFalse(set(required[mode]) & set(old_comparison[mode]))
            self.assertRegex(gate_source, rf'(?:if|elif) mode=="{mode}":\n(?:    [^\n]*\n)*?    minimum={floor}\n')
