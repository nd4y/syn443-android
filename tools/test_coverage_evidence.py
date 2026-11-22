from pathlib import Path
import ast
import re
import tempfile
import unittest
from coverage_evidence import ADAPTIVE_BUDGET_CLASSES, IDENTITY_CLASSES, OWNER_HEALTH_CLASSES, POLICY_CHECK_PLAN_CLASSES, verify_classes


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
        for mode, old_count, new_count in [('identity', 43, 14), ('emulator', 46, 21)]:
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
                'AdminEditorStoreTest': 12, 'AdminEditorWireTest': 5, 'AdminEditorUiTest': 12,
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
            ('emulator', 67, 524, 'app/src/androidTest/kotlin/io/syn443/android'),
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
            ('emulator', 30, 524, 'app/src/androidTest/kotlin/io/syn443/android', {
                'AdminPublishDispatchDeadlineTest': 3, 'AdminOperationCoordinatorTest': 10, 'AdminOperationUiTest': 5,
                'AdminOperationWireTest': 3, 'AdminOperationRouteTest': 4, 'AdminEditorOwnerMigrationTest': 5}),
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

    def test_adaptive_search_roots_match_complete_source_and_keep_additive_floor(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / 'tools/check_test_evidence.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        declarations = [node for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'ADAPTIVE_SEARCH_REQUIRED'
                            for target in node.targets)]
        self.assertEqual(1, len(declarations))
        required = ast.literal_eval(declarations[0].value)
        expected = set()
        for name, count in [('ManagedAdaptiveSearchStatusTest', 6), ('RouteSearchStatusTest', 8)]:
            path = root / 'app/src/androidTest/kotlin/io/syn443/android' / (name + '.kt')
            methods = re.findall(r'@Test\s+fun\s+(\w+)', path.read_text(encoding='utf-8'))
            self.assertEqual(count, len(methods))
            self.assertEqual(count, len(set(methods)))
            expected.update(('io.syn443.android.' + name, method) for method in methods)
        self.assertEqual(14, len(required))
        self.assertEqual(14, len(set(required)))
        self.assertEqual(expected, set(required))
        self.assertRegex(source, r'elif mode=="emulator":\n(?:    [^\n]*\n)*?    minimum=524\n')
        self.assertRegex(source, r'elif mode=="identity":\n(?:    [^\n]*\n)*?    minimum=249\n')

    def test_check_plan_roots_are_source_bound_and_every_missing_or_foreign_outcome_fails(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / 'tools/check_test_evidence.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        declaration, = [node for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'CHECK_PLAN_REQUIRED' for target in node.targets)]
        required = ast.literal_eval(declaration.value)
        self.assertEqual({'policy', 'emulator'}, set(required))
        guard, = [node for node in tree.body if isinstance(node, ast.If) and
                  isinstance(node.test, ast.Compare) and any(isinstance(value, ast.Name) and value.id == 'CHECK_PLAN_REQUIRED'
                                                           for value in node.test.comparators)]
        # Exercise the actual finite admission assertions, not a mirrored helper.
        admission = compile(ast.fix_missing_locations(ast.Module(body=guard.body[:3], type_ignores=[])), '<check-plan-admission>', 'exec')
        for mode, floor, folder, classes in [
            ('policy', 31, 'core/policy/src/test/kotlin/io/syn443/policy', {'RouteCheckProfileTest': 8, 'RouteCheckPlanPolicyTest': 3}),
            ('emulator', 524, 'app/src/androidTest/kotlin/io/syn443/android', {'RouteCheckPlanTest': 10}),
        ]:
            expected = set()
            for classname, count in classes.items():
                methods = re.findall(r'@Test\s+fun\s+(\w+)', (root / folder / (classname + '.kt')).read_text(encoding='utf-8'))
                self.assertEqual(count, len(methods)); self.assertEqual(count, len(set(methods)))
                expected.update(('io.syn443.' + ('policy.' if mode == 'policy' else 'android.') + classname, name) for name in methods)
            self.assertEqual(expected, set(required[mode])); self.assertEqual(len(expected), len(required[mode]))
            self.assertRegex(source, rf'(?:if|elif) mode=="{mode}":\n(?:    [^\n]*\n)*?    minimum={floor}\n')
            def check(identities):
                exec(admission, {'CHECK_PLAN_REQUIRED': required, 'mode': mode, 'identities': identities})
            check(expected)
            for missing in expected:
                with self.assertRaises(AssertionError):
                    check(expected - {missing})
                with self.assertRaises(AssertionError):
                    check(expected - {missing} | {('foreign.' + missing[0], missing[1])})
            with self.assertRaises(AssertionError):
                check(set())
        collector = ast.parse((root / 'tools/collect_public_emulator.py').read_text(encoding='utf-8'))
        declaration, = [node for node in collector.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'CLASS' for target in node.targets)]
        pattern = re.compile(ast.literal_eval(declaration.value.args[0]))
        self.assertIsNotNone(pattern.fullmatch('io.syn443.android.RouteCheckPlanTest'))
        self.assertIsNone(pattern.fullmatch('foreign.RouteCheckPlanTest'))

    def test_check_plan_four_logic_classes_require_complete_nonempty_ninety_percent_policy_evidence(self):
        expected = {'io.syn443.policy.RouteCheckProfile', 'io.syn443.policy.RouteCheckProfile.Companion',
                    'io.syn443.policy.RouteCheckProfiles', 'io.syn443.policy.RouteCheckProfiles.Inspection'}
        self.assertEqual(expected, POLICY_CHECK_PLAN_CLASSES)
        self.assertFalse(expected & IDENTITY_CLASSES)
        def row(name, covered=9, missed=1, counter=True):
            name = name.replace('io.syn443.policy.', 'io/syn443/policy/').replace('.Companion', '$Companion').replace('.Inspection', '$Inspection')
            body = f'<counter type="LINE" covered="{covered}" missed="{missed}"/>' if counter else ''
            return f'<class name="{name}">{body}</class>'
        names = sorted(expected)
        rows = [row(name) for name in names]
        verify_classes(self.report('<report>' + ''.join(rows) + '</report>'), expected)
        for changed in names:
            for replacement in ('', row(changed, counter=False), row(changed, 8, 2), row(changed, 0, 0), row('foreign.' + changed)):
                contents = ''.join(replacement if name == changed else row(name) for name in names)
                with self.assertRaises(AssertionError):
                    verify_classes(self.report('<report>' + contents + '</report>'), expected)
        with self.assertRaises(AssertionError):
            verify_classes(self.report('<report>' + ''.join(rows + [rows[0]]) + '</report>'), expected)
        root = Path(__file__).resolve().parent.parent
        tree = ast.parse((root / 'tools/check_test_evidence.py').read_text(encoding='utf-8'))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Name) and node.func.id == 'verify_classes' and node.args and
                 isinstance(node.args[-1], ast.Name) and node.args[-1].id == 'POLICY_CHECK_PLAN_CLASSES']
        self.assertEqual(1, len(calls))
        self.assertIn('core/policy/build/reports/jacoco/test/jacocoTestReport.xml', ast.unparse(calls[0]))


    def test_durable_budget_roots_require_every_unique_actual_name_and_exact_source_inventory(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / 'tools/check_test_evidence.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        declaration, = [node for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'DURABLE_BUDGET_REQUIRED' for target in node.targets)]
        required = ast.literal_eval(declaration.value)
        self.assertEqual({'jvm', 'emulator'}, set(required))
        guard, = [node for node in tree.body if isinstance(node, ast.If) and
                  isinstance(node.test, ast.Compare) and any(isinstance(value, ast.Name) and value.id == 'DURABLE_BUDGET_REQUIRED'
                                                           for value in node.test.comparators)]
        # Run the actual checker fragments in Actions, including its unchanged
        # global duplicate-outcome guard and both Android source owners.
        unique, = [node for node in tree.body if isinstance(node, ast.Assert) and
                   isinstance(node.msg, ast.Constant) and node.msg.value == 'Duplicate actual test outcomes']
        uniqueness = compile(ast.fix_missing_locations(ast.Module(body=[unique], type_ignores=[])), '<actual-unique>', 'exec')
        admission = compile(ast.fix_missing_locations(ast.Module(body=guard.body[:3], type_ignores=[])), '<durable-admission>', 'exec')
        complete = compile(ast.fix_missing_locations(ast.Module(body=guard.body, type_ignores=[])), '<durable-source>', 'exec')
        for mode, floor, folder, classes in [
            ('jvm', 21, 'core/decision/src/test/kotlin/io/syn443/decision', {'io.syn443.decision.AdaptiveProbeCheckpointTest': 7}),
            ('emulator', 524, 'app/src/androidTest/kotlin/io/syn443/android', {
                'io.syn443.android.AdaptiveProbeStoreTest': 10, 'io.syn443.android.AdaptiveAdmissionCoordinatorTest': 8}),
        ]:
            originals = {}
            expected = set()
            for owner, count in classes.items():
                path = root / folder / (owner.rsplit('.', 1)[1] + '.kt')
                original = path.read_text(encoding='utf-8')
                methods = re.findall(r'@Test\s+fun\s+(\w+)', original)
                self.assertEqual(count, len(methods)); self.assertEqual(count, len(set(methods)))
                expected.update((owner, name) for name in methods)
                originals[owner] = (path.name, original, methods)
            self.assertEqual(expected, set(required[mode])); self.assertEqual(sum(classes.values()), len(required[mode]))
            self.assertRegex(source, rf'(?:if|elif) mode=="{mode}":\n(?:    [^\n]*\n)*?    minimum={floor}\n')
            def check(identities, table=required):
                exec(admission, {'DURABLE_BUDGET_REQUIRED': table, 'mode': mode, 'identities': identities})
            check(expected)
            exec(uniqueness, {'identities': list(expected)})
            with self.assertRaises(AssertionError):
                exec(uniqueness, {'identities': list(expected) + [required[mode][0]]})
            for missing in expected:
                with self.assertRaises(AssertionError):
                    check(expected - {missing})
                with self.assertRaises(AssertionError):
                    check(expected - {missing} | {('foreign.' + missing[0], missing[1])})
            with self.assertRaises(AssertionError):
                check(set())
            duplicated = dict(required); duplicated[mode] = required[mode] + [required[mode][0]]
            with self.assertRaises(AssertionError):
                check(expected, duplicated)
            with tempfile.TemporaryDirectory() as directory:
                fixture_root = Path(directory)
                for filename, original, _ in originals.values():
                    fixture = fixture_root / folder / filename
                    fixture.parent.mkdir(parents=True, exist_ok=True)
                    fixture.write_text(original, encoding='utf-8')
                scope = {'DURABLE_BUDGET_REQUIRED': required, 'mode': mode, 'identities': expected, 'root': fixture_root, 're': re}
                exec(complete, scope.copy())
                for filename, original, methods in originals.values():
                    fixture = fixture_root / folder / filename
                    dropped = re.sub(r'@Test\s+(?=fun\s+' + re.escape(methods[0]) + r'\b)', '', original, count=1)
                    self.assertNotEqual(original, dropped)
                    for changed in (original.replace(methods[0], 'changedSyntheticName'),
                                    original.replace(methods[0], methods[1]), dropped,
                                    original + '\n@Test fun unexpectedSyntheticRoot() {}\n'):
                        fixture.write_text(changed, encoding='utf-8')
                        with self.assertRaises(AssertionError):
                            exec(complete, scope.copy())
                    fixture.unlink()
                    with self.assertRaises(FileNotFoundError):
                        exec(complete, scope.copy())
                    fixture.write_text(original, encoding='utf-8')
        self.assertRegex(source, r'elif mode=="policy":\n(?:    [^\n]*\n)*?    minimum=31\n')
        self.assertRegex(source, r'elif mode=="identity":\n(?:    [^\n]*\n)*?    minimum=249\n')
        collector = ast.parse((root / 'tools/collect_public_emulator.py').read_text(encoding='utf-8'))
        declaration, = [node for node in collector.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'CLASS' for target in node.targets)]
        pattern = re.compile(ast.literal_eval(declaration.value.args[0]))
        for name in ('AdaptiveProbeStoreTest', 'AdaptiveAdmissionCoordinatorTest'):
            self.assertIsNotNone(pattern.fullmatch('io.syn443.android.' + name))
            self.assertIsNone(pattern.fullmatch('foreign.' + name))

    def test_durable_budget_four_decision_classes_need_complete_nonempty_ninety_percent_evidence(self):
        expected = {'io.syn443.decision.AdaptiveProbeBudget', 'io.syn443.decision.AdaptiveProbeBudget.Companion',
                    'io.syn443.decision.AdaptiveProbeBudget.Checkpoint', 'io.syn443.decision.AdaptiveProbeBudget.Entry'}
        self.assertEqual(expected, ADAPTIVE_BUDGET_CLASSES)
        self.assertFalse(expected & (IDENTITY_CLASSES | POLICY_CHECK_PLAN_CLASSES))
        def row(name, covered=9, missed=1, counter=True):
            vm = name.replace('io.syn443.decision.', 'io/syn443/decision/')
            for nested in ('Companion', 'Checkpoint', 'Entry'):
                vm = vm.replace('.' + nested, '$' + nested)
            body = f'<counter type="LINE" covered="{covered}" missed="{missed}"/>' if counter else ''
            return f'<class name="{vm}">{body}</class>'
        names = sorted(expected)
        rows = [row(name) for name in names]
        verify_classes(self.report('<report>' + ''.join(rows) + '</report>'), expected)
        for changed in names:
            for replacement in ('', row(changed, counter=False), row(changed, 8, 2), row(changed, 0, 0),
                                row(changed, -1, 10), row('foreign.' + changed)):
                contents = ''.join(replacement if name == changed else row(name) for name in names)
                with self.assertRaises(AssertionError):
                    verify_classes(self.report('<report>' + contents + '</report>'), expected)
        for contents in (rows + [rows[0]], [value.replace('</class>', '<counter type="LINE" covered="9" missed="1"/></class>') for value in rows]):
            with self.assertRaises(AssertionError):
                verify_classes(self.report('<report>' + ''.join(contents) + '</report>'), expected)
        tree = ast.parse((Path(__file__).resolve().parent / 'check_test_evidence.py').read_text(encoding='utf-8'))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Name) and node.func.id == 'verify_classes' and node.args and
                 isinstance(node.args[-1], ast.Name) and node.args[-1].id == 'ADAPTIVE_BUDGET_CLASSES']
        self.assertEqual(1, len(calls))
        self.assertIn('core/decision/build/reports/jacoco/test/jacocoTestReport.xml', ast.unparse(calls[0]))


    def test_owner_transition_roots_bind_actual_unique_outcomes_and_complete_source_names(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / 'tools/check_test_evidence.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        declaration, = [node for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'OWNER_TRANSITION_REQUIRED' for target in node.targets)]
        required = ast.literal_eval(declaration.value)
        self.assertEqual({'jvm', 'emulator'}, set(required))
        guard, = [node for node in tree.body if isinstance(node, ast.If) and
                  isinstance(node.test, ast.Compare) and any(isinstance(value, ast.Name) and value.id == 'OWNER_TRANSITION_REQUIRED'
                                                           for value in node.test.comparators)]
        unique, = [node for node in tree.body if isinstance(node, ast.Assert) and
                   isinstance(node.msg, ast.Constant) and node.msg.value == 'Duplicate actual test outcomes']
        uniqueness = compile(ast.fix_missing_locations(ast.Module(body=[unique], type_ignores=[])), '<owner-unique>', 'exec')
        admission = compile(ast.fix_missing_locations(ast.Module(body=guard.body[:3], type_ignores=[])), '<owner-admission>', 'exec')
        complete = compile(ast.fix_missing_locations(ast.Module(body=guard.body, type_ignores=[])), '<owner-source>', 'exec')
        for mode, floor, folder, owner, count in [
            ('jvm', 21, 'core/decision/src/test/kotlin/io/syn443/decision', 'io.syn443.decision.RouteHealthOwnerChangeTest', 3),
            ('emulator', 524, 'app/src/androidTest/kotlin/io/syn443/android', 'io.syn443.android.AdaptiveOwnerTransitionTest', 6),
        ]:
            path = root / folder / (owner.rsplit('.', 1)[1] + '.kt')
            original = path.read_text(encoding='utf-8')
            methods = re.findall(r'@Test\s+fun\s+(\w+)', original)
            expected = {(owner, name) for name in methods}
            self.assertEqual(count, len(methods)); self.assertEqual(count, len(set(methods)))
            self.assertEqual(expected, set(required[mode])); self.assertEqual(count, len(required[mode]))
            self.assertRegex(source, rf'(?:if|elif) mode=="{mode}":\n(?:    [^\n]*\n)*?    minimum={floor}\n')
            def check(identities, table=required):
                exec(admission, {'OWNER_TRANSITION_REQUIRED': table, 'mode': mode, 'identities': identities})
            check(expected)
            exec(uniqueness, {'identities': list(expected)})
            with self.assertRaises(AssertionError):
                exec(uniqueness, {'identities': list(expected) + [required[mode][0]]})
            for missing in expected:
                with self.assertRaises(AssertionError):
                    check(expected - {missing})
                with self.assertRaises(AssertionError):
                    check(expected - {missing} | {('foreign.' + missing[0], missing[1])})
            duplicated = dict(required); duplicated[mode] = required[mode] + [required[mode][0]]
            with self.assertRaises(AssertionError):
                check(expected, duplicated)
            with self.assertRaises(AssertionError):
                check(set())
            with tempfile.TemporaryDirectory() as directory:
                fixture_root = Path(directory)
                fixture = fixture_root / folder / path.name
                fixture.parent.mkdir(parents=True)
                fixture.write_text(original, encoding='utf-8')
                scope = {'OWNER_TRANSITION_REQUIRED': required, 'mode': mode, 'identities': expected, 'root': fixture_root, 're': re}
                exec(complete, scope.copy())
                dropped = re.sub(r'@Test\s+(?=fun\s+' + re.escape(methods[0]) + r'\b)', '', original, count=1)
                self.assertNotEqual(original, dropped)
                for changed in (original.replace(methods[0], 'renamedSyntheticOwnerCase'),
                                original.replace(methods[0], methods[1]), dropped,
                                original + '\n@Test fun unexpectedSyntheticOwnerCase() {}\n'):
                    fixture.write_text(changed, encoding='utf-8')
                    with self.assertRaises(AssertionError):
                        exec(complete, scope.copy())
        self.assertRegex(source, r'elif mode=="policy":\n(?:    [^\n]*\n)*?    minimum=31\n')
        self.assertRegex(source, r'elif mode=="identity":\n(?:    [^\n]*\n)*?    minimum=249\n')
        collector = ast.parse((root / 'tools/collect_public_emulator.py').read_text(encoding='utf-8'))
        declaration, = [node for node in collector.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'CLASS' for target in node.targets)]
        pattern = re.compile(ast.literal_eval(declaration.value.args[0]))
        self.assertIsNotNone(pattern.fullmatch('io.syn443.android.AdaptiveOwnerTransitionTest'))
        self.assertIsNone(pattern.fullmatch('foreign.AdaptiveOwnerTransitionTest'))

    def test_owner_health_memory_requires_real_complete_nonempty_ninety_percent_evidence(self):
        expected = {'io.syn443.decision.RouteHealthMemory'}
        self.assertEqual(expected, OWNER_HEALTH_CLASSES)
        self.assertFalse(expected & (IDENTITY_CLASSES | POLICY_CHECK_PLAN_CLASSES | ADAPTIVE_BUDGET_CLASSES))
        def row(name='io/syn443/decision/RouteHealthMemory', covered=9, missed=1, counter=True):
            body = f'<counter type="LINE" covered="{covered}" missed="{missed}"/>' if counter else ''
            return f'<class name="{name}">{body}</class>'
        valid = row()
        verify_classes(self.report('<report>' + valid + '</report>'), expected)
        invalid = ['', row(counter=False), row(covered=8, missed=2), row(covered=0, missed=0),
                   row(covered=-1, missed=10), row(name='foreign/RouteHealthMemory'), valid + valid,
                   valid.replace('</class>', '<counter type="LINE" covered="9" missed="1"/></class>')]
        for contents in invalid:
            with self.assertRaises(AssertionError):
                verify_classes(self.report('<report>' + contents + '</report>'), expected)
        tree = ast.parse((Path(__file__).resolve().parent / 'check_test_evidence.py').read_text(encoding='utf-8'))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Name) and node.func.id == 'verify_classes' and node.args and
                 isinstance(node.args[-1], ast.Name) and node.args[-1].id == 'OWNER_HEALTH_CLASSES']
        self.assertEqual(1, len(calls))
        self.assertIn('core/decision/build/reports/jacoco/test/jacocoTestReport.xml', ast.unparse(calls[0]))


    def test_negative_path_continuity_roots_require_unique_outcomes_and_exact_source_owners(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / 'tools/check_test_evidence.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        declaration, = [node for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'PATH_CONTINUITY_REQUIRED' for target in node.targets)]
        required = ast.literal_eval(declaration.value)
        self.assertEqual({'jvm', 'emulator'}, set(required))
        guard, = [node for node in tree.body if isinstance(node, ast.If) and
                  isinstance(node.test, ast.Compare) and any(isinstance(value, ast.Name) and value.id == 'PATH_CONTINUITY_REQUIRED'
                                                           for value in node.test.comparators)]
        unique, = [node for node in tree.body if isinstance(node, ast.Assert) and
                   isinstance(node.msg, ast.Constant) and node.msg.value == 'Duplicate actual test outcomes']
        uniqueness = compile(ast.fix_missing_locations(ast.Module(body=[unique], type_ignores=[])), '<continuity-unique>', 'exec')
        admission = compile(ast.fix_missing_locations(ast.Module(body=guard.body[:3], type_ignores=[])), '<continuity-admission>', 'exec')
        complete = compile(ast.fix_missing_locations(ast.Module(body=guard.body, type_ignores=[])), '<continuity-source>', 'exec')
        for mode, floor, folder, owner, count in [
            ('jvm', 21, 'core/decision/src/test/kotlin/io/syn443/decision', 'io.syn443.decision.RouteHealthContinuityTest', 3),
            ('emulator', 524, 'app/src/androidTest/kotlin/io/syn443/android', 'io.syn443.android.AdaptivePathContinuityTest', 6),
        ]:
            path = root / folder / (owner.rsplit('.', 1)[1] + '.kt')
            original = path.read_text(encoding='utf-8')
            methods = re.findall(r'@Test\s+fun\s+(\w+)', original)
            expected = {(owner, name) for name in methods}
            self.assertEqual(count, len(methods)); self.assertEqual(count, len(set(methods)))
            self.assertEqual(expected, set(required[mode])); self.assertEqual(count, len(required[mode]))
            self.assertRegex(source, rf'(?:if|elif) mode=="{mode}":\n(?:    [^\n]*\n)*?    minimum={floor}\n')
            def check(identities, table=required):
                exec(admission, {'PATH_CONTINUITY_REQUIRED': table, 'mode': mode, 'identities': identities})
            check(expected)
            exec(uniqueness, {'identities': list(expected)})
            with self.assertRaises(AssertionError):
                exec(uniqueness, {'identities': list(expected) + [required[mode][0]]})
            for missing in expected:
                with self.assertRaises(AssertionError):
                    check(expected - {missing})
                with self.assertRaises(AssertionError):
                    check(expected - {missing} | {('foreign.' + missing[0], missing[1])})
            duplicated = dict(required); duplicated[mode] = required[mode] + [required[mode][0]]
            with self.assertRaises(AssertionError):
                check(expected, duplicated)
            with self.assertRaises(AssertionError):
                check(set())
            with tempfile.TemporaryDirectory() as directory:
                fixture_root = Path(directory)
                fixture = fixture_root / folder / path.name
                fixture.parent.mkdir(parents=True)
                fixture.write_text(original, encoding='utf-8')
                scope = {'PATH_CONTINUITY_REQUIRED': required, 'mode': mode, 'identities': expected, 'root': fixture_root, 're': re}
                exec(complete, scope.copy())
                dropped = re.sub(r'@Test\s+(?=fun\s+' + re.escape(methods[0]) + r'\b)', '', original, count=1)
                self.assertNotEqual(original, dropped)
                for changed in (original.replace(methods[0], 'renamedSyntheticContinuityCase'),
                                original.replace(methods[0], methods[1]), dropped,
                                original + '\n@Test fun unexpectedSyntheticContinuityCase() {}\n'):
                    fixture.write_text(changed, encoding='utf-8')
                    with self.assertRaises(AssertionError):
                        exec(complete, scope.copy())
                fixture.unlink()
                with self.assertRaises(FileNotFoundError):
                    exec(complete, scope.copy())
        self.assertRegex(source, r'elif mode=="recovery":\n(?:    [^\n]*\n)*?    minimum=15\n')
        self.assertRegex(source, r'elif mode=="policy":\n(?:    [^\n]*\n)*?    minimum=31\n')
        self.assertRegex(source, r'elif mode=="identity":\n(?:    [^\n]*\n)*?    minimum=249\n')
        collector = ast.parse((root / 'tools/collect_public_emulator.py').read_text(encoding='utf-8'))
        declaration, = [node for node in collector.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'CLASS' for target in node.targets)]
        pattern = re.compile(ast.literal_eval(declaration.value.args[0]))
        self.assertIsNotNone(pattern.fullmatch('io.syn443.android.AdaptivePathContinuityTest'))
        self.assertIsNone(pattern.fullmatch('foreign.AdaptivePathContinuityTest'))

    def test_support_bundle_outcomes_are_source_bound_and_never_satisfied_by_missing_roots(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / 'tools/check_test_evidence.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        names = {'SUPPORT_BUNDLE_REQUIRED', 'SUPPORT_BUNDLE_EXTERNAL_REQUIRED'}
        assignments = [node for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in names for target in node.targets)]
        self.assertEqual(2, len(assignments))
        values = {node.targets[0].id: ast.literal_eval(node.value) for node in assignments}
        required = values['SUPPORT_BUNDLE_REQUIRED']
        self.assertEqual([8,11,10,7,6,2,1,2], [len(methods) for methods in required.values()])
        self.assertTrue(any('directLogResponseAndEveryArchivedEntryOmitPrivateTransportAndCrashText' in methods
                            for methods in required.values()))
        all_cases = {(owner, name) for owner, methods in required.items() for name in methods}
        all_cases.add(values['SUPPORT_BUNDLE_EXTERNAL_REQUIRED'])
        self.assertEqual(48, len(all_cases))
        block, = [node for node in tree.body if isinstance(node, ast.If) and
                  any(isinstance(child, ast.Name) and child.id == 'SUPPORT_BUNDLE_REQUIRED' for child in ast.walk(node))]
        self.assertIsInstance(block, ast.If)
        complete = compile(ast.Module(body=assignments+[block], type_ignores=[]), '<support-gate>', 'exec')
        scope = {'root':root, 'mode':'emulator', 'identities':list(all_cases), 're':re}
        exec(complete, scope.copy())
        for missing in all_cases:
            with self.assertRaises(AssertionError):
                exec(complete, {**scope, 'identities':list(all_cases-{missing})})
        self.assertRegex(source, r'elif mode=="emulator":\n(?:    [^\n]*\n)*?    minimum=524\n')

    def test_packaged_proxy_chain_requires_both_android_outcomes(self):
        root = Path(__file__).resolve().parent.parent
        tree = ast.parse((root / 'tools/check_test_evidence.py').read_text(encoding='utf-8'))
        name = 'PACKAGED_CHAIN_REQUIRED'
        declaration, = [node for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(t, ast.Name) and t.id == name for t in node.targets)]
        block, = [node for node in tree.body if isinstance(node, ast.If) and
                  any(isinstance(t, ast.Name) and t.id == name for t in ast.walk(node))]
        cases = ast.literal_eval(declaration.value)
        cases_from_source = re.findall(r'@Test\s+fun\s+(\w+)', (root /
            'app/src/androidTest/kotlin/io/syn443/android/PackagedProxyChainTest.kt').read_text(encoding='utf-8'))
        self.assertEqual(cases, {('io.syn443.android.PackagedProxyChainTest', method) for method in cases_from_source})
        self.assertEqual(len(cases), 5)
        gate = compile(ast.Module(body=[declaration, block], type_ignores=[]), '<packaged-chain>', 'exec')
        projection = ('io.syn443.android.RouteSnapshotTest', 'currentFailedProbeOnlyShowsKnownCauseForItsStage')
        display = ('io.syn443.android.RouteFailureLabelTest', 'routeScreenExplainsEachFailureAndClearsItAfterRecovery')
        renewal = ('io.syn443.android.LoginControllerTest', 'foregroundPollRenewsExpiredCommittedPolicyWithoutStartingVpnOrChangingIdentity')
        outcomes = cases | {projection, display, renewal}
        exec(gate, {'mode':'emulator', 'identities':outcomes})
        for case in outcomes:
            with self.assertRaises(AssertionError):
                exec(gate, {'mode':'emulator', 'identities':outcomes - {case} | {('other', case[1])}})

    def test_netbird_report_roots_require_each_actual_outcome_and_exact_sources(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / 'tools/check_test_evidence.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        declaration, = [node for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'OVERLAY_REPORT_REQUIRED' for target in node.targets)]
        required = ast.literal_eval(declaration.value)
        expected = {(owner, name) for owner, names in required.items() for name in names}
        self.assertEqual(8, len(expected))
        self.assertEqual({'io.syn443.android.NetBirdReportTest': 5, 'io.syn443.android.NetBirdPagingUiTest': 2,
                          'io.syn443.android.NetBirdViewBridgeTest': 1}, {owner: len(names) for owner, names in required.items()})
        guard, = [node for node in tree.body if isinstance(node, ast.If) and node.lineno > declaration.lineno and
                  any(isinstance(child, ast.Name) and child.id == 'OVERLAY_REPORT_REQUIRED' for child in ast.walk(node))]
        compiled = compile(ast.fix_missing_locations(ast.Module(body=guard.body, type_ignores=[])), '<overlay-report-source-gate>', 'exec')
        scope = {'OVERLAY_REPORT_REQUIRED': required, 'mode': 'emulator', 'identities': expected, 'root': root, 're': re}
        exec(compiled, scope.copy())
        for missing in expected:
            with self.assertRaises(AssertionError):
                exec(compiled, dict(scope, identities=expected - {missing}))
            with self.assertRaises(AssertionError):
                exec(compiled, dict(scope, identities=expected - {missing} | {('foreign.' + missing[0], missing[1])}))
        with tempfile.TemporaryDirectory() as temporary:
            fixture_root = Path(temporary)
            folder = Path('app/src/androidTest/kotlin/io/syn443/android')
            for owner in required:
                path = folder / (owner.rsplit('.', 1)[1] + '.kt')
                destination = fixture_root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text((root / path).read_text(encoding='utf-8'), encoding='utf-8')
            scope['root'] = fixture_root
            exec(compiled, scope.copy())
            for owner, names in required.items():
                path = fixture_root / folder / (owner.rsplit('.', 1)[1] + '.kt')
                original = path.read_text(encoding='utf-8')
                name = sorted(names)[0]
                dropped = re.sub(r'@Test\s+(?=fun\s+' + re.escape(name) + r'\b)', '', original, count=1)
                self.assertNotEqual(original, dropped)
                for altered in (original.replace(name, 'substitutedReportRoot'), dropped,
                                original + '\n@Test fun extraReportRoot() {}\n'):
                    path.write_text(altered, encoding='utf-8')
                    with self.assertRaises(AssertionError):
                        exec(compiled, scope.copy())
                path.write_text(original, encoding='utf-8')
        self.assertRegex(source, r'elif mode=="emulator":\n(?:    [^\n]*\n)*?    minimum=524\n')
