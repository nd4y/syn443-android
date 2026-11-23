import os
import tempfile
import unittest
from unittest.mock import patch

from ci_input_artifacts import PACKAGES, fetch, main, validate_artifact
from protected_upgrade_inputs import producer_artifact


class ArtifactInputsTest(unittest.TestCase):
    source = 'a' * 40

    def artifact(self, number, created):
        return dict(id=number, name=PACKAGES, expired=False, created_at=created,
                    workflow_run=dict(id=17, head_sha=self.source), digest='sha256:' + 'b' * 64)

    def test_producer_id_cannot_be_replaced_by_another_attempt_or_run(self):
        item = self.artifact(19, '2025-01-01T01:01:00Z')
        validate_artifact(item, 19, PACKAGES, 17, self.source)
        for change in (dict(id=20), dict(expired=True), dict(name='other'),
                       dict(workflow_run={'id':16, 'head_sha':self.source}),
                       dict(workflow_run={'id':17, 'head_sha':'c' * 40}), dict(digest='missing')):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_artifact({**item, **change}, 19, PACKAGES, 17, self.source)
        with patch.dict(os.environ, {'APK_ARTIFACT_ID':''}), patch('ci_input_artifacts.api') as lookup:
            with self.assertRaises(ValueError):
                fetch(PACKAGES, 'APK_ARTIFACT_ID', [], 1)
            lookup.assert_not_called()

    def test_historical_selection_requires_a_unique_successful_producer_window(self):
        previous = self.artifact(98, '2025-01-01T01:01:00Z')
        current = self.artifact(67, '2025-01-01T02:01:00Z')
        build = dict(started_at='2025-01-01T02:00:00Z', completed_at='2025-01-01T02:05:00Z')
        run = dict(id=17, head_sha=self.source)
        self.assertEqual(producer_artifact([previous,current], PACKAGES, run, build), current)
        for items in ([previous], [previous,current,{**current,'id':101}]):
            with self.assertRaises(ValueError):
                producer_artifact(items, PACKAGES, run, build)

    def test_emulator_handoff_has_both_signed_apks_metadata_and_the_upgrade_receipt(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'GITHUB_ACTIONS':'true','RUNNER_TEMP':tmp}), patch('ci_input_artifacts.fetch') as read:
            main('emulator')
            seen={call.args[1]:{member for member,_,_ in call.args[2]} for call in read.call_args_list}
            self.assertEqual(seen, {
                'MANIFEST_ARTIFACT_ID':{'build-manifest.json'},
                'APK_ARTIFACT_ID':{'debug/app-debug.apk','androidTest/debug/app-debug-androidTest.apk',
                                   'debug/output-metadata.json','androidTest/debug/output-metadata.json'},
                'UPGRADE_ARTIFACT_ID':{'new-debug.apk','upgrade.json'},
            })
