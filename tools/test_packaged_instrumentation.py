import copy
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
import json

from build_manifest import APKS, apk_record
from run_packaged_instrumentation import parse_run, verify_apks


def event(name, position, code):
    fields = {'class': 'io.syn443.android.ExampleTest', 'test': name, 'current': position,
              'numtests': 2, 'id': 'AndroidJUnitRunner'}
    return ''.join(f'INSTRUMENTATION_STATUS: {key}={value}\n' for key, value in fields.items()) + f'INSTRUMENTATION_STATUS_CODE: {code}\n'


START = event('firstCase', 1, 1)
PASS = event('firstCase', 1, 0)
SECOND = event('secondCase', 2, 1)
END = 'INSTRUMENTATION_CODE: -1\n'


class PackagedInstrumentationTest(unittest.TestCase):
    def test_kotlin_lambda_reports_only_the_current_source_line(self):
        for function in ("ExampleTest.secondCase$lambda$12", "ExampleTest.secondCase$lambda-12",
                         "ExampleTest$secondCase$2.invoke"):
            stack = ("INSTRUMENTATION_STATUS: stack=private message\n"
                     "    at io.syn443.android.ExampleTest.firstCase$lambda$12(ExampleTest.kt:72)\n"
                     f"    at io.syn443.android.{function}(ExampleTest.kt:81)\n"
                     "    at io.syn443.android.ExampleTest.secondCase(ExampleTest.kt:90)\n")
            failure = event("secondCase", 2, -2).replace("INSTRUMENTATION_STATUS_CODE:", stack + "INSTRUMENTATION_STATUS_CODE:")
            displayed = io.StringIO()
            with redirect_stdout(displayed):
                parse_run(START + PASS + SECOND + failure + END)
            self.assertIn("Test source line: 81", displayed.getvalue())
            for private in ("private message", "lambda", "line: 72", "line: 90"):
                self.assertNotIn(private, displayed.getvalue())

    def test_failure_location_contains_only_the_current_public_test_line(self):
        stack = ('INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: private fixture message\n'
                 '    at io.syn443.android.AnotherTest.other(AnotherTest.kt:92)\n'
                 '    at io.syn443.android.ExampleTest.firstCase(ExampleTest.kt:93)\n'
                 '    at io.syn443.android.ExampleTest.secondCase(Other.kt:94)\n'
                 '    at io.syn443.android.ExampleTest.secondCase(ExampleTest.kt:42)\n')
        log = io.StringIO()
        with redirect_stdout(log):
            suite = parse_run(START + PASS + SECOND + stack + event('secondCase', 2, -2) + END)
        self.assertEqual(log.getvalue().splitlines(), ['failure: io.syn443.android.ExampleTest.secondCase', 'Test source line: 42'])
        self.assertEqual(suite[1][0].get('message'), 'AndroidJUnitRunner status -2')

    def test_keeps_all_real_statuses(self):
        for code, expected in [(0, None), (-1, 'error'), (-2, 'failure'), (-3, 'skipped'), (-4, 'skipped')]:
            with self.subTest(code=code):
                suite = parse_run(START + PASS + SECOND + event('secondCase', 2, code) + END)
                self.assertEqual([case.get('name') for case in suite], ['firstCase', 'secondCase'])
                self.assertEqual([node.tag for node in suite[1]], [expected] if expected else [])

    def test_incomplete_reordered_duplicate_and_foreign_results_fail(self):
        last = event('secondCase', 2, 0)
        for output in [END, START + END, PASS + SECOND + last + END, START + PASS + END,
                       START + PASS + SECOND + last, START + PASS + SECOND + last + END + END,
                       START + PASS + SECOND + event('otherCase', 2, 0) + END,
                       START + PASS + event('firstCase', 2, 1) + event('firstCase', 2, 0) + END,
                       START + PASS + SECOND + last + 'INSTRUMENTATION_RESULT: shortMsg=Process crashed.\n' + END,
                       START.replace('numtests=2', 'numtests=1') + PASS + SECOND + last + END,
                       START.replace('io.syn443.', 'other.') + PASS + SECOND + last + END]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                parse_run(output)

    def test_artifacts_must_match_both_files_and_the_producing_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            records = {}
            for path, package in APKS:
                apk = root / path
                apk.parent.mkdir(parents=True)
                apk.write_bytes(package.encode())
                metadata = {'applicationId': package, 'elements': [
                    {'outputFile': path.name, 'versionCode': 1, 'versionName': 'test'}]}
                apk.with_name('output-metadata.json').write_text(json.dumps(metadata))
                records[path.as_posix()] = apk_record(root, path, package)
            manifest = dict(schemaVersion=1, sourceCommit='a'*40, actionsRun=12, actionsAttempt=1, artifacts=records)
            verify_apks(root, manifest, 'a'*40, 12, 2)
            for field, value in [('sourceCommit', 'b'*40), ('actionsRun', 11), ('actionsAttempt', 3)]:
                wrong = dict(manifest, **{field: value})
                with self.subTest(field=field), self.assertRaises(ValueError):
                    verify_apks(root, wrong, 'a'*40, 12, 2)
            for path, _ in APKS:
                wrong = copy.deepcopy(manifest)
                wrong['artifacts'][path.as_posix()]['sha256'] = '0'*64
                with self.subTest(path=path), self.assertRaises(ValueError):
                    verify_apks(root, wrong, 'a'*40, 12, 2)
