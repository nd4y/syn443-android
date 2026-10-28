import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name('print_emulator_reports.py').resolve()


class FailureDiagnosticsTest(unittest.TestCase):
    def run_report(self, large=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / 'app/build/outputs/androidTest-results/synthetic'
            logs.mkdir(parents=True)
            (logs / 'TEST-synthetic.xml').write_text(
                '<testsuite><testcase classname="Synthetic" name="actualFailure">'
                '<failure/></testcase></testsuite>', encoding='utf-8')
            for i in range(12):
                (logs / f'a-passing-{i:02}.txt').write_text('unrelated passing output', encoding='utf-8')
            content = ('discarded prefix ' * 3000 if large else '') + '\x00actual failing trace at tail'
            (logs / 'z-Synthetic-actualFailure.txt').write_text(content, encoding='utf-8')
            return subprocess.check_output([sys.executable, str(SCRIPT)], cwd=root, text=True, encoding='utf-8', timeout=10)

    def test_failed_case_log_survives_alphabetical_preview_cutoff(self):
        output = self.run_report()
        self.assertIn('FAILED CASE Synthetic.actualFailure', output)
        self.assertIn('actual failing trace at tail', output)

    def test_failed_log_tail_is_bounded_and_control_characters_removed(self):
        output = self.run_report(large=True)
        self.assertIn('actual failing trace at tail', output)
        self.assertNotIn('\x00', output)
        self.assertLess(len(output.encode('utf-8')), 20000)


if __name__ == '__main__':
    unittest.main()
