"""Replay the broken synthetic case without publishing exception messages or device output."""
import json
import os
from pathlib import Path
import re
import subprocess

from run_packaged_instrumentation import verify_apks

root = Path(__file__).resolve().parents[1]
manifest = json.loads((Path(os.environ["RUNNER_TEMP"])/"build-manifest.json").read_bytes())
verify_apks(root, manifest, "adabc548cae353d93bec6e8b07a3ca97fb31a9d3", 44918106866, 1)
adb = ["adb", "-e"]
assert re.fullmatch(rb"emulator-\d+",subprocess.check_output(adb+["get-serialno"]).strip())
assert subprocess.check_output(adb+["emu","avd","name"]).splitlines()==[b"syn443-ci",b"OK"]
setup=(root/"tools/run_emulator_tests.sh").read_text()
setup=setup[setup.index("adb -e shell getprop ro.build.version.sdk\n"):setup.index("result=0\n# Capture the actual failing assertion")]
subprocess.run(["bash","-euo","pipefail","-c",setup],check=True)
subprocess.run(adb+["install","-r",str(root/"app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")],check=True)
method="splittingFullPagePreservesUnicodeAndReviewUntilContentChanges"
out=subprocess.check_output(adb+["shell","am","instrument","-w","-r","-e","listener",
    "io.syn443.android.NetBirdTestProgress,io.syn443.android.DiagnosticBundleTestProgress",
    "io.syn443.android.test/io.syn443.android.EnrollmentDriver"],timeout=1200).decode("utf-8","replace")
assert len(out)<8*1024*1024 and method in out
if re.search(r"OK \([1-9]\d+ tests\)",out):
    print("The original complete packaged instrumentation suite passed.")
else:
    assert re.search(r"(?m)^INSTRUMENTATION_STATUS_CODE: -(1|2)\s*$",out)
    lines=re.findall(r"(?m)^\s*at io\.syn443\.android\.AdminEditorUiTest(?:\$[\w$]+)?\.[\w$<>]+\(AdminEditorUiTest\.kt:([1-9]\d{0,3})\)\s*$",out)
    assert lines
    print("Original synthetic test failed at test source line(s):",",".join(dict.fromkeys(lines)))
    for marker in ("Failed to assert", "No node found", "not enabled", "EditableText", "editor-page-error", "editor-split-page", "editor-publish", "editor-save-local"):
        if marker in out: print("Static diagnostic marker:",marker)
