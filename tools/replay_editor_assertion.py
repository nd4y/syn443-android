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
for name in ("debug/app-debug.apk","androidTest/debug/app-debug-androidTest.apk"):
    subprocess.run(adb+["install","-r","-t",str(root/"app/build/outputs/apk"/name)],check=True,stdout=subprocess.DEVNULL)
method="splittingFullPagePreservesUnicodeAndReviewUntilContentChanges"
out=subprocess.check_output(adb+["shell","am","instrument","-w","-r","-e","class","io.syn443.android.AdminEditorUiTest#"+method,
    "io.syn443.android.test/io.syn443.android.EnrollmentDriver"],timeout=120).decode("utf-8","replace")
assert len(out)<1024*1024
if "OK (1 test)" in out:
    print("The isolated original case passed.")
else:
    assert re.search(r"(?m)^INSTRUMENTATION_STATUS_CODE: -(1|2)\s*$",out)
    lines=re.findall(r"(?m)^\s*at io\.syn443\.android\.AdminEditorUiTest(?:\$[\w$]+)?\.[\w$<>]+\(AdminEditorUiTest\.kt:([1-9]\d{0,3})\)\s*$",out)
    assert lines
    print("Original synthetic test failed at test source line(s):",",".join(dict.fromkeys(lines)))
    for marker in ("Failed to assert", "No node found", "not enabled", "EditableText", "editor-page-error", "editor-split-page", "editor-publish", "editor-save-local"):
        if marker in out: print("Static diagnostic marker:",marker)
