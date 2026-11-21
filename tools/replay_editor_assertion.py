"""Replay the broken synthetic case without publishing exception messages or device output."""
import json
import os
from pathlib import Path
import re
import subprocess

from run_packaged_instrumentation import verify_apks

root = Path(__file__).resolve().parents[1]
manifest = json.loads((Path(os.environ["RUNNER_TEMP"])/"build-manifest.json").read_bytes())
verify_apks(root, manifest, "d8d80829e98d9eff92b48a3771a2ae7c1163faec", 44932680946, 1)
adb = ["adb", "-e"]
assert re.fullmatch(rb"emulator-\d+",subprocess.check_output(adb+["get-serialno"]).strip())
assert subprocess.check_output(adb+["emu","avd","name"]).splitlines()==[b"syn443-ci",b"OK"]
setup=(root/"tools/run_emulator_tests.sh").read_text()
setup=setup[setup.index("adb -e shell getprop ro.build.version.sdk\n"):setup.index("result=0\n# Capture the actual failing assertion")]
subprocess.run(["bash","-euo","pipefail","-c",setup],check=True)
subprocess.run(adb+["install","-r",str(root/"app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")],check=True)
method="splittingFullPagePreservesUnicodeAndReviewUntilContentChanges"
from run_packaged_instrumentation import parse_run
package="io.syn443.android"
klass=package+".AdminEditorUiTest"
for label,filters in [("single",["-e","class",klass+"#"+method]),("class",["-e","class",klass]),("suite",[])]:
    out=subprocess.check_output(adb+["shell","am","instrument","-w","-r","-e","listener",
        package+".NetBirdTestProgress,"+package+".DiagnosticBundleTestProgress",*filters,
        package+".test/"+package+".EnrollmentDriver"],timeout=1200).decode("utf-8","replace")
    assert len(out)<8*1024*1024
    report=parse_run(out)
    case,=[c for c in report.iter("testcase") if c.get("classname")==klass and c.get("name")==method]
    if not list(case):
        print("Confirmed target passed:",label,flush=True)
        continue
    failures=[m.group(1) for m in re.finditer(r"(?ms)^INSTRUMENTATION_STATUS: stack=(.*?)(?=^INSTRUMENTATION_|\\Z)",out) if "AdminEditorUiTest."+method in m.group(1)]
    assert failures
    stack=failures[0]
    for name,pattern in {
        "display":r"assertIsDisplayed|is not displayed|not displayed",
        "no_node":r"did not find any node|found 0 nodes|No node found|could not find any|found no nodes|Exactly '1' node",
        "many_nodes":r"found [2-9] nodes",
        "text":r"assertTextEquals|hasText",
        "equals":r"expected:<|Assert\\.assertEquals",
        "focus":r"request focus|obtain focus",
        "unmerged_tree":r"unmerged tree",
        "assertion":r"AssertionError",
    }.items():
        if re.search(pattern,stack,re.IGNORECASE):print("Fixed diagnostic:",label,name)
    for marker in ("editor-page-input","editor-page-error","editor-content"):
        print("Known selector:",label,marker,marker in stack)
    for l in stack.splitlines():
        if "AdminEditorUiTest.kt:" in l:
            for loc in re.findall(r"AdminEditorUiTest\\.kt:([1-9]\\d{0,3})",l):print("Source:",label,loc)
    for xy in re.findall(r"Rect\\((-?[0-9.]+), (-?[0-9.]+), (-?[0-9.]+), (-?[0-9.]+)\\)",stack)[:4]:
        print("Diagnostic rectangle:",label,*[int(float(n)) for n in xy])
    break
