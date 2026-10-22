from pathlib import Path
import sys,xml.etree.ElementTree as ET
root=Path(__file__).resolve().parent.parent
mode=sys.argv[1]
if mode=="jvm":
    paths=list((root/"core/decision/build/test-results/test").glob("TEST-*.xml"))
    minimum=8
elif mode=="emulator":
    paths=list((root/"app/build/outputs/androidTest-results").rglob("TEST-*.xml"))
    minimum=20
elif mode=="host":
    paths=list((root/"core/host-lifecycle/build/test-results/test").glob("TEST-*.xml"))
    minimum=11
elif mode=="recovery":
    paths=list((root/"core/recovery/build/test-results/test").glob("TEST-*.xml"))
    minimum=7
else: raise SystemExit("unknown evidence type")
assert paths,"No JUnit XML evidence produced"
cases=[]
for path in paths:
    doc=ET.parse(path).getroot()
    for case in doc.iter("testcase"):
        if not case.attrib.get("classname","").startswith("io.syn443."): continue
        assert not any(case.find(k) is not None for k in ("skipped","failure","error")),(path,case.attrib)
        cases.append(case)
assert len(cases)>=minimum,(mode,len(cases),minimum)
if mode=="emulator":
    required={"selectionAndStaleNetworkResult", "explicitStopRejectsLateCompletion", "darkThemeByDefault",
              "workerRunsInSeparateProcessAndStops", "wedgedWorkerCanBeTerminatedAndRebound",
              "foreignSessionCannotTerminateHost", "realTunTrafficAndExplicitStop",
              "nativeCrashRecoversButNewerStopWins", "fullyFrozenNativeProcessIsKilledOutsideItsControlLoop",
              "closingActivityDoesNotStopVpn", "lostNetworkCannotRemainSelectedFromAStaleSystemSnapshot",
              "uiProcessDeathKeepsRealTunTraffic", "controllerDeathRetiresFrozenNativeAndPreservesIntent",
              "stopDuringForegroundServiceStartupNeverCrashesController", "twoHopTunTrafficCrossesBothProxies",
              "ingressFailureRecoversWithoutNativeRestart", "egressFailureRecoversWithoutNativeRestart",
              "controllerRestartBudgetSurvivesOwnerDeath", "notificationStopRetiresAFullyFrozenNativeHost",
              "unavailableOptionalOverlayDoesNotBlockVpnOrLeakPrivateRoute"}
    assert required <= {case.attrib.get("name") for case in cases}, "Required UI/process cases missing"
print(f"{mode}: {len(cases)} SYN443 test cases passed, zero skipped/failures/errors")

