#!/usr/bin/env bash
set -euo pipefail

case "$(adb -e shell getprop ro.hardware | tr -d '\r')" in
  ranchu|goldfish) ;;
  *) echo 'Refusing tests outside the disposable emulator'; exit 1 ;;
esac

# Network-dependent enrollment cases require a real, non-metered Wi-Fi underlay.
# Keep the disposable AVD on that transport across activity and process tests.
test "${GITHUB_ACTIONS:-}" = true
test "${SYN443_CI_AVD:-}" = syn443-ci
test "$(adb -e emu avd name | tr -d '\r')" = $'syn443-ci\nOK'
adb -e shell svc data disable
adb -e shell cmd connectivity airplane-mode enable
test "$(adb -e shell cmd connectivity airplane-mode | tr -d '\r')" = enabled
adb -e shell svc wifi enable

instrumentation_display=''
restore_instrumentation_display() {
  if [ -n "$instrumentation_display" ]; then
    if [ "$instrumentation_display" = null ]; then
      adb -e shell settings delete global stay_on_while_plugged_in
    else
      adb -e shell settings put global stay_on_while_plugged_in "$instrumentation_display"
    fi
    instrumentation_display=''
  fi
}

publish_support_bundle_report() {
  local source="$RUNNER_TEMP/syn443-support-protocol-result.xml"
  local target='app/build/outputs/androidTest-results/external/TEST-support-bundle.xml'
  if [ -f "$source" ]; then
    mkdir -p app/build/outputs/androidTest-results/external
    if [ -e "$target" ]; then cmp -s -- "$source" "$target"
    else cp -- "$source" "$target"; fi
  fi
}

print_netbird_test_progress() {
  # Only fixed synthetic source identities/phases may reach the public log.
  # These lifecycle markers cannot replace the actual JUnit outcome evidence.
  local report='io\.syn443\.android\.NetBirdReportTest#(unknownConnectionFieldsNeverBecomeDisconnectedZeroPeersOrVless|knownAndLegacySnapshotsRetainExplicitConnectionAndProxyLabels|pagedPeerCountsDistinguishDisplayedRetainedAndOmittedRows|completedPartialCancelledAndUnknownCoverageNeverClaimAllChecked|malformedPagesFieldsUtf8AndOverLimitPayloadsFailBounded)'
  local paging='io\.syn443\.android\.NetBirdPagingUiTest#(onlyCurrentViewResponseCompletesPendingPageWithoutExtraCommands|peerAndDiagnosticPagingControlsRespectBoundsAndOutstandingRequests)'
  local bridge='io\.syn443\.android\.NetBirdViewBridgeTest#nativeViewBridgeExistsAndInactiveQueryStartsNoEngineOrProbe'
  printf '\n=== Synthetic NetBird test progress (diagnostics only) ===\n'
  timeout 10s adb -e logcat -d -v raw -s Syn443TestProgress:I '*:S' \
    | tr -d '\r' \
    | grep -E -- "^SYN443_TEST_PROGRESS ((START|FINISH|FAIL) ($report|$paging|$bridge)|PHASE $bridge (construct|lookup|view_peers|diagnostics|invalid|close))$" \
    | tail -64 || true
}

print_bundle_test_progress() {
  # Fixed synthetic identities only; lifecycle markers are not JUnit PASS evidence.
  local archive='io\.syn443\.android\.DiagnosticArchiveTest#(storedArchiveHasExactNamesCrcManifestHashesAndOwnedInputBytes|missingAndErroredComponentsRemainExplicitAndIncomplete|duplicateAndTooManyComponentsFailBeforeArchiveCreation|componentByteLimitOmitsWholePayloadWithoutTruncatingJson|aggregateLimitIsDeterministicAndKeepsOtherComponents|allAvailableComponentsAreCompleteOnlyWithNoneReasons|truncatedAndProjectionOnlyComponentsNeverClaimComplete|namesSizesAndDiagnosticsCannotEscapeOrEchoInputs)'
  local projection='io\.syn443\.android\.DiagnosticProjectionTest#(knownSnapshotsProjectOnlyFixedPublicFields|nestedSecretsLabelsTargetsAndFreeTextNeverReachComponents|incorrectBooleanAndNumericTypesStayUnknownRatherThanFalseOrZero|eventsKeepOnlyLast64OrderedAllowlistedRecords|routeAndCheckCollectionsExposeCountsWithoutIdentifiers|overlayProjectionPreservesTypedConnectionsAndKnownModesOnly|crashesReprojectOnlyClosedKindsTimesAndStatuses|unavailableSourcesAndInvalidVersionsRemainExplicitAndBounded)'
  local controller='io\.syn443\.android\.SupportBundleControllerTest#(encryptedArchiveHasOwnedMetadataAndWholeVerifiedChunkReadback|cancelledBlockedCollectorRetainsActualSlotAndRejectsLatePublication|grantAndReadyExpiryAndBackwardsClockNeverFreshenAnOldArtifact|grantsAreObjectBoundAndRepeatedReadsNeverReplayCollection|malformedIdsOffsetsAndUnknownJobsNeverReadOrCreateStorage|corruptedTruncatedAndOversizedCiphertextFailBeforeAnyPlaintextChunk|recreatedProcessOwnerCannotReuseAKeyGrantOrOldEncryptedArtifact|foreignFilesAndSymlinkFilesOrDirectoriesArePreservedAndFailClosed|blockedReadKeepsItsSingleSlotAndCancelledVerifiedBytesCannotPublish|failedSourcesAtomicWriteFailuresAndOverLimitComponentsNeverAutoRetry)'
  local sources='io\.syn443\.android\.SupportBundleSourcesTest#(passiveCaptureLeavesItsSourcesUnchangedAndRunsEachSupplierOnce|changedContextRejectsCapturedHealthChecksAndOverlayWithoutRepeatingWork|missingOrFailingSourcesBecomePartialWithoutRawExceptionText|stateFileReadRejectsOversizeDepthUtf8TrailingAndSymlinkWithoutModifyingFiles)'
  local ui='io\.syn443\.android\.DiagnosticBundleUiTest#(idlePresentationDoesNotCollectOrExportUntilAnExplicitClick|readyPartialArchiveShowsCompositionSizeAndSeparateExportAction|busyCollectionCannotOverlapOrExportAndCancellationIsExplicit|routeCancellationRemainsResponsiveWhilePollingAndRejectsLateReadyReply|malformedUnknownOrInconsistentManifestNeverEnablesExportOrEchoesValues|delayedDocumentResultAfterRestorationUsesReviewedArtifactAndCancelledPickerNeverReplaysCollection)'
  local policy='io\.syn443\.android\.PassivePolicyDiagnosticTest#(historicalExportKeepsRealBatchWithoutInventingActivationOrChangingAuthority|expiredRetiredAndBackwardHistoryNeverBecomesCurrentOrGetsANewSampleTime)'
  local client='io\.syn443\.android\.SupportBundleClientTest#blockedCancellationAndDocumentWriteFailureRetainExportOwnershipUntilActualExit'
  printf '\n=== Synthetic support bundle test progress (diagnostics only) ===\n'
  timeout 10s adb -e logcat -d -v raw -s Syn443BundleProgress:I '*:S' \
    | tr -d '\r' \
    | grep -E -- "^SYN443_BUNDLE_PROGRESS (START|FINISH|FAIL) ($archive|$projection|$controller|$sources|$ui|$policy|$client)$" \
    | tail -64 || true
}

collect_diagnostics() {
  result=$?
  trap - EXIT
  publish_support_bundle_report || true
  print_netbird_test_progress || true
  print_bundle_test_progress || true
  restore_instrumentation_display || true
  python3 tools/print_emulator_reports.py || true
  printf '\n=== Disposable runner memory/disk ===\n'
  free -m || true
  df -h / || true
  sudo dmesg | tail -200 | sed -n '/[Oo]ut of memory\|[Kk]illed process\|oom-kill\|segfault\|general protection\|qemu-system/p' || true
  ps -C qemu-system-x86_64 -o pid=,stat=,rss=,etimes=,comm= || true
  if [ -f "$RUNNER_TEMP/syn443-preserved-emulator.log" ]; then tail -40 "$RUNNER_TEMP/syn443-preserved-emulator.log"; fi
  printf '\n=== Android crash buffer (diagnostics only) ===\n'
  timeout 20s adb -e logcat -b crash -d || true
  printf '\n=== Android service state (diagnostics only) ===\n'
  timeout 10s adb -e shell service list || true
  exit "$result"
}
trap collect_diagnostics EXIT

adb -e shell getprop ro.build.version.sdk
python3 tools/check_emulator_heap.py
python3 tools/prepare_emulator_art.py
adb -e shell df -h /data
# Disposable emulator only: prove the app stays dark with light system settings.
adb -e shell cmd uimode night no
test -f app/build/outputs/apk/debug/app-debug.apk
test -f app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
# Compose needs a visible root for UI assertions. Keep this fixture's screen
# awake only for instrumentation; the later lifecycle scenarios own their
# display, lock, reboot and idle conditions separately.
screen_original="$(adb -e shell settings get global stay_on_while_plugged_in | tr -d '\r')"
[[ "$screen_original" = null || "$screen_original" =~ ^[0-9]+$ ]]
instrumentation_display="$screen_original"
adb -e shell settings put global stay_on_while_plugged_in 7
adb -e shell input keyevent KEYCODE_WAKEUP
adb -e shell wm dismiss-keyguard
# Exercise real denial before any other app scenario can leave a system dialog
# in the AVD. Use a fresh install again for passive capture and instrumentation.
adb -e install -r app/build/outputs/apk/debug/app-debug.apk
adb -e install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
python3 tools/run_invitation_camera_permission.py
adb -e uninstall io.syn443.android.test
adb -e uninstall io.syn443.android
adb -e install -r app/build/outputs/apk/debug/app-debug.apk
# Exercise the new passive Provider/CLI path before ordinary status or login
# can initialize the fresh app. This never runs on a physical device.
python3 tools/run_support_bundle_smoke.py
# Permission changes happen before the instrumentation process exists.
adb -e shell appops set io.syn443.android ACTIVATE_VPN allow
if [ "$(adb -e shell getprop ro.build.version.sdk | tr -d '\r')" -ge 33 ]; then
  adb -e shell pm grant io.syn443.android android.permission.POST_NOTIFICATIONS
fi
result=0
# Capture the actual failing assertion before long native fault scenarios. A
# failed instrumentation run cannot satisfy the mandatory evidence gate anyway.
# Bound the owning host invocation, without pretending interruption stops JNI.
# A deadline fails this harness; it never proceeds to the external scenarios.
adb -e install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
# An enabled Wi-Fi switch is not evidence of a connected, usable underlay.
# Observe it from the app UID before the long instrumentation matrix starts.
python3 tools/run_enrolled_vpn.py --prepare-wifi
# The instrumentation deadline is 20 minutes. Leave the wrapper time to
# verify the APKs first and report the last checked-in test on interruption.
if ! timeout --signal=TERM --kill-after=20s 22m python3 tools/run_packaged_instrumentation.py run; then
  python3 tools/print_emulator_reports.py || true
  exit 1
fi
restore_instrumentation_display
# Restore a fresh package, UID permissions and data for the VPN scenarios.
adb -e uninstall io.syn443.android.test
adb -e uninstall io.syn443.android
adb -e install -r app/build/outputs/apk/debug/app-debug.apk
adb -e install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -e shell appops set io.syn443.android ACTIVATE_VPN allow
# Fail early on the new OS scenarios. Missing old outcomes can never pass the
# final evidence gate; successful runs still execute every previous scenario.
if ! python3 tools/run_route_lifecycle.py; then
  python3 tools/print_emulator_reports.py || true
  exit 1
fi
python3 tools/run_vpn_process_faults.py || result=1
python3 tools/run_vpn_revocation.py || result=1
python3 tools/run_vpn_fatal.py || result=1
python3 tools/run_vpn_competing.py || result=1
python3 tools/run_policy_activation.py || result=1
python3 tools/run_enrolled_vpn.py || result=1
publish_support_bundle_report || result=1
python3 tools/check_test_evidence.py emulator || result=1
exit "$result"

