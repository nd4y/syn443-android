from pathlib import Path
import sys,xml.etree.ElementTree as ET
root=Path(__file__).resolve().parent.parent
mode=sys.argv[1]
if mode=="jvm":
    paths=list((root/"core/decision/build/test-results/test").glob("TEST-*.xml"))
    minimum=8
elif mode=="emulator":
    paths=list((root/"app/build/outputs/androidTest-results").rglob("TEST-*.xml"))
    minimum=86
elif mode=="host":
    paths=list((root/"core/host-lifecycle/build/test-results/test").glob("TEST-*.xml"))
    minimum=11
elif mode=="recovery":
    paths=list((root/"core/recovery/build/test-results/test").glob("TEST-*.xml"))
    minimum=8
elif mode=="policy":
    paths=list((root/"core/policy/build/test-results/test").glob("TEST-*.xml"))
    minimum=15
elif mode=="observability":
    paths=list((root/"core/observability/build/test-results/test").glob("TEST-*.xml"))
    minimum=10
elif mode=="health":
    paths=list((root/"core/health/build/test-results/test").glob("TEST-*.xml"))
    minimum=18
elif mode=="identity":
    paths=list((root/"core/identity/build/test-results/test").glob("TEST-*.xml"))
    minimum=72
    from coverage_evidence import IDENTITY_CLASSES, verify_classes
    verify_classes(root/"core/identity/build/reports/jacoco/test/jacocoTestReport.xml", IDENTITY_CLASSES)
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
    identity_required={"keystoreIdentityPersistsSignsAndCannotExportPrivateMaterial", "identityKeysAreIndependentAndCannotDeleteUnrelatedAliases"}
    identity_required |= {"cancellationOrdersDeletionAfterInFlightCreationAndFencesQueuedCreation",
        "protectedStatePersistsWithoutPlaintextAndCallbackIsConsumedOnce",
        "cancelErasesSecretsAndLateEncryptionCannotResurrectThem",
        "interruptedIntentCiphertextPairFailsClosedAndCanStillBeCancelled",
        "authenticatedCiphertextCannotBeMovedAcrossNamespaceGenerationOrAuthority",
        "malformedOversizedOrMissingPublicIntentNeverBecomesSignedOut",
        "atomicBackupRecoveryAndBoundedCiphertextRejectTruncation",
        "cryptoIsWorkerOnlyAndPreparedPayloadsCannotCrossJournalsOrBeReusedAfterClose"}
    required={"selectionAndStaleNetworkResult", "explicitStopRejectsLateCompletion", "darkThemeByDefault",
              "workerRunsInSeparateProcessAndStops", "wedgedWorkerCanBeTerminatedAndRebound",
              "foreignSessionCannotTerminateHost", "realTunTrafficAndExplicitStop",
              "nativeCrashRecoversButNewerStopWins", "fullyFrozenNativeProcessIsKilledOutsideItsControlLoop",
              "closingActivityDoesNotStopVpn", "lostNetworkCannotRemainSelectedFromAStaleSystemSnapshot",
              "uiProcessDeathKeepsRealTunTraffic", "controllerDeathRetiresFrozenNativeAndPreservesIntent",
              "stopDuringForegroundServiceStartupNeverCrashesController", "twoHopTunTrafficCrossesBothProxies",
              "ingressFailureRecoversWithoutNativeRestart", "egressFailureRecoversWithoutNativeRestart",
              "controllerRestartBudgetSurvivesOwnerDeath", "notificationStopRetiresAFullyFrozenNativeHost",
              "unavailableOptionalOverlayDoesNotBlockVpnOrLeakPrivateRoute",
              "forceStopWaitsForForegroundReopenAndPreservesIntent"}
    required |= {"signedPolicyBootstrapsCurrentConfig", "invalidPolicyAndImportCannotReplaceActive",
                 "failedNativeCandidateRollsBackAndCannotReplay", "requiredRegressionRollsBack",
                 "baselineOutageCanCommitDegraded", "stopFencesPendingPolicy",
                 "controllerDeathDuringApplyRollsBackOffline", "expiredLeaseBlocksWithoutDirectFallback",
                 "offlineControlPlaneRetainsAuthorizedPath"}
    required.add("duplicateEngineFieldsCannotReplaceConfiguration")
    required.add("nativeOwnerRecreationKeepsIntentAndRejectsOldCallbacks")
    required.add("signedManagementReleasePreservesLocalState")
    required.add("externalConnectExtraCannotTurnVpnOn")
    required.add("healthyChangedCandidateCommits")
    required.add("intentSentinelIsNonWakeupAndCancelledByStop")
    required.add("localRestartBudgetDoesNotPoisonHealthyRenewal")
    required.add("missingVpnConsentPreservesIntentWithoutStartingForegroundService")
    required |= {"resourceRequestsAreBoundedRedactedAndDoNotChangeIntent", "resourceSnapshotIsExplicitAndVisible"}
    required |= {"slowAndroidSocketReadHasAnAbsoluteDeadline", "cancelledAndroidBatchCannotBecomeAFalseBaseline"}
    required |= identity_required
    required |= {"browserReservationAndCancellationPreserveVpnAndDeleteTheKey",
        "controllerRestartResumesSameBrowserGenerationWithoutANewKey",
        "exactErrorCallbackIsSingleUseAndNeverConnectsVpn"}
    required |= {"acceptedCommandIsBusyBeforeExecutorAdmissionAndCancellationDrainsItExactlyOnce",
        "fullQueueAndDiscardedCommandsCannotRemainBusyOrRunAfterCancellation",
        "actualControllerRegistersOnceAcrossRestartAndRevokesBeforeDeletingItsKey",
        "lostEnrollmentReplyRetriesExactPersistedBodyAndKeyAfterControllerRestart",
        "cancelledCommittedEnrollmentCannotReturnAndFreshOwnerLoginCleansItsOrphan",
        "unreadableJournalStillCancelsNetworkAndRetiresTheOwnedPrivateKey"}
    required |= {"assignmentJournalIsSeparateEncryptedAndCancellationFencesLateStorage",
        "assignmentCiphertextCannotCrossNamespaceGenerationDeviceKeyOrTrustScope",
        "assignmentBoundsOrphansMissingReceiptsAndWrongThreadFailClosed",
        "verifiedAssignmentPersistsAcrossControllerDeathAndIsErasedOnLogout",
        "wrongKeyAssignmentNeverGetsAReceiptOrUsableConfiguration",
        "rotatedSessionReplyLossRetriesItsPersistedOperationWithoutLosingThePolicy"}
    required |= {"physicalIdentityUsesOneEligibleNetworkForDnsAndEverySocket", "physicalIdentitySocketBypassesTheRunningVpnProxy",
        "identityRouteLossOrChangedLinkRejectsWorkWithoutSwitchingNetworks",
        "physicalIdentityRejectsMissingDuplicateAndOversizedInventory",
        "androidPhysicalBindingDoesNotChangeProcessDefaultNetwork"}
    required |= {"managedOverlayWithoutItsCredentialNamespaceCannotBecomeARuntimeCandidate", "assignedRuntimeViewIsWorkerPreparedAndCannotOutliveLogout"}
    required |= {"assignedActivationPersistsBeforeUseAndCommitsAcrossControllerRestart",
        "assignedFailedReplacementRollsBackAndRejectsStaleActivationResults",
        "assignedInterruptedActivationIsPoisonedBeforeRecoveryCanPublishIt",
        "assignedAbortAndLogoutFenceAcceptedButNotYetQueuedTransitions"}
    required |= {"assignedTransportOutageRetainsLeaseButConfirmedDenialWithdrawsIt",
        "logoutCannotAcknowledgeRetirementWhileTheNativeOwnerLockIsHeld",
        "withdrawnOrUnreadableAssignmentRejectsRuntimeCommandsWithoutCrashing",
        "enrolledSignedAssignmentStartsRealTun", "enrolledControllerDeathRecoversAuthorizedCache",
        "enrolledCandidateRegressionRollsBack", "enrolledRevocationStopsNativeWithoutLocalFallback",
        "enrolledLogoutRetiresFrozenNativeBeforeAcknowledging"}
    assert required <= {case.attrib.get("name") for case in cases}, "Required UI/process cases missing"
print(f"{mode}: {len(cases)} SYN443 test cases passed, zero skipped/failures/errors")

