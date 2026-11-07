from pathlib import Path
import sys,xml.etree.ElementTree as ET
root=Path(__file__).resolve().parent.parent
mode=sys.argv[1]
if mode=="jvm":
    paths=list((root/"core/decision/build/test-results/test").glob("TEST-*.xml"))
    minimum=8
elif mode=="emulator":
    paths=list((root/"app/build/outputs/androidTest-results").rglob("TEST-*.xml"))
    minimum=188
elif mode=="host":
    paths=list((root/"core/host-lifecycle/build/test-results/test").glob("TEST-*.xml"))
    minimum=11
elif mode=="recovery":
    paths=list((root/"core/recovery/build/test-results/test").glob("TEST-*.xml"))
    minimum=15
elif mode=="policy":
    paths=list((root/"core/policy/build/test-results/test").glob("TEST-*.xml"))
    minimum=16
elif mode=="observability":
    paths=list((root/"core/observability/build/test-results/test").glob("TEST-*.xml"))
    minimum=10
elif mode=="health":
    paths=list((root/"core/health/build/test-results/test").glob("TEST-*.xml"))
    minimum=23
elif mode=="identity":
    paths=list((root/"core/identity/build/test-results/test").glob("TEST-*.xml"))
    minimum=110
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
if mode=="policy":
    assert ("io.syn443.policy.PolicyTest","signedManagedOverlayCapabilityRetainsKeySignatureExpiryAndUnknownFeatureFences") in {(c.get("classname"),c.get("name")) for c in cases}, "Required signed managed-policy verifier case missing"
if mode=="health":
    assert {('io.syn443.health.ChecksTest',name) for name in {
        'positionalDiagnosticsKeepEachFailureSeparateFromLaterSuccessOrMismatch',
        'checksNeverStartedDoNotInheritAStageOrNetworkFailure'}} <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required per-check diagnostic cases missing'
    required={('io.syn443.health.AddressFallbackTest',name) for name in {
        'unavailableFirstFamilyFallsBackWithoutExtraWorkersOrLeakedSockets',
        'connectionFailureTriesOnlyFourDistinctAddressesAndKeepsFailureAttribution',
        'emptyDnsResultDoesNotAllocateSocketAndRemainsDnsFailure',
        'cancellationClosesCurrentAttemptAndCannotStartAnAlternative',
        'releasingAnOldOrForeignSocketCannotDetachTheCurrentAttempt',
        'unexpectedConnectionFailureClosesOnlyItsSocketAndNeverStartsAnAlternative'}}
    required.add(('io.syn443.health.TlsTest','certificateFailureDoesNotTryAnotherAddressOrWeakenTrust'))
    assert required <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required bounded address fallback cases missing'
if mode=="identity":
    assert ('io.syn443.identity.BootstrapTrustTest','appLinkUnwrapsOnlyAnExactHttpsCarrierAndRetainsInstallationTrust') in {
        (c.get('classname'),c.get('name')) for c in cases}, 'Required HTTPS enrollment carrier case missing'
    assert {('io.syn443.identity.AssignmentsTest','activationReportPersistsOnlyFinalCurrentEnvelopeDecisions'),
        ('io.syn443.identity.AuthProtocolTest','activationReportBindsBodyToCurrentDeviceProofAndSupportsOlderServers')} <= {
        (c.get('classname'),c.get('name')) for c in cases}, 'Required activation reporting cases missing'
    logout_required={('io.syn443.identity.AuthProtocolTest',name) for name in {
        'expiredAccessLogoutRefreshesInRamAndRevokesOnlyTheSameDeviceWithCurrentProof',
        'freshAccessLogoutDoesNotRotateAndExpiredRefreshOrBootCannotDispatch',
        'uncertainExpiredLogoutRefreshNeverReenrollsOrSendsAnOldRevocationCredential',
        'substitutedOrCancelledLogoutRefreshCannotReachRevocation'}}
    assert logout_required <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required expired-access logout cases missing'
    renewal_required={('io.syn443.identity.AssignmentsTest',name) for name in {
        'identicalExecutionRenewsDurablyWithoutCandidateActivationOrLossOfFailureHistory',
        'freshSignedLeaseCanAuthorizeKnownExpiredExecutionButNeverReviveItsExpiredReader',
        'renewalOfAuthorizedRollbackKeepsFailedCandidateQuarantinedAndOtherFallbackLeaseUnextended',
        'renewalDoesNotBypassChangedAuthorityCapabilitiesGateOrPendingActivation',
        'shorterRenewedLeaseTightensDeadlineAndNeverMakesAnUnrelatedActiveSnapshotGood'}}
    assert renewal_required <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required lease renewal cases missing'
    capability_required={('io.syn443.identity.CapabilityNegotiationTest',name) for name in {
        'canonicalAvailabilityAndOperationAreStableWithoutMutatingAnOldRequest',
        'malformedUnknownAndInconsistentHistoryCannotBecomeAvailability',
        'pendingAndApprovedRepliesAreBoundToExactOperationAndExpectedHead'}}
    capability_required.update({('io.syn443.identity.AuthProtocolTest',name) for name in {
        'deviceCapabilitiesReusePendingBytesAndRecoverAnUnknownApprovalAck',
        'independentlyApprovedCapabilitiesAreConfirmedBeforeBecomingProtectedMetadata',
        'oidcCapabilityApprovalRetainsTheOriginalDurableEnrollmentOperation',
        'capabilityErrorsUnknownModulesCancellationAndMalformedApprovalDoNotGrantAccess'}})
    capability_required.update({('io.syn443.identity.LoginRecoveryTest',name) for name in {
        'recordedCapabilitiesPreserveActivationGenerationSessionAndOverlayClaims',
        'legacyEnrollmentCanBeSupersededOnlyAfterItsBoundAcknowledgement'}})
    capability_required.add(('io.syn443.identity.LoginPayloadTest','confirmedCapabilitiesAreProtectedCanonicalAndAbsentFromLegacyBytes'))
    assert capability_required <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required capability negotiation cases missing'
    assert ("io.syn443.identity.OverlayEnrollmentTest","newCapabilityAdvertisementPreservesExactLegacyEnrollmentAndInvitationRetries") in {(c.get("classname"),c.get("name")) for c in cases}, "Required capability migration case missing"
    assert {("io.syn443.identity.OverlayEnrollmentTest",name) for name in {"interruptedRegistrationErasesSetupBeforeKeylessProbeAndNeedsNativeProof","keylessProbeCannotBorrowAnotherIdentityOrInventFreshEnrollment"}} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required keyless reconciliation ledger cases missing"
    login_overlay_required={'namespaceClaimSurvivesRefreshAndCancelUntilActualErasureCompletes','namespaceClaimsRejectUnsafePathsUnboundedSetsAndUnprovisionedAuthority','recoveryMetadataBeforeManagedOverlaysRetainsEmptyOwnershipClaims'}
    assert {("io.syn443.identity.LoginRecoveryTest",name) for name in login_overlay_required} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required managed namespace recovery cases missing"
    assert ("io.syn443.identity.AuthProtocolTest","overlayConsumptionKeepsItsOperationAfterCurrentReferenceAndEpochRefresh") in {(c.get("classname"),c.get("name")) for c in cases}, "Required expired-operation cleanup case missing"
    assert {("io.syn443.identity.OverlayEnrollmentTest",name) for name in {"grantReplacementKeepsIdentityButRequiresErasureAndANewAddressedReference","confirmedIdentityCannotDiscardItsGrantToSilentlyRegisterAgain"}} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required grant replacement cases missing"
    overlay_required={('io.syn443.identity.OverlayEnrollmentTest', 'pendingAuthorityCannotSwitchAccountKeyDeviceEpochReferenceOrGeneration'), ('io.syn443.identity.OverlayAssignmentsTest', 'unmanagedInlineSecretPathUnknownFieldsAndDuplicateIdentityAreRejected'), ('io.syn443.identity.OverlayAssignmentsTest', 'assignedIdentityDerivesOnlyFromLocalScopeAndSignedMetadata'), ('io.syn443.identity.OverlayEnrollmentTest', 'cancellationWithdrawsEveryPhaseAndCannotBeReactivated'), ('io.syn443.identity.OverlayEnrollmentTest', 'durableFlowRetainsOperationAndErasesBeforeAcknowledgment'), ('io.syn443.identity.OverlayEnrollmentTest', 'boundedOperationsAndCorruptJournalAreRejected'), ('io.syn443.identity.AuthProtocolTest', 'overlayCannotAcceptUnsignedSecretCrossScopeOrFalseConsumption'), ('io.syn443.identity.AuthProtocolTest', 'addressedOverlayDeliveryBindsProofBodySessionAndIndependentEnvelope')}
    assert overlay_required <= {(c.get("classname"),c.get("name")) for c in cases}, "Required addressed overlay state/protocol cases missing"
    assert {"manualClaimConfirmationAndCompletionConvergeOnNormalBoundSession",
        "sameProtectedPendingCanResumeAndThenUseExistingLoginPolicyLifecycle",
        "stateSubstitutionClockRollbackAndNumericCoercionFailClosed",
        "malformedOperationsStatesAndWrongKeyNeverReachNetwork",
        "transportCancellationAndServerErrorsRemainDistinct",
        "previousProtectedOidcPayloadWithoutInvitationVariantKeepsItsBinding"} <= {c.get("name") for c in cases}
if mode=="emulator":
    assert ('io.syn443.android.EnrollmentAppLinkTest','repeatViewIntentsPreviewOnlyAndClearTheirCarrier') in {
        (c.get('classname'),c.get('name')) for c in cases}, 'Required enrollment intent lifecycle case missing'
    assert ('io.syn443.android.LoginControllerTest','activationDeliveryUsesDurableDecisionAndCannotChangeLoginOnFailure') in {
        (c.get('classname'),c.get('name')) for c in cases}, 'Required Android activation reporting case missing'
    assert {('io.syn443.android.PolicyCheckSnapshotTest',name) for name in {
        'diagnosticsArePositionalBoundedAndReturnedAsIndependentCopies',
        'changedOwnerIntentNetworkActivationOrStoppedVpnCannotRelabelEvidenceAsCurrent',
        'staleOrBackwardClockKeepsHistoryWithoutClaimingCurrentHealth'}} <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required fenced policy diagnostic cases missing'
    assert {('io.syn443.android.LoginControllerTest',name) for name in {
        'logoutAfterAccessExpiryRotatesOnlyInRamRevokesAndErasesTheProtectedSession',
        'lostLogoutRefreshKeepsRecoveryTombstoneWithoutRestoringSecretsOrRetryingEnrollment'}} <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required Android expired-session retirement cases missing'
    assert ('io.syn443.android.HealthChecksTest','androidDnsRetainsBoundedDistinctAddressesForFallbackAndStillCancelsQuery') in {(c.get('classname'),c.get('name')) for c in cases}, 'Required Android DNS fallback case missing'
    assert ('io.syn443.android.LoginControllerTest','assignedLeaseRenewalPersistsWithoutNewActivationAndRetainsDeviceIdentityAcrossRestart') in {(c.get('classname'),c.get('name')) for c in cases}, 'Required durable Android lease renewal case missing'
    assert {('io.syn443.android.LoginControllerTest',name) for name in {
        'legacyCapabilityApprovalSurvivesRestartWithoutChangingAssignedPolicyOrDeviceIdentity',
        'lostCapabilityAckAndUnavailableEndpointKeepCurrentAssignmentAndStopStillWins',
        'oldEnrollmentAckCreatesANewPersistedRequestAndPendingApprovalCanPoll',
        'confirmedCapabilitiesSurviveRefreshAndCannotBecomePublicStatusMetadata'}} <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required capability lifecycle cases missing'
    assert ("io.syn443.android.OverlayVaultTest","changedSecurityEpochProbesSameIdentityWithoutBorrowingGrantOrAcknowledgingBeforeNativeProof") in {(c.get("classname"),c.get("name")) for c in cases}, "Required changed-authority keyless recovery case missing"
    assert ("io.syn443.android.LoginControllerTest","periodicManagedCredentialRetryUsesSameOperationWithoutFetchingPolicyOrBypassingBackoff") in {(c.get("classname"),c.get("name")) for c in cases}, "Required independent overlay retry case missing"
    assert ("io.syn443.android.HostProcessTest","rejectedForeignBindingCannotRetireTheCurrentDiagnosticSession") in {(c.get("classname"),c.get("name")) for c in cases}, "Required diagnostic binding ownership case missing"
    assert {("io.syn443.android.LoginControllerTest",name) for name in {"managedControllerClaimsNamespaceBeforeFetchAndRestoresProtectedMaterialWithoutRefetch","managedControllerNativeReceiptErasesGrantAndRecoversKeylessWhileConsumptionIsOffline","managedControllerLogoutFencesALateCredentialAndKeepsNoRuntimeMaterial","managedControllerRejectsSignedWrongAddressAndRetriesTheSameReservedOperation","managedCredentialOutageKeepsBasePolicyAndRetriesSameOperationBeforeEnrollment","managedGrantFailureNeverUsesAKeyAndAuthenticationDenialWithdrawsBaseAuthority","interruptedManagedRegistrationExpiresIntoKeylessProbeUntilCurrentNativeProof"}} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required managed controller integration cases missing"
    assert ("io.syn443.android.LoginControllerTest","activePendingIdentityAndFreshCandidateNeverConsumeEachOthersGrant") in {(c.get("classname"),c.get("name")) for c in cases}, "Required active/candidate same-identity fence missing"
    login_overlay_required={'persistedOverlayClaimsSurviveRestartAndRetireBeforeDeviceKey','unreadableOwnedOverlayKeepsLogoutPendingUntilTheSameCleanupCanResume'}
    assert {("io.syn443.android.LoginControllerTest",name) for name in login_overlay_required} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required controller SDK retirement cases missing"
    overlay_storage_required={'ownedNamespaceRetiresUnderLockAndLeavesEverySiblingAndOperatorFileUntouched', 'wrongEvidenceUnclaimedSDKAndAmbiguousManifestNeverAuthorizeErasure', 'symlinkAndOversizedTreesFailBeforeDeletingAnyOwnedFile', 'heldNativeOwnershipPreventsAllDeletionAndCancellationCannotBorrowIt', 'nativeOwnershipIsHeldThroughoutCleanupAndMainThreadCannotErase', 'interruptedDeletionKeepsOwnershipUntilTheSameRetirementCompletes'}
    assert {("io.syn443.android.ManagedOverlayStorageTest",name) for name in overlay_storage_required} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required owned SDK retirement cases missing"
    assert ("io.syn443.android.OverlayVaultTest","expiredPendingGrantCanBeReplacedOnlyAfterErasureAndServerAckWithoutTouchingSdkIdentity") in {(c.get("classname"),c.get("name")) for c in cases}, "Required grant erasure/replacement case missing"
    assert {("io.syn443.android.OverlayVaultTest",name) for name in {"managedProvisionerPersistsBeforeFetchAndErasesBeforeIndependentConsumption","managedProvisionerRenewalRetriesLostAckAndNeverResetsSdkKeys","managedProvisionerRejectsLateFetchAndNativeProofAfterCancellation"}} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required managed provisioning orchestration cases missing"
    assert {("io.syn443.android.OverlayVaultTest",name) for name in {"runtimeMaterialRendersOnlyItsSignedConfigAndLocallyDerivedOwnedDirectory","keylessMaterialCannotAdoptInlineKeysPathsOtherNamespacesOrCoercedMetadata","waitingMaterialKeepsSignedMetadataAndNeverCreatesCredentialOrSDKStorage","expiredUnconfirmedGrantErasesBeforeExistingIdentityProbeAndNeverFetchesAReplacement","interruptedRecoveryErasureFinishesWithoutBorrowingTheOldCiphertext"}} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required RAM material localization cases missing"
    overlay_vault_required={'perGrantKeyCiphertextAndDurableOperationSurviveProcessObjectsThenEraseBeforeAck', 'aLateCredentialCannotBeCachedOrBorrowedAfterTheTrustedUpperDeadline', 'missingKeyTamperingUnknownJournalAndOrphanCipherNeverResetEnrollment', 'cancellationRejectsLateAndQueuedCryptoAndWaitsForConfirmedOwnerRelease', 'interruptedCacheCommitRetainsReservedOperationAndCannotCrossStorageArea', 'mainThreadCannotEncryptDecryptOrMutateEnrollmentButMayPersistCancellation', 'retiredMetadataIsRemovedOnlyAfterConfirmedCredentialAndSdkErasure'}
    assert {("io.syn443.android.OverlayVaultTest",name) for name in overlay_vault_required} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required overlay Keystore/retirement cases missing"
    route_activation_required={"assignedActivationWaitsForCandidateRoutesAndIgnoresOptionalFailure",
        "assignedFinishRechecksLocalProofAfterEncryptedPreparation",
        "assignedActivationCannotReusePriorScopeOrIncompleteRouteProof",
        "enrolledAssignedRoutesCommitWithOptionalFailure",
        "enrolledRequiredRouteFailureCannotCommitThroughHealthyInternet",
        "enrolledStopFencesPendingCandidateRouteSuccess"}
    live_engine_required={"savedEngineCheckpointCannotClaimAnUnownedLiveProcess"}
    route_required={"independentRoutesKeepOptionalFailureAndUnconfiguredUnknown","routeLateNetworkAndEngineResultsCannotOverrideStop","duplicateRouteHeartbeatCannotRefreshAgeAndNewBatchCanReplaceResult","routeProfilesRejectUnsupportedTargetsDuplicatesAndWrongTypes","routeClientMetadataNeverReachesNativeConfiguration","lockedBootStatusHasUnknownIntentAndNoCredentialFields","routesAndSystemPolicyHaveVisibleControlsWithoutChangingIntent","routeChecksUseActualOutboundsAndSelectedProxy","requiredRouteFailureDegradesWithoutRestartAndRecovers","stopCancelsPendingRouteChecksAndRejectsLateSuccess","packageUpdatePreservesConfigIntentAndOffAcrossSystemCallback","rebootBeforeUnlockDoesNotReadCredentialStateThenReconciles","rebootWithOffIntentCannotStartOrSpendBudget","actualAlwaysOnLockdownRespectsNewerStop","forceStopThenPackageUpdateCannotResumeWithoutUserConnect"}
    fatal_required={"competingVpnOwnsTunAndRevokesOriginalWithoutRetryFight","fatalCommandsCannotStartAnOffNativeOwner","uncaughtJavaFaultRecoversRealTunAndRetainsIntent","uncaughtNativeFaultRecoversRealTunAndRetainsIntent","fatalCrashSeriesPreservesRestartBudgetAndStopFencesLateRecovery",
        "exitSnapshotFiltersRolesBoundsAndSortsWithoutIdentifiers","exitCategoriesAreFixedAndUnknownReasonCannotBecomeCrash","exitReadFailureAndInvalidQueryReturnUnavailableWithoutText","exitPidFilterRejectsStaleFutureAndForeignRecords","exitMetadataReadsRealPlatformWithoutChangingIntent","emptyExitHistoryIsAvailableAndDoesNotInventSuccess","engineExitHistoryHasVisibleOnDemandControls"}
    chat_required={"chatSqlOutboxPersistsCiphertextAndFencesAccountGeneration","chatSqlChunksPreserveTwentyFiveMiBAndRejectOversize","chatOutboxQuotaAndLogoutEraseTheOwnedKey","chatPhotoCompressionAppliesOrientationAndStripsGps","chatTextAndDocumentBoundariesDoNotAcceptInvalidMedia","supportChatHasVisibleTitleAndConnectionStatus"}
    chat_required |= {"chatRestartReclaimsUnsentFilesButPreservesDraftAttachments","chatVideoCompressionProducesBoundedMp4AndStripsLocation","chatCancellingActiveVideoExportRemovesPrivateTemporaryFiles"}
    chat_required |= {"chatReplyIsPrivateAndDenialDoesNotWithdrawAssignedPolicy","cancelledQueuedChatNeverTransmitsAndDoesNotPoisonNextRequest"}
    chat_required |= {"chatCancelledImportRollsBackPartialSqlAndCanBeRetried"}
    chat_required |= {"chatDecoderSelectionPreservesPhysicalCodecsAndExcludesBrokenVirtualDecoder"}
    chat_required |= {"chatResumesPersistedRefreshAfterTransportLossWithoutManualLogin"}
    chat_required |= {"chatCannotResumeRefreshFromAnObsoleteBootOrBypassRecoveryAdmission"}
    chat_required |= {"expiredPublicationReceiptRequiresReauthenticationInsteadOfPermanentProvisioning"}
    identity_required={"keystoreIdentityPersistsSignsAndCannotExportPrivateMaterial", "identityKeysAreIndependentAndCannotDeleteUnrelatedAliases"}
    identity_required |= {"cancellationOrdersDeletionAfterInFlightCreationAndFencesQueuedCreation",
        "protectedStatePersistsWithoutPlaintextAndCallbackIsConsumedOnce",
        "cancelErasesSecretsAndLateEncryptionCannotResurrectThem",
        "interruptedIntentCiphertextPairFailsClosedAndCanStillBeCancelled",
        "authenticatedCiphertextCannotBeMovedAcrossNamespaceGenerationOrAuthority",
        "malformedOversizedOrMissingPublicIntentNeverBecomesSignedOut",
        "atomicBackupRecoveryAndBoundedCiphertextRejectTruncation",
        "cryptoIsWorkerOnlyAndPreparedPayloadsCannotCrossJournalsOrBeReusedAfterClose"}
    required=fatal_required | route_required | live_engine_required | {"selectionAndStaleNetworkResult", "explicitStopRejectsLateCompletion", "darkThemeByDefault",
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
    required |= {"revocationDrainsNativeBeforeFinalOffAndSurvivesControllerDeath",
                 "revocationDrainPreservesNewerConnectAndRetiresFrozenOldOwner"}
    required.add("intentSentinelIsNonWakeupAndCancelledByStop")
    required.add("localRestartBudgetDoesNotPoisonHealthyRenewal")
    required.add("missingVpnConsentPreservesIntentWithoutStartingForegroundService")
    required |= {"resourceRequestsAreBoundedRedactedAndDoNotChangeIntent", "resourceSnapshotIsExplicitAndVisible"}
    required |= {"slowAndroidSocketReadHasAnAbsoluteDeadline", "cancelledAndroidBatchCannotBecomeAFalseBaseline",
                 "androidDnsLiteralNeverStartsPlatformQuery", "androidDnsCallbacksKeepFailuresDistinctAndCancelQuery",
                 "androidDnsDeadlineCancelsQueryAndRejectsLateSuccess", "androidDnsCancellationReleasesWorkersForNextPolicyCheck"}
    required |= identity_required | chat_required | route_activation_required
    required |= {"qrImageReturnsOnlyASyntacticallyBoundedInvitation",
        "floorsPersistAcrossRecreationAndCorruptionNeverResetsToInstallationRoot",
        "manualInvitationStaysLocalUntilConfirmationAndThenUsesOrdinarySession",
        "cancelledClaimCannotCompleteOrResurrectItsRetiredKey",
        "signedServiceCanPrepareKeycloakWithoutClaimingTheInvitation",
        "expiredManualApprovalRequiresActionInsteadOfPollingForever"}
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
        "enrolledLogoutRetiresFrozenNativeBeforeAcknowledging",
        "pendingPollFencesStaleGenerationAndCannotReviveLogout",
        "enrolledPendingAssignmentRetriesWhileVisible"}
    assert required <= {case.attrib.get("name") for case in cases}, "Required UI/process cases missing"
print(f"{mode}: {len(cases)} SYN443 test cases passed, zero skipped/failures/errors")

