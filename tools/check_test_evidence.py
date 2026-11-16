from pathlib import Path
import sys,xml.etree.ElementTree as ET
root=Path(__file__).resolve().parent.parent
mode=sys.argv[1]
if mode=="jvm":
    paths=list((root/"core/decision/build/test-results/test").glob("TEST-*.xml"))
    minimum=8
elif mode=="emulator":
    paths=list((root/"app/build/outputs/androidTest-results").rglob("TEST-*.xml"))
    minimum=327
elif mode=="host":
    paths=list((root/"core/host-lifecycle/build/test-results/test").glob("TEST-*.xml"))
    minimum=11
elif mode=="recovery":
    paths=list((root/"core/recovery/build/test-results/test").glob("TEST-*.xml"))
    minimum=15
elif mode=="policy":
    paths=list((root/"core/policy/build/test-results/test").glob("TEST-*.xml"))
    minimum=20
elif mode=="observability":
    paths=list((root/"core/observability/build/test-results/test").glob("TEST-*.xml"))
    minimum=10
elif mode=="health":
    paths=list((root/"core/health/build/test-results/test").glob("TEST-*.xml"))
    minimum=23
elif mode=="identity":
    paths=list((root/"core/identity/build/test-results/test").glob("TEST-*.xml"))
    minimum=135
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
identities=[(c.get("classname"),c.get("name")) for c in cases]
assert len(identities)==len(set(identities)), "Duplicate actual test outcomes"
if mode=="recovery":
    assert ("io.syn443.recovery.PhysicalNetworkSelectionTest","captiveCandidateCannotBeSelectedEvenWithPriorProof") in {
        (c.get("classname"),c.get("name")) for c in cases}, "Required captive network case missing"
if mode=="jvm":
    assert {("io.syn443.decision.RouteGraphTest",name) for name in {
        "sharedGraphQueriesAndBoundsAgreeWithGo",
        "sharedMalformedGraphsNeverAcquirePartialAuthority",
        "graphFrontierEnumeratesOnlyBoundGroupPathsWithStableIDs",
        "graphWarmHintDoesNotBypassModeTemplateExpiryOrContext",
        "exactCatalogueAndCandidateBoundaryCannotBeTruncated",
        "perIntentBoundDeduplicatesSharedTemplatesAndRejectsSplitOverflow",
        "utf8ByteLimitsAndOwnedMetadataSurviveCallerMutation",
    }} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required route graph conformance cases missing"
    from coverage_evidence import verify_classes
    verify_classes(root/"core/decision/build/reports/jacoco/test/jacocoTestReport.xml", {
        "io.syn443.decision.RouteGraph", "io.syn443.decision.RouteGraph.Companion",
    })
    assert {("io.syn443.decision.RouteFrontierTest",name) for name in {
        "boundedCursorCoversSparseGraphWithoutDuplicateOrWrongExitPaths",
        "allHopsAndEdgesSatisfyModeAndFullPathCapabilityRequirements",
        "warmHintComesFirstOnlyIfItStillBelongsToTheGraph",
        "oldOrExpiredCursorNeverResumes",
        "oversizedTemplateFailsInsteadOfReportingTruncatedCoverage",
    }} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required route search cases missing"
    assert {("io.syn443.decision.RouteHealthMemoryTest",name) for name in {
        "pathFailuresQuarantineThenDemandFreshEvidence",
        "commonFailuresAndAnotherTrafficClassCannotPoisonPath",
        "authorizationFailureWaitsForContextAndRejectsLateCompletion",
        "capacityCannotEvictAnActiveQuarantineOrConfigurationFence",
    }} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required route health cases missing"
    assert {("io.syn443.decision.FailoverAdmissionTest",name) for name in {
        "independentFailuresAndCurrentVerifiedReservePermitOneSwitch",
        "conservativeRevisionRequiresThreeIndependentBatchesAndSixtySecondsBetweenSwitches",
        "targetFailureAndWrongScopeDoNotCountTowardFailover",
        "staleOrDifferentCheckGroupCannotAuthorizeReplacement",
        "stabilityThenEnergyTakePriorityOverLatency",
        "evidenceFromAnotherExitCannotAuthorizeAReplacementOrAdvanceFailureCount",
        "optionalReserveIsDeferredOnlyAfterIndependentFailuresAgainstHealthyComparator",
    }} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required failover admission cases missing"
if mode=="emulator":
    assert ("io.syn443.android.RuntimeHeapTest", "actualArtHeapSupportsTheMandatoryStorageAndUiSuite") in {
        (c.get("classname"),c.get("name")) for c in cases}, "Required actual ART heap case missing"
    assert {
        ("io.syn443.android.PrototypeTest", "homeShowsVpnBeforeAccountAndKeepsToolsCollapsed"),
        ("io.syn443.android.VpnPrimaryActionTest", "startRequiresKnownReadyStateAndStopDoesNotRequireReadiness"),
    } <= {(c.get("classname"),c.get("name")) for c in cases}, "Required VPN home UI cases missing"
    assert {("io.syn443.android.RouteSnapshotTest",name) for name in {
        "sshWithoutServerPinCannotBeImportedAssignedOrRendered",
        "insecureProxyAndDnsTlsCannotBeImportedAssignedOrRendered",
        "routeExitProofIsRequiredAndReportsMismatchWithoutExposingAddresses",
        "countryExitCheckKeepsStrictFieldsAndReportsMismatchPrivately",
        "savedEngineCheckpointCannotClaimAnUnownedLiveProcess",
    }} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required peer verification cases missing"
    assert {("io.syn443.android.ManagedFailoverTest",name) for name in {
        "twoSameScopeBatchesSelectOnlyTheVerifiedConcreteReserve",
        "conservativeRevisionRequiresThirdCurrentRouteBatch",
        "nativeSelectionPlanContainsOnlyConcreteChecksForTheExactConfig",
        "meteredMaintenanceKeepsRequiredChecksAndOnlyFullComparisonsCountTowardSwitch",
        "wifiInternalPlanCannotEnableDirectOrMismatchedCheckFallback",
        "routineBatchesDeferOnlyCoolingReserveAndKeepRequiredSelector",
        "firstValidatedManagedBatchBypassesCadenceOnceWithoutCancellingInFlightWork",
    }} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required managed Wi-Fi failover cases missing"
    assert {
        ("io.syn443.android.TechnicalTelemetryDiskTest","encryptedQueueRestartsWithoutExposingAnotherEnrollment"),
        ("io.syn443.android.TechnicalTelemetryDiskTest","consentFenceDropsPriorEventsAndRawDiagnosticStrings"),
        ("io.syn443.android.TechnicalTelemetryDiskTest","onlyConfirmedRouteSelectionCarriesItsPolicyAndAlgorithmRevisions"),
        ("io.syn443.android.PhysicalIdentityRouteTest","technicalTelemetryCannotUseMeteredWifiOrCellular"),
    } <= {(c.get("classname"),c.get("name")) for c in cases}, "Required technical telemetry device cases missing"
if mode=="policy":
    assert {("io.syn443.policy.PolicyTest",name) for name in {
        "signedManagedOverlayCapabilityRetainsKeySignatureExpiryAndUnknownFeatureFences",
        "managedRouteChecksKeepTheirSignedBindingAndCapability",
        "reserveCooldownRequiresBoundConfigurationAndHasAnIndependentRollbackFingerprint",
        "exitCheckRequiresMatchingCapabilityOnKeyBoundConfiguration",
        "countryCheckRequiresItsOwnBoundCapabilityAndCannotReuseIpAuthority",
        "decisionRevisionMustMatchKeyBoundFailoverCapability",
    }} <= {(c.get("classname"),c.get("name")) for c in cases}, "Required signed managed-policy verifier case missing"
if mode=="health":
    assert {('io.syn443.health.ChecksTest',name) for name in {
        'positionalDiagnosticsKeepEachFailureSeparateFromLaterSuccessOrMismatch',
        'checksNeverStartedDoNotInheritAStageOrNetworkFailure',
        'oneAdmissionRetryUsesFreedCapacityAndRunsTheProbeOnlyOnce'}} <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required per-check diagnostic cases missing'
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
    chat_recovery={("io.syn443.identity.ChatRefreshGateTest",name) for name in {'cancellationAndBusyDoNotInventAPathOrAccumulateFailureBackoff', 'healthyPollingAndManualActionsHaveIndependentBoundedIntervals', 'authorityFailureNeedsAnExplicitRetryAndANewAccountStartsFresh', 'serverThrottlingCannotBeBypassedByTheRetryButton', 'repeatedOfflineFailuresBackOffWithoutPollingOrDroppingTheTail', 'concurrentRefreshRequestsAdmitExactlyOneOwnedAttempt', 'staleCompletionsAndInvalidClocksCannotReleaseANewerWorker'}}
    chat_recovery.add(("io.syn443.identity.AuthProtocolTest","disabledChatSelfIsUnavailableWithoutBorrowingAnotherEndpointOrSession"))
    assert chat_recovery <= {(c.get("classname"),c.get("name")) for c in cases}, "Required bounded chat recovery outcomes missing"
    runtime_required={("io.syn443.identity.RuntimeObservationTest",name) for name in {
        "wireIsClosedSmallRedactedAndCompatibleWithAllSupportedPhases",
        "invalidNumbersPhasesAndContradictoryEvidenceNeverProduceARequest",
        "exactPendingRetrySurvivesSerializationWithoutRefreshingItsTimestamp",
        "oldOrChangedFactsReserveANewSequenceBeforeTheNextUpload",
        "acknowledgmentAndConsentWithdrawalKeepTheCursorAndRejectSubstitution",
        "samplesUseOnlyTheTrustedTimeWindowAndRefuseUnboundedUncertainty",
        "durableAttemptAndErrorBudgetsSurviveRestartAcknowledgmentConsentAndClockUncertainty"}}
    runtime_required.update({("io.syn443.identity.AuthProtocolTest",name) for name in {
        "runtimeObservationBindsTheExactRetryBodyAndRequiresAnEmptyAcknowledgment",
        "optionalRuntimeFailuresDoNotReplaceAuthorityAndReauthenticationIsStillRequired"}})
    assert runtime_required <= {(c.get("classname"),c.get("name")) for c in cases}, "Runtime wire/queue evidence missing"
    assert {
        ("io.syn443.identity.AuthProtocolTest","technicalTelemetryIsProofBoundAndDisabledEndpointDoesNotAcknowledge"),
        ("io.syn443.identity.TelemetryTest","acknowledgmentRemovesOnlyTheOriginalPrefixAndNeverAnotherScope"),
        ("io.syn443.identity.TelemetryTest","queueCapsBatchesAndExpiresOldEvidenceWithoutReordering"),
    } <= {(c.get("classname"),c.get("name")) for c in cases}, "Required telemetry queue or wire cases missing"
    assert ('io.syn443.identity.BootstrapTrustTest','appLinkUnwrapsOnlyAnExactHttpsCarrierAndRetainsInstallationTrust') in {
        (c.get('classname'),c.get('name')) for c in cases}, 'Required HTTPS enrollment carrier case missing'
    assert ('io.syn443.identity.BootstrapTrustTest','installationProfileIsBoundedAndHasNoImportedRotationHistory') in {
        (c.get('classname'),c.get('name')) for c in cases}, 'Required installation profile case missing'
    assert ('io.syn443.identity.BootstrapTrustTest','installationUpgradeRequiresClosedVersionAndAdjacentDistinctRoots') in {
        (c.get('classname'),c.get('name')) for c in cases}, 'Required installation upgrade profile case missing'
    assert {('io.syn443.identity.AuthProtocolTest','administrationHintIsBoundedAndOlderServersDenyNavigation'),
        ('io.syn443.identity.AuthProtocolTest','sourceFetchUploadBindsTheCompleteBinaryFrameToTheDeviceProof'),
        ('io.syn443.identity.AuthProtocolTest','conditionalSourceLeaseSignsMetadataAndFallsBackOnOldServers'),
        ('io.syn443.identity.BoundedHttpTest','subscriptionTlsPreservesQueryAndBoundsDecodedGzip'),
        ('io.syn443.identity.BoundedHttpTest','conditionalProviderLengthDoesNotCreateBodyOrRelaxIdentityFraming'),
        ('io.syn443.identity.SubscriptionDownloadTest','privateAddressesRequireExplicitScopeAndNeverAllowMetadataOrLoopback'),
        ('io.syn443.identity.SubscriptionDownloadTest','validatorsAreScopedToTheOriginalRepresentationEvenOnSameOriginRedirect'),
        ('io.syn443.identity.SubscriptionDownloadTest','redirectRechecksResolvedAddressesAndNeverRestoresRemovedCredentials')} <= {
        (c.get('classname'),c.get('name')) for c in cases}, 'Required device source transport cases missing'
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
    assert {('io.syn443.android.LoginControllerTest',name) for name in {
        'expiredRefreshFamilyRequiresLoginWithoutContactingTheServer',
        'expiredRefreshFamilyPreservesAnAuthorizedOfflinePolicy',
        'repeatKeycloakLoginKeepsDevicePolicyAndFencesPreviousResults',
        'repeatKeycloakLoginRejectsWrongOwnerAndDifferentDevice',
    }} <= {(c.get('classname'),c.get('name')) for c in cases}, 'Required expired refresh family cases missing'
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
    route_required.add("adbLocalConfigPreviewDoesNotWriteAndApplyFencesStaleBase")
    route_required.add("assignmentQuotedStringStreamingMatchesReferenceDefaultsEscapesAndUnicode")
    fatal_required={"competingVpnOwnsTunAndRevokesOriginalWithoutRetryFight","fatalCommandsCannotStartAnOffNativeOwner","uncaughtJavaFaultRecoversRealTunAndRetainsIntent","uncaughtNativeFaultRecoversRealTunAndRetainsIntent","fatalCrashSeriesPreservesRestartBudgetAndStopFencesLateRecovery",
        "exitSnapshotFiltersRolesBoundsAndSortsWithoutIdentifiers","exitCategoriesAreFixedAndUnknownReasonCannotBecomeCrash","exitReadFailureAndInvalidQueryReturnUnavailableWithoutText","exitPidFilterRejectsStaleFutureAndForeignRecords","exitMetadataReadsRealPlatformWithoutChangingIntent","emptyExitHistoryIsAvailableAndDoesNotInventSuccess","engineExitHistoryHasVisibleOnDemandControls"}
    chat_required={"chatSqlOutboxPersistsCiphertextAndFencesAccountGeneration","chatSqlChunksPreserveTwentyFiveMiBAndRejectOversize","chatOutboxQuotaAndLogoutEraseTheOwnedKey","chatPhotoCompressionAppliesOrientationAndStripsGps","chatTextAndDocumentBoundariesDoNotAcceptInvalidMedia","supportChatHasVisibleTitleAndConnectionStatus","supportChatKeepsItsRootAcrossRepeatedRecreation","supportChatResumesAfterRepeatedBackgroundTransitions"}
    chat_required.add("chatReadinessRejectsMissingRootTitleAndStatus")
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
              "idleFaultClientClosesWithoutFalseHealthOrEscapingItsWorker",
              "resetReadinessIsReadOnlyAndCannotAuthorizeAnActiveOwner",
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
        "installationUpgradeCommitsBothSignaturesAndKeepsTheRevisionFloor",
        "administrationEntryUsesTrustedMetadataAndCannotOutliveItsLoginGeneration",
        "olderIdentityServerKeepsAdministrationHiddenWithoutChangingLogin",
        "subscriptionRouteRequiresValidatedWifiAndNeverUsesCellular",
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
        "assignmentEscapedByteOverflowLeavesItsPreviousCiphertextAndReceiptIntact",
        "assignmentLargeCanonicalSnapshotsRoundTripWithoutFullStringBuffers",
        "assignmentStreamingCiphertextKeepsItsLegacyV1EncodingAndCanonicalUnicode",
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
    required |= {"encryptedRuntimeRetrySurvivesRestartAndConsentWithdrawalRetainsOnlyItsCursor",
        "runtimeQueueRejectsCiphertextSubstitutionTruncationAndOversizeWithoutReplacingIt",
        "runtimeCaptureNeverTurnsCachedOnlineOrAnUnboundEngineIntoPositiveEvidence",
        "runtimeQueueRejectsMainThreadStorageAccess",
        "runtimeTransportReportsOnlyTheSelectedPhysicalNetworkAndFencesItsClassChanges",
        "runtimeUploadNeedsExplicitConsentAndCannotBorrowAnArtificialVpnOnHint",
        "runtimeAttemptBudgetSurvivesEncryptedRestartAndCannotBeResetByConsentOrRetry"}
    assert required <= {case.attrib.get("name") for case in cases}, "Required UI/process cases missing"
print(f"{mode}: {len(cases)} SYN443 test cases passed, zero skipped/failures/errors")


# Closed managed runtime outcomes are mandatory even if the aggregate count is green.
ADAPTIVE_REQUIRED = {'emulator': [('io.syn443.android.AdaptiveEngineConfigTest', 'managedCatalogueValidatesEveryProtocolAndRetainsNativeExtractionMetadata'), ('io.syn443.android.AdaptiveEngineConfigTest', 'managedMappingsChecksAndEnvelopeTypesFailClosed'), ('io.syn443.android.AdaptiveEngineConfigTest', 'unsafeNormalizedCredentialsTlsSshAndTransportsCannotEnterAdaptiveCatalogue'), ('io.syn443.android.AdaptiveEngineConfigTest', 'ordinaryDependenciesAndNetBirdKeepOwnedBoundedPaths'), ('io.syn443.android.AdaptiveEngineConfigTest', 'fiveHundredProfilesAndUtf8BoundsRemainExplicit'), ('io.syn443.android.AdaptiveEngineConfigTest', 'renderCopiesAndLegacyBehaviorRemainUnchanged'), ('io.syn443.android.ManagedAdaptiveRoutesTest', 'contextEpochAndNewEngineFenceRejectStaleReports'), ('io.syn443.android.ManagedAdaptiveRoutesTest', 'protectedWireBoundsPreserveOriginalSyntaxAndEscapedRootKeys'), ('io.syn443.android.ManagedAdaptiveRoutesTest', 'nativeBusyAndLostAcknowledgementsNeverReleaseAnUnknownOwner'), ('io.syn443.android.ManagedAdaptiveRoutesTest', 'freshBoundReceiptCommitsOnceAndRejectsWrongPaths'), ('io.syn443.android.ManagedAdaptiveRoutesTest', 'roundRobinAndMinuteBudgetRemainSharedAcrossGroups'), ('io.syn443.android.ManagedAdaptiveRoutesTest', 'hourBudgetSurvivesContextRebindAndForce'), ('io.syn443.android.ManagedAdaptiveRoutesTest', 'healthyMeteredModesConfirmCurrentWithoutExploration'), ('io.syn443.android.ManagedAdaptiveRoutesTest', 'latencySwitchRequiresTwoFreshSignificantComparableSamples'), ('io.syn443.android.ManagedAdaptiveRoutesTest', 'failedReserveCannotOverwriteHealthyRouteOrLeakEndpoints')], 'policy': [('io.syn443.policy.AdaptivePolicyTest', 'signedAdaptiveConfigurationRequiresExactKeyBoundCapabilityAndAlgorithm'), ('io.syn443.policy.AdaptivePolicyTest', 'adaptiveFieldPresenceNullAndLegacyFailoverCannotDowngradeAuthority'), ('io.syn443.policy.AdaptivePolicyTest', 'countryPredicatesKeepIndependentCapabilitiesOnAdaptivePolicies')], 'jvm': [('io.syn443.decision.AdaptiveRuntimeTest', 'closedWireOwnsCanonicalProfilesMappingsAndHash'), ('io.syn443.decision.AdaptiveRuntimeTest', 'strictShapeAndCanonicalBase64CannotBeCoerced'), ('io.syn443.decision.AdaptiveRuntimeTest', 'catalogueAndGroupGuardsRejectUnsafeOrUnboundInputs'), ('io.syn443.decision.AdaptiveRuntimeTest', 'goCanonicalStringsAndNumberLexemesArePreserved'), ('io.syn443.decision.AdaptiveRuntimeTest', 'fiveHundredProfilesFitWithoutTruncation'), ('io.syn443.decision.AdaptiveRuntimeTest', 'wholeWireAndPerProfileByteBoundariesRemainExact'), ('io.syn443.decision.AdaptiveRuntimeTest', 'dedicatedParserBoundsDepthArraysObjectsAndSharedTokens'), ('io.syn443.decision.AdaptiveRuntimeTest', 'publicGraphKeepsSeparateGroupMappingsAndNoObservedExitAuthority')]}
if mode in ADAPTIVE_REQUIRED:
    if mode == 'emulator':
        ADAPTIVE_REQUIRED[mode].append(('io.syn443.android.ManagedAdaptiveRoutesTest', 'currentCheckFailureRequiresFreshBoundReplacementAndMonotonicTime'))
    assert set(ADAPTIVE_REQUIRED[mode]) <= {(c.get("classname"),c.get("name")) for c in cases}, "Missing actual managed adaptive outcome"


# Pure lease continuity and RAM traversal hints never substitute for native evidence.
CONTINUITY_REQUIRED = {'jvm': [('io.syn443.decision.RouteFrontierResumeTest', 'fiveHundredCandidatesResumeAcrossExpiryWithoutPrefixReplay'), ('io.syn443.decision.RouteFrontierResumeTest', 'positionBindsGraphInstanceGroupModeEveryContextFieldAndHints'), ('io.syn443.decision.RouteFrontierResumeTest', 'unsafeContextAndClockInvalidationCannotBecomeRenewableExpiry'), ('io.syn443.decision.RouteFrontierResumeTest', 'warmHintsAndSixtyFourOverlappingTemplatesStayDeduplicatedAfterRenewal'), ('io.syn443.decision.RouteFrontierResumeTest', 'fourSlotsAnd4096RawPositionsResumePastIneligibleAndDuplicateQuanta'), ('io.syn443.decision.RouteFrontierResumeTest', 'positionAndGraphOwnershipSurviveCallerBufferAndHintMutation')], 'policy': [('io.syn443.policy.PolicyLeaseSemanticsTest', 'exactlyFiveSignedLeaseFieldsMayChangeWithoutChangingContentOrAuthority'), ('io.syn443.policy.PolicyLeaseSemanticsTest', 'parentContentPredicateRetainsEveryOtherFieldAndExactEngine'), ('io.syn443.policy.PolicyLeaseSemanticsTest', 'authorityChangesForSignedCriticalPayloadChanges'), ('io.syn443.policy.PolicyLeaseSemanticsTest', 'realSignerRotationRootSetBootstrapAndInstallationAnchorAreIndependentFences'), ('io.syn443.policy.PolicyLeaseSemanticsTest', 'authorityRejectsUnknownMalformedSignerAndMismatchedVerifiedCopies')], 'emulator': [('io.syn443.android.ManagedAdaptiveRoutesFairnessTest', 'fiveHundredLastWorkingPathSurvivesTTLAndHourlyPauseWithoutBudgetReset'), ('io.syn443.android.ManagedAdaptiveRoutesFairnessTest', 'emptyCPUQuantumYieldsToAnotherDueGroupWithoutAnotherProbe'), ('io.syn443.android.ManagedAdaptiveRoutesFairnessTest', 'cooldownCPUQuantumYieldsWithoutBypassingHalfOpenOrHealthyGroup'), ('io.syn443.android.ManagedAdaptiveRoutesFairnessTest', 'realContextNativeEpochAndClockChangesDoNotBorrowPositionsOrResetBudgets'), ('io.syn443.android.AssignedPolicyRuntimeContinuityTest', 'signedPureLeaseUsesWorkerAuthorityAndCurrentReceiptWithoutHandlerHashing'), ('io.syn443.android.AssignedPolicyRuntimeContinuityTest', 'missingCorruptAndMalformedAnchorKeepStrictEnvelopeIdentityAndParentPermission'), ('io.syn443.android.AssignedPolicyRuntimeContinuityTest', 'preparedBindingsFenceBootDeadlineClockRawLoginAndCurrentTicket'), ('io.syn443.android.AssignedPolicyRuntimeContinuityTest', 'stagedCandidateCannotRunAndApplyingBindingUsesParentActivationDeadline'), ('io.syn443.android.AssignedPolicyRuntimeContinuityTest', 'sameTicketPreparedReplacementCannotLeakStaleAnchorBinding'), ('io.syn443.android.AssignedPolicyRuntimeContinuityTest', 'selectedAAndPendingBReceiptSurvivePureRenewalWithSingleNativeAcknowledgement'), ('io.syn443.android.AssignedPolicyRuntimeContinuityTest', 'signerAnchorAndNonLeaseFieldsResetScopeAndDiscardOldPendingProof'), ('io.syn443.android.AssignedPolicyRuntimeContinuityTest', 'downgradeScopeModeAndBootCannotBorrowStableExecutionOrReviveOwner'), ('io.syn443.android.AssignedPolicyRuntimeContinuityTest', 'persistedAnchorFingerprintExcludesFloorsButRotatesAndCorruptionFailsClosed')]}
if mode in CONTINUITY_REQUIRED:
    assert set(CONTINUITY_REQUIRED[mode]) <= set(identities), "Missing actual policy/search continuity outcomes"


# Passive symptoms request a budgeted fresh check and never establish failure.
RECOVERY_RESERVE_REQUIRED = {'jvm': [('io.syn443.decision.AdaptiveProbeBudgetTest', 'routineSixLeavesTwoRecoveryStartsAndMinuteBoundaryRemainsStrict'), ('io.syn443.decision.AdaptiveProbeBudgetTest', 'repeatedReadinessAndCpuQuantaDoNotChargeOrRelaxFiveSecondSpacing'), ('io.syn443.decision.AdaptiveProbeBudgetTest', 'routineNinetySixReservesHourCapacityButTotalOneTwentyEightStillCapsAllWork'), ('io.syn443.decision.AdaptiveProbeBudgetTest', 'sixteenGroupsCanMaintainContinuouslyAndRecoverAtOldFifteenMinuteThirtySixSecondExhaustion'), ('io.syn443.decision.AdaptiveProbeBudgetTest', 'invalidOrBackwardBootTimePermanentlySealsWithoutRefillingHistory'), ('io.syn443.decision.AdaptiveProbeBudgetTest', 'cadenceIsBoundedAndDiagnosticsNeverExposeAdmissionHistory')], 'emulator': [('io.syn443.android.AdaptiveRecoveryAdmissionTest', 'sixteenHealthyGroupsReserveRecoveryAfterNinetySixForcedRoutineStarts'), ('io.syn443.android.AdaptiveRecoveryAdmissionTest', 'malformedStaleForeignAndOldABASelectionHintsCannotChangeRoutesOrStartWork'), ('io.syn443.android.AdaptiveRecoveryAdmissionTest', 'duplicateHeartbeatsDoNotRequeueACompletedHintOrGrantMissingACKToken'), ('io.syn443.android.AdaptiveRecoveryAdmissionTest', 'busyAndPendingNativeOwnersKeepOneAdmissionAndHungOwnerRequiresRetirement'), ('io.syn443.android.AdaptiveRecoveryAdmissionTest', 'wrongSelectedReceiptCannotMintTokenOrReadinessAndValidACKIsConsumedOnce'), ('io.syn443.android.AdaptiveRecoveryAdmissionTest', 'sixteenGroupsSustainTwoHoursOfPacedMaintenanceWithRecoveryCapacity'), ('io.syn443.android.AdaptiveRecoveryAdmissionTest', 'forceAndRealContextChangesPreserveMinuteAdmissionDebt')]}
if mode in RECOVERY_RESERVE_REQUIRED:
    assert set(RECOVERY_RESERVE_REQUIRED[mode]) <= set(identities), "Missing actual recovery reserve and passive-hint outcomes"


ADMIN_BROWSER_REQUIRED = [('io.syn443.android.AdminPanelBrowserTest', 'currentDeviceTargetBuildsDarkTitledCustomTabWithoutCredentialExtras'), ('io.syn443.android.AdminPanelBrowserTest', 'malformedOriginAndNoncanonicalDeviceCannotBecomeNavigationTarget'), ('io.syn443.android.AdminPanelBrowserTest', 'completeTargetRejectsInjectedPathQueryAuthorityAndFragment'), ('io.syn443.android.AdminPanelBrowserTest', 'unavailableBrowserFailsOneExactCustomTabLaunchWithoutAuthorityFallback'), ('io.syn443.android.LoginControllerTest', 'administrationEntryUsesTrustedMetadataAndCannotOutliveItsLoginGeneration'), ('io.syn443.android.LoginControllerTest', 'cancelledPrequeuePanelDiscoveryCannotExposeOldGenerationTarget')]
if mode=="emulator":
    assert set(ADMIN_BROWSER_REQUIRED) <= set(identities), "Missing trusted current-device admin navigation outcomes"

# Signed administrative discovery is separate from device/bootstrap/session authority.
ADMIN_BOOTSTRAP_REQUIRED = {
    "identity": [("io.syn443.identity.BootstrapTrustTest", name) for name in {
        "signedAdminMetadataPreservesLegacyBytesAndDeviceBootstrapAuthority",
        "signedAdminMetadataIsBoundToSignatureRevisionAndDescriptorExpiry",
        "sharedAdminBootstrapVectorsRequireClosedSignedMetadataAndExactLegacyBytes",
    }],
    "emulator": [("io.syn443.android.BootstrapTrustStoreTest", name) for name in {
        "adminDescriptorCacheIsEncryptedProjectionBoundAndIndependentOfDeviceAuthority",
        "removedAdminMetadataAndCacheReplayCannotBypassCommittedRevisionOrRetiredRoot",
        "adminCacheExpiryAbsenceAndOversizeFailClosedWithoutChangingDeviceJournal",
    }],
}
if mode in ADMIN_BOOTSTRAP_REQUIRED:
    assert set(ADMIN_BOOTSTRAP_REQUIRED[mode]) <= set(identities), "Missing signed administrative metadata trust outcomes"

# The native administrative core has its own identity/key/session and no app UI exposure.
ADMIN_AUTH_REQUIRED = {
    ("io.syn443.identity.AdminIdentityTest", name) for name in {
        "administrativeAuthorityBindsMetadataAndServiceWithoutConstructingDeviceBootstrap",
        "browserAuthorizationUsesFixedAdministrativeCallbackScopePkceAndDpopKey",
        "callbackShapeRejectsDeviceForeignDuplicateInjectedAndMalformedResponses",
        "pendingAuthorityKeyGenerationBootClockAndFiveMinuteBoundaryAreIndependentFences",
        "validatedOauthDenialIsConsumedRedactedAndNeverBecomesCredentials",
    }
} | {
    ("io.syn443.identity.AdminProtocolTest", name) for name in {
        "administrativeDiscoveryPinsKeycloakEndpointsAlgorithmsAndHttpsDateBeforeTokenDispatch",
        "codeExchangeAndRefreshUseSeparatePkceDpopAndNeverExtendOriginalEightHourLease",
        "refreshAllowsMissingIdTokenButRejectsChangedSubjectNonceAudienceOrKey",
        "optionalIdTokenAccessHashMustMatchBothInitialAndRotatedAccessTokens",
        "refreshMustRotateItsPairAndCanOnlyShortenTheRemainingSessionLease",
        "signedTokenSubstitutionsCannotTurnDeviceAudienceOrForeignClaimsIntoAdminAuthority",
        "tokenReplyTypesBoundsDuplicateJsonSignatureAndExpiryConsistencyAreRequired",
        "issuerNonceChallengeIsOneRetryWithFreshProofAndIdenticalCodeRequest",
        "refreshNonceChallengeKeepsOneDispatchOwnerAndMissingOrStaleChallengeCannotRetry",
        "uncertainRefreshTransportPermanentlyRetiresPairInsteadOfReplayingIt",
        "cancellationBeforeDispatchRetainsPairButLateCancellationRequiresNewAuthentication",
        "callbackReplayGenerationBootAndDeadlineCannotDispatchAuthorizationCode",
        "bootClockOrPendingExpiryDuringProofCannotDispatchExpiredCodeOrRefresh",
        "issuerAndSessionCannotCrossAdministrativeAuthorityOrSeparateDpopKey",
        "expiredSessionBootRollbackAndStaleHttpsDateCannotResurrectCredentials",
        "concurrentRefreshHasOneOwnerAndLocalLogoutDoesNotCallServerOrDeviceIdentity",
        "localLogoutClosesTheFamilyDuringInflightRefreshAndAcrossCompletedRotations",
        "cancelledOrRebootedDiscoveryAndMalformedKeysNeverReturnAdministrativeState",
    }
}
if mode == "identity":
    assert len(ADMIN_AUTH_REQUIRED) == 23 and ADMIN_AUTH_REQUIRED <= set(identities), "Missing separate administrative OAuth identity outcomes"
    verify_classes(root/"core/identity/build/reports/jacoco/test/jacocoTestReport.xml", {
        "io.syn443.identity.AdminIdentity", "io.syn443.identity.AdminIdentity.Companion", "io.syn443.identity.AdminPending",
        "io.syn443.identity.AdminProtocol", "io.syn443.identity.AdminIssuerState", "io.syn443.identity.AdminSession",
        "io.syn443.identity.AdminSessionFamily", "io.syn443.identity.AdminLogout",
    })

# Current signed administrative admission and controller-owned RAM budget.
ADMIN_DISCOVERY_REQUIRED = {'identity': [('io.syn443.identity.AdminDiscoveryTest', 'signedDiscoveryRequiresTheExactCommittedFloorAndFullDeviceProjection'), ('io.syn443.identity.AdminDiscoveryTest', 'metadataRevisionAndTrustRootBindDiscoveryWithoutChangingDeviceBootstrapAuthority'), ('io.syn443.identity.AdminDiscoveryTest', 'absentExpiredTamperedAndUncommittedDescriptorsCannotProduceDiscoveryTickets'), ('io.syn443.identity.AdminDiscoveryTest', 'publicFactoryRequiresSuccessfulFreshDiscoveryBeforeBrowserAuthorization'), ('io.syn443.identity.AdminDiscoveryTest', 'missingChangedOrThrowingDiscoverySourcesFailClosedButLogoutStaysLocal'), ('io.syn443.identity.AdminDiscoveryTest', 'metadataChangeDuringActualDpopSigningCannotDispatchAuthorizationCode'), ('io.syn443.identity.AdminDiscoveryTest', 'changedInflightHttpOrPostJwtTrustCannotPublishSessionOrReplayRefresh'), ('io.syn443.identity.AdminDiscoveryTest', 'entireTrustedWindowRejectsExpiryEvenWhileStoreWallSecondsStillAcceptTheTicket'), ('io.syn443.identity.AdminDiscoveryTest', 'rediscoveryKeepsExplicitAndLastGoodSameBootFloorsAndNeverRevivesOldOwners'), ('io.syn443.identity.AdminDiscoveryTest', 'ownedTicketAndGuardDiagnosticsNeverRevealMetadataOrBinding'), ('io.syn443.identity.AdminDiscoveryTest', 'completedDiscoveryClockPublicationCannotOverwriteANewerSameBootFloor')], 'emulator': [('io.syn443.android.BootstrapTrustStoreTest', 'adminDiscoveryTicketMatchesOneVerifiedSnapshotAndLeavesDeviceJournalUnchanged'), ('io.syn443.android.BootstrapTrustStoreTest', 'signedAdminRevisionChangesDiscoveryBindingWithoutChangingDeviceIdentity'), ('io.syn443.android.BootstrapTrustStoreTest', 'adminDiscoveryRejectsAbsentRemovedExpiredForeignCorruptAndRetiredRootSnapshots'), ('io.syn443.android.ManagedAdaptiveRoutesFairnessTest', 'sharedControllerBudgetSurvivesCoordinatorRecreationWithMinuteDebtAndPendingScopeFences'), ('io.syn443.android.ManagedAdaptiveRoutesFairnessTest', 'sharedControllerBudgetRetainsRoutineReserveAndRollingHourAcrossNativeRecreation'), ('io.syn443.android.ManagedAdaptiveRoutesFairnessTest', 'sharedControllerBudgetKeepsSpacingAndClockSealWhileIndependentFixturesRemainIsolated')]}
if mode in ADMIN_DISCOVERY_REQUIRED:
    assert set(ADMIN_DISCOVERY_REQUIRED[mode]) <= set(identities), "Missing current admin discovery or controller-owned budget outcomes"

# Native administrative owner, private Control API and UI are separate from the VPN identity.
NATIVE_ADMIN_REQUIRED = {'identity': [('io.syn443.identity.AdminControlTest', 'threeReadActionsBindExactSignedOriginBodyAccessTokenAndFreshDpopProofs'), ('io.syn443.identity.AdminControlTest', 'paginationRequiresAtMostThirtyTwoUniqueOrderedDevicesAndExactContinuation'), ('io.syn443.identity.AdminControlTest', 'configurationPreservesTheEntireUtf8ReplyAndRejectsMismatchedOuterMetadata'), ('io.syn443.identity.AdminControlTest', 'runtimeReadsValidateRequestedIdentityReportClockAndRecentStaleNoneSemantics'), ('io.syn443.identity.AdminControlTest', 'expiredAccessCannotUseAnOtherwiseLiveRefreshFamilyOrStartAHiddenRefresh'), ('io.syn443.identity.AdminControlTest', 'foreignKeyBootClockLogoutConsumedAndUnguardedOwnersCannotSendControlRequests'), ('io.syn443.identity.AdminControlTest', 'revokedTrustDuringSigningOrResponseCannotDispatchOrPublishARead'), ('io.syn443.identity.AdminControlTest', 'cancellationAndLogoutDuringReadNeverPublishDataOrConsumeRefreshOwnership'), ('io.syn443.identity.AdminControlTest', 'finiteServerErrorsAndDpopNonceChallengesNeverRetryOrRotateTokens'), ('io.syn443.identity.AdminControlTest', 'replyBoundsDuplicateJsonWrongContentAndStaleDatesCannotReachThePrivateMailbox'), ('io.syn443.identity.AdminControlTest', 'newApiClockCanRejectAccessButCannotExtendLeaseOrRollBackItsAcceptedFloor'), ('io.syn443.identity.AdminControlTest', 'configurationInventoryAcceptsWideLayersAnd4096EffectiveOriginsWithoutTruncation'), ('io.syn443.identity.AdminControlTest', 'configurationJsonKeepsExactBoundsGrammarAndUnrelatedParserLimits')], 'emulator': [('io.syn443.android.AdminControllerTest', 'signedAdminLoginAndThreePrivateReadsKeepDeviceVpnAndPublicStatusUnchanged'), ('io.syn443.android.AdminControllerTest', 'foreignCallbackPreservesUnusedAttemptWhileDenialAndCodeReplayNeverReuseCredentials'), ('io.syn443.android.AdminControllerTest', 'revokedContextAfterRealSignedCodeDispatchCannotPublishLateSessionOrAdmitAnotherOwner'), ('io.syn443.android.AdminControllerTest', 'logoutDuringBlockedRotatingRefreshRetainsBusyUntilActualExitAndRejectsItsLatePair'), ('io.syn443.android.AdminControllerTest', 'exactReadCancellationAndMailboxExpiryNeverReleaseABlockedOwnerOrRetireAValidSession'), ('io.syn443.android.AdminControllerTest', 'recreatedReservedBrowserAuthenticatedAndRetiringRecordsRequireFreshOwnedKeyRetirement'), ('io.syn443.android.AdminControllerTest', 'corruptOrMissingAdminAesKeyNeverResetsTheJournalOrCreatesANewOwner'), ('io.syn443.android.AdminControllerTest', 'dueRefreshRotatesOnceWhileUncertainDeliveryCannotReplayTheOldPair'), ('io.syn443.android.AdminControllerTest', 'readDenialAndTransportFailurePreserveValidSessionButUnauthorizedReadRetiresIt'), ('io.syn443.android.AdminControllerTest', 'browserHandoffsExpireConsumeOnceAndCancelOnlyTheirBlockedFreshAuthorization'), ('io.syn443.android.AdminControllerTest', 'bootClockRollbackAndNewDeviceContextCannotBorrowAnAuthenticatedOwner'), ('io.syn443.android.AdminControllerTest', 'cancelledPublicationOfAnAlreadyReturnedRefreshRetiresItsConsumedFamilyImmediately'), ('io.syn443.android.AdminKeyJournalTest', 'adminOwnershipRetirementDeletesOnlyItsPersistedKeyAndPreservesDeviceSentinel'), ('io.syn443.android.AdminKeyJournalTest', 'recreatedAdminPhaseRecordsContainNoCredentialsAndRequireExplicitOwnedRetirement'), ('io.syn443.android.AdminKeyJournalTest', 'adminJournalCasRejectsStaleWritersInvalidCountersAliasesAndPhaseShortcuts'), ('io.syn443.android.AdminKeyJournalTest', 'adminJournalCiphertextRejectsTamperingTruncationOversizeAndForeignNamespace'), ('io.syn443.android.AdminKeyJournalTest', 'missingAdminAesKeyAndOrphanedAtomicWritesNeverResetOwnership'), ('io.syn443.android.AdminKeyJournalTest', 'adminKeystoreAndJournalRejectMainBinderWorkAndForeignAliases'), ('io.syn443.android.AdminKeyJournalTest', 'cancelledAdminKeyCreationCannotOutrunPersistedRetirementOrRecreateItsAlias'), ('io.syn443.android.AdminNativeUiTest', 'signedOutOffersSeparateAdminLoginAndFullPanelWithoutVpnActions'), ('io.syn443.android.AdminNativeUiTest', 'authorizedPageUsesExplicitNextCursorAndReadOnlyDeviceSelection'), ('io.syn443.android.AdminNativeUiTest', 'configurationAndStaleRuntimeStayReadOnlyCollapsedAndExplicitlyLastReported'), ('io.syn443.android.AdminNativeUiTest', 'busyReadBlocksAnotherReadButLeavesAdministrativeLogoutAvailable'), ('io.syn443.android.AdminNativeUiTest', 'unknownErrorsRenderFiniteRussianTextWithoutRawControllerReason'), ('io.syn443.android.AdminNativeUiTest', 'documentDecoderBoundsUtf8AndSplitsFullTextOffMainWithoutBreakingSurrogates'), ('io.syn443.android.AdminNativeUiTest', 'devicePageDecoderKeepsThirtyTwoRowBoundOrderingAndCursor'), ('io.syn443.android.AdminLoginBrowserTest', 'trustedControllerAdminLoginUsesDarkTitledCustomTabWithoutAppHeaders'), ('io.syn443.android.AdminLoginBrowserTest', 'unsafeOriginsInjectedFieldsDeviceCallbacksAndWeakProofsNeverBecomeBrowserIntents'), ('io.syn443.android.AdminLoginBrowserTest', 'explicitSeparateIssuerIsPreservedWithoutDeviceOrWebPanelFallback'), ('io.syn443.android.AdminLoginBrowserTest', 'unavailableBrowserAttemptsOneExactCustomTabAndDoesNotFallback'), ('io.syn443.android.AdminEntryControlsTest', 'separateAdminAccountDoesNotRequireWebGrantAndStaysCollapsedByDefault'), ('io.syn443.android.AdminEntryControlsTest', 'currentWebGrantShowsHomeShortcutAndUnprovisionedAccountCannotOfferSeparateLogin'), ('io.syn443.android.LoginControllerTest', 'signedAdminDiscoveryContextPreservesDeviceIdentityAndFencesTrustAndReauthentication'), ('io.syn443.android.LoginControllerTest', 'adminDiscoveryContextRejectsMainAndBinderNamedThreadsWithoutChangingDeviceState')]}
if mode in NATIVE_ADMIN_REQUIRED:
    assert set(NATIVE_ADMIN_REQUIRED[mode]) <= set(identities), "Missing native administrative ownership, API, storage or UI outcomes"
