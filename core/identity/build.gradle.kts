plugins { kotlin("jvm"); kotlin("plugin.serialization"); jacoco }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
dependencies {
    implementation(project(":core:policy"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.13.0")
    testImplementation("junit:junit:4.13.2")
}
sourceSets { test { resources.srcDir(rootProject.file("contracts/v1")) } }
tasks.test { finalizedBy(tasks.jacocoTestReport) }
tasks.jacocoTestReport { dependsOn(tasks.test); reports { xml.required.set(true); html.required.set(true) } }
jacoco { toolVersion = "0.8.13" }
tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    violationRules { rule {
        element = "CLASS"
        includes = listOf("io.syn443.identity.ChatRefreshGate", "io.syn443.identity.Identity", "io.syn443.identity.Bootstrap", "io.syn443.identity.Pending",
            "io.syn443.identity.BoundedHttp", "io.syn443.identity.BoundedHttpKt", "io.syn443.identity.BoundedHttp.Scope", "io.syn443.identity.RuntimeObservation", "io.syn443.identity.RuntimeObservation.Report", "io.syn443.identity.RuntimeObservation.Snapshot", "io.syn443.identity.AuthProtocol", "io.syn443.identity.IdentityScope",
            "io.syn443.identity.TrustedTime", "io.syn443.identity.TrustedTime.Companion",
            "io.syn443.identity.AdminIdentity", "io.syn443.identity.AdminIdentity.Companion", "io.syn443.identity.AdminPending",
            "io.syn443.identity.AdminProtocol", "io.syn443.identity.AdminIssuerState", "io.syn443.identity.AdminSession",
            "io.syn443.identity.AdminSessionFamily", "io.syn443.identity.AdminLogout",
            "io.syn443.identity.AdminDiscovery", "io.syn443.identity.AdminDiscoveryGuard", "io.syn443.identity.AdminProtocol.Companion",
            "io.syn443.identity.AdminControl", "io.syn443.identity.AdminControl.Read", "io.syn443.identity.AdminActivation", "io.syn443.identity.AdminDeviceSummary", "io.syn443.identity.AdminDevicePage",
            "io.syn443.identity.AdminDeviceConfiguration", "io.syn443.identity.AdminRuntimeReport", "io.syn443.identity.AdminDeviceRuntime",
            "io.syn443.identity.AdminControlJson", "io.syn443.identity.AdminControlJson.Reader",
            "io.syn443.identity.AdminServiceDiscovery", "io.syn443.identity.AdminServiceDiscovery.Companion", "io.syn443.identity.AdminServiceManifest",
            "io.syn443.identity.AdminLayerControl", "io.syn443.identity.AdminLayerAction", "io.syn443.identity.AdminLayerEdit",
            "io.syn443.identity.AdminLayerRequest", "io.syn443.identity.AdminLayerExpected", "io.syn443.identity.AdminLayerProposal", "io.syn443.identity.AdminLayerReply",
            "io.syn443.identity.AdminLayerInventory", "io.syn443.identity.AdminLayerDraft", "io.syn443.identity.AdminLayerDraftSummary", "io.syn443.identity.AdminLayerDraftList",
            "io.syn443.identity.AdminLayerDiscarded", "io.syn443.identity.AdminLayerPublishedHead", "io.syn443.identity.AdminLayerPreview", "io.syn443.identity.AdminLayerJob",
            "io.syn443.identity.AdminLayerJson", "io.syn443.identity.AdminLayerJson.Reader", "io.syn443.identity.AdminLayerJson.Document", "io.syn443.identity.AdminLayerOwnership",
            "io.syn443.identity.IdentityOperation", "io.syn443.identity.IdentityOperation.Companion",
            "io.syn443.identity.LoginRecovery", "io.syn443.identity.LoginIntent", "io.syn443.identity.RegistrationTombstone",
            "io.syn443.identity.LoginPayload", "io.syn443.identity.LoginPayload.Companion", "io.syn443.identity.CapabilityNegotiation",
            "io.syn443.identity.Assignments", "io.syn443.identity.AssignmentIdentity", "io.syn443.identity.AssignmentState", "io.syn443.identity.AssignmentPermit", "io.syn443.identity.ProvisioningRetry",
            "io.syn443.identity.BootstrapTrust", "io.syn443.identity.AuthenticatedInvite",
            "io.syn443.identity.InvitationProtocol", "io.syn443.identity.InvitationOperation", "io.syn443.identity.InvitationOperation.Companion",
            "io.syn443.identity.InvitationState", "io.syn443.identity.InvitationPending",
            "io.syn443.identity.ManagedOverlay", "io.syn443.identity.OverlayAddress",
            "io.syn443.identity.OverlayCredentials", "io.syn443.identity.OverlayCredentialBinding", "io.syn443.identity.OverlaySetupSecret", "io.syn443.identity.OverlayOperation", "io.syn443.identity.OverlayEnrollment", "io.syn443.identity.OverlayEnrollments", "io.syn443.identity.OverlayAssignments")
        limit { counter = "LINE"; minimum = "0.90".toBigDecimal() }
    } }
}
tasks.check { dependsOn(tasks.jacocoTestReport, tasks.jacocoTestCoverageVerification) }

// Keep evidence available even when the unchanged coverage gate rejects a build.
tasks.jacocoTestCoverageVerification { mustRunAfter(tasks.jacocoTestReport) }
