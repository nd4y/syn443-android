plugins { kotlin("jvm"); kotlin("plugin.serialization"); jacoco }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
dependencies {
    implementation(project(":core:policy"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
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
        includes = listOf("io.syn443.identity.Identity", "io.syn443.identity.Bootstrap", "io.syn443.identity.Pending",
            "io.syn443.identity.BoundedHttp", "io.syn443.identity.BoundedHttpKt", "io.syn443.identity.BoundedHttp.Scope", "io.syn443.identity.AuthProtocol", "io.syn443.identity.IdentityScope",
            "io.syn443.identity.TrustedTime", "io.syn443.identity.TrustedTime.Companion",
            "io.syn443.identity.IdentityOperation", "io.syn443.identity.IdentityOperation.Companion",
            "io.syn443.identity.LoginRecovery", "io.syn443.identity.LoginIntent", "io.syn443.identity.RegistrationTombstone",
            "io.syn443.identity.LoginPayload", "io.syn443.identity.LoginPayload.Companion",
            "io.syn443.identity.Assignments", "io.syn443.identity.AssignmentIdentity", "io.syn443.identity.AssignmentState", "io.syn443.identity.AssignmentPermit", "io.syn443.identity.ProvisioningRetry",
            "io.syn443.identity.BootstrapTrust", "io.syn443.identity.AuthenticatedInvite",
            "io.syn443.identity.InvitationProtocol", "io.syn443.identity.InvitationOperation", "io.syn443.identity.InvitationOperation.Companion",
            "io.syn443.identity.InvitationState", "io.syn443.identity.InvitationPending")
        limit { counter = "LINE"; minimum = "0.90".toBigDecimal() }
    } }
}
tasks.check { dependsOn(tasks.jacocoTestReport, tasks.jacocoTestCoverageVerification) }

// Keep evidence available even when the unchanged coverage gate rejects a build.
tasks.jacocoTestCoverageVerification { mustRunAfter(tasks.jacocoTestReport) }
