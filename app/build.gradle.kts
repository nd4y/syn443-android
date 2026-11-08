import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty

plugins {
    id("com.android.application")
    kotlin("plugin.serialization")
    id("org.jetbrains.kotlin.plugin.compose")
}
abstract class PrototypeAssets : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputFile: RegularFileProperty
    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty
    @TaskAction fun generate() {
        val output=outputDirectory.get().asFile
        output.mkdirs()
        output.resolve("decision-vectors.json").writeBytes(inputFile.get().asFile.readBytes())
    }
}
// Runtime uses only the decision example. Wire/signature evidence remains a JVM test resource.
val prototypeAssets = tasks.register<PrototypeAssets>("preparePrototypeAssets") {
    inputFile.set(rootProject.layout.projectDirectory.file("contracts/v1/decision-vectors.json"))
    outputDirectory.set(layout.buildDirectory.dir("generated/prototypeAssets"))
}
androidComponents.onVariants { variant ->
    variant.sources.assets?.addGeneratedSourceDirectory(prototypeAssets, PrototypeAssets::outputDirectory)
}
val enrollmentLinkHost = providers.environmentVariable("SYN443_ENROLLMENT_LINK_HOST").orElse("").get()
    .ifBlank { "links.example.invalid" }
val installationProfile = providers.environmentVariable("SYN443_INSTALLATION_PROFILE").orElse("").get()
require(installationProfile.length <= 12_000 && installationProfile.matches(Regex("[A-Za-z0-9_-]*"))) {
    "SYN443_INSTALLATION_PROFILE must be a bounded base64url profile"
}
val dnsLabel = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
require(enrollmentLinkHost.length <= 253 && enrollmentLinkHost.matches(Regex("(?:$dnsLabel\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"))) {
    "SYN443_ENROLLMENT_LINK_HOST must be a lowercase public DNS hostname"
}
android {
    namespace = "io.syn443.android"
    compileSdk = 37
    defaultConfig {
        applicationId = "io.syn443.android"
        minSdk = 29
        targetSdk = 37
        versionCode = 68
        versionName = "0.9.40-policy-retry-deadline"
        testInstrumentationRunner = "io.syn443.android.EnrollmentDriver"
        manifestPlaceholders["enrollmentLinkHost"] = enrollmentLinkHost
        buildConfigField("String", "ENROLLMENT_LINK_HOST", "\"$enrollmentLinkHost\"")
        buildConfigField("String", "INSTALLATION_PROFILE", "\"$installationProfile\"")
    }
    buildFeatures { compose = true; aidl = true; buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions { animationsDisabled = true }
    lint { abortOnError = true; warningsAsErrors = true }
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencies {
    implementation(project(":core:identity"))
    implementation(project(":core:health"))
    implementation(project(":core:observability"))
    implementation(project(":core:policy"))
    implementation(project(":core:host-lifecycle"))
    implementation(project(":core:recovery"))
    implementation(files(rootProject.file("native/build/engine.aar")))
    implementation(project(":core:decision"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("com.google.zxing:core:3.5.4")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    implementation("androidx.media3:media3-transformer:1.11.1")
    implementation("androidx.media3:media3-effect:1.11.1")
    androidTestImplementation(platform("androidx.compose:compose-bom:2026.09.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    // Compose UI 1.12.1 transitively requests Espresso 3.5.0, incompatible with API 37.
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

