import groovy.json.JsonOutput
import groovy.json.JsonSlurper
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
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val engineLock: RegularFileProperty
    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty
    @TaskAction fun generate() {
        val output=outputDirectory.get().asFile
        output.mkdirs()
        output.resolve("decision-vectors.json").writeBytes(inputFile.get().asFile.readBytes())
        val lock = JsonSlurper().parse(engineLock.get().asFile) as Map<*, *>
        val sources = lock["sources"] as Map<*, *>
        fun revision(name: String): String {
            val value = (sources[name] as? Map<*, *>)?.get("revision") as? String
            require(value != null && value.matches(Regex("[a-f0-9]{40}"))) {
                "Missing or invalid embedded engine revision for $name"
            }
            return value
        }
        output.resolve("engine-builds.json").writeText(JsonOutput.toJson(linkedMapOf(
            "schemaVersion" to 1,
            "singBoxRevision" to revision("sing-box"),
            "netBirdRevision" to revision("netbird"),
        )))
    }
}
// Package the decision example and the public embedded engine build revisions.
val prototypeAssets = tasks.register<PrototypeAssets>("preparePrototypeAssets") {
    inputFile.set(rootProject.layout.projectDirectory.file("contracts/v1/decision-vectors.json"))
    engineLock.set(rootProject.layout.projectDirectory.file("native/engine-lock.json"))
    outputDirectory.set(layout.buildDirectory.dir("generated/prototypeAssets"))
}
androidComponents.onVariants { variant ->
    variant.sources.assets?.addGeneratedSourceDirectory(prototypeAssets, PrototypeAssets::outputDirectory)
}
if (providers.gradleProperty("syn443CiUpgrade").orNull == "true") {
    require(providers.environmentVariable("GITHUB_ACTIONS").orNull == "true")
    androidComponents.onVariants(androidComponents.selector().withBuildType("debug")) { variant ->
        variant.outputs.forEach { output -> output.versionCode.set(Math.addExact(output.versionCode.get(), 1)) }
    }
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
    compileSdk {
        version = release(37) {
            minorApiLevel = 1
        }
    }
    defaultConfig {
        applicationId = "io.syn443.android"
        minSdk = 29
        targetSdk = 37
        versionCode = 158
        versionName = "0.9.130-engine-builds"
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
    val composeBom = platform("androidx.compose:compose-bom:2026.11.01")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.browser:browser:1.10.0")
    implementation("androidx.work:work-multiprocess:2.12.0")
    implementation("com.google.zxing:core:3.5.4")
    implementation("com.google.re2j:re2j:1.8")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.13.0")
    implementation("androidx.media3:media3-transformer:1.11.1")
    implementation("androidx.media3:media3-effect:1.11.1")
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    // Compose UI 1.12.1 transitively requests Espresso 3.5.0, incompatible with API 37.
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("com.squareup.okhttp3:mockwebserver3:5.5.1")
    androidTestImplementation("com.squareup.okhttp3:okhttp-tls:5.5.1")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

