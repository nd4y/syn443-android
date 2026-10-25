plugins { kotlin("jvm"); kotlin("plugin.serialization"); jacoco }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
dependencies {
    implementation(project(":core:policy"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    testImplementation("junit:junit:4.13.2")
}
tasks.test { finalizedBy(tasks.jacocoTestReport) }
tasks.jacocoTestReport { dependsOn(tasks.test); reports { xml.required.set(true); html.required.set(true) } }
jacoco { toolVersion = "0.8.13" }
tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    violationRules { rule {
        element = "CLASS"
        includes = listOf("io.syn443.identity.Identity", "io.syn443.identity.Bootstrap", "io.syn443.identity.Pending")
        limit { counter = "LINE"; minimum = "0.90".toBigDecimal() }
    } }
}
tasks.check { dependsOn(tasks.jacocoTestReport, tasks.jacocoTestCoverageVerification) }
