plugins {
    kotlin("jvm")
    jacoco
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
dependencies { testImplementation("junit:junit:4.13.2") }
tasks.test { finalizedBy(tasks.jacocoTestReport) }
tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports { xml.required.set(true); html.required.set(true) }
}
tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    violationRules {
        rule {
            limit { counter = "LINE"; minimum = "0.95".toBigDecimal() }
            limit { counter = "BRANCH"; minimum = "0.90".toBigDecimal() }
        }
    }
}
tasks.check { dependsOn(tasks.jacocoTestCoverageVerification) }
jacoco { toolVersion = "0.8.13" }
