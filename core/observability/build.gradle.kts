plugins { kotlin("jvm"); jacoco }
kotlin { jvmToolchain(17) }
dependencies { testImplementation("junit:junit:4.13.2") }
jacoco { toolVersion = "0.8.13" }
tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports { xml.required.set(true); html.required.set(true) }
}
tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    violationRules { rule { limit { counter = "LINE"; minimum = "0.90".toBigDecimal() } } }
}
tasks.check { dependsOn(tasks.jacocoTestReport, tasks.jacocoTestCoverageVerification) }
