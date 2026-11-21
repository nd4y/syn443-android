pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        maven("https://maven-central.storage-download.googleapis.com/maven2/") {
            name = "GoogleHostedMavenCentral"
            content {
                includeVersion("com.journeyapps", "zxing-android-embedded", "4.3.0")
                for (module in listOf("mockwebserver3", "mockwebserver3-jvm", "okhttp", "okhttp-android", "okhttp-jvm", "okhttp-tls")) {
                    includeVersion("com.squareup.okhttp3", module, "5.5.1")
                }
            }
        }
        mavenCentral()
    }
}
rootProject.name = "SYN443"
include(":core:decision", ":core:host-lifecycle", ":core:recovery", ":core:policy", ":core:observability", ":core:health", ":core:identity", ":app")

