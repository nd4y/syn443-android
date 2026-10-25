pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "SYN443"
include(":core:decision", ":core:host-lifecycle", ":core:recovery", ":core:policy", ":core:observability", ":core:health", ":app")

