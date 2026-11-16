plugins { id("com.android.application") }

// Independent diagnostic APK. No dependency or task edge to :app/native engines.
android {
    namespace = "io.syn443.emulatorheap"
    compileSdk = 37
    defaultConfig {
        applicationId = "io.syn443.emulatorheap"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "1-diagnostic-only"
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint { abortOnError = true; warningsAsErrors = true }
}
dependencies { testImplementation("junit:junit:4.13.2") }
