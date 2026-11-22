package io.syn443.android

import android.content.pm.PackageManager
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.update.UpdateActivity
import io.syn443.android.update.VerifiedUpdate
import io.syn443.identity.ReleaseArtifact
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

class VerifiedUpdateTest {
    @get:Rule val compose = createAndroidComposeRule<UpdateActivity>()

    @Test fun updateScreenShowsInstalledBuildAndCannotInstallWithoutAnAcceptedOffer() {
        compose.onNodeWithText("Установлена версия " + BuildConfig.VERSION_NAME).assertIsDisplayed()
        compose.onNodeWithText("Перейти к установке").assertDoesNotExist()
        if (BuildConfig.INSTALLATION_PROFILE.isEmpty()) {
            compose.onNodeWithText("В этой сборке канал обновлений не настроен.").assertIsDisplayed()
            compose.onNodeWithText("Выбрать манифест обновления").assertDoesNotExist()
        }
    }

    @Suppress("DEPRECATION")
    @Test fun packageManagerRechecksRealPackageSignerSdkAndEmbeddedAbiHashes() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val file = File(context.applicationInfo.sourceDir)
        val local = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val cert = checkNotNull(local.signingInfo).apkContentsSigners.single().toByteArray().inputStream().use(::hash)
        val libs = ZipFile(file).use { zip ->
            zip.entries().asSequence().mapNotNull { entry ->
                val match = Regex("lib/([^/]+)/libgojni[.]so").matchEntire(entry.name) ?: return@mapNotNull null
                match.groupValues[1] to zip.getInputStream(entry).use(::hash)
            }.toMap()
        }
        assertEquals(setOf("arm64-v8a", "x86_64"), libs.keys)
        val digest = "0".repeat(64)
        val apk = ReleaseArtifact(context.packageName, local.longVersionCode, context.applicationInfo.minSdkVersion,
            context.applicationInfo.targetSdkVersion, libs, digest, file.length(), "a".repeat(40), digest, digest)
        val verifier = VerifiedUpdate(context)
        verifier.verifyArchive(file, apk, cert)
        assertThrows(Exception::class.java) { verifier.verifyArchive(file, apk, digest) }
        assertThrows(Exception::class.java) { verifier.verifyArchive(file, apk.copy(versionCode=apk.versionCode+1), cert) }
        assertThrows(Exception::class.java) { verifier.verifyArchive(file, apk.copy(nativeLibraries=libs.mapValues { digest }), cert) }
    }
    private fun hash(input: InputStream): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(65_536)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            md.update(buffer, 0, count)
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
