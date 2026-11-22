package io.syn443.android.update

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import androidx.core.content.FileProvider
import io.syn443.android.BuildConfig
import io.syn443.android.vpn.SealedFile
import io.syn443.identity.*
import io.syn443.policy.Canonical
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

class UpdatePackageProvider : FileProvider()

internal class UpdateOffer(val envelope: String, val release: ApprovedRelease, val binding: String, val policy: String)
internal class StagedUpdate(val offer: UpdateOffer, val file: File) : AutoCloseable {
    override fun close() { file.delete() }
}

/** Called from an IO worker in the application's ordinary UI process. */
internal class VerifiedUpdate(private val context: Context) {
    companion object {
        private val journalLock = Any()
        private const val MIME = "application/vnd.android.package-archive"
    }

    private val apkDirectory = File(context.cacheDir, "verified-updates")
    private val authority by lazy { requireNotNull(BootstrapTrust.installationProfile(BuildConfig.INSTALLATION_PROFILE).releaseAuthority) }
    private val pm = context.packageManager
    @Suppress("DEPRECATION")
    private fun installedPackage(): PackageInfo = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)

    private fun signer(info: PackageInfo): String {
        val signing = checkNotNull(info.signingInfo)
        require(!signing.hasMultipleSigners())
        val bytes = signing.apkContentsSigners.single().toByteArray()
        return MessageDigest.getInstance("SHA-256").digest(bytes).toHex()
    }

    private fun floorStore(scope: ReleaseScope): SealedFile {
        // A certificate change cannot silently reset the persisted revision for this enrollment and channel.
        val namespace = listOf(scope.serviceId, scope.deviceId, scope.channel).joinToString("\n")
        return SealedFile(context, "apk-release-" + Identity.hash(namespace.toByteArray(Charsets.US_ASCII)))
    }

    fun readEnvelope(uri: Uri): String {
        require(uri.scheme == "content")
        return checkNotNull(context.contentResolver.openInputStream(uri)).use { input ->
            val buffer = ByteArray(BootstrapTrust.MAX_MANIFEST + 2)
            var size = 0
            while (size < buffer.size) {
                val count = input.read(buffer, size, buffer.size - size)
                if (count == -1) break
                require(count > 0)
                size += count
            }
            require(size in 1 until buffer.size && buffer.take(size).all { it.toInt() in 0..127 })
            String(buffer, 0, size, Charsets.US_ASCII).removeSuffix("\n")
        }
    }

    fun preview(envelope: String): UpdateOffer = synchronized(journalLock) {
        val remote = checkNotNull(context.contentResolver.call(Uri.parse("content://io.syn443.control"), "release-context", null, null))
        require(remote.getBoolean("ok"))
        val local = installedPackage()
        val installedCertificate = checkNotNull(local.signingInfo).apkContentsSigners.single().toByteArray()
        val signingKey = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(installedCertificate.inputStream()).publicKey.encoded
        require(!signingKey.contentEquals(java.util.Base64.getDecoder().decode(authority.anchor.spki)))
        val scope = ReleaseScope(authority.serviceId, checkNotNull(remote.getString("device")), authority.channel, signer(local))
        val installed = InstalledReleaseContext(local.longVersionCode, android.os.Build.VERSION.SDK_INT,
            android.os.Build.SUPPORTED_ABIS.toList(), checkNotNull(remote.getStringArrayList("capabilities")),
            checkNotNull(remote.getString("evaluator")), checkNotNull(remote.getString("schema")))
        val prior = floorStore(scope).read(rejectAbandonedWrite = true)?.let { Canonical.json.decodeFromString<ReleaseFloor>(it) }
        val approved = ReleaseAdmission.verify(envelope, authority.anchor, scope, installed, prior,
            TimeWindow(remote.getLong("lowerMs"), remote.getLong("upperMs")))
        UpdateOffer(envelope, approved, checkNotNull(remote.getString("binding")), checkNotNull(remote.getString("policy")))
    }

    private fun revalidate(offer: UpdateOffer): UpdateOffer = preview(offer.envelope).also {
        require(it.binding == offer.binding && it.policy == offer.policy && it.release.floor == offer.release.floor)
    }

    fun stage(offer: UpdateOffer, apkUri: Uri): StagedUpdate {
        require(apkUri.scheme == "content" && apkUri.authority != "io.syn443.update.apk")
        revalidate(offer)
        require(apkDirectory.isDirectory || apkDirectory.mkdir())
        val file = File.createTempFile("candidate-", ".apk", apkDirectory)
        try {
            checkNotNull(context.contentResolver.openInputStream(apkUri)).use { source ->
                file.outputStream().use { target -> offer.release.verifyBytes(source, target); target.fd.sync() }
            }
            require(file.setReadOnly())
            verifyArchive(file, offer.release.apk, offer.release.floor.scope.signerCertificateSha256)
            revalidate(offer)
            return StagedUpdate(offer, file)
        } catch (e: Throwable) {
            file.delete()
            throw e
        }
    }

    @Suppress("DEPRECATION")
    internal fun verifyArchive(file: File, apk: ReleaseArtifact, signerCertificate: String) {
        val info = checkNotNull(pm.getPackageArchiveInfo(file.path, PackageManager.GET_SIGNING_CERTIFICATES))
        val app = checkNotNull(info.applicationInfo)
        require(info.packageName == context.packageName && info.packageName == apk.packageName &&
            info.longVersionCode == apk.versionCode && app.minSdkVersion == apk.minSdk && app.targetSdkVersion == apk.targetSdk &&
            signer(info) == signerCertificate)
        ZipFile(file).use { zip ->
            val native = mutableMapOf<String, String>()
            val lib = Regex("lib/([^/]+)/libgojni[.]so")
            require(zip.size() <= 65_535)
            for (entry in zip.entries()) {
                val abi = lib.matchEntire(entry.name)?.groupValues?.get(1) ?: continue
                require(abi in apk.nativeLibraries && abi !in native && entry.size in 1..(128L shl 20))
                native[abi] = zip.getInputStream(entry).use { hashSized(it, entry.size) }
            }
            require(native == apk.nativeLibraries)
        }
    }

    private fun hashSized(stream: InputStream, size: Long): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        var remaining = size
        while (remaining > 0) {
            val read = stream.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            require(read > 0)
            digest.update(buffer, 0, read)
            remaining -= read
        }
        require(stream.read() == -1)
        return digest.digest().toHex()
    }

    @Suppress("DEPRECATION")
    fun installer(update: StagedUpdate): Intent {
        require(pm.canRequestPackageInstalls() && update.file.parentFile == apkDirectory && update.file.isFile)
        update.file.inputStream().use { update.offer.release.verifyBytes(it) }
        val uri = FileProvider.getUriForFile(context, "io.syn443.update.apk", update.file)
        val intent = Intent(Intent.ACTION_VIEW).setDataAndType(uri, MIME).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        val flags = PackageManager.MATCH_DEFAULT_ONLY or PackageManager.MATCH_SYSTEM_ONLY
        val system = pm.resolveActivity(intent, flags)?.activityInfo ?: error("No Android installer")
        require(pm.queryIntentActivities(intent, flags).any { it.activityInfo.packageName == system.packageName && it.activityInfo.name == system.name })
        intent.component = ComponentName(system.packageName, system.name)
        synchronized(journalLock) {
            val current = revalidate(update.offer)
            val floor = floorStore(current.release.floor.scope)
            val raw = Canonical.json.encodeToString(current.release.floor)
            if (floor.read(rejectAbandonedWrite = true) != raw) {
                floor.write(raw)
                check(floor.read(rejectAbandonedWrite = true) == raw)
            }
        }
        return intent
    }

    fun pruneAbandoned(now: Long = System.currentTimeMillis()) {
        // A process can disappear between the system handoff and its callback.
        apkDirectory.listFiles()?.filter { it.isFile && it.name.matches(Regex("candidate-[0-9]+[.]apk")) &&
            it.lastModified() in 1 until (now - 24 * 60 * 60_000L) }?.forEach { it.delete() }
    }
}

private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
