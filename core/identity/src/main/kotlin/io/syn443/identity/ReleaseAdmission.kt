package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

/** Public update authority distributed inside the installed APK. Incoming release files cannot replace it. */
@Serializable data class ReleaseAuthority(val serviceId: String, val channel: String, val anchor: TrustAnchor) {
    fun validate(installation: TrustAnchor, retired: TrustAnchor?) {
        val id = Regex("[A-Za-z0-9_-]{1,64}")
        require(id.matches(serviceId) && id.matches(channel) && anchor.lastTransition.isEmpty())
        BootstrapTrust.validateAnchor(anchor)
        for (other in listOfNotNull(installation, retired)) require(anchor.id != other.id && anchor.spki != other.spki)
    }

    fun appliesTo(bootstrap: Bootstrap): Boolean =
        serviceId == bootstrap.serviceId && anchor.id !in bootstrap.roots && anchor.spki !in bootstrap.roots.values

    override fun toString() = "ReleaseAuthority([redacted])"
}

@Serializable data class ReleaseScope(val serviceId: String, val deviceId: String, val channel: String,
    val signerCertificateSha256: String) {
    override fun toString() = "ReleaseScope([redacted])"
}
@Serializable data class ReleaseFloor(val scope: ReleaseScope, val rootEpoch: Long, val securityEpoch: Long,
    val revision: Long, val revocationFloor: Long, val payloadSha256: String)
@Serializable data class InstalledReleaseContext(val versionCode: Long, val sdk: Int, val abis: List<String>,
    val requiredEngineCapabilities: List<String>, val evaluator: String, val schema: String)
@Serializable data class ReleaseArtifact(@SerialName("package") val packageName: String, val versionCode: Long,
    val minSdk: Int, val targetSdk: Int, val nativeLibraries: Map<String, String>, val sha256: String,
    val bytes: Long, val sourceCommit: String, val engineLockSha256: String, val contractLockSha256: String)
@Serializable private data class Compatibility(val minimumInstalledVersionCode: Long, val engineCapabilities: List<String>,
    val evaluators: List<String>, val schemas: List<String>)
@Serializable private data class Manifest(val schemaVersion: Int, val audience: String, val scope: ReleaseScope,
    val rootEpoch: Long, val securityEpoch: Long, val revision: Long, val revocationFloor: Long, val issuedAt: Long,
    val notBefore: Long, val expires: Long, val apk: ReleaseArtifact, val compatibility: Compatibility)

class ApprovedRelease internal constructor(val apk: ReleaseArtifact, val floor: ReleaseFloor) {
    /** The caller owns the streams and discards any staged output on failure. */
    fun verifyBytes(input: InputStream, staged: OutputStream? = null) {
        val buffer = ByteArray(64 * 1024)
        val hash = MessageDigest.getInstance("SHA-256")
        var total = 0L
        while (total < apk.bytes) {
            val count = input.read(buffer, 0, minOf(buffer.size.toLong(), apk.bytes - total).toInt())
            require(count > 0)
            hash.update(buffer, 0, count)
            staged?.write(buffer, 0, count)
            total += count
        }
        require(input.read() == -1 && hash.digest().joinToString("") { "%02x".format(it) } == apk.sha256)
    }
}

object ReleaseAdmission {
    private const val SAFE = 9_007_199_254_740_991L
    private val id = Regex("[A-Za-z0-9_-]{1,64}")
    private val name = Regex("[A-Za-z0-9._-]{1,64}")
    private val sha = Regex("[0-9a-f]{64}")
    private val platforms = setOf("arm64-v8a", "x86_64")

    fun verify(envelope: String, anchor: TrustAnchor, expected: ReleaseScope, installed: InstalledReleaseContext,
               previous: ReleaseFloor?, time: TimeWindow): ApprovedRelease {
        val raw = BootstrapTrust.signed(envelope, "syn443-apk-release+jws", anchor)
        val manifest = Canonical.json.decodeFromString<Manifest>(raw)
        require(Canonical.encode(Canonical.parse(Canonical.json.encodeToString(manifest))) == raw)
        require(manifest.schemaVersion == 1 && manifest.audience == "syn443-device-release" && manifest.scope == expected)
        require(id.matches(expected.serviceId) && id.matches(expected.channel) && sha.matches(expected.signerCertificateSha256))
        require(expected.deviceId.length == 43 && Policy.decode64(expected.deviceId).size == 32)
        require(manifest.rootEpoch == anchor.epoch && manifest.securityEpoch in 1..SAFE && manifest.revision in 1..SAFE)
        require(manifest.revocationFloor in 0..manifest.revision && time.lowerMs > 0 && time.upperMs >= time.lowerMs)
        require(manifest.issuedAt in 1..manifest.notBefore && manifest.notBefore <= time.lowerMs / 1000 &&
            manifest.expires in 1..SAFE && manifest.expires > time.upperMs / 1000 &&
            manifest.expires - manifest.issuedAt <= 7 * 86400)

        val apk = manifest.apk
        require(apk.packageName == "io.syn443.android" && apk.versionCode in 2..2_100_000_000L &&
            apk.minSdk in 29..apk.targetSdk && apk.targetSdk <= 100 && apk.bytes in 1..(256L shl 20))
        require(sha.matches(apk.sha256) && apk.sourceCommit.matches(Regex("[0-9a-f]{40}")) &&
            sha.matches(apk.engineLockSha256) && sha.matches(apk.contractLockSha256))
        require(apk.nativeLibraries.isNotEmpty() && apk.nativeLibraries.all { (abi, digest) -> abi in platforms && sha.matches(digest) })
        val limits = manifest.compatibility
        for (values in listOf(limits.engineCapabilities, limits.evaluators, limits.schemas)) {
            require(values.size in 1..32 && values.all(name::matches) && values == values.distinct().sorted())
        }
        require(limits.minimumInstalledVersionCode in 1 until apk.versionCode &&
            installed.versionCode in limits.minimumInstalledVersionCode until apk.versionCode && installed.sdk >= apk.minSdk)
        require(installed.abis.size in 1..16 && installed.abis.any(apk.nativeLibraries::containsKey) &&
            installed.evaluator in limits.evaluators && installed.schema in limits.schemas &&
            installed.requiredEngineCapabilities.size <= 32 && limits.engineCapabilities.containsAll(installed.requiredEngineCapabilities))

        val next = ReleaseFloor(expected, manifest.rootEpoch, manifest.securityEpoch, manifest.revision,
            manifest.revocationFloor, Policy.hash(raw))
        if (previous != null) {
            require(previous.scope == expected && sha.matches(previous.payloadSha256) &&
                previous.rootEpoch in 1..next.rootEpoch && previous.securityEpoch in 1..next.securityEpoch &&
                previous.revision in 1..next.revision && previous.revocationFloor in 0..previous.revision &&
                previous.revocationFloor <= next.revocationFloor && (previous.revision < next.revision || previous == next))
        }
        return ApprovedRelease(apk, next)
    }
}
