package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.json.*
import java.io.File

/** Actions only. Read the real Go-issued wire after the disposable signing key has been removed. */
object ReleaseDeliveryFixture {
    @JvmStatic fun main(args: Array<String>) {
        require(args.isEmpty())
        val directory = File(checkNotNull(System.getenv("SYN443_RELEASE_FIXTURE_DIR")))
        require(directory.isDirectory && !File(directory, "release-key.pem").exists())
        fun document(name: String) = Canonical.parse(File(directory, name).readText()).jsonObject
        val trust = document("installed.json")
        val expected = Canonical.json.decodeFromJsonElement<ReleaseScope>(trust.getValue("scope"))
        val installed = Canonical.json.decodeFromJsonElement<InstalledReleaseContext>(trust.getValue("installed"))
        val anchor = Canonical.json.decodeFromJsonElement<TrustAnchor>(trust.getValue("anchor"))
        val goFloor = Canonical.json.decodeFromJsonElement<ReleaseFloor>(document("accepted.json").getValue("floor"))
        val now = System.currentTimeMillis()
        fun read(revision: Int, scope: ReleaseScope = expected, floor: ReleaseFloor? = null): ApprovedRelease {
            val envelope = File(directory, "issued-$revision.jws").readText(Charsets.US_ASCII).removeSuffix("\n")
            return ReleaseAdmission.verify(envelope, anchor, scope, installed, floor, TimeWindow(now, now))
        }
        check(read(1).floor.revision == 1L)
        val current = read(2, floor=goFloor)
        check(current.floor == goFloor)
        File(directory, "normal.apk").inputStream().use { current.verifyBytes(it) }
        check(runCatching { read(1, floor=goFloor) }.isFailure)
        val other = Canonical.json.decodeFromJsonElement<ReleaseScope>(document("other-device.json").getValue("scope"))
        check(runCatching { read(2, scope=other) }.isFailure)
        check(runCatching { File(directory, "different-signed.apk").inputStream().use { current.verifyBytes(it) } }.isFailure)
    }
}
