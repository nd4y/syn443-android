package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class ReleaseAdmissionTest {
    private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val anchor = TrustAnchor("fixture-release", Base64.getEncoder().encodeToString(key.public.encoded), 1)
    private val sha = Policy.hash("synthetic package")
    private val scope = ReleaseScope("service", Identity.hash("device".toByteArray()), "pilot", sha)
    private val platform = InstalledReleaseContext(19, 35, listOf("arm64-v8a"), listOf("tun.v1"), "m1-local-v1", "policy-v1")
    private val clock = TimeWindow(100_001, 101_002)
    private val body = Canonical.parse("""{
        "schemaVersion":1,"audience":"syn443-device-release","scope":{"serviceId":"service","deviceId":"${scope.deviceId}","channel":"pilot","signerCertificateSha256":"$sha"},
        "rootEpoch":1,"securityEpoch":2,"revision":8,"revocationFloor":3,"issuedAt":90,"notBefore":100,"expires":102,
        "apk":{"package":"io.syn443.android","versionCode":20,"minSdk":29,"targetSdk":37,"nativeLibraries":{"arm64-v8a":"$sha"},
        "sha256":"$sha","bytes":17,"sourceCommit":"${"a".repeat(40)}","engineLockSha256":"$sha","contractLockSha256":"$sha"},
        "compatibility":{"minimumInstalledVersionCode":17,"engineCapabilities":["tun.v1"],"evaluators":["m1-local-v1"],"schemas":["policy-v1"]}
    }""").jsonObject

    private fun signed(value: JsonObject = body, type: String = "syn443-apk-release+jws"): String {
        val header = buildJsonObject { put("alg", "ES256"); put("kid", anchor.id); put("typ", type) }
        val input = Identity.encode(Canonical.encode(header).toByteArray()) + "." + Identity.encode(Canonical.encode(value).toByteArray())
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private); update(input.toByteArray(Charsets.US_ASCII)); sign()
        }
        return input + "." + Identity.encode(Identity.derToRaw(signature))
    }
    private fun verify(wire: String = signed(), recipient: ReleaseScope = scope, device: InstalledReleaseContext = platform,
                       floor: ReleaseFloor? = null, time: TimeWindow = clock) =
        ReleaseAdmission.verify(wire, anchor, recipient, device, floor, time)

    @Test fun authenticatesDeviceSignerChannelAndEntireTrustedTimeWindow() {
        val wire = signed()
        assertEquals(20L, verify(wire).apk.versionCode)
        for (other in listOf(scope.copy(serviceId="other"), scope.copy(channel="stable"),
                scope.copy(deviceId=Identity.hash("other".toByteArray())), scope.copy(signerCertificateSha256=Policy.hash("other"))))
            assertThrows(Exception::class.java) { verify(wire, recipient=other) }
        for (time in listOf(TimeWindow(99_999,100_500), TimeWindow(100_001,102_000), TimeWindow(105_000,104_999)))
            assertThrows(Exception::class.java) { verify(wire, time=time) }
        assertThrows(Exception::class.java) { verify(signed(type="syn443-bootstrap+jws")) }
        assertThrows(Exception::class.java) { verify(signed(JsonObject(body + ("extra" to JsonPrimitive(1))))) }
        assertThrows(Exception::class.java) { verify(signed(JsonObject(body + ("revision" to JsonPrimitive("8"))))) }
        assertThrows(Exception::class.java) { verify(signed(JsonObject(body - "revocationFloor"))) }
    }
    @Test fun migrationAbiAndActivePolicyMustAllBeCompatible() {
        val wire = signed()
        for (bad in listOf(platform.copy(versionCode=16), platform.copy(versionCode=20), platform.copy(sdk=28),
                platform.copy(abis=listOf("x86")), platform.copy(evaluator="other"), platform.copy(schema="other"),
                platform.copy(requiredEngineCapabilities=listOf("other.v1"))))
            assertThrows(Exception::class.java) { verify(wire, device=bad) }
        assertEquals(20L, verify(wire, device=platform.copy(sdk=42)).apk.versionCode)
    }
    @Test fun acceptedFloorSurvivesRetriesAndRejectsConflictsOrBackwardsSteps() {
        val floor = verify().floor
        assertEquals(floor, verify(floor=floor).floor)
        for ((field, n) in listOf("revision" to 7, "securityEpoch" to 1, "revocationFloor" to 2, "expires" to 103))
            assertThrows(Exception::class.java) { verify(signed(JsonObject(body + (field to JsonPrimitive(n)))), floor=floor) }
        val next = verify(signed(JsonObject(body + ("revision" to JsonPrimitive(9)))), floor=floor).floor
        assertEquals(9L, next.revision)
        assertThrows(Exception::class.java) { verify(floor=next) }
    }
    @Test fun streamedPackageMustMatchSizeAndDigestBeforeItCanBeHandedOff() {
        val accepted = verify()
        val bytes = "synthetic package".toByteArray()
        val output = ByteArrayOutputStream()
        accepted.verifyBytes(bytes.inputStream(), output)
        assertArrayEquals(bytes, output.toByteArray())
        for (bad in listOf(bytes.drop(1).toByteArray(), bytes + 0.toByte(), bytes.clone().also { it[0]=0 }))
            assertThrows(Exception::class.java) { accepted.verifyBytes(bad.inputStream()) }
    }
}
