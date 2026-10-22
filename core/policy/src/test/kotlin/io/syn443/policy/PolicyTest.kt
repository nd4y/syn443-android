package io.syn443.policy

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class PolicyTest {
    private val now = 1_800_000_000_000L
    private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val roots = mapOf("test-root" to Base64.getEncoder().encodeToString(key.public.encoded))
    private fun enc(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    private fun payload(revision: Long = 1): Payload {
        val config = """{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""
        return Payload(1, revision, 0, 0, "device-example", "syn443-device", now - 1000, now - 1000, now + 300000, now + 600000,
            listOf("engine-config.v1", "tun.lease.v1"), "m1-local-v1", enc(config.toByteArray()), Policy.hash(config),
            Gate(30, false, listOf(Check("internet", "https_204", "https://health.example.org/generate_204"))))
    }
    private fun sign(p: Payload = payload(), header: String = """{"alg":"ES256","kid":"test-root","typ":"syn443-policy+jws"}"""): String = signText(Canonical.encode(Canonical.parse(Policy.json.encodeToString(p))), header)
    private fun signText(text: String, header: String = """{"alg":"ES256","kid":"test-root","typ":"syn443-policy+jws"}"""): String {
        val input = enc(header.toByteArray()) + "." + enc(text.toByteArray())
        val signature = Signature.getInstance("SHA256withECDSAinP1363Format").run { initSign(key.private); update(input.toByteArray()); sign() }
        return input + "." + enc(signature)
    }
    private fun verify(raw: String) = Policy.verify(raw, roots, "device-example", now)
    private fun invalid(block: () -> Unit) { try { block(); fail("invalid policy accepted") } catch (_: IllegalArgumentException) { } catch (_: NoSuchElementException) { } }
    @Test fun signatureAudienceAndHash() {
        val signed = sign(); assertEquals(1, verify(signed).payload.revision)
        invalid { Policy.verify(signed, roots, "another-device", now) }
        val parts = signed.split('.'); invalid { verify(parts[0] + "." + enc("{}".toByteArray()) + "." + parts[2]) }
        invalid { verify(sign(payload().copy(contentHash = "0".repeat(64)))) }
    }
    @Test fun unknownRootAlgorithmAndHeadersRejected() {
        invalid { Policy.verify(sign(), emptyMap(), "device-example", now) }
        invalid { verify(sign(header = """{"alg":"none","kid":"test-root","typ":"syn443-policy+jws"}""")) }
        invalid { verify(sign(header = """{"alg":"ES256","jku":"https://keys.example.org","kid":"test-root","typ":"syn443-policy+jws"}""")) }
    }
    @Test fun duplicateUnknownAndNonCanonicalJsonRejected() {
        invalid { Canonical.parse("""{"revision":1,"\u0072evision":2}""") }
        val raw = Canonical.encode(Canonical.parse(Policy.json.encodeToString(payload())))
        invalid { verify(signText(" " + raw)) }
        invalid { verify(signText(raw.dropLast(1) + ",\"unknown\":true}")) }
        invalid { verify(signText(raw.replace("\"port\":0,", ""))) }
        listOf("1e2", "1.0", "9007199254740992", "01", "[1,]", "\"\\ud800\"").forEach { invalid { Canonical.parse(it) } }
    }
    @Test fun leaseCapabilitiesAndGatesAreLocalLimits() {
        invalid { verify(sign(payload().copy(offlineUntilMs = now))) }
        invalid { verify(sign(payload().copy(notBeforeMs = now + 1))) }
        invalid { verify(sign(payload().copy(offlineUntilMs = now + 604800001))) }
        invalid { verify(sign(payload().copy(requiredCapabilities = listOf("remote.code")))) }
        invalid { verify(sign(payload().copy(requiredCapabilities = listOf("engine-config.v1")))) }
        invalid { verify(sign(payload().copy(activation = Gate(121, false, payload().activation.checks)))) }
        invalid { verify(sign(payload().copy(activation = Gate(30, false, listOf(Check("bad", "https_204", "http://health.example.org")))))) }
        invalid { verify(sign(payload().copy(activation = Gate(30, false, listOf(Check("bad", "shell", "anything")))))) }
    }
    @Test fun replayAndFloorsSurviveSerialization() {
        val p = verify(sign()); val j = Policy.stage(Journal(), p)
        val disk = Policy.json.decodeFromString<Journal>(Policy.json.encodeToString(j))
        invalid { Policy.stage(disk.copy(phase = "rolled_back", candidate = null), p) }
        invalid { Policy.stage(Journal(epoch = 2), verify(sign(payload(3).copy(securityEpoch = 1)))) }
        invalid { Policy.stage(Journal(floor = 2), verify(sign(payload(3).copy(revocationFloor = 1)))) }
    }
    @Test fun commitAndSingleRollbackNeverPromoteFailure() {
        val v = verify(sign()); val first = Policy.finish(Policy.begin(Policy.stage(Journal(), v), listOf(true)), v, listOf(true), true)
        assertEquals("committed", first.phase); assertEquals(v.envelope, first.lastGood)
        val next = verify(sign(payload(2))); val applying = Policy.begin(Policy.stage(first, next), listOf(true))
        val failed = Policy.finish(applying, next, listOf(false), true)
        assertEquals("rolled_back", failed.phase); assertEquals(first.active, failed.active)
        assertEquals(listOf(2L), failed.failedRevisions); invalid { Policy.stage(failed, next) }
        invalid { Policy.stage(failed, verify(sign(payload(3)))) }
        assertEquals("rolled_back", Policy.finish(applying, next, listOf(true), false).phase)
    }
    @Test fun baselineOutageCanDegradeButNeverHideRegression() {
        val v = verify(sign(payload().copy(activation = payload().activation.copy(allowDegraded = true))))
        val staged = Policy.stage(Journal(), v)
        assertEquals("degraded", Policy.finish(Policy.begin(staged, listOf(false)), v, listOf(false), true).phase)
        assertEquals("rolled_back", Policy.finish(Policy.begin(staged, listOf(true)), v, listOf(false), true).phase)
    }
    @Test fun jcsUsesUtf16OrderingAndDoesNotEscapeHtml() {
        val raw = """{"z":"<>&","a":0,"\ud83d\ude00":1,"\ue000":2}"""
        val canonical = Canonical.encode(Canonical.parse(raw))
        assertTrue(canonical.startsWith("{\"a\":0,\"z\":\"<>&\","))
        assertTrue(canonical.indexOf("😀") < canonical.indexOf("\ue000"))
        assertEquals(canonical, Canonical.encode(Canonical.parse(canonical)))
    }
    @Test fun goPublisherConformance() {
        val fixture = Policy.json.parseToJsonElement(checkNotNull(javaClass.classLoader?.getResourceAsStream("policy-vectors.json")).bufferedReader().use { it.readText() }).jsonObject
        fun bytes(name: String) = fixture.getValue(name).jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val wire = listOf("headerHex", "payloadHex", "signatureHex").joinToString(".") { enc(bytes(it)) }
        val root = Base64.getEncoder().encodeToString(bytes("spkiHex"))
        val verified = Policy.verify(wire, mapOf("test-root" to root), fixture.getValue("device").jsonPrimitive.content, fixture.getValue("nowMs").jsonPrimitive.long)
        assertEquals(verified.payload.contentHash, Policy.hash(verified.engineConfig))
    }
    @Test fun releaseStillNeedsAuthorizedRevisionAndHealthyChecks() {
        val first = verify(sign())
        val committed = Policy.finish(Policy.begin(Policy.stage(Journal(), first), listOf(true)), first, listOf(true), true)
        val release = verify(sign(payload(2).copy(operation = "release")))
        val applying = Policy.begin(Policy.stage(committed, release), listOf(true))
        assertEquals("released", Policy.finish(applying, release, listOf(true), true).phase)
        assertEquals("rolled_back", Policy.finish(applying, release, listOf(false), true).phase)
        invalid { verify(sign(payload().copy(operation = "unrecognized"))) }
    }
    @Test fun trustedTimeCannotRewindOrSurviveBootWithoutFreshTime() {
        val anchor = TimeAnchor(now, 5000, 1)
        assertEquals(now + 1000, TrustedTime.estimate(anchor, 6000, 1))
        invalid { TrustedTime.estimate(anchor, 4999, 1) }
        invalid { TrustedTime.estimate(anchor, 6000, 2) }
        val refreshed = TrustedTime.accept(anchor, now, 5500, 1)
        assertEquals(now + 500, refreshed.wall)
        assertEquals(now + 1000, TrustedTime.estimate(refreshed, 6000, 1))
        invalid { TrustedTime.accept(refreshed, now - 1000, 6000, 1) }
        val boot = TrustedTime.accept(refreshed, now + 10000, 20, 2)
        assertEquals(now + 10000, TrustedTime.estimate(boot, 20, 2))
        invalid { TrustedTime.estimate(TimeAnchor(TrustedTime.MAX, 0, 1), 1, 1) }
    }
}
