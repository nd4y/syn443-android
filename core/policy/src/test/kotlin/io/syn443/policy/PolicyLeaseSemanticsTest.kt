package io.syn443.policy

import kotlinx.serialization.encodeToString
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** Signed, memory-only policy leases. No API, device, filesystem or network. */
class PolicyLeaseSemanticsTest {
    private val now = 1_800_000_000_000L
    private val key = key()
    private val anotherKey = key()
    private val thumb = enc(ByteArray(32) { 7 })
    private val bootstrap = Policy.hash("synthetic-bootstrap-authority")
    private val anchor = Policy.hash("synthetic-installation-anchor")
    private val roots = mapOf("root-a" to spki(key))
    private val engine = """{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""

    private fun key(curve: String = "secp256r1"): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec(curve))
    }.generateKeyPair()
    private fun enc(value: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun spki(key: KeyPair) = Base64.getEncoder().encodeToString(key.public.encoded)
    private fun payload() = Payload(2, 5, 0, 0, "device-example", "syn443-device", now - 20_000, now - 10_000,
        now + 300_000, now + 600_000, listOf("engine-config.v1", "tun.lease.v1", "policy.keybound.v2"),
        Policy.BASELINE_ALGORITHM, enc(engine.toByteArray()), Policy.hash(engine),
        Gate(30, false, listOf(Check("internet", "https_204", "https://health.example.invalid/generate_204"))),
        keyThumbprint = thumb)
    private fun signed(p: Payload, key: KeyPair = this.key, kid: String = "root-a"): String {
        val header = """{"alg":"ES256","kid":"$kid","typ":"syn443-policy+jws"}"""
        val body = Canonical.encode(Canonical.parse(Policy.json.encodeToString(p)))
        val input = enc(header.toByteArray()) + "." + enc(body.toByteArray())
        val signature = Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initSign(key.private); update(input.toByteArray()); sign()
        }
        return input + "." + enc(signature)
    }
    private fun verified(p: Payload = payload(), key: KeyPair = this.key, kid: String = "root-a",
                         roots: Map<String, String> = this.roots): Verified =
        Policy.verifyBound(signed(p, key, kid), roots, p.targetDevice, p.keyThumbprint, now)
    private fun stamp(v: Verified, roots: Map<String, String> = this.roots, bootstrap: String = this.bootstrap,
                      anchor: String = this.anchor) = PolicyLeaseSemantics.authority(v, roots, bootstrap, anchor)
    private fun rejected(block: () -> Unit) = assertThrows(IllegalArgumentException::class.java, block)

    @Test fun exactlyFiveSignedLeaseFieldsMayChangeWithoutChangingContentOrAuthority() {
        val p = payload()
        val old = verified(p)
        val before = stamp(old)
        assertTrue(before.matches(Regex("[a-f0-9]{64}")))
        val variants = listOf(
            p.copy(revision = p.revision + 1),
            p.copy(issuedAtMs = p.issuedAtMs + 1),
            p.copy(notBeforeMs = p.notBeforeMs + 1),
            p.copy(refreshAfterMs = p.refreshAfterMs + 1),
            p.copy(offlineUntilMs = p.offlineUntilMs + 1),
            p.copy(revision = p.revision + 1, issuedAtMs = p.issuedAtMs + 1, notBeforeMs = p.notBeforeMs + 1,
                refreshAfterMs = p.refreshAfterMs + 1, offlineUntilMs = p.offlineUntilMs + 1),
        )
        for (candidate in variants) {
            val next = verified(candidate)
            assertTrue(PolicyLeaseSemantics.sameContent(old, next))
            assertTrue(PolicyLeaseSemantics.sameContent(next, old))
            assertEquals(before, stamp(next))
        }
        // ECDSA envelope/signature identity is not execution identity.
        assertEquals(before, stamp(verified(p)))
    }

    @Test fun parentContentPredicateRetainsEveryOtherFieldAndExactEngine() {
        val old = verified()
        val p = old.payload
        val c = p.activation.checks.single()
        // Deliberately isolate one field at a time. Some combinations are not
        // valid policies; sameContent is a predicate, not an admission gate.
        val variants = listOf(
            p.copy(schemaVersion = 1), p.copy(securityEpoch = 1), p.copy(revocationFloor = 1),
            p.copy(targetDevice = "another-device"), p.copy(audience = "another-audience"),
            p.copy(requiredCapabilities = p.requiredCapabilities + "netbird.direct"),
            p.copy(requiredCapabilities = p.requiredCapabilities.reversed()),
            p.copy(algorithmRevision = Policy.CONFIRMED_ALGORITHM),
            p.copy(engineConfigB64 = enc("{}".toByteArray())), p.copy(contentHash = Policy.hash("another-engine")),
            p.copy(operation = "release"), p.copy(keyThumbprint = enc(ByteArray(32) { 8 })),
            p.copy(activation = p.activation.copy(timeoutSeconds = 31)),
            p.copy(activation = p.activation.copy(allowDegraded = true)),
            p.copy(activation = p.activation.copy(checks = listOf(c.copy(id = "another-check")))),
            p.copy(activation = p.activation.copy(checks = listOf(c.copy(type = "tcp_banner")))),
            p.copy(activation = p.activation.copy(checks = listOf(c.copy(target = "https://another.example.invalid/204")))),
            p.copy(activation = p.activation.copy(checks = listOf(c.copy(port = 443)))),
            p.copy(activation = p.activation.copy(checks = listOf(c.copy(expected = "different")))),
            p.copy(activation = p.activation.copy(checks = listOf(c.copy(required = false)))),
        )
        for (candidate in variants) {
            assertFalse(PolicyLeaseSemantics.sameContent(old, old.copy(payload = candidate)))
        }
        assertFalse(PolicyLeaseSemantics.sameContent(old, old.copy(engineConfig = old.engineConfig + " ")))
    }

    @Test fun authorityChangesForSignedCriticalPayloadChanges() {
        val old = verified()
        val p = old.payload
        val differentEngine = engine.replace("\"tag\":\"direct\"", "\"tag\":\"replacement\"")
            .replace("\"final\":\"direct\"", "\"final\":\"replacement\"")
        val changedEngine = p.copy(engineConfigB64 = enc(differentEngine.toByteArray()), contentHash = Policy.hash(differentEngine))
        val variants = listOf(
            p.copy(securityEpoch = 1), p.copy(revocationFloor = 1), p.copy(targetDevice = "another-device"),
            p.copy(requiredCapabilities = p.requiredCapabilities + "netbird.direct"),
            p.copy(requiredCapabilities = p.requiredCapabilities.reversed()),
            p.copy(operation = "release"), p.copy(keyThumbprint = enc(ByteArray(32) { 8 })),
            p.copy(activation = p.activation.copy(timeoutSeconds = 31)),
            p.copy(activation = p.activation.copy(allowDegraded = true)),
            p.copy(activation = p.activation.copy(checks = listOf(p.activation.checks.single().copy(target = "https://another.example.invalid/204")))),
            changedEngine,
        )
        for (candidate in variants) {
            val next = verified(candidate)
            assertFalse(PolicyLeaseSemantics.sameContent(old, next))
            assertNotEquals(stamp(old), stamp(next))
        }
        val legacy = p.copy(schemaVersion = 1, keyThumbprint = "", requiredCapabilities = p.requiredCapabilities - "policy.keybound.v2")
        val legacyVerified = Policy.verify(signed(legacy), roots, legacy.targetDevice, now)
        assertNotEquals(stamp(old), stamp(legacyVerified))
        val failoverEngine = engine.dropLast(1) + ",\"route_failover\":{}}"
        val failover = p.copy(algorithmRevision = Policy.CONFIRMED_ALGORITHM,
            requiredCapabilities = p.requiredCapabilities + listOf("route.health.v1", "route.failover.v1", Policy.ROUTE_DECISION),
            engineConfigB64 = enc(failoverEngine.toByteArray()), contentHash = Policy.hash(failoverEngine))
        assertNotEquals(stamp(old), stamp(verified(failover)))
    }

    @Test fun realSignerRotationRootSetBootstrapAndInstallationAnchorAreIndependentFences() {
        val old = verified()
        val sameKidOtherRoot = mapOf("root-a" to spki(anotherKey))
        val rotated = verified(key = anotherKey, roots = sameKidOtherRoot)
        assertTrue(PolicyLeaseSemantics.sameContent(old, rotated))
        assertNotEquals(stamp(old), stamp(rotated, sameKidOtherRoot))
        // Both keys are already pinned: the parent's content-only predicate
        // historically permits this valid signer rotation, while actual
        // native execution continuity must nevertheless reset.
        val twoKeys = mapOf("root-a" to spki(key), "root-b" to spki(anotherKey))
        val otherSigner = verified(key = anotherKey, kid = "root-b", roots = twoKeys)
        assertTrue(PolicyLeaseSemantics.sameContent(old, otherSigner))
        assertNotEquals(stamp(old, twoKeys), stamp(otherSigner, twoKeys))
        val both = linkedMapOf("root-a" to spki(key), "root-b" to spki(key))
        val sameKeyOtherKid = verified(kid = "root-b", roots = both)
        assertTrue(PolicyLeaseSemantics.sameContent(old, sameKeyOtherKid))
        assertNotEquals(stamp(old, both), stamp(sameKeyOtherKid, both))
        assertNotEquals(stamp(old), stamp(old, both))
        val changedUnusedRoot = both + ("root-b" to spki(anotherKey))
        assertNotEquals(stamp(old, both), stamp(old, changedUnusedRoot))
        assertEquals(stamp(old, both), stamp(old, both.toList().reversed().toMap()))
        assertEquals(stamp(old), stamp(old, roots.mapValues { (_, root) -> root.trimEnd('=') }))
        assertNotEquals(stamp(old), stamp(old, bootstrap = Policy.hash("another-bootstrap")))
        assertNotEquals(stamp(old), stamp(old, anchor = Policy.hash("another-anchor")))
        val rawURLDigest = enc(ByteArray(32) { 11 })
        assertTrue(stamp(old, bootstrap = rawURLDigest, anchor = rawURLDigest).matches(Regex("[a-f0-9]{64}")))
    }

    @Test fun authorityRejectsUnknownMalformedSignerAndMismatchedVerifiedCopies() {
        val old = verified()
        rejected { stamp(old, emptyMap()) }
        rejected { stamp(old, mapOf("another-root" to spki(key))) }
        rejected { stamp(old, mapOf("root-a" to "not-an-spki")) }
        rejected { stamp(old, mapOf("root-a" to spki(key("secp384r1")))) }
        rejected { stamp(old, roots + ("invalid root id" to spki(key))) }
        rejected { stamp(old, (0..4).associate { "root-$it" to spki(key) }) }
        for (value in listOf("", "not-a-digest", "a".repeat(65), "A".repeat(64), "_".repeat(43))) {
            rejected { stamp(old, bootstrap = value) }
            rejected { stamp(old, anchor = value) }
        }
        rejected { stamp(old.copy(payload = old.payload.copy(revision = old.payload.revision + 1))) }
        rejected { stamp(old.copy(engineConfig = old.engineConfig + " ")) }
        for (raw in listOf("", "a.b.c.d", "_".repeat(524_289))) rejected { stamp(old.copy(envelope = raw)) }
        val parts = old.envelope.split('.')
        val badHeaders = listOf(
            """{"alg":"none","kid":"root-a","typ":"syn443-policy+jws"}""",
            """{"alg":"ES256","kid":1,"typ":"syn443-policy+jws"}""",
            """{"alg":"ES256","kid":"unknown","typ":"syn443-policy+jws"}""",
            """{"alg":"ES256","kid":"root-a","typ":"another-type"}""",
            """{"alg":"ES256","kid":"root-a","typ":"syn443-policy+jws","url":"https://keys.example.invalid"}""",
            """{"alg":"ES256","kid":"root-a","kid":"root-a","typ":"syn443-policy+jws"}""",
        )
        for (header in badHeaders) {
            rejected { stamp(old.copy(envelope = enc(header.toByteArray()) + "." + parts[1] + "." + parts[2])) }
        }
    }
}
