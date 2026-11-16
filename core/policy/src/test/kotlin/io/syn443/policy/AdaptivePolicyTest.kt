package io.syn443.policy

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlinx.serialization.encodeToString
import org.junit.Assert.*
import org.junit.Test

class AdaptivePolicyTest {
    private val now = 1_700_000_000_000L
    private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val roots = mapOf("adaptive-test" to Base64.getEncoder().encodeToString(key.public.encoded))
    private val thumb = enc(ByteArray(32) { 7 })
    private fun enc(raw: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    private fun engine(country: Boolean = false): String {
        val intent = if (country) "RU" else "INTERNAL"
        val graph = """{"edges":[],"groups":[{"features":["TCP","IPV4"],"id":"inside","intent":"$intent","templates":["one"]}],"hops":[{"entryModes":["WIFI"],"exitClass":"$intent","features":["TCP","IPV4"],"id":"hop"}],"schemaVersion":1,"templates":[{"id":"one","slots":[["hop"]]}]}"""
        val catalogue = """{"hop":{"server":"192.0.2.1","server_port":443,"tag":"hop","type":"http"}}"""
        val wire = """{"catalogueB64":"${enc(catalogue.toByteArray())}","graphB64":"${enc(graph.toByteArray())}","groups":{"inside":"managed-inside"},"schemaVersion":1}"""
        val check = if (country) """{"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"RU"}"""
            else """{"method":"tcp","target":"192.0.2.7:22"}"""
        return """{"outbounds":[{"type":"syn443-adaptive","tag":"managed-inside","group":"inside"}],"route":{"final":"managed-inside"},"route_checks":[{"outbound":"managed-inside","checks":[$check]}],"adaptive_routes":$wire}"""
    }
    private fun payload(config: String = engine()): Payload = Payload(
        schemaVersion = 2, revision = 1, securityEpoch = 0, revocationFloor = 0,
        targetDevice = "adaptive-device", audience = "syn443-device", issuedAtMs = now - 1000,
        notBeforeMs = now - 1000, refreshAfterMs = now + 300000, offlineUntilMs = now + 600000,
        requiredCapabilities = listOf("engine-config.v1", "tun.lease.v1", "policy.keybound.v2", "route.health.v1", Policy.ROUTE_DECISION, Policy.ROUTE_ADAPTIVE_TCP),
        algorithmRevision = Policy.ADAPTIVE_ALGORITHM, engineConfigB64 = enc(config.toByteArray()), contentHash = Policy.hash(config),
        activation = Gate(30, false, listOf(Check("internet", "https_204", "https://health.example.invalid/generate_204"))), keyThumbprint = thumb,
    )
    private fun sign(payload: Payload): String {
        val header = """{"alg":"ES256","kid":"adaptive-test","typ":"syn443-policy+jws"}"""
        val text = Canonical.encode(Canonical.parse(Policy.json.encodeToString(payload)))
        val input = enc(header.toByteArray()) + "." + enc(text.toByteArray())
        val signature = Signature.getInstance("SHA256withECDSAinP1363Format").run { initSign(key.private); update(input.toByteArray()); sign() }
        return input + "." + enc(signature)
    }
    private fun verify(payload: Payload): Verified = Policy.verifyBound(sign(payload), roots, "adaptive-device", thumb, now)
    private fun rejected(action: () -> Unit) {
        try { action(); fail("invalid adaptive policy acquired authority") }
        catch (_: IllegalArgumentException) { }
        catch (_: NoSuchElementException) { }
    }
    private fun withEngine(payload: Payload, engine: String): Payload = payload.copy(engineConfigB64 = enc(engine.toByteArray()), contentHash = Policy.hash(engine))

    @Test fun signedAdaptiveConfigurationRequiresExactKeyBoundCapabilityAndAlgorithm() {
        val base = payload()
        val verified = verify(base)
        assertEquals(engine(), verified.engineConfig)
        assertEquals(Policy.ADAPTIVE_ALGORITHM, verified.payload.algorithmRevision)
        assertEquals(thumb, verified.payload.keyThumbprint)
        for (capability in listOf(Policy.ROUTE_ADAPTIVE_TCP, Policy.ROUTE_DECISION, "route.health.v1", "policy.keybound.v2", "engine-config.v1", "tun.lease.v1")) {
            rejected { verify(base.copy(requiredCapabilities = base.requiredCapabilities - capability)) }
        }
        for (algorithm in listOf(Policy.BASELINE_ALGORITHM, Policy.CONFIRMED_ALGORITHM, "remote-executable")) {
            rejected { verify(base.copy(algorithmRevision = algorithm)) }
        }
        rejected { verify(base.copy(operation = "release")) }
        rejected { verify(base.copy(schemaVersion = 1, keyThumbprint = "", requiredCapabilities = base.requiredCapabilities - "policy.keybound.v2")) }
        rejected { verify(base.copy(contentHash = "0".repeat(64))) }
        rejected { Policy.verifyBound(sign(base), roots, "adaptive-device", enc(ByteArray(32) { 8 }), now) }
        rejected { Policy.verifyBound(sign(base), roots, "other-device", thumb, now) }
        rejected { Policy.verifyBound(sign(base), emptyMap(), "adaptive-device", thumb, now) }
        rejected { verify(base.copy(offlineUntilMs = now)) }
    }

    @Test fun adaptiveFieldPresenceNullAndLegacyFailoverCannotDowngradeAuthority() {
        val base = payload()
        for (field in listOf("null", "[]", "true", "1", "\"opaque\"")) {
            val raw = engine().substringBefore("\"adaptive_routes\":") + "\"adaptive_routes\":$field}"
            rejected { verify(withEngine(base, raw)) }
        }
        for (value in listOf("null", "{}")) {
            val raw = engine().dropLast(1) + ",\"route_failover\":$value}"
            rejected { verify(withEngine(base, raw)) }
        }
        for (capability in listOf("route.failover.v1", Policy.RESERVE_PROBE_COOLDOWN)) {
            rejected { verify(base.copy(requiredCapabilities = base.requiredCapabilities + capability)) }
        }
        val ordinary = """{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""
        rejected { verify(withEngine(base, ordinary)) }
        rejected { verify(withEngine(base, ordinary).copy(algorithmRevision = Policy.BASELINE_ALGORITHM)) }
        val baseline = withEngine(base, ordinary).copy(algorithmRevision = Policy.BASELINE_ALGORITHM,
            requiredCapabilities = base.requiredCapabilities - Policy.ROUTE_ADAPTIVE_TCP - Policy.ROUTE_DECISION)
        assertEquals(ordinary, verify(baseline).engineConfig)
        rejected { verify(baseline.copy(engineConfigB64 = base.engineConfigB64, contentHash = base.contentHash)) }
        // The signed activation failed snapshot cannot be retried by merely
        // changing revision; the validated algorithm/capability binding remains.
        val failed = Policy.rollback(Policy.stage(Journal(), verify(base)), 1, "activation_failed")
        rejected { Policy.stage(failed, verify(base.copy(revision = 2))) }
    }

    @Test fun countryPredicatesKeepIndependentCapabilitiesOnAdaptivePolicies() {
        val base = payload(engine(country = true))
        rejected { verify(base) }
        val country = base.copy(requiredCapabilities = base.requiredCapabilities + Policy.ROUTE_EXIT_COUNTRY)
        assertEquals(engine(country = true), verify(country).engineConfig)
        rejected { verify(country.copy(requiredCapabilities = country.requiredCapabilities - Policy.ROUTE_EXIT_COUNTRY + Policy.ROUTE_EXIT_IP)) }
        rejected { verify(withEngine(country, engine())) }
        val both = engine(country = true).replace("\"checks\":[{", "\"checks\":[{\"method\":\"https_exit_ip\",\"target\":\"https://address.example.invalid/ip\",\"expected_ip\":\"192.0.2.9\"},{")
        val combined = withEngine(country, both).copy(requiredCapabilities = country.requiredCapabilities + Policy.ROUTE_EXIT_IP)
        assertEquals(both, verify(combined).engineConfig)
        rejected { verify(combined.copy(requiredCapabilities = combined.requiredCapabilities - Policy.ROUTE_EXIT_COUNTRY)) }
        rejected { verify(combined.copy(requiredCapabilities = combined.requiredCapabilities - Policy.ROUTE_EXIT_IP)) }
    }
}
