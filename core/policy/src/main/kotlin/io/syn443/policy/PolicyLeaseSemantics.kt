package io.syn443.policy

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** Execution identity for an already verified lease, not a verification or
 * authorization gate. Call authority on the identity worker only; it processes
 * the full bounded configuration and must not run on a Binder/UI handler. */
object PolicyLeaseSemantics {
    private val leaseFields = setOf("revision", "issuedAtMs", "notBeforeMs", "refreshAfterMs", "offlineUntilMs")
    private val keyID = Regex("[a-zA-Z0-9_-]{1,64}")
    private val hexDigest = Regex("[a-f0-9]{64}")
    private val urlDigest = Regex("[A-Za-z0-9_-]{43}")
    private val p256Order = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

    /** Exactly the parent's existing pure-lease predicate. Its caller still
     * checks journal phase, epochs, floors, revision and current authority. A
     * valid signer rotation may pass this predicate but changes authority(). */
    fun sameContent(old: Verified, next: Verified): Boolean {
        val p = old.payload
        val n = next.payload
        return old.engineConfig == next.engineConfig && p.copy(revision = n.revision, issuedAtMs = n.issuedAtMs,
            notBeforeMs = n.notBeforeMs, refreshAfterMs = n.refreshAfterMs, offlineUntilMs = n.offlineUntilMs) == n
    }

    private fun digestIdentity(value: String): Boolean {
        if (hexDigest.matches(value)) return true
        if (!urlDigest.matches(value)) return false
        val decoded = Policy.decode64(value)
        return decoded.size == 32
    }

    private fun normalizedRoot(raw: String): String {
        require(raw.length in 1..4096)
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(raw))) as ECPublicKey
        require(key.params.order == p256Order && key.params.cofactor == 1 && key.params.curve.field.fieldSize == 256)
        return Base64.getEncoder().encodeToString(key.encoded)
    }

    /** Every non-lease payload field, exact engine, signer, pinned roots,
     * service/bootstrap identity and installation anchor participate. There is
     * no unsigned/unknown-signer fallback. Equal hashes do not renew a native
     * lease, revive an expired owner or bypass current-generation checks. */
    fun authority(verified: Verified, roots: Map<String, String>, bootstrapAuthority: String, anchorFingerprint: String): String {
        require(digestIdentity(bootstrapAuthority) && digestIdentity(anchorFingerprint))
        require(roots.size in 1..4 && roots.keys.all(keyID::matches))
        val raw = verified.envelope
        require(raw.length in 1..524_288 && raw.all { it.code < 128 })
        val parts = raw.split('.')
        require(parts.size == 3 && parts[0].length <= 1024)
        val headerText = Policy.utf8(Policy.decode64(parts[0]))
        val header = Canonical.parse(headerText).jsonObject
        require(header.keys == setOf("alg", "kid", "typ") && headerText == Canonical.encode(header) &&
            header.values.all { it is JsonPrimitive && it.isString })
        fun member(name: String) = (header.getValue(name) as JsonPrimitive).content
        require(member("alg") == "ES256" && member("typ") == "syn443-policy+jws")
        val kid = member("kid")
        require(keyID.matches(kid) && roots.containsKey(kid))
        require(Policy.decode64(parts[2]).size == 64)

        // Verified is intentionally a small value type. Reject mismatched
        // copies at this helper boundary instead of producing an authority for
        // data other than the already verified signed payload/engine.
        val payload = Canonical.parse(Policy.json.encodeToString(verified.payload)).jsonObject
        require(Canonical.encode(payload) == Policy.utf8(Policy.decode64(parts[1])))
        val engine = verified.engineConfig.toByteArray(Charsets.UTF_8)
        require(engine.size in 1..262_144 && Base64.getUrlEncoder().withoutPadding().encodeToString(engine) == verified.payload.engineConfigB64 &&
            Policy.hash(verified.engineConfig) == verified.payload.contentHash)
        val normalizedRoots = roots.toSortedMap().mapValues { (_, root) -> JsonPrimitive(normalizedRoot(root)) }
        val semantic = JsonObject(payload.filterKeys { it !in leaseFields })
        val digest = MessageDigest.getInstance("SHA-256")
        fun put(value: String) {
            val bytes = value.toByteArray(Charsets.UTF_8)
            digest.update(ByteBuffer.allocate(4).putInt(bytes.size).array())
            digest.update(bytes)
        }
        put("syn443-policy-lease-authority-v1")
        put(Canonical.encode(semantic))
        put(verified.engineConfig)
        put(kid)
        put(normalizedRoots.getValue(kid).content)
        put(Canonical.encode(JsonObject(normalizedRoots)))
        put(bootstrapAuthority)
        put(anchorFingerprint)
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
