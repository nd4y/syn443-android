package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.URI
import java.net.URLEncoder
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

@Serializable data class Bootstrap(val serviceId: String, val issuer: String, val clientId: String,
    val apiOrigin: String, val roots: Map<String, String>, val tlsCaDer: String = "") {
    fun validate() {
        require(serviceId.matches(Regex("[a-zA-Z0-9_-]{1,64}")))
        require(clientId.matches(Regex("[a-zA-Z0-9_-]{1,128}")))
        Identity.https(issuer); require(!issuer.endsWith('/'))
        val api = Identity.https(apiOrigin); require(api.path.isEmpty())
        require(roots.size in 1..4)
        roots.forEach { (id, key) ->
            require(id.matches(Regex("[a-zA-Z0-9_-]{1,64}")))
            val parsed = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(key))) as ECPublicKey
            require(parsed.params.order == Identity.ecParameters.order && parsed.params.cofactor == 1)
        }
        // Development CA is trusted only from the operator bootstrap, never from API responses.
        require(tlsCaDer.length <= 8192)
        if (tlsCaDer.isNotEmpty()) require(api.host == "127.0.0.1")
    }
}
@Serializable data class Pending(val generation: Long, val state: String, val nonce: String,
    val verifier: String, val thumbprint: String, val bootCount: Int, val startedElapsedMs: Long) {
    fun current(generation: Long, bootCount: Int, elapsedMs: Long) = this.generation == generation &&
        this.bootCount == bootCount && elapsedMs >= startedElapsedMs && elapsedMs - startedElapsedMs < 300_000
}
data class Callback(val code: String?, val error: String?)
data class UserIdentity(val subject: String)

/** Pure protocol core. Private-key operations are supplied by the Android Keystore adapter. */
object Identity {
    const val callback = "syn443://oauth/callback"
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    val ecParameters: ECParameterSpec = AlgorithmParameters.getInstance("EC").run {
        init(ECGenParameterSpec("secp256r1")); getParameterSpec(ECParameterSpec::class.java)
    }
    fun encode(raw: ByteArray): String = encoder.encodeToString(raw)
    fun hash(raw: ByteArray): String = encode(MessageDigest.getInstance("SHA-256").digest(raw))
    fun random(): String = ByteArray(32).also { SecureRandom().nextBytes(it) }.let(::encode)
    fun https(raw: String): URI {
        require(raw.length in 1..2048 && raw.all { it.code in 33..126 })
        val u = URI(raw)
        require(u.scheme == "https" && !u.host.isNullOrEmpty() && u.rawUserInfo == null && u.rawQuery == null && u.rawFragment == null && (u.port == -1 || u.port in 1..65535))
        require(u.rawPath == u.path && !u.path.contains("//") && u.normalize() == u)
        return u
    }
    fun objectJSON(raw: String): JsonObject {
        require(raw.toByteArray(Charsets.UTF_8).size in 1..65_536)
        return Canonical.parse(raw).jsonObject
    }
    fun newPending(generation: Long, thumbprint: String, boot: Int, elapsedMs: Long): Pending {
        require(generation >= 0 && thumbprint.matches(Regex("[A-Za-z0-9_-]{43}")) && boot >= 0 && elapsedMs >= 0)
        return Pending(generation, random(), random(), random(), thumbprint, boot, elapsedMs)
    }
    fun authorization(bootstrap: Bootstrap, pending: Pending): String {
        bootstrap.validate()
        return bootstrap.issuer + "/protocol/openid-connect/auth?" + form(linkedMapOf(
            "client_id" to bootstrap.clientId, "redirect_uri" to callback, "response_type" to "code", "scope" to "openid",
            "state" to pending.state, "nonce" to pending.nonce, "code_challenge_method" to "S256",
            "code_challenge" to hash(pending.verifier.toByteArray(Charsets.US_ASCII)), "dpop_jkt" to pending.thumbprint))
    }
    fun form(values: Map<String, String>) = values.entries.joinToString("&") {
        URLEncoder.encode(it.key, "UTF-8") + "=" + URLEncoder.encode(it.value, "UTF-8")
    }
    private fun query(raw: String): Map<String, String> {
        require(raw.length in 1..8192)
        fun decode(value: String): String {
            val out = ByteArrayOutputStream(); var index = 0
            while (index < value.length) {
                val c = value[index++]
                when (c) {
                    '%' -> { require(index + 2 <= value.length); out.write(value.substring(index, index+2).toInt(16)); index += 2 }
                    '+' -> out.write(32)
                    else -> { require(c.code in 33..126); out.write(c.code) }
                }
            }
            return Policy.utf8(out.toByteArray()).also { require(it.none(Char::isISOControl)) }
        }
        val result = linkedMapOf<String, String>()
        raw.split('&').forEach { item ->
            require(result.size < 8 && item.contains('=')); val pair = item.split('=', limit=2)
            val name = decode(pair[0]); require(name !in result); result[name] = decode(pair[1])
        }
        return result
    }
    fun callback(raw: String, bootstrap: Bootstrap, pending: Pending, generation: Long, boot: Int, elapsedMs: Long): Callback {
        require(pending.current(generation, boot, elapsedMs) && raw.length <= 8192)
        val u = URI(raw)
        require(u.scheme == "syn443" && u.host == "oauth" && u.rawPath == "/callback" && u.port == -1 && u.rawUserInfo == null && u.rawFragment == null)
        val q = query(requireNotNull(u.rawQuery))
        require(q.keys.all { it in setOf("code", "state", "iss", "session_state", "error", "error_description", "error_uri") })
        require(q["state"] == pending.state && q["iss"] == bootstrap.issuer)
        val code = q["code"]; val error = q["error"]
        require((code == null) != (error == null))
        if (code != null) require(code.length in 1..4096)
        if (error != null) require(error.matches(Regex("[a-z_]{1,64}")))
        return Callback(code, error)
    }
    fun jwk(key: ECPublicKey): JsonObject {
        require(key.params.order == ecParameters.order && key.params.cofactor == 1)
        fun coordinate(n: BigInteger): String { val b = n.toByteArray(); require(n.signum() >= 0 && n.bitLength() <= 256); return encode(ByteArray(32).also { b.copyInto(it, 32-minOf(b.size,32), maxOf(0,b.size-32)) }) }
        return buildJsonObject { put("crv","P-256"); put("kty","EC"); put("x",coordinate(key.w.affineX)); put("y",coordinate(key.w.affineY)) }
    }
    fun thumbprint(key: ECPublicKey): String = hash(Canonical.encode(jwk(key)).toByteArray(Charsets.US_ASCII))
    private fun fixed(n: BigInteger): ByteArray {
        require(n.signum() > 0 && n < ecParameters.order)
        val b=n.toByteArray(); return ByteArray(32).also { b.copyInto(it,32-minOf(b.size,32),maxOf(0,b.size-32)) }
    }
    fun derToRaw(der: ByteArray): ByteArray {
        require(der.size in 8..72 && der[0] == 0x30.toByte() && (der[1].toInt() and 255) == der.size-2)
        var offset=2
        fun integer(): BigInteger {
            require(offset+2<=der.size && der[offset++]==2.toByte()); val length=der[offset++].toInt() and 255
            require(length in 1..33 && offset+length<=der.size)
            val bytes=der.copyOfRange(offset,offset+length); offset+=length
            require(bytes[0].toInt()>=0 && !(length>1 && bytes[0]==0.toByte() && bytes[1].toInt()>=0))
            return BigInteger(bytes)
        }
        val r=integer(); val s=integer();require(offset==der.size); return fixed(r)+fixed(s)
    }
    fun proof(key: ECPublicKey, sign: (ByteArray)->ByteArray, method: String, uri: String, nowSeconds: Long,
        token: String = "", nonce: String = "", body: ByteArray? = null): String {
        https(uri); require(method in setOf("GET","POST") && nowSeconds>0 && nonce.length<=256 && token.length<=16_384 && (body?.size?:0)<=8192)
        val header=buildJsonObject { put("alg","ES256"); put("jwk",jwk(key)); put("typ","dpop+jwt") }
        val claims=buildJsonObject { put("htm",method); put("htu",uri); put("iat",nowSeconds); put("jti",random())
            if(token.isNotEmpty())put("ath",hash(token.toByteArray(Charsets.US_ASCII)))
            if(nonce.isNotEmpty())put("nonce",nonce)
            if(body!=null)put("req_hash",hash(body)) }
        val input=encode(Canonical.encode(header).toByteArray(Charsets.US_ASCII))+"."+encode(Canonical.encode(claims).toByteArray(Charsets.UTF_8))
        return input+"."+encode(derToRaw(sign(input.toByteArray(Charsets.US_ASCII))))
    }
    fun rsaKeys(raw: String): Map<String, RSAPublicKey> {
        val values=objectJSON(raw).getValue("keys").jsonArray;require(values.size in 1..16)
        val result=linkedMapOf<String,RSAPublicKey>()
        values.forEach { element -> val key=element.jsonObject
            if(key["kty"]?.string()=="RSA" && key["use"]?.string()=="sig" && key["alg"]?.string()=="RS256") {
                val id=key.getValue("kid").string();require(id.length in 1..128 && id !in result)
                val n=BigInteger(1,Policy.decode64(key.getValue("n").string()));val e=BigInteger(1,Policy.decode64(key.getValue("e").string()))
                require(n.bitLength() in 2048..4096 && e==BigInteger.valueOf(65537))
                result[id]=KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n,e)) as RSAPublicKey
            }
        }; require(result.isNotEmpty());return result
    }
    private fun jwt(raw: String, keys: Map<String,RSAPublicKey>): JsonObject {
        require(raw.length in 1..16_384);val parts=raw.split('.');require(parts.size==3)
        val header=objectJSON(Policy.utf8(Policy.decode64(parts[0])))
        require(header.keys==setOf("alg","kid","typ") && header.getValue("alg").string()=="RS256" && header.getValue("typ").string() in setOf("JWT","at+jwt"))
        val key=keys.getValue(header.getValue("kid").string())
        require(Signature.getInstance("SHA256withRSA").run { initVerify(key);update((parts[0]+"."+parts[1]).toByteArray(Charsets.US_ASCII));verify(Policy.decode64(parts[2])) })
        return objectJSON(Policy.utf8(Policy.decode64(parts[1])))
    }
    private fun JsonElement.string(): String { val v=jsonPrimitive; require(v.isString);return v.content }
    private fun JsonElement.integer(): Long { val v=jsonPrimitive;require(!v.isString);return v.long }
    private fun claims(raw: String,keys: Map<String,RSAPublicKey>,issuer: String,audience: String,client: String,now: Long): JsonObject {
        val c=jwt(raw,keys);require(c.getValue("iss").string()==issuer)
        val a=c.getValue("aud");val audiences=if(a is JsonArray)a.map { it.string() } else listOf(a.string())
        require(audience in audiences && (audiences.size==1 && c["azp"]==null || c["azp"]?.string()==client))
        val exp=c.getValue("exp").integer();val iat=c.getValue("iat").integer()
        require(exp>now && exp>iat && exp-iat<=600 && iat<=now+30 && iat>=now-600 && (c["nbf"]?.integer()?:0)<=now+30)
        val subject=c.getValue("sub").string();require(subject.toByteArray(Charsets.UTF_8).size in 1..256 && subject.none(Char::isISOControl));return c
    }
    fun identity(idToken: String,accessToken: String,keys: Map<String,RSAPublicKey>,bootstrap: Bootstrap,pending: Pending,nowSeconds: Long): UserIdentity {
        val id=claims(idToken,keys,bootstrap.issuer,bootstrap.clientId,bootstrap.clientId,nowSeconds)
        require(id.getValue("nonce").string()==pending.nonce)
        val access=claims(accessToken,keys,bootstrap.issuer,"syn443-api",bootstrap.clientId,nowSeconds)
        require(access.getValue("azp").string()==bootstrap.clientId && access.getValue("sub")==id.getValue("sub"))
        require(access.getValue("cnf").jsonObject.getValue("jkt").string()==pending.thumbprint)
        return UserIdentity(id.getValue("sub").string())
    }
}
