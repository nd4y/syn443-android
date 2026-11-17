package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.io.ByteArrayOutputStream
import java.net.URI
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicBoolean

enum class AdminFailure { CANCELLED, TRANSPORT, INVALID_REPLY, ACCESS_DENIED, REAUTHENTICATE, SESSION_EXPIRED,
    CONFLICT, INVALID_CONFIGURATION, LIMITED }
class AdminException(val reason:AdminFailure):Exception(reason.name)

/** Caller supplies metadata only after signed service verification. This is not a device Bootstrap. */
class AdminIdentity internal constructor(metadata:AdminBootstrap,val serviceBinding:String,
    internal val editorServiceHash:String=serviceBinding) {
    val metadata:AdminBootstrap=metadata.copy()
    val authority:String
    init {
        authority=try {
            this.metadata.validate()
            require(digest(serviceBinding) && digest(editorServiceHash))
            Identity.hash(Canonical.encode(buildJsonObject {
                put("adminBootstrap",Canonical.parse(Canonical.json.encodeToString(this@AdminIdentity.metadata)))
                put("serviceBinding",serviceBinding)
            }).toByteArray(Charsets.UTF_8))
        } catch(_:Exception) {throw AdminException(AdminFailure.INVALID_REPLY)}
    }
    override fun toString()="AdminIdentity([redacted])"

    internal fun pending(generation:Long,thumbprint:String,boot:Int,elapsed:Long):AdminPending {
        require(generation>=0 && digest(thumbprint) && boot>=0 && elapsed>=0)
        return AdminPending(generation,Identity.random(),Identity.random(),Identity.random(),thumbprint,authority,boot,elapsed)
    }
    internal fun binding(pending:AdminPending,generation:Long,thumbprint:String,boot:Int,elapsed:Long) {
        require(pending.authority==authority && pending.keyThumbprint==thumbprint &&
            pending.generation==generation && pending.bootCount==boot && elapsed>=pending.startedElapsedMs &&
            elapsed-pending.startedElapsedMs<300_000)
    }
    internal fun current(pending:AdminPending,generation:Long,thumbprint:String,boot:Int,elapsed:Long) {
        binding(pending,generation,thumbprint,boot,elapsed)
        require(!pending.consumed.get())
    }
    internal fun authorization(pending:AdminPending,generation:Long,thumbprint:String,boot:Int,elapsed:Long):String {
        current(pending,generation,thumbprint,boot,elapsed)
        return metadata.issuer+"/protocol/openid-connect/auth?"+Identity.form(linkedMapOf(
            "client_id" to AdminBootstrap.CLIENT_ID,"redirect_uri" to AdminBootstrap.CALLBACK,
            "response_type" to "code","scope" to AdminBootstrap.SCOPE,"state" to pending.state,
            "nonce" to pending.nonce,"code_challenge_method" to "S256",
            "code_challenge" to Identity.hash(pending.verifier.toByteArray(Charsets.US_ASCII)),
            "dpop_jkt" to thumbprint,"acr_values" to AdminBootstrap.ASSURANCE_ACR,"max_age" to "300"))
    }
    /** Invalid foreign callbacks do not consume the current attempt. A validated callback is one-use. */
    internal fun callback(raw:String,pending:AdminPending,generation:Long,thumbprint:String,boot:Int,elapsed:Long):String {
        current(pending,generation,thumbprint,boot,elapsed)
        require(raw.length in 1..8192 && raw.all {it.code in 33..126})
        val uri=URI(raw)
        require(uri.scheme=="syn443" && uri.rawAuthority=="admin" && uri.rawPath=="/oauth/callback" &&
            uri.rawUserInfo==null && uri.port == -1 && uri.rawFragment==null && !uri.isOpaque)
        val fields=query(requireNotNull(uri.rawQuery))
        require(fields.keys.all {it in setOf("code","state","iss","session_state","error","error_description","error_uri")})
        require(fields["state"]==pending.state && fields["iss"]==metadata.issuer)
        val code=fields["code"];val error=fields["error"]
        require((code==null)!=(error==null))
        if(code!=null)require(code.length in 1..4096)
        if(error!=null)require(error.matches(Regex("[a-z_]{1,64}")))
        if(!pending.consumed.compareAndSet(false,true))throw AdminException(AdminFailure.REAUTHENTICATE)
        if(error!=null)throw AdminException(AdminFailure.ACCESS_DENIED)
        return requireNotNull(code)
    }
    internal data class TokenIdentity(val subject:String,val accessExpiresSeconds:Long) {
        override fun toString()="AdminTokenIdentity([redacted])"
    }
    internal fun tokens(idToken:String?,accessToken:String,keys:Map<String,RSAPublicKey>,thumbprint:String,
        nonce:String,time:TimeWindow,initial:Boolean,subject:String?=null):TokenIdentity {
        val access=claims(accessToken,keys,AdminBootstrap.AUDIENCE,time)
        require(access.getValue("azp").text()==AdminBootstrap.CLIENT_ID)
        val confirmation=access.getValue("cnf").jsonObject
        require(confirmation.keys==setOf("jkt") && confirmation.getValue("jkt").text()==thumbprint)
        val scopes=scope(access.getValue("scope").text())
        require(scopes.containsAll(setOf("openid","syn443.control")) && "offline_access" !in scopes)
        val actual=access.getValue("sub").text()
        require(subject==null || subject==actual)
        if(initial)require(idToken!=null)
        if(idToken!=null) {
            val id=claims(idToken,keys,AdminBootstrap.CLIENT_ID,time)
            require(id.getValue("sub").text()==actual)
            if(initial || "nonce" in id)require(id.getValue("nonce").text()==nonce)
            if(initial) {
                val authenticated=id.getValue("auth_time").integer()
                require(authenticated>0 && authenticated<=Long.MAX_VALUE/1000)
                val authenticatedMs=authenticated*1000
                require(authenticatedMs<=Math.addExact(time.lowerMs,30_000) &&
                    authenticatedMs>=Math.subtractExact(time.upperMs,330_000))
            }
            id["at_hash"]?.let {
                val digest=MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray(Charsets.US_ASCII))
                require(it.text()==Identity.encode(digest.copyOfRange(0,16)))
            }
            id["cnf"]?.let {val cnf=it.jsonObject;require(cnf.keys==setOf("jkt") && cnf.getValue("jkt").text()==thumbprint)}
        }
        return TokenIdentity(actual,access.getValue("exp").integer())
    }
    private fun claims(raw:String,keys:Map<String,RSAPublicKey>,audience:String,time:TimeWindow):JsonObject {
        require(raw.length in 1..16_384 && raw.all {it.code in 33..126})
        val parts=raw.split('.');require(parts.size==3)
        val header=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[0])))
        require(header.keys==setOf("alg","kid","typ") && header.getValue("alg").text()=="RS256" &&
            header.getValue("typ").text() in setOf("JWT","at+jwt"))
        val key=keys.getValue(header.getValue("kid").text())
        require(Signature.getInstance("SHA256withRSA").run {
            initVerify(key);update((parts[0]+"."+parts[1]).toByteArray(Charsets.US_ASCII));verify(Policy.decode64(parts[2]))
        })
        val claims=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[1])))
        require(claims.getValue("iss").text()==metadata.issuer && claims.getValue("azp").text()==AdminBootstrap.CLIENT_ID)
        val value=claims.getValue("aud")
        val audiences=if(value is JsonArray)value.map {it.text()} else listOf(value.text())
        require(audiences.size in 1..8 && audiences.distinct().size==audiences.size && audience in audiences &&
            audiences.all {it.length in 1..128} && "syn443-api" !in audiences && "syn443-android" !in audiences)
        val exp=claims.getValue("exp").integer();val iat=claims.getValue("iat").integer()
        require(iat>0 && exp>iat && exp-iat<=600 && exp<=Long.MAX_VALUE/1000)
        val expMs=exp*1000;val iatMs=Math.multiplyExact(iat,1000)
        require(expMs>time.upperMs && iatMs<=Math.addExact(time.lowerMs,30_000) &&
            iatMs>=time.upperMs-600_000)
        claims["nbf"]?.let {require(it.integer() in 0..Long.MAX_VALUE/1000 && it.integer()*1000<=Math.addExact(time.lowerMs,30_000))}
        val sub=claims.getValue("sub").text()
        require(sub.toByteArray(Charsets.UTF_8).size in 1..256 && sub.none(Char::isISOControl))
        return claims
    }
    companion object {
        internal fun digest(raw:String)=raw.matches(Regex("[A-Za-z0-9_-]{43}")) &&
            runCatching {Policy.decode64(raw).size==32}.getOrDefault(false)
        internal fun scope(raw:String):Set<String> {
            val values=raw.split(' ')
            require(values.size in 1..32 && values.distinct().size==values.size &&
                values.all {it.matches(Regex("[A-Za-z0-9._:-]{1,128}"))})
            return values.toSet()
        }
        internal fun JsonElement.text():String=jsonPrimitive.let {require(it.isString);it.content}
        internal fun JsonElement.integer():Long=jsonPrimitive.let {require(!it.isString);it.long}
        private fun query(raw:String):Map<String,String> {
            require(raw.length in 1..8192)
            fun decode(value:String):String {
                val out=ByteArrayOutputStream();var i=0
                while(i<value.length) {
                    val c=value[i++]
                    when(c) {
                        '%'->{require(i+2<=value.length);out.write(value.substring(i,i+2).toInt(16));i+=2}
                        '+'->out.write(32)
                        else->{require(c.code in 33..126);out.write(c.code)}
                    }
                }
                return Policy.utf8(out.toByteArray()).also {require(it.none(Char::isISOControl))}
            }
            val result=linkedMapOf<String,String>()
            raw.split('&').forEach {
                require(result.size<8 && '=' in it);val pair=it.split('=',limit=2)
                val key=decode(pair[0]);require(key !in result);result[key]=decode(pair[1])
            }
            return result
        }
    }
}

/** Process-owned attempt. No serialized CAS state or reconstruction is accepted as authorization. */
class AdminPending internal constructor(val generation:Long,val state:String,val nonce:String,val verifier:String,
    val keyThumbprint:String,val authority:String,val bootCount:Int,val startedElapsedMs:Long) {
    internal val consumed=AtomicBoolean()
    override fun toString()="AdminPending([redacted])"
}
