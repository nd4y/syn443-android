package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

enum class AuthFailure { CANCELLED, TRANSPORT, INVALID_REPLY, ACCESS_DENIED, REAUTHENTICATE, CONFLICT, PENDING, THROTTLED, UNAVAILABLE }
class AuthException(val reason:AuthFailure):Exception(reason.name)

interface ProofKey { val publicKey:ECPublicKey; fun sign(input:ByteArray):ByteArray }
fun interface IdentityExchange {
    fun request(method:String,url:String,headers:Map<String,String>,body:ByteArray?,scope:BoundedHttp.Scope,maxBody:Int):Reply
}

/** One multi-request operation, permanently cancelled on user Stop/Logout. */
class IdentityScope {
    private val cancelled=AtomicBoolean()
    private val current=AtomicReference<BoundedHttp.Scope?>()
    fun cancel() {cancelled.set(true);current.get()?.cancel()}
    internal fun <T> request(block:(BoundedHttp.Scope)->T):T {
        fun active() {if(cancelled.get())throw DeliveryException(DeliveryFailure.CANCELLED)}
        active();val child=BoundedHttp.Scope();check(current.compareAndSet(null,child))
        try {active();return block(child).also {active()}}
        finally {child.cancel();current.compareAndSet(child,null)}
    }
}

class IssuerState internal constructor(internal val keys:Map<String,RSAPublicKey>,val time:TrustedTime,internal val authority:String)
@Serializable class UserCredential internal constructor(val accessToken:String,val subject:String,val keyThumbprint:String,val time:TrustedTime,internal val authority:String) {
    override fun toString()="UserCredential([redacted])"
}
@Serializable data class DeviceSession(val deviceId:String,val accessToken:String,val refreshToken:String,
    val accessUntilMs:Long,val refreshUntilMs:Long,val generation:Long,val nonce:String) {
    override fun toString()="DeviceSession([redacted])"
}
@Serializable data class SessionReply(val session:DeviceSession,val time:TrustedTime,val authority:String,val keyThumbprint:String) {
    override fun toString()="SessionReply([redacted])"
}
data class PolicyReply(val envelope:String,val time:TrustedTime) {
    override fun toString()="PolicyReply([redacted])"
}

/** Immutable request must be persisted before dispatch; retries retain the exact body and ID. */
@Serializable data class IdentityOperation(val path:String,val body:String) {
    override fun toString()="IdentityOperation([redacted])"
    init {
        require(path in setOf("/v1/devices/enroll","/v1/identity/devices/revoke","/v1/device/session/refresh","/v1/device/revoke"))
        require(body.toByteArray(Charsets.UTF_8).size<=8192)
        val o=Identity.objectJSON(body)
        require(o.getValue("requestId").text().matches(Regex("[A-Za-z0-9_-]{24,128}")))
        when(path) {
            "/v1/devices/enroll" -> {
                require(o.keys==setOf("requestId","key","capabilities"))
                val key=o.getValue("key").jsonObject
                require(key.keys==setOf("crv","kty","x","y") && key.getValue("crv").text()=="P-256" && key.getValue("kty").text()=="EC")
                require(opaque(key.getValue("x").text()) && opaque(key.getValue("y").text()))
                val caps=o.getValue("capabilities").jsonArray.map {it.text()}
                require(caps.size in 3..16 && caps.distinct().size==caps.size && caps.all {it.matches(Regex("[a-zA-Z0-9._-]{1,64}"))} && caps.containsAll(requiredCapabilities))
            }
            "/v1/identity/devices/revoke" -> {
                require(o.keys==setOf("requestId","thumbprints"))
                val keys=o.getValue("thumbprints").jsonArray.map {it.text()}
                require(keys.size in 1..16 && keys.distinct().size==keys.size && keys.all(::opaque))
            }
            else -> require(o.keys==setOf("requestId"))
        }
    }
    companion object {
        val requiredCapabilities=listOf("engine-config.v1","tun.lease.v1","policy.keybound.v2")
        fun enroll(key:ECPublicKey)=IdentityOperation("/v1/devices/enroll",Canonical.encode(buildJsonObject {
            put("requestId",Identity.random());put("key",Identity.jwk(key));put("capabilities",JsonArray(requiredCapabilities.map(::JsonPrimitive)))
        }))
        fun cleanup(thumbprints:List<String>)=IdentityOperation("/v1/identity/devices/revoke",Canonical.encode(buildJsonObject {
            put("requestId",Identity.random());put("thumbprints",JsonArray(thumbprints.map(::JsonPrimitive)))
        }))
        fun refresh()=mutation("/v1/device/session/refresh")
        fun revoke()=mutation("/v1/device/revoke")
        private fun mutation(path:String)=IdentityOperation(path,Canonical.encode(buildJsonObject {put("requestId",Identity.random())}))
    }
}

private fun JsonElement.text():String = jsonPrimitive.let {require(it.isString);it.content}
private fun JsonElement.number():Long = jsonPrimitive.let {require(!it.isString);it.long}
private fun opaque(raw:String):Boolean=raw.matches(Regex("[A-Za-z0-9_-]{43}")) && runCatching {Policy.decode64(raw).size==32}.getOrDefault(false)

/** Synchronous protocol worker. The Android controller owns persistence and generation fencing. */
class AuthProtocol(bootstrap:Bootstrap,private val key:ProofKey,private val exchange:IdentityExchange,
    private val boot:()->Int,private val elapsed:()->Long) {
    private val bootstrap=bootstrap.copy(roots=bootstrap.roots.toMap())
    init {this.bootstrap.validate()}
    val thumbprint:String get()=Identity.thumbprint(key.publicKey)
    internal val authority:String=Identity.bootstrapAuthority(this.bootstrap)
    private fun request(scope:IdentityScope,method:String,url:String,headers:Map<String,String>,body:ByteArray?,maxBody:Int):Reply =
        scope.request {exchange.request(method,url,headers,body,it,maxBody)}
    private val oidcBase=bootstrap.issuer+"/protocol/openid-connect"
    private fun json(reply:Reply):JsonObject {
        require(reply.single("content-type")?.substringBefore(';')?.trim()?.lowercase()=="application/json")
        return Identity.objectJSON(Policy.utf8(reply.body))
    }
    private fun observed(reply:Reply,started:Long,floor:TrustedTime?=null):TrustedTime =
        TrustedTime.observe(requireNotNull(reply.single("date")),boot(),started,elapsed(),floor)
    private inline fun <T> checked(block:()->T):T = try {block()} catch(e:AuthException) {throw e
    } catch(e:DeliveryException) {throw AuthException(if(e.reason==DeliveryFailure.CANCELLED)AuthFailure.CANCELLED else AuthFailure.TRANSPORT)
    } catch(e:Exception) {throw AuthException(AuthFailure.INVALID_REPLY)}
    private fun status(reply:Reply,expected:Int) {
        if(reply.status==expected)return
        throw AuthException(when(reply.status) {
            202->AuthFailure.PENDING;401->AuthFailure.REAUTHENTICATE;403->AuthFailure.ACCESS_DENIED
            409->AuthFailure.CONFLICT;429->AuthFailure.THROTTLED;in 500..599->AuthFailure.UNAVAILABLE
            else->AuthFailure.INVALID_REPLY
        })
    }
    fun discover(scope:IdentityScope):IssuerState=checked {
        val start=elapsed()
        val reply=request(scope,"GET",bootstrap.issuer+"/.well-known/openid-configuration",mapOf("Cache-Control" to "no-store"),null,65_536)
        status(reply,200);val o=json(reply)
        require(o.getValue("issuer").text()==bootstrap.issuer && o.getValue("authorization_endpoint").text()==oidcBase+"/auth" &&
            o.getValue("token_endpoint").text()==oidcBase+"/token" && o.getValue("jwks_uri").text()==oidcBase+"/certs")
        require("RS256" in o.getValue("id_token_signing_alg_values_supported").jsonArray.map {it.text()} &&
            "ES256" in o.getValue("dpop_signing_alg_values_supported").jsonArray.map {it.text()} &&
            "S256" in o.getValue("code_challenge_methods_supported").jsonArray.map {it.text()})
        val initial=observed(reply,start)
        val keysStart=elapsed()
        val jwks=request(scope,"GET",oidcBase+"/certs",mapOf("Cache-Control" to "no-store"),null,65_536)
        status(jwks,200);json(jwks)
        IssuerState(Identity.rsaKeys(Policy.utf8(jwks.body)),observed(jwks,keysStart,initial),authority)
    }
    fun exchangeCode(code:String,pending:Pending,issuer:IssuerState,scope:IdentityScope):UserCredential=checked {
        require(code.length in 1..4096 && pending.thumbprint==thumbprint && issuer.authority==authority && pending.current(pending.generation,boot(),elapsed()))
        val url=oidcBase+"/token"
        val body=Identity.form(linkedMapOf("grant_type" to "authorization_code","client_id" to bootstrap.clientId,
            "redirect_uri" to Identity.callback,"code_verifier" to pending.verifier,"code" to code)).toByteArray(Charsets.UTF_8)
        var nonce=""
        for(attempt in 0..1) {
            val start=elapsed()
            val proof=Identity.proof(key.publicKey,key::sign,"POST",url,issuer.time.proofSecond(boot(),start),nonce=nonce)
            val reply=request(scope,"POST",url,mapOf("Content-Type" to "application/x-www-form-urlencoded","DPoP" to proof),body,65_536)
            if(reply.status in setOf(400,401) && attempt==0 && json(reply)["error"]?.text()=="use_dpop_nonce") {
                nonce=challenge(reply);continue
            }
            status(reply,200);val o=json(reply);require(o.getValue("token_type").text()=="DPoP")
            val access=o.getValue("access_token").text();val id=o.getValue("id_token").text()
            val expires=o.getValue("expires_in").number();require(expires in 1..600)
            val time=observed(reply,start,issuer.time);val now=time.window(boot(),elapsed()).upperMs/1000
            val identity=Identity.identity(id,access,issuer.keys,bootstrap,pending,now)
            return@checked UserCredential(access,identity.subject,thumbprint,time,authority)
        }
        throw AuthException(AuthFailure.REAUTHENTICATE)
    }
    private fun challenge(reply:Reply):String = requireNotNull(reply.single("dpop-nonce")).also {
        require(it.length in 1..256 && it.all {c->c.code in 33..126})
    }
    private data class Delivered(val reply:Reply,val time:TrustedTime)
    private fun api(path:String,body:String?,token:String,nonce:String,floor:TrustedTime,scope:IdentityScope,maxReply:Int=if(body==null)524_288 else 65_536):Delivered {
        require(token.length in 24..16_384 && token.all {it.code in 33..126})
        val url=bootstrap.apiOrigin+path;val method=if(body==null)"GET" else "POST";val bytes=body?.toByteArray(Charsets.UTF_8)
        var currentNonce=nonce
        for(attempt in 0..1) {
            val limit=if(path=="/v1/chat/uploads/part")360_448 else if(path.startsWith("/v1/chat/"))32_768 else 8192
            val start=elapsed();val proof=Identity.proof(key.publicKey,key::sign,method,url,floor.proofSecond(boot(),start),token,currentNonce,bytes,limit)
            val headers=linkedMapOf("Authorization" to "DPoP $token","DPoP" to proof)
            if(body!=null)headers["Content-Type"]="application/json"
            val reply=request(scope,method,url,headers,bytes,maxReply)
            if(reply.status==401 && attempt==0 && json(reply)["code"]?.text()=="use_dpop_nonce") {
                currentNonce=challenge(reply);continue
            }
            status(reply,if(path.endsWith("/revoke"))204 else 200)
            return Delivered(reply,observed(reply,start,floor))
        }
        throw AuthException(AuthFailure.REAUTHENTICATE)
    }
    fun enroll(op:IdentityOperation,user:UserCredential,scope:IdentityScope):SessionReply=checked {
        require(op.path=="/v1/devices/enroll" && user.keyThumbprint==thumbprint && user.authority==authority && Identity.objectJSON(op.body).getValue("key")==Identity.jwk(key.publicKey))
        val result=api(op.path,op.body,user.accessToken,"",user.time,scope)
        SessionReply(session(result),result.time,authority,thumbprint)
    }
    fun cleanup(op:IdentityOperation,user:UserCredential,scope:IdentityScope):TrustedTime=checked {
        require(op.path=="/v1/identity/devices/revoke" && user.keyThumbprint==thumbprint && user.authority==authority)
        api(op.path,op.body,user.accessToken,"",user.time,scope).time
    }
    fun refresh(op:IdentityOperation,previous:SessionReply,scope:IdentityScope):SessionReply=checked {
        require(op.path=="/v1/device/session/refresh");bound(previous)
        require(previous.time.window(boot(),elapsed()).upperMs<previous.session.refreshUntilMs)
        val result=api(op.path,op.body,previous.session.refreshToken,previous.session.nonce,previous.time,scope)
        val next=session(result)
        require(next.deviceId==previous.session.deviceId && next.generation==Math.addExact(previous.session.generation,1) &&
            next.accessToken!=previous.session.accessToken && next.refreshToken!=previous.session.refreshToken && next.nonce!=previous.session.nonce &&
            next.refreshUntilMs==previous.session.refreshUntilMs)
        SessionReply(next,result.time,authority,thumbprint)
    }
    fun revoke(op:IdentityOperation,current:SessionReply,scope:IdentityScope):TrustedTime=checked {
        require(op.path=="/v1/device/revoke");bound(current)
        api(op.path,op.body,current.session.accessToken,current.session.nonce,current.time,scope).time
    }
    fun policy(current:SessionReply,scope:IdentityScope):PolicyReply=checked {
        bound(current)
        require(current.time.window(boot(),elapsed()).upperMs<current.session.accessUntilMs)
        val result=api("/v1/device/policy",null,current.session.accessToken,current.session.nonce,current.time,scope)
        require(result.reply.single("content-type")=="application/jose")
        val envelope=Policy.utf8(result.reply.body)
        val upper=result.time.window(boot(),elapsed()).upperMs
        Policy.verifyBound(envelope,bootstrap.roots,current.session.deviceId,thumbprint,upper)
        PolicyReply(envelope,result.time)
    }
    /** One bounded chunk/operation; the controller rechecks the account before every call. */
    fun chat(action:String,body:String,current:SessionReply,scope:IdentityScope):String=checked {
        bound(current)
        require(action in setOf("self","inbox","messages","send","read","uploads/begin","uploads/part","uploads/status","uploads/complete","uploads/cancel","download"))
        require(body.toByteArray(Charsets.UTF_8).size<=if(action=="uploads/part")360_448 else 32_768)
        require(Canonical.parse(body) is JsonObject)
        require(current.time.window(boot(),elapsed()).upperMs<current.session.accessUntilMs)
        val result=api("/v1/chat/$action",body,current.session.accessToken,current.session.nonce,current.time,scope,524_288)
        require(result.reply.single("content-type")?.substringBefore(';')?.trim()?.lowercase()=="application/json")
        Policy.utf8(result.reply.body).also {Canonical.parse(it)}
    }
    private fun bound(current:SessionReply) {require(current.authority==authority && current.keyThumbprint==thumbprint)}
    private fun session(result:Delivered):DeviceSession {
        val o=json(result.reply)
        require(o.keys==setOf("deviceId","accessToken","refreshToken","accessUntilMs","refreshUntilMs","generation","nonce"))
        val s=DeviceSession(o.getValue("deviceId").text(),o.getValue("accessToken").text(),o.getValue("refreshToken").text(),
            o.getValue("accessUntilMs").number(),o.getValue("refreshUntilMs").number(),o.getValue("generation").number(),o.getValue("nonce").text())
        val w=result.time.window(boot(),elapsed())
        require(listOf(s.deviceId,s.accessToken,s.refreshToken,s.nonce).all(::opaque) && s.accessToken!=s.refreshToken && s.generation in 0..9_007_199_254_740_991 &&
            s.accessUntilMs>w.upperMs && s.accessUntilMs<=Math.addExact(w.lowerMs,600_000) && s.refreshUntilMs>=s.accessUntilMs &&
            s.refreshUntilMs<=Math.addExact(w.lowerMs,86_400_000))
        return s
    }
}
