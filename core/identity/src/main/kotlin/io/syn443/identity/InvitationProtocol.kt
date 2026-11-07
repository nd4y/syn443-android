package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.security.interfaces.ECPublicKey

private fun JsonElement.inviteText()=jsonPrimitive.let {require(it.isString);it.content}
private fun JsonElement.inviteLong()=jsonPrimitive.let {require(!it.isString);it.long}
private fun inviteOpaque(raw:String)=raw.matches(Regex("[A-Za-z0-9_-]{43}")) && runCatching {Policy.decode64(raw).size==32}.getOrDefault(false)

/** Persist before dispatch; retries reuse the exact body with a new key proof. */
@Serializable data class InvitationOperation(val path:String,val body:String) {
    override fun toString()="InvitationOperation([redacted])"
    init {
        require(body.toByteArray(Charsets.UTF_8).size<=8192)
        val value=Identity.objectJSON(body)
        require("requestId" in value)
        require(value.getValue("requestId").inviteText().matches(Regex("[A-Za-z0-9_-]{24,128}")))
        when(path) {
            "/v1/invitations/claim" -> {
                require(value.keys==setOf("requestId","code","key","capabilities") && inviteOpaque(value.getValue("code").inviteText()))
                val key=value.getValue("key").jsonObject
                require(key.keys==setOf("crv","kty","x","y") && key.getValue("crv").inviteText()=="P-256" && key.getValue("kty").inviteText()=="EC")
                require(inviteOpaque(key.getValue("x").inviteText()) && inviteOpaque(key.getValue("y").inviteText()))
                require(listOf(IdentityOperation.requiredCapabilities,IdentityOperation.supportedCapabilities).any{
                    value.getValue("capabilities")==JsonArray(it.map(::JsonPrimitive))})
            }
            "/v1/invitations/status","/v1/invitations/complete","/v1/invitations/abandon" ->
                require(value.keys==setOf("requestId","id") && inviteOpaque(value.getValue("id").inviteText()))
            else -> error("invitation path")
        }
    }
    companion object {
        fun claim(code:String,key:ECPublicKey)=InvitationOperation("/v1/invitations/claim",Canonical.encode(buildJsonObject {
            put("requestId",Identity.random());put("code",code);put("key",Identity.jwk(key))
            put("capabilities",JsonArray(IdentityOperation.supportedCapabilities.map(::JsonPrimitive)))
        }))
        fun mutation(action:String,id:String)=InvitationOperation("/v1/invitations/$action",Canonical.encode(buildJsonObject {
            put("requestId",Identity.random());put("id",id)
        }))
    }
}

@Serializable data class InvitationState(val id:String,val version:Long,val state:String,val pairCode:String,val nonce:String,
    val deviceId:String,val expires:Long,val ownerTag:String,val error:String="") {
    override fun toString()="InvitationState([redacted])"
    fun validate() {
        require(inviteOpaque(id) && inviteOpaque(nonce) && inviteOpaque(ownerTag) && version in 2..9_007_199_254_740_991L && expires>0)
        require(pairCode.matches(Regex("[0-9]{6}")) && (deviceId.isEmpty()||inviteOpaque(deviceId)))
        require(state in setOf("pending_approval","provisioning","ready","completed","expired","revoked"))
        require(error in setOf("","authorization_changed","unsupported_capabilities","temporarily_unavailable","reauthentication_required"))
        if(state in setOf("ready","completed"))require(deviceId.isNotEmpty())
    }
}
@Serializable data class InvitationReply(val state:InvitationState,val time:TrustedTime) {
    override fun toString()="InvitationReply([redacted])"
}
@Serializable data class InvitationCompletion(val session:SessionReply,val ownerTag:String) {
    override fun toString()="InvitationCompletion([redacted])"
}
@Serializable data class InvitationPending(val claim:InvitationOperation,val time:TrustedTime?=null,
    val reply:InvitationReply?=null,val completion:InvitationOperation?=null) {
    override fun toString()="InvitationPending([redacted])"
    fun validate(thumbprint:String) {
        require(claim.path=="/v1/invitations/claim")
        val key=Identity.objectJSON(claim.body).getValue("key")
        require(Identity.hash(Canonical.encode(key).toByteArray(Charsets.UTF_8))==thumbprint)
        reply?.state?.validate()
        require(reply==null||time!=null)
        completion?.let {require(reply!=null && it.path=="/v1/invitations/complete" &&
            Identity.objectJSON(it.body).getValue("id").inviteText()==reply.state.id)}
    }
}

/** The authenticated bootstrap supplies the origin; no issuer login is needed.
 * TLS Date anchors time before any key/code request. No redirect is followed by
 * the bounded exchange; the controller owns physical-network/generation fences. */
class InvitationProtocol(private val bootstrap:Bootstrap,private val key:ProofKey,private val exchange:IdentityExchange,
    private val boot:()->Int,private val elapsed:()->Long) {
    init {bootstrap.validate()}
    private val authority=Identity.bootstrapAuthority(bootstrap)
    private val thumbprint=Identity.thumbprint(key.publicKey)
    private inline fun<T>checked(block:()->T):T=try {block()}catch(e:AuthException){throw e}
        catch(e:DeliveryException){throw AuthException(if(e.reason==DeliveryFailure.CANCELLED)AuthFailure.CANCELLED else AuthFailure.TRANSPORT)}
        catch(_:Exception){throw AuthException(AuthFailure.INVALID_REPLY)}
    private fun json(reply:Reply):JsonObject {
        require(reply.single("content-type")?.substringBefore(';')?.trim()?.lowercase()=="application/json")
        return Identity.objectJSON(Policy.utf8(reply.body))
    }
    private fun status(reply:Reply) {
        if(reply.status==200)return
        throw AuthException(when(reply.status){202->AuthFailure.PENDING;401->AuthFailure.REAUTHENTICATE;403->AuthFailure.ACCESS_DENIED
            409->AuthFailure.CONFLICT;429->AuthFailure.THROTTLED;in 500..599->AuthFailure.UNAVAILABLE;else->AuthFailure.INVALID_REPLY})
    }
    fun time(scope:IdentityScope,previous:TrustedTime?=null):TrustedTime=checked {
        val start=elapsed()
        val reply=scope.request {exchange.request("GET",bootstrap.apiOrigin+"/v1/invitations/time",mapOf("Cache-Control" to "no-store"),null,it,8192)}
        status(reply);val value=json(reply)
        require(value.keys==setOf("serviceId") && value.getValue("serviceId").inviteText()==bootstrap.serviceId)
        val now=TrustedTime.observe(requireNotNull(reply.single("date")),boot(),start,elapsed())
        // Reboot invalidates elapsed-time anchors but must not roll back UTC.
        require(previous==null || now.upperMs>=previous.lowerMs)
        now
    }
    private fun dispatch(op:InvitationOperation,nonce:String,time:TrustedTime,scope:IdentityScope):Pair<Reply,TrustedTime> {
        val start=elapsed();val body=op.body.toByteArray(Charsets.UTF_8);val url=bootstrap.apiOrigin+op.path
        val proof=Identity.proof(key.publicKey,key::sign,"POST",url,time.proofSecond(boot(),start),nonce=nonce,body=body)
        val reply=scope.request {exchange.request("POST",url,mapOf("Content-Type" to "application/json","DPoP" to proof),body,it,8192)}
        status(reply)
        return reply to TrustedTime.observe(requireNotNull(reply.single("date")),boot(),start,elapsed(),time)
    }
    fun claim(op:InvitationOperation,time:TrustedTime,scope:IdentityScope):InvitationReply=checked {
        require(op.path=="/v1/invitations/claim" && Identity.objectJSON(op.body).getValue("key")==Identity.jwk(key.publicKey))
        val (reply,observed)=dispatch(op,"",time,scope);state(reply,observed)
    }
    fun status(op:InvitationOperation,previous:InvitationReply,time:TrustedTime,scope:IdentityScope):InvitationReply=checked {
        require(op.path=="/v1/invitations/status");bound(op,previous)
        val (reply,observed)=dispatch(op,previous.state.nonce,time,scope);val result=state(reply,observed)
        require(result.state.id==previous.state.id && result.state.nonce==previous.state.nonce && result.state.pairCode==previous.state.pairCode &&
            result.state.ownerTag==previous.state.ownerTag && result.state.expires==previous.state.expires && result.state.version>=previous.state.version &&
            (previous.state.deviceId.isEmpty()||result.state.deviceId==previous.state.deviceId))
        result
    }
    private fun bound(op:InvitationOperation,previous:InvitationReply) {
        previous.state.validate();require(Identity.objectJSON(op.body).getValue("id").inviteText()==previous.state.id)
    }
    private fun state(reply:Reply,time:TrustedTime):InvitationReply {
        val value=json(reply)
        val required=setOf("id","version","state","pairCode","nonce","deviceId","expires","ownerTag")
        require(value.keys==required || value.keys==required+"error")
        value.getValue("version").inviteLong();value.getValue("expires").inviteLong()
        return InvitationReply(Canonical.json.decodeFromJsonElement<InvitationState>(value).also {it.validate()},time)
    }
    fun complete(op:InvitationOperation,previous:InvitationReply,time:TrustedTime,scope:IdentityScope):InvitationCompletion=checked {
        require(op.path=="/v1/invitations/complete" && previous.state.state in setOf("ready","completed"));bound(op,previous)
        val(reply,observed)=dispatch(op,previous.state.nonce,time,scope);val value=json(reply)
        require(value.keys==setOf("session","ownerTag") && value.getValue("ownerTag").inviteText()==previous.state.ownerTag)
        val raw=value.getValue("session").jsonObject
        require(raw.keys==setOf("deviceId","accessToken","refreshToken","accessUntilMs","refreshUntilMs","generation","nonce"))
        for(field in listOf("accessUntilMs","refreshUntilMs","generation"))raw.getValue(field).inviteLong()
        val session=Canonical.json.decodeFromJsonElement<DeviceSession>(raw);val window=observed.window(boot(),elapsed())
        require(listOf(session.deviceId,session.accessToken,session.refreshToken,session.nonce).all(::inviteOpaque) && session.accessToken!=session.refreshToken &&
            session.deviceId==previous.state.deviceId && session.generation==0L && session.accessUntilMs>window.upperMs &&
            session.accessUntilMs<=Math.addExact(window.lowerMs,600_000) && session.refreshUntilMs>=session.accessUntilMs &&
            session.refreshUntilMs<=Math.addExact(window.lowerMs,86_400_000))
        InvitationCompletion(SessionReply(session,observed,authority,thumbprint),previous.state.ownerTag)
    }
    fun abandon(op:InvitationOperation,previous:InvitationReply,time:TrustedTime,scope:IdentityScope):TrustedTime=checked {
        require(op.path=="/v1/invitations/abandon");bound(op,previous)
        val(reply,observed)=dispatch(op,previous.state.nonce,time,scope);val value=json(reply)
        require(value.keys==setOf("revoked") && value.getValue("revoked").jsonPrimitive.let {!it.isString&&it.boolean})
        observed
    }
}
