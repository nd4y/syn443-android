package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable data class RegisteredLogin(val ownerTag:String,val deviceId:String,val revision:Long) {
    override fun toString()="RegisteredLogin([redacted])"
    companion object {
        fun from(intent:LoginIntent)=if(intent.reauthRevision==0L)null
            else RegisteredLogin(intent.ownerTag,intent.deviceId,intent.reauthRevision)
    }
}

/** Protected worker-only cache. A policy envelope belongs in the separate activation journal. */
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class LoginPayload(val bootstrap:Bootstrap,val pending:Pending?=null,
    val user:UserCredential?=null,val session:SessionReply?=null,val invitation:InvitationPending?=null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val advertisedCapabilities:List<String>?=null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val registration:RegisteredLogin?=null) {
    override fun toString()="LoginPayload([redacted])"
    fun encode():String {
        validate()
        return Canonical.encode(Canonical.parse(Canonical.json.encodeToString(this))).also {Identity.objectJSON(it)}
    }
    private fun opaque(s:String)=s.matches(Regex("[A-Za-z0-9_-]{43}")) && runCatching {Policy.decode64(s).size==32}.getOrDefault(false)
    private fun validate() {
        bootstrap.validate();require(listOf(pending,user,session,invitation).count {it!=null}==1)
        advertisedCapabilities?.let {
            require(session!=null && it==CapabilityNegotiation.canonical(it) && IdentityOperation.supportedCapabilities.containsAll(it))
        }
        val authority=Identity.bootstrapAuthority(bootstrap)
        pending?.let {
            require(it.generation>=0 && it.bootCount>=0 && it.startedElapsedMs>=0 && listOf(it.state,it.nonce,it.verifier,it.thumbprint).all(::opaque))
        }
        user?.let {
            require(it.authority==authority && opaque(it.keyThumbprint) && it.accessToken.length in 24..16_384 &&
                it.accessToken.all {c->c.code in 33..126})
            LoginRecovery.ownerTag(bootstrap,it.subject)
        }
        session?.let {
            val s=it.session
            require(it.authority==authority && opaque(it.keyThumbprint) && listOf(s.deviceId,s.accessToken,s.refreshToken,s.nonce).all(::opaque) &&
                s.accessToken!=s.refreshToken && s.generation>=0 && s.accessUntilMs>0 && s.refreshUntilMs>=s.accessUntilMs)
        }
    }
    /** Called after authenticated decryption and before any network/key/policy effect. */
    fun requireBound(intent:LoginIntent):LoginPayload {
        validate();LoginRecovery.validate(intent)
        require(intent.authority==Identity.bootstrapAuthority(bootstrap) && intent.serviceId==bootstrap.serviceId)
        require(registration==RegisteredLogin.from(intent))
        invitation?.let {
            require(intent.method=="invite" && intent.phase in setOf(LoginPhase.INVITING,LoginPhase.NEEDS_REAUTH))
            it.validate(intent.thumbprint)
            require(intent.ownerTag==(it.reply?.state?.ownerTag?:""))
            require(intent.maybeRegistered==(it.completion!=null))
        }
        pending?.let {
            require(intent.phase in setOf(LoginPhase.BROWSER,LoginPhase.EXCHANGING,LoginPhase.NEEDS_REAUTH) &&
                it.generation==intent.generation && it.thumbprint==intent.thumbprint && (!intent.maybeRegistered || registration!=null))
        }
        user?.let {
            require(intent.phase in setOf(LoginPhase.AUTHENTICATED,LoginPhase.CLEANUP,LoginPhase.ENROLLING,LoginPhase.NEEDS_REAUTH) &&
                it.keyThumbprint==intent.thumbprint && LoginRecovery.ownerTag(bootstrap,it.subject)==intent.ownerTag)
        }
        session?.let {
            require(intent.phase in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING,LoginPhase.NEEDS_REAUTH) &&
                it.keyThumbprint==intent.thumbprint && it.session.deviceId==intent.deviceId && it.session.generation==intent.sessionGeneration)
        }
        return this
    }
    companion object {
        fun decode(raw:String,intent:LoginIntent):LoginPayload {
            val original=Identity.objectJSON(raw)
            // The previous protected format had no invitation variant. Normalize
            // this one absent null field; every existing credential/binding check remains.
            val parsed=if("invitation" in original)original else JsonObject(original+ ("invitation" to JsonNull))
            return Canonical.json.decodeFromJsonElement<LoginPayload>(parsed).requireBound(intent).also {
                require(Canonical.encode(parsed)==it.encode()) // No numeric-string coercion or omitted fields.
            }
        }
    }
}
