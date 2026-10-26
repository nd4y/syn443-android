package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.security.interfaces.ECPublicKey

@Serializable enum class LoginPhase {
    SIGNED_OUT, RESERVED, BROWSER, EXCHANGING, AUTHENTICATED, CLEANUP, ENROLLING,
    PROVISIONING, POLICY_CACHED, REFRESHING, NEEDS_REAUTH, RETIRING
}
enum class LoginResume { IDLE, KEY_RESERVATION, BROWSER, AUTHENTICATED, RETRY_CLEANUP, RETRY_ENROLLMENT,
    SESSION, REANCHOR_SESSION, RETRY_REFRESH, REAUTHENTICATE, CANCEL_AND_CLEANUP, COMPLETE_RETIRE }

/** Nonsecret recovery metadata. Neither ownerTag nor thumbprint is an authorization credential. */
@Serializable data class RegistrationTombstone(val ownerTag:String,val thumbprint:String) {
    override fun toString()="RegistrationTombstone([redacted])"
}

/** Public intent fence, written before the referenced protected payload/network effect. */
@Serializable data class LoginIntent(
    val generation:Long=0,val revision:Long=0,val phase:LoginPhase=LoginPhase.SIGNED_OUT,
    val authority:String="",val serviceId:String="",val keyAlias:String="",val thumbprint:String="",
    val ownerTag:String="",val protectedHash:String="",val maybeRegistered:Boolean=false,
    val deviceId:String="",val sessionGeneration:Long = -1,val policyHash:String="",
    val operation:IdentityOperation?=null,val operationBoot:Int = -1,val operationElapsedMs:Long = -1,
    val refreshReturnPhase:LoginPhase?=null,val tombstones:List<RegistrationTombstone> = emptyList(),
    val retiringAliases:List<String> = emptyList()
) {
    override fun toString()="LoginIntent(phase=$phase, [redacted])"
}

/** Deterministic transition core; the Android single writer persists before performing effects. */
object LoginRecovery {
    private const val maximum=9_007_199_254_740_991L
    private fun digest(value:String)=value.matches(Regex("[A-Za-z0-9_-]{43}")) &&
        runCatching {Policy.decode64(value).size==32}.getOrDefault(false)
    fun ownedAlias(alias:String)=alias.startsWith("syn443-dpop-") && digest(alias.removePrefix("syn443-dpop-"))
    private fun next(n:Long)=Math.addExact(n,1).also {require(it<=maximum)}
    private fun current(s:LoginIntent,generation:Long) {validate(s);require(s.generation==generation)}
    private fun revised(s:LoginIntent)=s.copy(revision=next(s.revision)).also(::validate)
    private fun operation(s:LoginIntent,op:IdentityOperation,boot:Int,elapsed:Long,phase:LoginPhase)=s.copy(
        phase=phase,operation=op,operationBoot=boot,operationElapsedMs=elapsed)
    private fun withoutOperation(s:LoginIntent)=s.copy(operation=null,operationBoot= -1,operationElapsedMs= -1,refreshReturnPhase=null)
    fun encode(s:LoginIntent):String {validate(s);return Canonical.encode(Canonical.parse(Canonical.json.encodeToString(s)))}
    fun decode(raw:String):LoginIntent {
        val o=Identity.objectJSON(raw)
        for(name in listOf("generation","revision","sessionGeneration","operationBoot","operationElapsedMs"))
            o[name]?.jsonPrimitive?.let {require(!it.isString);it.long}
        o["maybeRegistered"]?.jsonPrimitive?.let {require(!it.isString && it.booleanOrNull!=null)}
        return Canonical.json.decodeFromJsonElement<LoginIntent>(o).also(::validate)
    }
    fun ownerTag(bootstrap:Bootstrap,subject:String):String {
        bootstrap.validate();require(subject.toByteArray(Charsets.UTF_8).size in 1..256 && subject.none(Char::isISOControl))
        return Identity.hash(Canonical.encode(buildJsonObject {
            put("service",bootstrap.serviceId);put("issuer",bootstrap.issuer);put("subject",subject)
        }).toByteArray(Charsets.UTF_8))
    }
    fun validate(s:LoginIntent) {
        require(s.generation in 0..maximum && s.revision in 0..maximum)
        require(s.tombstones.size<=32 && s.tombstones.distinct().size==s.tombstones.size &&
            s.tombstones.all {digest(it.ownerTag) && digest(it.thumbprint)})
        require(s.retiringAliases.size<=32 && s.retiringAliases.distinct().size==s.retiringAliases.size && s.retiringAliases.all(::ownedAlias))
        if(s.phase in setOf(LoginPhase.SIGNED_OUT,LoginPhase.RETIRING)) {
            require(listOf(s.authority,s.serviceId,s.keyAlias,s.thumbprint,s.ownerTag,s.protectedHash,s.deviceId,s.policyHash).all {it.isEmpty()} &&
                !s.maybeRegistered && s.sessionGeneration== -1L && s.operation==null && s.operationBoot== -1 && s.operationElapsedMs== -1L && s.refreshReturnPhase==null)
            require((s.phase==LoginPhase.RETIRING)==s.retiringAliases.isNotEmpty());return
        }
        require(digest(s.authority) && s.serviceId.matches(Regex("[A-Za-z0-9_-]{1,64}")) && ownedAlias(s.keyAlias) && s.keyAlias !in s.retiringAliases)
        if(s.phase==LoginPhase.RESERVED) require(s.thumbprint.isEmpty() && s.protectedHash.isEmpty())
        else require(digest(s.thumbprint) && digest(s.protectedHash))
        if(s.phase in setOf(LoginPhase.RESERVED,LoginPhase.BROWSER,LoginPhase.EXCHANGING)) require(s.ownerTag.isEmpty() && !s.maybeRegistered)
        else require(digest(s.ownerTag) || s.phase==LoginPhase.NEEDS_REAUTH && s.ownerTag.isEmpty() && !s.maybeRegistered)
        require(s.maybeRegistered || s.deviceId.isEmpty() && s.sessionGeneration== -1L && s.policyHash.isEmpty())
        require(!s.maybeRegistered || digest(s.ownerTag))
        require((s.deviceId.isEmpty() && s.sessionGeneration== -1L) || digest(s.deviceId) && s.sessionGeneration in 0..maximum)
        require(s.policyHash.isEmpty() || digest(s.policyHash) && s.deviceId.isNotEmpty())
        val path=when(s.phase) {
            LoginPhase.CLEANUP->"/v1/identity/devices/revoke"
            LoginPhase.ENROLLING->"/v1/devices/enroll"
            LoginPhase.REFRESHING->"/v1/device/session/refresh"
            else->null
        }
        if(path==null) require(s.operation==null && s.operationBoot== -1 && s.operationElapsedMs== -1L)
        else require(s.operation?.path==path && s.operationBoot>=0 && s.operationElapsedMs>=0)
        if(s.phase==LoginPhase.CLEANUP) {
            require(!s.maybeRegistered)
            val batch=cleanupThumbprints(checkNotNull(s.operation))
            require(batch.all {t->RegistrationTombstone(s.ownerTag,t) in s.tombstones})
        }
        if(s.phase==LoginPhase.ENROLLING) {
            require(s.maybeRegistered && s.deviceId.isEmpty())
            val key=Identity.objectJSON(checkNotNull(s.operation).body).getValue("key")
            require(Identity.hash(Canonical.encode(key).toByteArray(Charsets.UTF_8))==s.thumbprint)
        }
        if(s.phase in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING)) require(s.maybeRegistered && s.deviceId.isNotEmpty())
        if(s.phase==LoginPhase.POLICY_CACHED)require(s.policyHash.isNotEmpty())
        if(s.phase==LoginPhase.REFRESHING)require(s.refreshReturnPhase in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED))
        else require(s.refreshReturnPhase==null)
    }
    fun reserve(s:LoginIntent,generation:Long,bootstrap:Bootstrap,alias:String):LoginIntent {
        current(s,generation);require(s.phase==LoginPhase.SIGNED_OUT && s.retiringAliases.isEmpty() && ownedAlias(alias))
        return revised(s.copy(generation=next(s.generation),phase=LoginPhase.RESERVED,
            authority=Identity.bootstrapAuthority(bootstrap),serviceId=bootstrap.serviceId,keyAlias=alias))
    }
    fun prepared(s:LoginIntent,generation:Long,thumbprint:String,protectedHash:String):LoginIntent {
        current(s,generation);require(s.phase==LoginPhase.RESERVED && s.tombstones.none {it.thumbprint==thumbprint})
        return revised(s.copy(phase=LoginPhase.BROWSER,thumbprint=thumbprint,protectedHash=protectedHash))
    }
    fun consumeCallback(s:LoginIntent,generation:Long):LoginIntent {
        current(s,generation);require(s.phase==LoginPhase.BROWSER)
        return revised(s.copy(phase=LoginPhase.EXCHANGING))
    }
    fun authenticated(s:LoginIntent,generation:Long,bootstrap:Bootstrap,user:UserCredential,protectedHash:String):LoginIntent {
        current(s,generation);require(s.phase==LoginPhase.EXCHANGING && s.authority==Identity.bootstrapAuthority(bootstrap) &&
            user.authority==s.authority && user.keyThumbprint==s.thumbprint)
        return revised(s.copy(phase=LoginPhase.AUTHENTICATED,ownerTag=ownerTag(bootstrap,user.subject),protectedHash=protectedHash))
    }
    private fun cleanupThumbprints(op:IdentityOperation)=Identity.objectJSON(op.body).getValue("thumbprints").jsonArray.map {it.jsonPrimitive.content}
    fun beginCleanup(s:LoginIntent,generation:Long,boot:Int,elapsed:Long):LoginIntent {
        current(s,generation)
        if(s.phase==LoginPhase.CLEANUP)return s
        require(s.phase==LoginPhase.AUTHENTICATED)
        val batch=s.tombstones.filter {it.ownerTag==s.ownerTag}.take(16).map {it.thumbprint};require(batch.isNotEmpty())
        return revised(operation(s,IdentityOperation.cleanup(batch),boot,elapsed,LoginPhase.CLEANUP))
    }
    fun cleanupAcknowledged(s:LoginIntent,generation:Long,body:String):LoginIntent {
        current(s,generation);require(s.phase==LoginPhase.CLEANUP && s.operation?.body==body)
        val batch=cleanupThumbprints(checkNotNull(s.operation)).toSet()
        return revised(withoutOperation(s).copy(phase=LoginPhase.AUTHENTICATED,
            tombstones=s.tombstones.filterNot {it.ownerTag==s.ownerTag && it.thumbprint in batch}))
    }
    fun beginEnrollment(s:LoginIntent,generation:Long,key:ECPublicKey,boot:Int,elapsed:Long):LoginIntent {
        current(s,generation);require(Identity.thumbprint(key)==s.thumbprint)
        if(s.phase==LoginPhase.ENROLLING)return s
        require(s.phase==LoginPhase.AUTHENTICATED && s.tombstones.size<32 && s.tombstones.none {it.ownerTag==s.ownerTag})
        return revised(operation(s,IdentityOperation.enroll(key),boot,elapsed,LoginPhase.ENROLLING).copy(maybeRegistered=true))
    }
    fun enrolled(s:LoginIntent,generation:Long,reply:SessionReply,protectedHash:String):LoginIntent {
        current(s,generation);require(s.phase==LoginPhase.ENROLLING && reply.authority==s.authority && reply.keyThumbprint==s.thumbprint && reply.session.generation==0L)
        return revised(withoutOperation(s).copy(phase=LoginPhase.PROVISIONING,protectedHash=protectedHash,
            deviceId=reply.session.deviceId,sessionGeneration=reply.session.generation))
    }
    fun policyCached(s:LoginIntent,generation:Long,policyHash:String,protectedHash:String):LoginIntent {
        current(s,generation);require(s.phase in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED))
        return revised(s.copy(phase=LoginPhase.POLICY_CACHED,policyHash=policyHash,protectedHash=protectedHash))
    }
    fun beginRefresh(s:LoginIntent,generation:Long,boot:Int,elapsed:Long):LoginIntent {
        current(s,generation)
        if(s.phase==LoginPhase.REFRESHING)return s
        require(s.phase in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED))
        return revised(operation(s,IdentityOperation.refresh(),boot,elapsed,LoginPhase.REFRESHING).copy(refreshReturnPhase=s.phase))
    }
    fun refreshed(s:LoginIntent,generation:Long,body:String,reply:SessionReply,protectedHash:String):LoginIntent {
        current(s,generation);require(s.phase==LoginPhase.REFRESHING && s.operation?.body==body && reply.authority==s.authority &&
            reply.keyThumbprint==s.thumbprint && reply.session.deviceId==s.deviceId && reply.session.generation==next(s.sessionGeneration))
        return revised(withoutOperation(s).copy(phase=checkNotNull(s.refreshReturnPhase),protectedHash=protectedHash,sessionGeneration=reply.session.generation))
    }
    fun needsReauthentication(s:LoginIntent,generation:Long):LoginIntent {
        current(s,generation);require(s.phase !in setOf(LoginPhase.SIGNED_OUT,LoginPhase.RESERVED,LoginPhase.RETIRING))
        return revised(withoutOperation(s).copy(phase=LoginPhase.NEEDS_REAUTH))
    }
    fun cancel(s:LoginIntent,generation:Long):LoginIntent {
        current(s,generation)
        if(s.phase in setOf(LoginPhase.SIGNED_OUT,LoginPhase.RETIRING))return s
        val tombstones=if(s.maybeRegistered)(s.tombstones+RegistrationTombstone(s.ownerTag,s.thumbprint)).distinct() else s.tombstones
        return LoginIntent(generation=next(s.generation),revision=next(s.revision),phase=LoginPhase.RETIRING,
            tombstones=tombstones,retiringAliases=(s.retiringAliases+s.keyAlias).distinct()).also(::validate)
    }
    fun retired(s:LoginIntent,generation:Long,alias:String,nativeOwnerReleased:Boolean,protectedStateErased:Boolean):LoginIntent {
        current(s,generation);require(s.phase==LoginPhase.RETIRING && alias in s.retiringAliases && nativeOwnerReleased && protectedStateErased)
        val remaining=s.retiringAliases-alias
        return revised(s.copy(phase=if(remaining.isEmpty())LoginPhase.SIGNED_OUT else LoginPhase.RETIRING,retiringAliases=remaining))
    }
    fun resume(s:LoginIntent,protectedStateMatches:Boolean,keyMatches:Boolean,boot:Int,elapsed:Long,pending:Pending?=null,anchorBoot:Int = -1):LoginResume {
        validate(s);require(boot>=0 && elapsed>=0)
        if(s.phase==LoginPhase.SIGNED_OUT)return LoginResume.IDLE
        if(s.phase==LoginPhase.RETIRING)return LoginResume.COMPLETE_RETIRE
        if(s.phase==LoginPhase.RESERVED)return LoginResume.KEY_RESERVATION
        if(!protectedStateMatches || !keyMatches)return LoginResume.CANCEL_AND_CLEANUP
        fun retryable()=s.operationBoot==boot && elapsed>=s.operationElapsedMs && elapsed-s.operationElapsedMs<180_000
        return when(s.phase) {
            LoginPhase.BROWSER->if(pending?.current(s.generation,boot,elapsed)==true && pending.thumbprint==s.thumbprint)LoginResume.BROWSER else LoginResume.REAUTHENTICATE
            LoginPhase.EXCHANGING,LoginPhase.NEEDS_REAUTH->LoginResume.REAUTHENTICATE
            LoginPhase.AUTHENTICATED->if(anchorBoot==boot)LoginResume.AUTHENTICATED else LoginResume.REAUTHENTICATE
            LoginPhase.CLEANUP->if(retryable())LoginResume.RETRY_CLEANUP else LoginResume.REAUTHENTICATE
            LoginPhase.ENROLLING->if(retryable())LoginResume.RETRY_ENROLLMENT else LoginResume.REAUTHENTICATE
            LoginPhase.REFRESHING->if(retryable())LoginResume.RETRY_REFRESH else LoginResume.REAUTHENTICATE
            LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED->if(anchorBoot==boot)LoginResume.SESSION else LoginResume.REANCHOR_SESSION
            else->error("unreachable login phase")
        }
    }
}
