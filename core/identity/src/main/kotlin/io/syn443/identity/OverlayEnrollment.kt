package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable data class OverlayOperation(val operationId:String,val namespace:String,val reference:String,val version:Long) {
    init {
        require(operationId.matches(Regex("[A-Za-z0-9_-]{24,128}")))
        require(namespace.startsWith("managed-netbird/") && overlayDigest(namespace.removePrefix("managed-netbird/")))
        require(overlayDigest(reference) && version in 1..9_007_199_254_740_991L)
    }
    fun body():String=Canonical.encode(buildJsonObject {
        put("operationId",operationId);put("namespace",namespace);put("reference",reference);put("version",version)
    })
    fun requireBound(binding:OverlayCredentialBinding) {
        require(namespace==ManagedOverlay.namespace(binding.address) && reference==binding.reference && version==binding.version)
    }
    override fun toString()="OverlayOperation([redacted])"
}
internal fun overlayDigest(value:String)=value.length==43 && runCatching {Policy.decode64(value).size==32}.getOrDefault(false)

enum class OverlayPhase { RESERVED, CACHED, ENROLLING, REGISTERED, ERASING, ERASED, ACKNOWLEDGED, RETIRING, RETIRED }

/** No setup bytes, key paths or SDK private identity enter this durable ledger.
 * A reserved operation precedes any request; ENROLLING precedes native effects.
 * REGISTERED is accepted only after the native owner proves durable registration.
 * Local key erasure must finish before acknowledging consumption to the server. */
@Serializable data class OverlayEnrollment(val revision:Long,val loginGeneration:Long,val identityTag:String,
    val bindingTag:String,val operation:OverlayOperation,val phase:OverlayPhase=OverlayPhase.RESERVED,
    val protectedHash:String="",val credentialUntilMs:Long=0,val identityEvidence:String="") {
    override fun toString()="OverlayEnrollment([redacted])"
}

object OverlayEnrollments {
    private fun identity(binding:OverlayCredentialBinding):String=Identity.hash(Canonical.encode(buildJsonObject {
        put("namespace",ManagedOverlay.namespace(binding.address));put("key",binding.keyThumbprint)
    }).toByteArray(Charsets.UTF_8))
    private fun permissionTag(binding:OverlayCredentialBinding):String=Identity.hash(Canonical.encode(buildJsonObject {
        put("identity",identity(binding));put("reference",binding.reference);put("version",binding.version);put("epoch",binding.securityEpoch)
    }).toByteArray(Charsets.UTF_8))
    fun validate(value:OverlayEnrollment) {
        require(value.revision in 1..9_007_199_254_740_991L && value.loginGeneration in 0..9_007_199_254_740_991L)
        require(overlayDigest(value.identityTag) && overlayDigest(value.bindingTag))
        value.operation.body() // Constructor invariants also apply to copied/deserialized values.
        require(value.protectedHash.isEmpty() || overlayDigest(value.protectedHash))
        require(value.identityEvidence.isEmpty() || overlayDigest(value.identityEvidence))
        require(value.credentialUntilMs in 0..9_007_199_254_740_991L)
        when(value.phase) {
            OverlayPhase.RESERVED -> require(value.protectedHash.isEmpty() && value.credentialUntilMs==0L && value.identityEvidence.isEmpty())
            OverlayPhase.CACHED,OverlayPhase.ENROLLING -> require(overlayDigest(value.protectedHash) && value.credentialUntilMs>0 && value.identityEvidence.isEmpty())
            OverlayPhase.REGISTERED,OverlayPhase.ERASING -> require(overlayDigest(value.protectedHash) && value.credentialUntilMs>0 && overlayDigest(value.identityEvidence))
            OverlayPhase.ERASED,OverlayPhase.ACKNOWLEDGED -> require(value.protectedHash.isEmpty() && value.credentialUntilMs==0L && overlayDigest(value.identityEvidence))
            OverlayPhase.RETIRING,OverlayPhase.RETIRED -> require(value.protectedHash.isEmpty() && value.credentialUntilMs==0L)
        }
    }
    fun reserve(binding:OverlayCredentialBinding,generation:Long):OverlayEnrollment {
        require(overlayDigest(binding.keyThumbprint) && binding.securityEpoch in 0..9_007_199_254_740_991L)
        val operation=OverlayOperation(Identity.random(),ManagedOverlay.namespace(binding.address),binding.reference,binding.version)
        return OverlayEnrollment(1,generation,identity(binding),permissionTag(binding),operation).also(::validate)
    }
    /** A completed SDK identity survives a refreshed setup reference/security epoch;
     * a pending enrollment cannot silently switch its operation or enroll twice. */
    fun requireAuthorized(value:OverlayEnrollment,binding:OverlayCredentialBinding,generation:Long) {
        validate(value);require(value.loginGeneration==generation && value.identityTag==identity(binding))
        require(value.phase !in setOf(OverlayPhase.RETIRING,OverlayPhase.RETIRED))
        if(value.phase in setOf(OverlayPhase.RESERVED,OverlayPhase.CACHED,OverlayPhase.ENROLLING)) {
            require(value.bindingTag==permissionTag(binding));value.operation.requireBound(binding)
        }
    }
    private fun next(value:OverlayEnrollment,phase:OverlayPhase)=value.copy(revision=Math.addExact(value.revision,1),phase=phase)
    fun cached(value:OverlayEnrollment,protectedHash:String,untilMs:Long):OverlayEnrollment {
        validate(value);require(value.phase==OverlayPhase.RESERVED)
        return next(value,OverlayPhase.CACHED).copy(protectedHash=protectedHash,credentialUntilMs=untilMs).also(::validate)
    }
    fun enrolling(value:OverlayEnrollment):OverlayEnrollment {
        validate(value);require(value.phase in setOf(OverlayPhase.CACHED,OverlayPhase.ENROLLING))
        return next(value,OverlayPhase.ENROLLING).also(::validate)
    }
    fun registered(value:OverlayEnrollment,evidence:String):OverlayEnrollment {
        validate(value);require(value.phase==OverlayPhase.ENROLLING)
        return next(value,OverlayPhase.REGISTERED).copy(identityEvidence=evidence).also(::validate)
    }
    fun erasing(value:OverlayEnrollment):OverlayEnrollment {
        validate(value);require(value.phase in setOf(OverlayPhase.REGISTERED,OverlayPhase.ERASING))
        return next(value,OverlayPhase.ERASING).also(::validate)
    }
    fun erased(value:OverlayEnrollment):OverlayEnrollment {
        validate(value);require(value.phase==OverlayPhase.ERASING)
        return next(value,OverlayPhase.ERASED).copy(protectedHash="",credentialUntilMs=0).also(::validate)
    }
    fun acknowledged(value:OverlayEnrollment):OverlayEnrollment {
        validate(value);require(value.phase in setOf(OverlayPhase.ERASED,OverlayPhase.ACKNOWLEDGED))
        return next(value,OverlayPhase.ACKNOWLEDGED).also(::validate)
    }
    /** The controller persists this fence first, then cancels work and waits for
     * confirmed native release before touching owned SDK files or keys. */
    fun retiring(value:OverlayEnrollment):OverlayEnrollment {
        validate(value);require(value.phase!=OverlayPhase.RETIRED)
        return next(value,OverlayPhase.RETIRING).copy(protectedHash="",credentialUntilMs=0).also(::validate)
    }
    fun retired(value:OverlayEnrollment):OverlayEnrollment {
        validate(value);require(value.phase==OverlayPhase.RETIRING)
        return next(value,OverlayPhase.RETIRED).also(::validate)
    }
}
