package io.syn443.android.vpn

import android.os.Looper
import io.syn443.identity.*
import io.syn443.policy.Policy

/** Worker-owned orchestration. The caller first persists the login namespace
 * claim, then supplies current signed-policy admission. No callback may perform
 * crypto, I/O or acquire a controller/UI lock. SDK storage is never touched here. */
internal class ManagedOverlayProvisioner(private val vault:OverlayVault,
    private val binding:OverlayCredentialBinding,private val generation:Long,
    private val roots:Map<String,String>,private val admitted:()->Boolean,
    private val window:()->TimeWindow,private val fetch:(OverlayOperation)->String,
    private val consume:(OverlayOperation)->Unit) {
    private fun worker() {
        if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
            throw LoginStorageException(LoginStorageFailure.WRONG_THREAD)
    }
    private fun current(value:OverlayEnrollment) {
        if(!admitted())throw LoginStorageException(LoginStorageFailure.STALE)
        OverlayEnrollments.requireIdentity(value,binding,generation)
        require(value.phase !in setOf(OverlayPhase.RETIRING,OverlayPhase.RETIRED))
        require(binding.offlineUntilMs>window().upperMs)
    }
    /** The returned owner is RAM only. A null result means either registered keyless use or a RECONCILING
     * probe; callers must inspect the durable phase. Only a private native
     * registration proof can confirm a probe, never merely existing key files. */
    fun prepare():OverlaySetupSecret? {
        worker();if(!admitted())throw LoginStorageException(LoginStorageFailure.STALE)
        var value=vault.snapshot() ?: vault.reserve(binding,generation)
        current(value)
        if(value.phase==OverlayPhase.RECONCILING_ERASING || value.phase==OverlayPhase.ENROLLING &&
            value.operation.reference==binding.reference && value.operation.version==binding.version &&
            (value.credentialUntilMs<=window().upperMs ||
                runCatching{OverlayEnrollments.requireAuthorized(value,binding,generation)}.isFailure)) {
            // The same SDK identity may already have registered before a root/
            // security-epoch update. Do not discard it or re-fetch the old key
            // under the new authority; erase the setup value and probe sealed
            // existing SDK keys, requiring current private native proof.
            value=vault.reconcileExisting(value);current(value)
        }
        if(value.phase==OverlayPhase.RECONCILING && value.operation.reference==binding.reference && value.operation.version==binding.version)return null
        val pending=value.phase in setOf(OverlayPhase.RESERVED,OverlayPhase.CACHED,OverlayPhase.ENROLLING)
        if(value.phase in setOf(OverlayPhase.DISCARDING,OverlayPhase.DISCARDED,OverlayPhase.RECONCILING) || pending &&
            (runCatching{OverlayEnrollments.requireAuthorized(value,binding,generation)}.isFailure ||
                value.credentialUntilMs>0 && value.credentialUntilMs<=window().upperMs)) {
            if(value.phase!=OverlayPhase.DISCARDED)value=vault.discardUnregistered(value)
            current(value)
            // If dispatch never happened, the server atomically abandons this
            // issued grant. A lost ACK retries the exact old operation.
            consume(value.operation);current(value)
            value=vault.replaceDiscarded(value,binding,generation,true)
        }
        OverlayEnrollments.requireAuthorized(value,binding,generation)
        if(value.phase==OverlayPhase.RESERVED) {
            val envelope=fetch(value.operation);current(value)
            val time=window()
            vault.prepare(value,envelope,binding,roots,time.lowerMs,time.upperMs).use{value=vault.cache(it)}
        }
        if(value.phase==OverlayPhase.CACHED)value=vault.enrolling(value)
        if(value.phase in setOf(OverlayPhase.REGISTERED,OverlayPhase.ERASING))value=vault.eraseRegistered(value)
        current(value)
        if(value.phase in setOf(OverlayPhase.ERASED,OverlayPhase.ACKNOWLEDGED))return null
        require(value.phase==OverlayPhase.ENROLLING)
        val time=window()
        val secret=vault.credential(value,binding,roots,time.lowerMs,time.upperMs)
        try{current(value);return secret}catch(e:Exception){secret.close();throw e}
    }
    /** Caller has fenced the private native proof by current host session,
     * recovery generation and signed config hash. Recheck that fence after every
     * durable/crypto step; a late proof cannot authorize a new native launch. */
    fun registered(namespace:String,evidence:String,stillCurrent:()->Boolean):OverlayEnrollment {
        worker();require(namespace==ManagedOverlay.namespace(binding.address))
        require(evidence.length==43 && Policy.decode64(evidence).size==32)
        check(stillCurrent());var value=checkNotNull(vault.snapshot());current(value)
        if(value.phase==OverlayPhase.ENROLLING)value=vault.registered(value,evidence)
        else if(value.phase==OverlayPhase.RECONCILING)value=vault.registeredRecovered(value,evidence)
        else require(value.identityEvidence==evidence)
        check(stillCurrent());current(value)
        if(value.phase in setOf(OverlayPhase.REGISTERED,OverlayPhase.ERASING))value=vault.eraseRegistered(value)
        check(stillCurrent());current(value)
        require(value.phase in setOf(OverlayPhase.ERASED,OverlayPhase.ACKNOWLEDGED));return value
    }
    /** Separable from preparation: an offline consumption endpoint must not
     * prevent an already registered SDK identity from using its current lease. */
    fun acknowledge():OverlayEnrollment {
        worker();val value=checkNotNull(vault.snapshot());current(value)
        require(value.phase in setOf(OverlayPhase.ERASED,OverlayPhase.ACKNOWLEDGED))
        if(value.phase==OverlayPhase.ACKNOWLEDGED)return value
        consume(value.operation);current(value)
        return vault.acknowledged(value)
    }
    override fun toString()="ManagedOverlayProvisioner([redacted])"
}
