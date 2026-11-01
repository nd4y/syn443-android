package io.syn443.identity

import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class LoginRecoveryTest {
    companion object {
        private val root=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private val bootstrap=Bootstrap("fixture","https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",
            mapOf("test-root" to Base64.getEncoder().encodeToString(root.public.encoded)))
        private const val now=1_800_000_000_000L
        private fun h()=Identity.random()
        private fun alias()="syn443-dpop-"+h()
        private fun invalid(block:()->Unit) {try {block();fail("invalid login transition accepted")}catch(_:IllegalArgumentException) {}}
        private fun tomb(subject:String="fixture-owner")=RegistrationTombstone(LoginRecovery.ownerTag(bootstrap,subject),h())
    }
    private class Flow(val initial:LoginIntent=LoginIntent(),val subject:String="fixture-owner") {
        val key=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair().public as ECPublicKey
        val thumb=Identity.thumbprint(key)
        val reserved=LoginRecovery.reserve(initial,initial.generation,bootstrap,alias())
        val generation=reserved.generation
        val browser=LoginRecovery.prepared(reserved,generation,thumb,h())
        val pending=Identity.newPending(generation,thumb,2,1000)
        val exchanging=LoginRecovery.consumeCallback(browser,generation)
        val user=UserCredential(h(),subject,thumb,TrustedTime(2,1000,now,now+1000),Identity.bootstrapAuthority(bootstrap))
        val authenticated=LoginRecovery.authenticated(exchanging,generation,bootstrap,user,h())
        fun enrolling(s:LoginIntent=authenticated)=LoginRecovery.beginEnrollment(s,generation,key,2,1000)
        fun reply(n:Long=0)=SessionReply(DeviceSession(h(),h(),h(),now+590_000,now+86_000_000,n,h()),user.time,user.authority,thumb)
        fun registered():LoginIntent=LoginRecovery.enrolled(enrolling(),generation,reply(),h())
        fun cached()=LoginRecovery.policyCached(registered(),generation,h(),h())
        fun resume(s:LoginIntent,boot:Int=2,elapsed:Long=2000,payload:Boolean=true,key:Boolean=true,p:Pending?=pending,anchor:Int=2)=
            LoginRecovery.resume(s,payload,key,boot,elapsed,p,anchor)
    }
    @Test fun acknowledgedRetirementRemovesOnlyItsOwnPublicTombstone() {
        val foreign=tomb("another-owner");val f=Flow(LoginIntent(tombstones=listOf(foreign)))
        val retiring=LoginRecovery.cancel(f.enrolling(),f.generation)
        val own=RegistrationTombstone(f.authenticated.ownerTag,f.thumb)
        val acknowledged=LoginRecovery.serverRevoked(retiring,retiring.generation,own)
        assertEquals(listOf(foreign),acknowledged.tombstones)
        assertEquals(retiring.retiringAliases,acknowledged.retiringAliases)
        invalid {LoginRecovery.serverRevoked(retiring,f.generation,own)}
        invalid {LoginRecovery.serverRevoked(acknowledged,acknowledged.generation,own)}
        invalid {LoginRecovery.serverRevoked(LoginIntent(tombstones=listOf(own)),0,own)}
    }
    @Test fun recoveryIntentContainsNoCredentialsAndRoundTripsExactly() {
        val f=Flow();val states=listOf(LoginIntent(),f.reserved,f.browser,f.exchanging,f.authenticated,f.enrolling(),f.registered(),f.cached())
        for(s in states) {
            val wire=LoginRecovery.encode(s);assertEquals(s,LoginRecovery.decode(wire))
            assertFalse(wire.contains(f.user.accessToken));assertFalse(wire.contains(f.subject));assertFalse(wire.contains("accessToken"));assertFalse(wire.contains("refreshToken"))
            assertFalse(s.toString().contains(s.keyAlias.takeIf {it.isNotEmpty()}?:"never-printed"))
        }
        val restored=Policy.json.decodeFromString<UserCredential>(Policy.json.encodeToString(f.user))
        assertEquals(f.user.accessToken,restored.accessToken);assertEquals(f.user.authority,restored.authority)
        assertEquals("RegistrationTombstone([redacted])",tomb().toString())
    }
    @Test fun reservationRequiresCurrentUserIntentAndNeverReusesAnOldGeneration() {
        val f=Flow();assertEquals(1L,f.generation)
        val retired=LoginRecovery.cancel(f.browser,f.generation)
        val signedOut=LoginRecovery.retired(retired,retired.generation,f.reserved.keyAlias,true,true)
        invalid {LoginRecovery.reserve(signedOut,f.generation,bootstrap,alias())}
        val next=LoginRecovery.reserve(signedOut,signedOut.generation,bootstrap,alias());assertTrue(next.generation>retired.generation)
        invalid {LoginRecovery.prepared(next,f.generation,f.thumb,h())}
        invalid {LoginRecovery.reserve(LoginIntent(generation=9_007_199_254_740_991),9_007_199_254_740_991,bootstrap,alias())}
    }
    @Test fun callbackIsConsumedDurablyBeforeCodeExchangeAndCannotBeReplayed() {
        val f=Flow();invalid {LoginRecovery.consumeCallback(f.exchanging,f.generation)}
        invalid {LoginRecovery.consumeCallback(f.browser,f.generation-1)}
        assertEquals(LoginResume.REAUTHENTICATE,f.resume(f.exchanging))
        val failed=LoginRecovery.needsReauthentication(f.exchanging,f.generation)
        assertFalse(failed.maybeRegistered);assertEquals(LoginResume.REAUTHENTICATE,f.resume(failed))
        assertTrue(LoginRecovery.cancel(failed,f.generation).tombstones.isEmpty())
    }
    @Test fun registeredAndCachedSessionsSurviveProcessRecreationWithoutEnrollment() {
        val f=Flow();val registered=LoginRecovery.decode(LoginRecovery.encode(f.registered()))
        assertEquals(LoginResume.SESSION,f.resume(registered));assertNull(registered.operation)
        assertEquals(LoginResume.REANCHOR_SESSION,f.resume(registered,boot=3,anchor=2))
        val cached=LoginRecovery.policyCached(registered,f.generation,h(),h())
        assertEquals(LoginResume.SESSION,f.resume(cached));assertEquals(registered.deviceId,cached.deviceId)
        assertEquals(0L,cached.sessionGeneration);assertNull(cached.operation)
        assertEquals(LoginResume.REANCHOR_SESSION,f.resume(cached,boot=3))
    }
    @Test fun registrationIsMarkedBeforeDispatchAndUnknownOutcomeRetainsExactOperation() {
        val f=Flow();val first=f.enrolling();assertTrue(first.maybeRegistered)
        assertEquals(first,LoginRecovery.beginEnrollment(first,f.generation,f.key,3,99_000))
        assertEquals(LoginResume.RETRY_ENROLLMENT,f.resume(first,elapsed=180_999))
        assertEquals(LoginResume.REAUTHENTICATE,f.resume(first,elapsed=181_000))
        assertEquals(LoginResume.REAUTHENTICATE,f.resume(first,boot=3))
        assertEquals(LoginResume.REAUTHENTICATE,f.resume(first,elapsed=999))
        invalid {LoginRecovery.beginEnrollment(f.browser,f.generation,f.key,2,1000)}
        invalid {LoginRecovery.beginEnrollment(f.authenticated,f.generation,root.public as ECPublicKey,2,1000)}
    }
    @Test fun cancelledUnknownRegistrationKeepsOnlyPublicTombstoneAndWipesBeforeSignout() {
        val f=Flow();val cancelled=LoginRecovery.cancel(f.enrolling(),f.generation)
        assertEquals(LoginPhase.RETIRING,cancelled.phase);assertEquals(f.generation+1,cancelled.generation)
        assertEquals(listOf(RegistrationTombstone(LoginRecovery.ownerTag(bootstrap,f.subject),f.thumb)),cancelled.tombstones)
        assertTrue(cancelled.protectedHash.isEmpty());assertTrue(cancelled.deviceId.isEmpty());assertTrue(cancelled.ownerTag.isEmpty())
        assertEquals(LoginResume.COMPLETE_RETIRE,f.resume(cancelled,payload=false,key=false))
        invalid {LoginRecovery.enrolled(cancelled,f.generation,f.reply(),h())}
        invalid {LoginRecovery.retired(cancelled,cancelled.generation,f.reserved.keyAlias,false,true)}
        invalid {LoginRecovery.retired(cancelled,cancelled.generation,f.reserved.keyAlias,true,false)}
        invalid {LoginRecovery.retired(cancelled,cancelled.generation,alias(),true,true)}
        val out=LoginRecovery.retired(cancelled,cancelled.generation,f.reserved.keyAlias,true,true)
        assertEquals(LoginPhase.SIGNED_OUT,out.phase);assertEquals(LoginResume.IDLE,f.resume(out))
        assertEquals(cancelled,LoginRecovery.cancel(cancelled,cancelled.generation));assertEquals(out,LoginRecovery.cancel(out,out.generation))
        val next=Flow(out);invalid {LoginRecovery.prepared(next.reserved,next.generation,f.thumb,h())}
    }
    @Test fun indistinguishableOwnerCleanupAcknowledgementNeverDropsAnotherAccount() {
        val a=tomb();val b=tomb("other-owner");val f=Flow(LoginIntent(tombstones=listOf(a,b)))
        val pending=LoginRecovery.beginCleanup(f.authenticated,f.generation,2,1000)
        assertTrue(pending.operation!!.body.contains(a.thumbprint));assertFalse(pending.operation.body.contains(b.thumbprint))
        val done=LoginRecovery.cleanupAcknowledged(pending,f.generation,pending.operation.body)
        assertEquals(listOf(b),done.tombstones);assertTrue(f.enrolling(done).maybeRegistered)
        assertNotEquals(LoginRecovery.ownerTag(bootstrap,"fixture-owner"),LoginRecovery.ownerTag(bootstrap,"other-owner"))
        assertNotEquals(LoginRecovery.ownerTag(bootstrap,"fixture-owner"),LoginRecovery.ownerTag(bootstrap.copy(serviceId="another-service"),"fixture-owner"))
        // Operator-approved signing-root changes do not lose the owner of an old cleanup entry.
        assertEquals(LoginRecovery.ownerTag(bootstrap,"fixture-owner"),LoginRecovery.ownerTag(bootstrap.copy(roots=mapOf("another-root" to bootstrap.roots.values.single())),"fixture-owner"))
    }
    @Test fun cleanupDrainsSixteenAtATimeAndDoesNotRegenerateAnUnknownRequest() {
        val f=Flow(LoginIntent(tombstones=List(32){tomb()}))
        val first=LoginRecovery.beginCleanup(f.authenticated,f.generation,2,1000)
        assertEquals(first,LoginRecovery.beginCleanup(first,f.generation,3,999_000))
        assertEquals(LoginResume.RETRY_CLEANUP,f.resume(first));assertEquals(LoginResume.REAUTHENTICATE,f.resume(first,boot=3))
        invalid {f.enrolling(f.authenticated)}
        invalid {LoginRecovery.cleanupAcknowledged(first,f.generation,first.operation!!.body+" ")}
        val halfway=LoginRecovery.cleanupAcknowledged(first,f.generation,first.operation!!.body);assertEquals(16,halfway.tombstones.size)
        val second=LoginRecovery.beginCleanup(halfway,f.generation,2,2000);assertNotEquals(first.operation,second.operation)
        val done=LoginRecovery.cleanupAcknowledged(second,f.generation,second.operation!!.body)
        assertTrue(done.tombstones.isEmpty());assertTrue(f.enrolling(done).maybeRegistered)
        val foreign=Flow(LoginIntent(tombstones=List(32){tomb("other-owner")}))
        invalid {LoginRecovery.beginCleanup(foreign.authenticated,foreign.generation,2,1000)}
        invalid {foreign.enrolling()};assertFalse(foreign.authenticated.maybeRegistered)
    }
    @Test fun refreshRequiresOneGenerationExactOperationAndDoesNotReplaceThePolicyLease() {
        val f=Flow();val cached=f.cached();val pending=LoginRecovery.beginRefresh(cached,f.generation,2,1000)
        assertEquals(pending,LoginRecovery.beginRefresh(pending,f.generation,3,999_000))
        val next=f.reply(1).let {it.copy(session=it.session.copy(deviceId=cached.deviceId))}
        val done=LoginRecovery.refreshed(pending,f.generation,pending.operation!!.body,next,h())
        assertEquals(cached.policyHash,done.policyHash);assertEquals(LoginPhase.POLICY_CACHED,done.phase);assertEquals(1L,done.sessionGeneration)
        invalid {LoginRecovery.refreshed(done,f.generation,pending.operation.body,next,h())}
        invalid {LoginRecovery.refreshed(pending,f.generation,pending.operation.body+" ",next,h())}
        invalid {LoginRecovery.refreshed(pending,f.generation,pending.operation.body,next.copy(authority=h()),h())}
        invalid {LoginRecovery.refreshed(pending,f.generation,pending.operation.body,next.copy(keyThumbprint=h()),h())}
        invalid {LoginRecovery.refreshed(pending,f.generation,pending.operation.body,next.copy(session=next.session.copy(deviceId=h())),h())}
        invalid {LoginRecovery.refreshed(pending,f.generation,pending.operation.body,next.copy(session=next.session.copy(generation=2)),h())}
        val provisioning=f.registered();val rotating=LoginRecovery.beginRefresh(provisioning,f.generation,2,1000)
        val reply=f.reply(1).let {it.copy(session=it.session.copy(deviceId=provisioning.deviceId))}
        assertEquals(LoginPhase.PROVISIONING,LoginRecovery.refreshed(rotating,f.generation,rotating.operation!!.body,reply,h()).phase)
    }
    @Test fun uncertainRefreshNeverResetsItsIdempotencyClockOrImplicitlyRegistersAgain() {
        val f=Flow();val state=LoginRecovery.beginRefresh(f.cached(),f.generation,2,1000)
        assertEquals(LoginResume.RETRY_REFRESH,f.resume(state,elapsed=180_999))
        assertEquals(LoginResume.REAUTHENTICATE,f.resume(state,elapsed=181_000))
        assertEquals(LoginResume.REAUTHENTICATE,f.resume(state,boot=3))
        val reauth=LoginRecovery.needsReauthentication(state,f.generation)
        assertEquals(state.policyHash,reauth.policyHash);assertEquals(state.deviceId,reauth.deviceId);assertNull(reauth.operation)
        invalid {LoginRecovery.beginEnrollment(reauth,f.generation,f.key,2,1000)}
    }
    @Test fun keyOrCiphertextMismatchBlocksEveryActiveCredentialPhase() {
        val f=Flow();val cleanupFlow=Flow(LoginIntent(tombstones=listOf(tomb())))
        val states=listOf(f.browser,f.exchanging,f.authenticated,f.enrolling(),f.registered(),f.cached(),
            LoginRecovery.beginRefresh(f.cached(),f.generation,2,1000),LoginRecovery.needsReauthentication(f.cached(),f.generation))
        for(s in states) {assertEquals(LoginResume.CANCEL_AND_CLEANUP,f.resume(s,payload=false));assertEquals(LoginResume.CANCEL_AND_CLEANUP,f.resume(s,key=false))}
        val cleanup=LoginRecovery.beginCleanup(cleanupFlow.authenticated,cleanupFlow.generation,2,1000)
        assertEquals(LoginResume.CANCEL_AND_CLEANUP,cleanupFlow.resume(cleanup,payload=false))
        invalid {LoginRecovery.policyCached(LoginRecovery.cancel(f.registered(),f.generation),f.generation,h(),h())}
    }
    @Test fun browserRecoveryBindsPendingGenerationThumbprintBootAndDeadline() {
        val f=Flow();assertEquals(LoginResume.BROWSER,f.resume(f.browser))
        for(p in listOf(null,f.pending.copy(generation=f.generation+1),f.pending.copy(thumbprint=h()),f.pending.copy(bootCount=3)))
            assertEquals(LoginResume.REAUTHENTICATE,f.resume(f.browser,p=p))
        assertEquals(LoginResume.REAUTHENTICATE,f.resume(f.browser,elapsed=301_000))
        assertEquals(LoginResume.REAUTHENTICATE,f.resume(f.browser,elapsed=999))
        assertEquals(LoginResume.REAUTHENTICATE,f.resume(f.authenticated,anchor=3))
        assertEquals(LoginResume.AUTHENTICATED,f.resume(f.authenticated))
        assertEquals(LoginResume.KEY_RESERVATION,f.resume(f.reserved,payload=false,key=false))
        invalid {f.resume(f.browser,boot= -1)};invalid {f.resume(f.browser,elapsed= -1)}
    }
    @Test fun metadataRejectsUnboundedAmbiguousOrInconsistentStates() {
        val f=Flow();val same=tomb()
        val bad=listOf(LoginIntent(tombstones=List(33){tomb()}),LoginIntent(tombstones=listOf(same,same)),
            LoginIntent(tombstones=listOf(same.copy(ownerTag="invalid"))),LoginIntent(retiringAliases=listOf(alias())),
            LoginIntent(phase=LoginPhase.RETIRING),LoginIntent(revision= -1),
            f.reserved.copy(retiringAliases=listOf(f.reserved.keyAlias)),f.browser.copy(protectedHash="invalid"),
            f.browser.copy(operation=IdentityOperation.refresh()),f.registered().copy(sessionGeneration= -1),
            f.authenticated.copy(policyHash=h()),f.cached().copy(policyHash=""),f.authenticated.copy(maybeRegistered=true,ownerTag=""),
            f.enrolling().copy(thumbprint=h()),LoginRecovery.beginRefresh(f.registered(),f.generation,2,1000).copy(refreshReturnPhase=LoginPhase.BROWSER))
        for(s in bad)invalid {LoginRecovery.validate(s)}
        invalid {LoginRecovery.reserve(LoginIntent(),0,bootstrap,"syn443-policy-v1")}
        invalid {LoginRecovery.authenticated(f.exchanging,f.generation,bootstrap,f.user,h().dropLast(1))}
        invalid {LoginRecovery.authenticated(f.exchanging,f.generation,bootstrap,UserCredential(h(),f.subject,h(),f.user.time,f.user.authority),h())}
        invalid {LoginRecovery.ownerTag(bootstrap,"bad\nsubject")}
    }
    @Test fun acknowledgementsAndPreparationCannotCrossGenerationsOrScopes() {
        val f=Flow(LoginIntent(tombstones=listOf(tomb())));val s=LoginRecovery.beginCleanup(f.authenticated,f.generation,2,1000)
        invalid {LoginRecovery.cleanupAcknowledged(s,f.generation-1,s.operation!!.body)}
        val cancelled=LoginRecovery.cancel(s,f.generation)
        invalid {LoginRecovery.retired(cancelled,f.generation,f.reserved.keyAlias,true,true)}
        invalid {LoginRecovery.prepared(f.browser,f.generation,f.thumb,h())}
        invalid {LoginRecovery.authenticated(f.browser,f.generation,bootstrap,f.user,h())}
        invalid {LoginRecovery.enrolled(f.enrolling(LoginRecovery.cleanupAcknowledged(s,f.generation,s.operation!!.body)),f.generation,f.reply(1),h())}
        invalid {LoginRecovery.policyCached(f.browser,f.generation,h(),h())}
        invalid {LoginRecovery.beginRefresh(f.browser,f.generation,2,1000)}
        invalid {LoginRecovery.needsReauthentication(f.reserved,f.generation)}
    }
    @Test fun wireMetadataRejectsCoercionDuplicatesUnknownFieldsAndMalformedTypes() {
        val f=Flow();val wire=LoginRecovery.encode(f.browser)
        for(invalidWire in listOf(wire.replace("\"generation\":1","\"generation\":\"1\""),
            wire.replace("\"maybeRegistered\":false","\"maybeRegistered\":\"false\""),wire.dropLast(1)+",\"extra\":true}",
            wire.dropLast(1)+",\"generation\":1}",wire.replace("\"BROWSER\"","\"FUTURE\""),wire.replace("\"revision\":2","\"revision\":true")))
            try {LoginRecovery.decode(invalidWire);fail("invalid persisted metadata accepted")}catch(_:Exception) {}
        assertEquals(LoginIntent(),LoginRecovery.decode("{}"))
    }
}
