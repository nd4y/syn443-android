package io.syn443.identity

import io.syn443.policy.*
import kotlinx.serialization.encodeToString
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class AssignmentsTest {
    private val root=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
    private val device=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
    private val bootstrap=Bootstrap("fixture","https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",
        mapOf("fixture-root" to Base64.getEncoder().encodeToString(root.public.encoded)))
    private val now=1_800_000_000_000L
    private val time=TrustedTime(1,1000,now,now+1000)
    private val thumb=Identity.thumbprint(device.public as ECPublicKey)
    private val authority=Identity.bootstrapAuthority(bootstrap)
    private val session=SessionReply(DeviceSession(Identity.random(),Identity.random(),Identity.random(),now+590_000,now+86_000_000,0,Identity.random()),time,authority,thumb)
    private val login=LoginIntent(generation=1,revision=5,phase=LoginPhase.PROVISIONING,authority=authority,serviceId=bootstrap.serviceId,
        keyAlias="syn443-dpop-"+Identity.random(),thumbprint=thumb,ownerTag=LoginRecovery.ownerTag(bootstrap,"test"),protectedHash=Identity.random(),
        maybeRegistered=true,deviceId=session.session.deviceId,sessionGeneration=0)
    private val payload=LoginPayload(bootstrap,session=session)
    private val engine="""{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""
    private fun policy(revision:Long=1)=Payload(2,revision,0,0,login.deviceId,"syn443-device",now,now,now+30_000,now+3_600_000,
        IdentityOperation.requiredCapabilities,"m1-local-v1",Identity.encode(engine.toByteArray()),Policy.hash(engine),
        Gate(30,false,listOf(Check("internet","https_204","https://health.example.org/generate_204"))),keyThumbprint=thumb)
    private fun signed(p:Payload=policy()):String {
        val header="""{"alg":"ES256","kid":"fixture-root","typ":"syn443-policy+jws"}"""
        val input=Identity.encode(header.toByteArray())+"."+Identity.encode(Canonical.encode(Canonical.parse(Policy.json.encodeToString(p))).toByteArray())
        val signature=Signature.getInstance("SHA256withECDSAinP1363Format").run {initSign(root.private);update(input.toByteArray());sign()}
        return input+"."+Identity.encode(signature)
    }
    private fun receive(state:AssignmentState=AssignmentState(),p:Payload=policy(),intent:LoginIntent=login)=
        Assignments.receive(state,intent,payload,PolicyReply(signed(p),time),1,1000)
    private fun acknowledged(state:AssignmentState)=LoginRecovery.policyCached(login,1,Assignments.receipt(state,login,payload,1,1000),login.protectedHash)
    private fun invalid(block:()->Unit) {assertThrows(IllegalArgumentException::class.java,block)}
    @Test fun firstAssignmentRequiresDurableReceiptAndSuccessfulChecksWithoutUnsignedFallback() {
        val state=receive();assertEquals("prepared",state.journal.phase)
        assertEquals(state,Policy.json.decodeFromString<AssignmentState>(Policy.json.encodeToString(state)))
        assertEquals("AssignmentIdentity([redacted])",state.identity.toString());assertFalse(state.toString().contains(login.deviceId))
        invalid {Assignments.authorized(state,login,payload,1,1000,true)}
        val current=acknowledged(state)
        assertThrows(IllegalStateException::class.java) {Assignments.authorized(state,current,payload,1,1000)}
        assertEquals(engine,Assignments.authorized(state,current,payload,1,1000,true).engineConfig)
        val active=Assignments.finish(Assignments.begin(state,current,payload,listOf(false),1,1000),current,payload,listOf(true),true,1,1000)
        assertEquals(engine,Assignments.authorized(active,current,payload,1,1000).engineConfig)
    }
    @Test fun journalCannotCrossLoginGenerationAuthorityKeyDeviceOrRetiredIdentity() {
        val state=receive();val current=acknowledged(state)
        invalid {Assignments.receipt(state,login.copy(generation=2),payload,1,1000)}
        invalid {Assignments.receipt(state,login.copy(authority=Identity.random()),payload,1,1000)}
        invalid {Assignments.receipt(state,login.copy(thumbprint=Identity.random()),payload,1,1000)}
        invalid {Assignments.receipt(state,login.copy(deviceId=Identity.random()),payload,1,1000)}
        invalid {Assignments.authorized(state,current.copy(policyHash=Identity.random()),payload,1,1000,true)}
        invalid {Assignments.receipt(state,LoginRecovery.needsReauthentication(current,1),payload,1,1000)}
        invalid {Assignments.receive(state.copy(identity=null),login,payload,PolicyReply(signed(),time),1,1000)}
        invalid {Assignments.receipt(state.copy(time=null),login,payload,1,1000)}
    }
    @Test fun signaturesOwnKeyCapabilitiesReleaseAndConservativeTimeAreRequired() {
        invalid {receive(p=policy().copy(keyThumbprint=Identity.random()))}
        invalid {receive(p=policy().copy(targetDevice=Identity.random()))}
        invalid {receive(p=policy().copy(schemaVersion=1,keyThumbprint="",requiredCapabilities=listOf("engine-config.v1","tun.lease.v1")))}
        invalid {receive(p=policy().copy(operation="release"))}
        invalid {receive(p=policy().copy(requiredCapabilities=IdentityOperation.requiredCapabilities+"netbird.direct"))}
        invalid {receive(p=policy().copy(notBeforeMs=now+1))}
        invalid {Assignments.receive(AssignmentState(),login,payload,PolicyReply(signed().dropLast(1)+"!",time),1,1000)}
        val state=receive();val current=acknowledged(state)
        invalid {Assignments.authorized(state,current,payload,2,1000,true)}
        invalid {Assignments.authorized(state,current,payload,1,999,true)}
        invalid {Assignments.authorized(state,current,payload,1,3_600_000,true)}
    }
    @Test fun interruptedHandoffCanRepeatReceiptButCannotApplyDifferentCandidate() {
        val state=receive();val receipt=Assignments.receipt(state,login,payload,1,1000)
        assertEquals(receipt,Assignments.receipt(state,login,payload,1,1000))
        val current=acknowledged(state)
        val changed=receive(state,policy(2).copy(activation=policy().activation.copy(timeoutSeconds=31)),current)
        invalid {Assignments.authorized(changed,current,payload,1,1000,true)}
        assertEquals(2,Assignments.authorized(changed,acknowledged(changed),payload,1,1000,true).payload.revision)
        val applying=Assignments.begin(state,current,payload,listOf(false),1,1000)
        invalid {receive(applying,policy(2),current)}
        invalid {Assignments.begin(state,current,payload,emptyList(),1,1000)}
    }
    @Test fun failedCandidateCannotReplayAndLastKnownGoodMustRemainAuthorized() {
        val first=receive();val current=acknowledged(first)
        val good=Assignments.finish(Assignments.begin(first,current,payload,listOf(false),1,1000),current,payload,listOf(true),true,1,1000)
        val second=receive(good,policy(2).copy(activation=policy().activation.copy(timeoutSeconds=31)),current);val updated=acknowledged(second)
        val failed=Assignments.finish(Assignments.begin(second,updated,payload,listOf(true),1,1000),updated,payload,listOf(false),true,1,1000)
        assertEquals("rolled_back",failed.journal.phase)
        assertEquals(1,Assignments.authorized(failed,updated,payload,1,1000).payload.revision)
        invalid {receive(failed,policy(3).copy(activation=policy().activation.copy(timeoutSeconds=31)),updated)}
        val repeated=Assignments.receive(failed,updated,payload,PolicyReply(checkNotNull(failed.journal.desired),time),1,1000)
        assertEquals("rolled_back",repeated.journal.phase);assertNull(repeated.journal.candidate)
        invalid {Assignments.authorized(failed.copy(journal=failed.journal.copy(floor=2)),updated,payload,1,1000)}
    }
    @Test fun refreshedSessionsKeepPolicyScopeAndClockUpdatesCannotRollbackOrJump() {
        val state=receive();val current=acknowledged(state)
        val refreshing=LoginRecovery.beginRefresh(current,1,1,1000)
        assertEquals(engine,Assignments.authorized(state,refreshing,payload,1,1000,true).engineConfig)
        val nextTime=TrustedTime(1,2000,now+1000,now+2000)
        val refreshed=Assignments.receive(state,current,payload,PolicyReply(checkNotNull(state.journal.candidate),nextTime),1,2000)
        assertEquals(state.journal,refreshed.journal)
        invalid {Assignments.receive(state,current,payload,PolicyReply(signed(),TrustedTime(1,1000,now-2000,now-1000)),1,1000)}
        invalid {Assignments.receive(state,current,payload,PolicyReply(signed(),TrustedTime(1,1000,now+40_000,now+41_000)),1,1000)}
        invalid {receive(state.copy(journal=state.journal.copy(epoch=1)),policy(2),current)}
    }
    @Test fun runtimePermitStartsOnlyAfterDurableBeginAndUsesConservativeMonotonicDeadline() {
        val prepared=receive();val current=acknowledged(prepared)
        assertThrows(IllegalStateException::class.java) {Assignments.permit(prepared,current,payload,1,1000)}
        val applying=Assignments.begin(prepared,current,payload,listOf(false),1,1000)
        val permit=Assignments.permit(applying,current,payload,1,1000)
        assertEquals(31_000L,permit.deadlineElapsed)
        assertEquals(engine,permit.authorized(current,applying,1,1000).engineConfig)
        assertEquals(engine,permit.authorized(current,applying,1,permit.deadlineElapsed-1).engineConfig)
        invalid {permit.authorized(current,applying,1,permit.deadlineElapsed)}
        invalid {permit.authorized(current,applying,1,999)};invalid {permit.authorized(current,applying,2,1000)}
        assertEquals("AssignmentPermit([redacted])",permit.toString())
        val committed=Assignments.finish(applying,current,payload,listOf(true),true,1,1000)
        invalid {permit.authorized(current,committed,1,1000)}
        assertEquals(engine,Assignments.permit(committed,current,payload,1,1000).authorized(current,committed,1,1000).engineConfig)
    }
    @Test fun runtimePermitFencesLogoutDifferentReceiptIdentityActivationAndRevocation() {
        val prepared=receive();val current=acknowledged(prepared)
        val applying=Assignments.begin(prepared,current,payload,listOf(false),1,1000)
        val permit=Assignments.permit(applying,current,payload,1,1000)
        for(changed in listOf(LoginRecovery.cancel(current,1),current.copy(policyHash=Identity.random()),current.copy(generation=2),
            current.copy(authority=Identity.random()),current.copy(deviceId=Identity.random()),current.copy(thumbprint=Identity.random())))
            invalid {permit.authorized(changed,applying,1,1000)}
        for(changed in listOf(applying.copy(identity=null),applying.copy(journal=applying.journal.copy(activationGeneration=2)),
            applying.copy(journal=applying.journal.copy(floor=2)),applying.copy(journal=applying.journal.copy(epoch=1)),
            applying.copy(journal=applying.journal.copy(candidate="different envelope"))))invalid {permit.authorized(current,changed,1,1000)}
        val refreshing=LoginRecovery.beginRefresh(current,1,1,1000)
        assertEquals(engine,permit.authorized(refreshing,applying,1,1000).engineConfig)
        invalid {permit.authorized(refreshing.copy(refreshReturnPhase=LoginPhase.PROVISIONING),applying,1,1000)}
    }
    @Test fun leaseRenewalCannotResurrectAnExpiredNativeReaderOrChangeItsIdentityOrConfig() {
        val prepared=receive();val current=acknowledged(prepared)
        val good=Assignments.finish(Assignments.begin(prepared,current,payload,listOf(false),1,1000),current,payload,listOf(true),true,1,1000)
        val old=Assignments.permit(good,current,payload,1,1000)
        val renewed=receive(good,policy(2).copy(offlineUntilMs=now+7_200_000),current);val newer=acknowledged(renewed)
        val applying=Assignments.begin(renewed,newer,payload,listOf(true),1,1000)
        val next=Assignments.permit(applying,newer,payload,1,1000)
        assertSame(next,old.renew(next,newer,applying,1,2000))
        invalid {old.renew(next,newer,applying,1,old.deadlineElapsed)}
        invalid {old.renew(next,newer,applying,2,1000)}
        val otherEngine=engine.replace("direct","alternate")
        val changed=receive(good,policy(2).copy(engineConfigB64=Identity.encode(otherEngine.toByteArray()),contentHash=Policy.hash(otherEngine)),current)
        val otherLogin=acknowledged(changed);val otherApplying=Assignments.begin(changed,otherLogin,payload,listOf(true),1,1000)
        invalid {old.renew(Assignments.permit(otherApplying,otherLogin,payload,1,1000),otherLogin,otherApplying,1,2000)}
        // A separately verified owner still cannot replace a live native lease in place.
        val foreignState=applying.copy(identity=applying.identity!!.copy(loginGeneration=2))
        val foreignLogin=newer.copy(generation=2)
        invalid {old.renew(Assignments.permit(foreignState,foreignLogin,payload,1,1000),foreignLogin,foreignState,1,2000)}
    }
    @Test fun lateChecksAndRebootCannotCommitAnExpiredActivation() {
        val first=receive();val current=acknowledged(first)
        val applying=Assignments.begin(first,current,payload,listOf(false),1,1000)
        assertEquals(31_000L,applying.applyDeadlineElapsed);assertEquals(1,applying.applyBoot)
        for((boot,elapsed) in listOf(1 to 31_000L,2 to 1000L)) {
            val rejected=Assignments.finish(applying,current,payload,listOf(true),true,boot,elapsed)
            assertEquals("rolled_back",rejected.journal.phase);assertNull(rejected.journal.active)
            assertEquals(0L,rejected.applyDeadlineElapsed);assertEquals(-1,rejected.applyBoot)
            invalid {Assignments.permit(applying,current,payload,boot,elapsed)}
        }
        val committed=Assignments.finish(applying,current,payload,listOf(true),true,1,30_999)
        assertEquals("committed",committed.journal.phase);assertEquals(0L,committed.applyDeadlineElapsed)
        assertTrue(Assignments.permit(committed,current,payload,1,30_999).deadlineElapsed>31_000)
    }
    @Test fun interruptedCandidateIsPoisonedWithoutWallClockOrAnUnsignedFallback() {
        val first=receive();val current=acknowledged(first)
        assertSame(first,Assignments.abort(first,current,payload,"interrupted_activation"))
        val applying=Assignments.begin(first,current,payload,listOf(false),1,1000)
        val aborted=Assignments.abort(applying,current,payload,"interrupted_activation")
        assertEquals("rolled_back",aborted.journal.phase);assertNull(aborted.journal.active)
        assertTrue(aborted.journal.failedRevisions.contains(1));assertEquals(0L,aborted.applyDeadlineElapsed)
        invalid {Assignments.abort(applying,current,payload,"arbitrary sensitive reason")}
        invalid {Assignments.abort(applying,LoginRecovery.cancel(current,1),payload,"interrupted_activation")}
        invalid {receive(aborted,policy(2),current)}
    }
    @Test fun erasureRequiresNewerLogoutAndConfirmedNativeAndNamespaceRetirement() {
        val state=receive();val retired=LoginRecovery.cancel(login,1)
        invalid {Assignments.retire(state,login,true,true)}
        invalid {Assignments.retire(state,retired,false,true)}
        invalid {Assignments.retire(state,retired,true,false)}
        invalid {Assignments.retire(state.copy(identity=state.identity!!.copy(loginGeneration=retired.generation)),retired,true,true)}
        assertEquals(AssignmentState(),Assignments.retire(state,retired,true,true))
        assertEquals(AssignmentState(),Assignments.retire(AssignmentState(),retired,true,true))
    }
}
