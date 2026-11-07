package io.syn443.identity

import io.syn443.policy.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
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
    @Test fun activationReportPersistsOnlyFinalCurrentEnvelopeDecisions() {
        val first=receive();val enrolled=acknowledged(first)
        assertNull(Assignments.report(first,enrolled,payload,1,1000))
        val applying=Assignments.begin(first,enrolled,payload,listOf(false),1,1000)
        assertNull(Assignments.report(applying,enrolled,payload,1,1000))
        val committed=Assignments.finish(applying,enrolled,payload,listOf(true),true,1,1000)
        val restored=Policy.json.decodeFromString<AssignmentState>(Policy.json.encodeToString(committed))
        val report=checkNotNull(Assignments.report(restored,enrolled,payload,1,1000))
        assertEquals(DeviceActivationReport(1,1,enrolled.policyHash,committed.journal.activationGeneration,"committed",1),report)
        assertFalse(report.toString().contains(enrolled.policyHash))
        invalid {Assignments.report(restored,enrolled.copy(policyHash=Identity.random()),payload,1,1000)}
        invalid {Assignments.report(restored,enrolled,payload,2,1000)}
        val renewed=receive(committed,policy(2).copy(offlineUntilMs=now+7_200_000),enrolled)
        assertEquals("committed",renewed.journal.phase)
        assertNull(Assignments.report(renewed,acknowledged(renewed),payload,1,1000))
        val changed=receive(committed,policy(2).copy(activation=policy().activation.copy(timeoutSeconds=31)),enrolled)
        val current=acknowledged(changed)
        val rollback=Assignments.abort(Assignments.begin(changed,current,payload,listOf(true),1,1000),current,payload,"required_route_failed")
        assertEquals(DeviceActivationReport(1,2,current.policyHash,rollback.journal.activationGeneration,"rolled_back",1),
            Assignments.report(rollback,current,payload,1,1000))
        assertEquals(1L,Assignments.authorized(rollback,current,payload,1,1000).payload.revision)
    }
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
        assertEquals("committed",renewed.journal.phase)
        val next=Assignments.permit(renewed,newer,payload,1,1000)
        assertSame(next,old.renew(next,newer,renewed,1,2000))
        invalid {old.renew(next,newer,renewed,1,old.deadlineElapsed)}
        invalid {old.renew(next,newer,renewed,2,1000)}
        val otherEngine=engine.replace("direct","alternate")
        val changed=receive(good,policy(2).copy(engineConfigB64=Identity.encode(otherEngine.toByteArray()),contentHash=Policy.hash(otherEngine)),current)
        val otherLogin=acknowledged(changed);val otherApplying=Assignments.begin(changed,otherLogin,payload,listOf(true),1,1000)
        invalid {old.renew(Assignments.permit(otherApplying,otherLogin,payload,1,1000),otherLogin,otherApplying,1,2000)}
        // A separately verified owner still cannot replace a live native lease in place.
        val foreignState=renewed.copy(identity=renewed.identity!!.copy(loginGeneration=2))
        val foreignLogin=newer.copy(generation=2)
        invalid {old.renew(Assignments.permit(foreignState,foreignLogin,payload,1,1000),foreignLogin,foreignState,1,2000)}
    }
    private fun committed():AssignmentState {
        val first=receive();val current=acknowledged(first)
        return Assignments.finish(Assignments.begin(first,current,payload,listOf(false),1,1000),current,payload,listOf(true),true,1,1000)
    }
    @Test fun identicalExecutionRenewsDurablyWithoutCandidateActivationOrLossOfFailureHistory() {
        val good=committed().let {it.copy(journal=it.journal.copy(failedRevisions=listOf(9),failedSnapshots=listOf("quarantine")))}
        val current=acknowledged(good);val renewed=receive(good,policy(10).copy(offlineUntilMs=now+7_200_000),current)
        assertEquals(good.journal.activationGeneration,renewed.journal.activationGeneration)
        assertEquals("committed",renewed.journal.phase);assertNull(renewed.journal.candidate)
        assertEquals(renewed.journal.desired,renewed.journal.active);assertEquals(renewed.journal.active,renewed.journal.lastGood)
        assertEquals(good.journal.failedRevisions,renewed.journal.failedRevisions)
        assertEquals(good.journal.failedSnapshots,renewed.journal.failedSnapshots)
        assertEquals(good.journal.reason,renewed.journal.reason);assertEquals(10L,renewed.journal.maxRevision)
        invalid {Assignments.permit(renewed,current,payload,1,1000)} // New durable receipt is mandatory.
        val restored=Policy.json.decodeFromString<AssignmentState>(Policy.json.encodeToString(renewed))
        val next=acknowledged(restored)
        assertEquals(engine,Assignments.permit(restored,next,payload,1,1000).authorized(next,restored,1,1000).engineConfig)
        assertEquals(renewed,Assignments.receive(renewed,next,payload,PolicyReply(checkNotNull(renewed.journal.desired),time),1,1000))
    }
    @Test fun freshSignedLeaseCanAuthorizeKnownExpiredExecutionButNeverReviveItsExpiredReader() {
        val good=committed();val current=acknowledged(good)
        val old=Assignments.permit(good,current,payload,1,1000)
        val elapsed=3_602_000L;val refreshedTime=TrustedTime(1,elapsed,now+3_601_000,now+3_602_000)
        val fresh=policy(2).copy(issuedAtMs=now+3_600_000,notBeforeMs=now+3_600_000,
            refreshAfterMs=now+3_630_000,offlineUntilMs=now+7_200_000)
        invalid {Assignments.authorized(good,current,payload,1,elapsed)}
        val renewed=Assignments.receive(good,current,payload,PolicyReply(signed(fresh),refreshedTime),1,elapsed)
        assertEquals("committed",renewed.journal.phase);assertEquals(good.journal.activationGeneration,renewed.journal.activationGeneration)
        val next=LoginRecovery.policyCached(current,1,Assignments.receipt(renewed,current,payload,1,elapsed),current.protectedHash)
        val permit=Assignments.permit(renewed,next,payload,1,elapsed)
        assertEquals(engine,permit.authorized(next,renewed,1,elapsed).engineConfig)
        invalid {old.renew(permit,next,renewed,1,elapsed)}
        invalid {Assignments.receive(good,current,payload,PolicyReply(signed(policy(3)),refreshedTime),1,elapsed)}
    }
    @Test fun renewalOfAuthorizedRollbackKeepsFailedCandidateQuarantinedAndOtherFallbackLeaseUnextended() {
        val good=committed();val current=acknowledged(good)
        val bad=policy(2).copy(activation=policy().activation.copy(timeoutSeconds=31))
        val prepared=receive(good,bad,current);val next=acknowledged(prepared)
        val rolled=Assignments.abort(Assignments.begin(prepared,next,payload,listOf(true),1,1000),next,payload,"native_activation_failed")
        val renewed=receive(rolled,policy(3),next)
        assertEquals("rolled_back",renewed.journal.phase);assertEquals("native_activation_failed",renewed.journal.reason)
        assertEquals(rolled.journal.activationGeneration,renewed.journal.activationGeneration)
        assertEquals(rolled.journal.failedSnapshots,renewed.journal.failedSnapshots)
        assertEquals(rolled.journal.failedRevisions,renewed.journal.failedRevisions)
        assertEquals(renewed.journal.active,renewed.journal.lastGood)
        invalid {receive(renewed,bad.copy(revision=4),acknowledged(renewed))}
        val degraded=good.copy(journal=good.journal.copy(phase="degraded",lastGood="unrelated-fallback",reason="baseline_also_unavailable"))
        val refreshed=receive(degraded,policy(2),current)
        assertEquals("degraded",refreshed.journal.phase);assertEquals("unrelated-fallback",refreshed.journal.lastGood)
        assertEquals(degraded.journal.reason,refreshed.journal.reason)
    }
    @Test fun renewalDoesNotBypassChangedAuthorityCapabilitiesGateOrPendingActivation() {
        val good=committed();val current=acknowledged(good)
        val changes=listOf(policy(2).copy(securityEpoch=1),policy(2).copy(revocationFloor=1),
            policy(2).copy(requiredCapabilities=IdentityOperation.supportedCapabilities - Policy.RESERVE_PROBE_COOLDOWN),
            policy(2).copy(activation=policy().activation.copy(timeoutSeconds=31)),
            policy(2).copy(engineConfigB64=Identity.encode(engine.replace("direct","alternate").toByteArray()),contentHash=Policy.hash(engine.replace("direct","alternate"))))
        changes.forEach {p->val staged=receive(good,p,current);assertEquals("prepared",staged.journal.phase)
            assertEquals(good.journal.activationGeneration+1,staged.journal.activationGeneration);assertEquals(good.journal.active,staged.journal.active)}
        val pending=receive(good,changes.last(),current)
        assertEquals("prepared",receive(pending,policy(3),acknowledged(pending)).journal.phase)
        val applying=Assignments.begin(pending,acknowledged(pending),payload,listOf(true),1,1000)
        invalid {receive(applying,policy(3),acknowledged(pending))}
        val inconsistent=listOf(good.copy(applyBoot=1),good.copy(applyDeadlineElapsed=2000),
            good.copy(journal=good.journal.copy(candidate=good.journal.active)),
            good.copy(journal=good.journal.copy(phase="rolled_back",lastGood=null)),
            good.copy(journal=good.journal.copy(phase="rejected")))
        inconsistent.forEach {assertEquals("prepared",receive(it,policy(2),current).journal.phase)}
        invalid {receive(good,policy(),current)} // A differently signed replay cannot renew.
        val corrupt=good.copy(journal=good.journal.copy(active=good.journal.active!!.dropLast(1)+"!"))
        invalid {receive(corrupt,policy(2),current)}
    }
    @Test fun shorterRenewedLeaseTightensDeadlineAndNeverMakesAnUnrelatedActiveSnapshotGood() {
        val good=committed();val current=acknowledged(good)
        val renewed=receive(good,policy(2).copy(offlineUntilMs=now+60_000),current);val next=acknowledged(renewed)
        assertEquals(60_000L,Assignments.permit(renewed,next,payload,1,1000).deadlineElapsed)
        val staged=receive(good,policy(3).copy(securityEpoch=1),current)
        val lifted=staged.copy(journal=staged.journal.copy(phase="committed",candidate=null))
        assertEquals("prepared",receive(lifted,policy(4).copy(securityEpoch=1),acknowledged(lifted)).journal.phase)
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
        assertEquals("required_route_failed",Assignments.abort(applying,current,payload,"required_route_failed").journal.reason)
        assertEquals("rolled_back",aborted.journal.phase);assertNull(aborted.journal.active)
        assertTrue(aborted.journal.failedRevisions.contains(1));assertEquals(0L,aborted.applyDeadlineElapsed)
        invalid {Assignments.abort(applying,current,payload,"arbitrary sensitive reason")}
        invalid {Assignments.abort(applying,LoginRecovery.cancel(current,1),payload,"interrupted_activation")}
        invalid {receive(aborted,policy(2),current)}
    }
    @Test fun existingCanonicalCacheShapeSurvivesTheActivationDeadlineExtension() {
        val state=receive();val raw=Policy.json.encodeToString(state)
        // Existing encrypted records are compared with their exact pre-upgrade encoding on read.
        assertEquals(setOf("identity","journal","time"),Policy.json.parseToJsonElement(raw).jsonObject.keys)
        val restored=Policy.json.decodeFromString<AssignmentState>(raw)
        assertEquals(raw,Policy.json.encodeToString(restored));assertEquals(0L,restored.applyDeadlineElapsed)
        val current=acknowledged(restored);val applying=Assignments.begin(restored,current,payload,listOf(false),1,1000)
        val running=Policy.json.encodeToString(applying)
        assertEquals(setOf("identity","journal","time","applyDeadlineElapsed","applyBoot"),Policy.json.parseToJsonElement(running).jsonObject.keys)
        assertEquals(applying,Policy.json.decodeFromString<AssignmentState>(running))
        val aborted=Assignments.abort(applying,current,payload,"interrupted_activation")
        val encoded=Policy.json.parseToJsonElement(Policy.json.encodeToString(aborted)).jsonObject
        assertEquals(setOf("identity","journal","time","activationReport"),encoded.keys)
        val legacyAbort=Policy.json.encodeToString(JsonObject(encoded - "activationReport"))
        val restoredAbort=Policy.json.decodeFromString<AssignmentState>(legacyAbort)
        assertNull(restoredAbort.activationReport)
        assertEquals(legacyAbort,Policy.json.encodeToString(restoredAbort))
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
