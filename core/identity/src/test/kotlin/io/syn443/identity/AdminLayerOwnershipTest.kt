package io.syn443.identity

import org.junit.Assert.*
import org.junit.Test
import java.security.Signature

/** Signed discovery/OAuth fixtures; these value snapshots never authorize a server publication. */
class AdminLayerOwnershipTest {
    private fun noIo(f:AdminControlFixture,action:()->Unit) {
        val oauth=f.oauth.calls.size;val control=f.calls.size;val signed=f.signatures
        action()
        assertEquals(oauth,f.oauth.calls.size);assertEquals(control,f.calls.size);assertEquals(signed,f.signatures)
    }

    private class Preview(val request:AdminLayerRequest,val result:String,val value:AdminLayerPreview) {
        fun ready()="""{"id":"${request.expected.jobId}","state":"ready","result":$result}"""
    }

    private fun preview(f:AdminControlFixture,session:AdminSession,expiresAfter:Long=180_000,
        actor:String?=null,origin:String?=null):Preview {
        val owned=f.client.layerOwnership(session);val actualActor=actor?:owned.actor;val actualOrigin=origin?:owned.apiOrigin
        val issued=f.oauth.wall
        val proposal=AdminLayerControl.proposal("""{"draftId":"synthetic-draft","draftRevision":1,"targetKind":"device","targetId":"${f.device}","mode":"wifi","approvalUntilMs":${issued+3_600_000},"bundles":[{"device":"${f.device}","baseRevision":1,"baseHash":"${"a".repeat(64)}","layers":[{"id":"synthetic-template","kind":"template","priority":0,"revision":1,"changes":[{"path":"/display","operation":"set","value":{"label":"synthetic"}}],"permissions":[]}]}]}""")
        val request=AdminLayerControl.preview(proposal,actualActor,actualOrigin,Identity.random())
        val v="""{"schemaVersion":1,"origin":"$actualOrigin","actor":"$actualActor","requestId":"${request.requestId}","draftId":"synthetic-draft","draftRevision":1,"draftHash":"${"b".repeat(64)}","targetKind":"device","targetId":"${f.device}","mode":"wifi","dependencyHash":"${"c".repeat(64)}","effectiveHash":"${"d".repeat(64)}","recipients":[{"owner":"${Identity.hash("synthetic recipient".toByteArray())}","device":"${f.device}","thumbprint":"${Identity.hash("synthetic key".toByteArray())}","grantHash":"${Identity.hash("synthetic grant".toByteArray())}","baseRevision":1,"baseHash":"${"a".repeat(64)}","capabilitiesHash":"${"e".repeat(64)}"}],"issuedAtMs":$issued,"expiresAtMs":${issued+expiresAfter}}"""
        val pair=AdminControlFixture.ec()
        val input=Identity.encode("""{"alg":"ES256","typ":"syn443-configuration-preview+jws","kid":"synthetic-preview"}""".toByteArray())+"."+Identity.encode(v.toByteArray())
        val signature=Signature.getInstance("SHA256withECDSA").run {
            initSign(pair.private);update(input.toByteArray(Charsets.US_ASCII));sign()
        }
        val ticket=input+"."+Identity.encode(Identity.derToRaw(signature))
        val result="""{"previewId":"${request.expected.jobId}","ticket":"$ticket","preview":$v}"""
        val ready="""{"id":"${request.expected.jobId}","state":"ready","result":$result}"""
        // Actual closed response/ticket binding parser; local signature shape is not server authority.
        val parsed=AdminLayerControl.parseReply(request,ready,owned.time) as AdminLayerJob
        return Preview(request,result,checkNotNull(parsed.preview))
    }

    @Test fun offlineOwnershipOutlivesAccessWithoutIoSigningOrExtendingOriginalSessionLease() {
        val f=AdminControlFixture(lifetime=2_000_000);val session=f.login()
        val first=f.client.layerOwnership(session)
        assertEquals(Identity.hash((f.oauth.metadata.issuer+"\u0000"+session.subject).toByteArray()),first.actor)
        assertEquals(f.oauth.metadata.apiOrigin,first.apiOrigin);assertEquals(f.oauth.boot,first.bootCount)
        assertTrue(AdminIdentity.digest(first.serviceHash));assertEquals(session.sessionUntilElapsedMs,first.sessionUntilElapsedMs)
        assertTrue(session.sessionUntilElapsedMs<=session.time.elapsedMs+28_800_000)
        assertTrue(session.sessionUntilElapsedMs>session.time.elapsedMs+25_200_000)
        f.oauth.elapsed=session.accessUntilElapsedMs+1
        noIo(f) {
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE) {f.client.listDevices("",session,IdentityScope())}
            val offline=f.client.layerOwnership(session)
            assertEquals(first.serviceHash,offline.serviceHash);assertEquals(first.actor,offline.actor)
            assertEquals(first.apiOrigin,offline.apiOrigin);assertEquals(f.oauth.elapsed,offline.observedElapsedMs)
            assertEquals(first.sessionUntilElapsedMs,offline.sessionUntilElapsedMs);assertTrue(session.available())
            val label=offline.toString();assertEquals("AdminLayerOwnership([redacted])",label)
            for(secret in listOf(session.accessToken,session.refreshToken,session.subject,offline.actor,offline.apiOrigin))assertFalse(label.contains(secret))
            f.oauth.elapsed=session.sessionUntilElapsedMs-1
            assertEquals(first.sessionUntilElapsedMs,f.client.layerOwnership(session).sessionUntilElapsedMs)
            f.oauth.elapsed=session.sessionUntilElapsedMs
            AdminAuthFixture.failure(AdminFailure.SESSION_EXPIRED) {f.client.layerOwnership(session)}
        }
    }

    @Test fun ownershipRejectsRemovedExpiredForeignBootClockAndConsumedFamiliesWithoutIo() {
        for(mode in 0..6) {
            val f=AdminControlFixture(lifetime=if(mode==6)2 else 2_000_000);val session=f.login()
            val tested=if(mode==5)AdminControlFixture().login() else session
            when(mode) {
                0->f.enabled=false
                1->f.oauth.boot++
                2->f.oauth.elapsed--
                3->f.client.logout(session)
                4->assertTrue(session.consume())
                6->f.oauth.elapsed+=2000
            }
            noIo(f) {
                AdminAuthFixture.failure(if(mode==5)AdminFailure.INVALID_REPLY else AdminFailure.REAUTHENTICATE) {
                    f.client.layerOwnership(tested)
                }
            }
        }
        val f=AdminControlFixture();val session=f.login()
        noIo(f) {AdminAuthFixture.failure(AdminFailure.INVALID_REPLY) {f.oauth.client.layerOwnership(session)}}
    }

    @Test fun ownershipUsesAcceptedTimeFloorAndRefreshPreservesOriginalLeaseAndLogoutFamilyFence() {
        val f=AdminControlFixture();val session=f.login();val before=f.client.layerOwnership(session)
        val review=preview(f,session);val previousReviewDeadline=f.client.layerReviewDeadline(review.value,session)
        f.handler={f.reply(f.page(),at=f.oauth.wall+10_000)}
        f.client.listDevices("",session,IdentityScope())
        noIo(f) {
            val fresh=f.client.layerOwnership(session)
            assertTrue(fresh.time.lowerMs>=before.time.lowerMs+10_000)
            assertTrue(fresh.time.upperMs>=before.time.upperMs+10_000)
            assertEquals(before.sessionUntilElapsedMs,fresh.sessionUntilElapsedMs)
            assertTrue(f.client.layerReviewDeadline(review.value,session)<=previousReviewDeadline-10_000)
        }
        val rotated=AdminControlFixture(lifetime=2_000_000);val previous=rotated.login()
        rotated.oauth.elapsed+=60_000
        val issuer=rotated.client.discover(IdentityScope())
        val next=rotated.client.refresh(previous,issuer,IdentityScope())
        assertEquals(previous.sessionUntilElapsedMs,next.sessionUntilElapsedMs);assertFalse(previous.available())
        noIo(rotated) {
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE) {rotated.client.layerOwnership(previous)}
            val fresh=rotated.client.layerOwnership(next)
            assertEquals(previous.sessionUntilElapsedMs,fresh.sessionUntilElapsedMs)
            assertEquals(Identity.hash((rotated.oauth.metadata.issuer+"\u0000"+next.subject).toByteArray()),fresh.actor)
            rotated.client.logout(previous)
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE) {rotated.client.layerOwnership(next)}
        }
    }

    @Test fun parsedPreviewReviewDeadlineNeverRenewsAndRejectsForeignActorOriginAndReplay() {
        val f=AdminControlFixture(lifetime=2_000_000);val session=f.login();val case=preview(f,session)
        val owned=f.client.layerOwnership(session)
        val first=f.client.layerReviewDeadline(case.value,session)
        assertEquals(owned.observedElapsedMs+case.value.issuedAtMs+90_000-owned.time.upperMs,first)
        noIo(f) {
            f.oauth.elapsed+=30_000
            assertTrue(f.client.layerReviewDeadline(case.value,session)<=first)
            assertTrue(f.client.layerReviewDeadline(case.value,session)<=first)
        }
        val foreignActor=preview(f,session,actor=Identity.random())
        val foreignOrigin=preview(f,session,origin="https://foreign-control.example.invalid")
        val actor=f.client.layerOwnership(session).actor
        val restored=AdminLayerControl.restoreRequest(case.request.bodyBytes(),AdminLayerControl.replayContext(case.request,actor,owned.apiOrigin),
            checkNotNull(case.request.expected.proposal).wireJson(),actor,owned.apiOrigin)
        val replay=checkNotNull((AdminLayerControl.parseReply(restored,case.ready(),f.client.layerOwnership(session).time) as AdminLayerJob).preview)
        assertTrue(replay.replayOnly)
        noIo(f) {
            for(invalid in listOf(foreignActor.value,foreignOrigin.value,replay)) {
                AdminAuthFixture.failure(AdminFailure.INVALID_REPLY) {f.client.layerReviewDeadline(invalid,session)}
            }
            f.oauth.elapsed=first
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY) {f.client.layerReviewDeadline(case.value,session)}
        }
        val clipped=AdminControlFixture(lifetime=2_000_000);val current=clipped.login()
        val short=preview(clipped,current,expiresAfter=45_000);val shortOwned=clipped.client.layerOwnership(current)
        noIo(clipped) {
            assertEquals(shortOwned.observedElapsedMs+short.value.expiresAtMs-shortOwned.time.upperMs,
                clipped.client.layerReviewDeadline(short.value,current))
        }
        clipped.oauth.elapsed=current.sessionUntilElapsedMs-5000
        val nearExpiry=preview(clipped,current)
        noIo(clipped) {assertEquals(current.sessionUntilElapsedMs,clipped.client.layerReviewDeadline(nearExpiry.value,current))}
    }
}
