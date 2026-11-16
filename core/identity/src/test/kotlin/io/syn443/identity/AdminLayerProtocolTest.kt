package io.syn443.identity

import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.Signature

/** Real signed service/IdP/DPoP owners; only the bounded HTTP peer is replaced. */
class AdminLayerProtocolTest {
    private fun proposal(f:AdminControlFixture)=AdminLayerControl.proposal("""{
        "draftId":"synthetic-draft","draftRevision":1,"targetKind":"device","targetId":"${f.device}",
        "mode":"wifi","approvalUntilMs":${f.oauth.wall+600_000},"bundles":[{
        "device":"${f.device}","baseRevision":1,"baseHash":"${"a".repeat(64)}","layers":[
        {"id":"synthetic-template","kind":"template","priority":0,"revision":1,
        "changes":[{"path":"/network/dnsStrategy","operation":"set","value":"ipv4_only"}],"permissions":[]},
        {"id":"${f.device}","kind":"device","priority":0,"revision":1,"changes":[],"permissions":[]}]}]}""")

    private fun saved(f:AdminControlFixture,p:AdminLayerProposal)=
        """{"id":"${p.draftId}","revision":1,"proposal":${p.wireJson()},"savedAtMs":${f.oauth.wall}}"""

    private fun verify(f:AdminControlFixture,call:AdminControlFixture.Call,session:AdminSession,action:AdminLayerRequest) {
        assertEquals("POST",call.method);assertEquals(f.oauth.metadata.apiOrigin+AdminControl.PATH,call.url)
        assertEquals(setOf("Content-Type","Cache-Control","Authorization","DPoP"),call.headers.keys)
        assertEquals("application/json",call.headers["Content-Type"]);assertEquals("no-store",call.headers["Cache-Control"])
        assertEquals("DPoP "+session.accessToken,call.headers["Authorization"])
        assertEquals(524_288,call.max);assertArrayEquals(action.bodyBytes(),checkNotNull(call.body))
        val raw=call.headers.getValue("DPoP").split('.')
        val header=Identity.objectJSON(Policy.utf8(Policy.decode64(raw[0])))
        assertEquals(setOf("alg","typ","jwk"),header.keys)
        assertEquals("ES256",header.getValue("alg").jsonPrimitive.content)
        assertEquals("dpop+jwt",header.getValue("typ").jsonPrimitive.content)
        assertEquals(Identity.jwk(f.oauth.key.publicKey),header["jwk"])
        val claims=f.claims(call)
        assertEquals(call.url,claims.getValue("htu").jsonPrimitive.content)
        assertEquals("POST",claims.getValue("htm").jsonPrimitive.content)
        assertEquals(Identity.hash(checkNotNull(call.body)),claims.getValue("req_hash").jsonPrimitive.content)
        assertEquals(Identity.hash(session.accessToken.toByteArray(Charsets.US_ASCII)),claims.getValue("ath").jsonPrimitive.content)
        assertFalse("nonce" in claims);assertTrue(AdminIdentity.digest(claims.getValue("jti").jsonPrimitive.content))
        val sig=Policy.decode64(raw[2]);assertEquals(64,sig.size)
        fun integer(bytes:ByteArray):ByteArray {val value=BigInteger(1,bytes).toByteArray();return byteArrayOf(2,value.size.toByte())+value}
        val values=integer(sig.copyOfRange(0,32))+integer(sig.copyOfRange(32,64))
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(f.oauth.key.publicKey);update((raw[0]+"."+raw[1]).toByteArray(Charsets.US_ASCII))
            verify(byteArrayOf(0x30,values.size.toByte())+values)
        })
    }

    @Test fun mutationUsesOnlyCurrentSignedOriginAndExactImmutableBodyWithFreshVerifiedDpop() {
        val f=AdminControlFixture();val session=f.login();val oauth=f.oauth.calls.size
        val p=proposal(f);val request=AdminLayerControl.saveDraft(0,p,Identity.random())
        val original=request.bodyBytes();request.bodyBytes().fill(0)
        f.handler={f.reply(saved(f,p))}
        val result=f.client.layerAction(request,session,IdentityScope()) as AdminLayerDraft
        assertEquals(1L,result.revision);assertEquals(p.wireJson(),result.proposal.wireJson())
        assertArrayEquals(original,request.bodyBytes());verify(f,f.calls.single(),session,request)
        assertEquals(Identity.hash((f.oauth.metadata.issuer+"\u0000"+session.subject).toByteArray()),f.client.layerActor(session))
        assertEquals(oauth,f.oauth.calls.size);assertTrue(session.available())
        assertFalse(result.toString().contains(p.draftId));assertFalse(request.toString().contains(p.targetId))
    }

    @Test fun lostMutationAcknowledgementRequiresExplicitSameBodyRetryAndNewProofWithoutTokenRotation() {
        val f=AdminControlFixture();val session=f.login();val oauth=f.oauth.calls.size
        val p=proposal(f);val request=AdminLayerControl.saveDraft(0,p,Identity.random())
        f.handler={throw DeliveryException(DeliveryFailure.TRANSPORT)}
        AdminAuthFixture.failure(AdminFailure.TRANSPORT) {f.client.layerAction(request,session,IdentityScope())}
        assertEquals(1,f.calls.size);assertTrue(session.available())
        f.handler={f.reply(saved(f,p))}
        f.client.layerAction(request,session,IdentityScope())
        assertEquals(2,f.calls.size);assertArrayEquals(f.calls[0].body,f.calls[1].body)
        assertNotEquals(f.claims(f.calls[0])["jti"],f.claims(f.calls[1])["jti"])
        f.calls.forEach {verify(f,it,session,request)}
        assertEquals(oauth,f.oauth.calls.size)
    }

    @Test fun full256KiBPrivateDraftUsesItsScopedProofBoundWithoutRelaxingOtherIdentityRequests() {
        val f=AdminControlFixture();val session=f.login();val requestId=Identity.random()
        val original=proposal(f).wireJson()
        // Private drafts may retain intermediate values before the authoritative
        // settings compiler runs at preview. This tests the actual API byte limit.
        fun request(size:Int):Pair<AdminLayerProposal,AdminLayerRequest> {
            val p=AdminLayerControl.proposal(original.replace("\"ipv4_only\"","\""+"x".repeat(size)+"\""))
            return p to AdminLayerControl.saveDraft(0,p,requestId)
        }
        val empty=request(0).second.bodyBytes().size
        val (p,request)=request(262_144-empty)
        assertEquals(262_144,request.bodyBytes().size)
        f.handler={f.reply(saved(f,p))}
        val reply=f.client.layerAction(request,session,IdentityScope()) as AdminLayerDraft
        assertEquals(p.wireJson(),reply.proposal.wireJson());verify(f,f.calls.single(),session,request)
        assertThrows(IllegalArgumentException::class.java) {
            Identity.proof(f.oauth.key.publicKey,f.oauth.key::sign,"POST",f.oauth.metadata.apiOrigin+"/other",
                f.oauth.wall/1000,token=session.accessToken,body=ByteArray(8193))
        }
        assertEquals(1,f.calls.size)
    }

    @Test fun layerErrorCodesKeepConflictValidationQuotaAndFreshAuthenticationDistinctWithoutNonceRetry() {
        val f=AdminControlFixture();val session=f.login();val oauth=f.oauth.calls.size
        val request=AdminLayerControl.listDrafts("device",f.device,Identity.random())
        val cases=listOf(Triple(400,"catalog_invalid",AdminFailure.INVALID_CONFIGURATION),
            Triple(409,"catalog_revision_conflict",AdminFailure.CONFLICT),Triple(429,"catalog_quota",AdminFailure.LIMITED),
            Triple(403,"catalog_reauthentication_required",AdminFailure.REAUTHENTICATE),
            Triple(403,"catalog_denied",AdminFailure.ACCESS_DENIED),Triple(401,"catalog_denied",AdminFailure.REAUTHENTICATE),
            Triple(409,"catalog_denied",AdminFailure.INVALID_REPLY),Triple(400,"catalog_revision_conflict",AdminFailure.INVALID_REPLY),
            Triple(429,"catalog_denied",AdminFailure.INVALID_REPLY),Triple(503,"catalog_unavailable",AdminFailure.TRANSPORT),
            Triple(302,"catalog_denied",AdminFailure.INVALID_REPLY))
        for((status,code,reason) in cases) {
            val before=f.calls.size
            f.handler={f.reply("""{"code":"$code"}""",status,mapOf("dpop-nonce" to listOf("synthetic-nonce")))}
            AdminAuthFixture.failure(reason){f.client.layerAction(request,session,IdentityScope())}
            assertEquals(before+1,f.calls.size);assertEquals(oauth,f.oauth.calls.size)
            assertFalse("nonce" in f.claims(f.calls.last()));assertTrue(session.available())
        }
        f.handler={f.reply("""{"code":"catalog_revision_conflict","extra":true}""",409)}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.layerAction(request,session,IdentityScope())}
    }

    @Test fun foreignActorOriginConsumedOrExpiredAccessCannotSignOrDispatchALayerOperation() {
        val f=AdminControlFixture();val session=f.login();val p=proposal(f)
        val signatures=f.signatures;val oauth=f.oauth.calls.size
        for(request in listOf(AdminLayerControl.preview(p,Identity.hash("other-actor".toByteArray()),f.oauth.metadata.apiOrigin,Identity.random()),
            AdminLayerControl.preview(p,f.client.layerActor(session),"https://other-admin.example.invalid",Identity.random()))) {
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.layerAction(request,session,IdentityScope())}
        }
        assertTrue(f.calls.isEmpty());assertEquals(signatures,f.signatures);assertEquals(oauth,f.oauth.calls.size)
        val request=AdminLayerControl.listDrafts("device",f.device,Identity.random())
        f.oauth.elapsed+=300_000
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.layerAction(request,session,IdentityScope())}
        assertTrue(f.calls.isEmpty());assertEquals(signatures,f.signatures);assertEquals(oauth,f.oauth.calls.size)
        val other=AdminControlFixture();val used=other.login();val before=other.signatures
        other.client.logout(used)
        assertThrows(AdminException::class.java){other.client.layerAction(request,used,IdentityScope())}
        assertTrue(other.calls.isEmpty());assertEquals(before,other.signatures)
    }

    @Test fun revokedTrustOrCancellationDuringSigningAndResponseCannotReturnAReadOrMutationResult() {
        for(stage in 0..2) {
            val f=AdminControlFixture();val session=f.login();val scope=IdentityScope()
            val request=AdminLayerControl.listDrafts("device",f.device,Identity.random())
            val reply="""{"targetKind":"device","targetId":"${f.device}","drafts":[]}"""
            if(stage==0)f.signHook={f.enabled=false}
            else f.handler={if(stage==1)f.enabled=false else scope.cancel();f.reply(reply)}
            val failure=assertThrows(AdminException::class.java){f.client.layerAction(request,session,scope)}
            assertEquals(if(stage==2)AdminFailure.CANCELLED else AdminFailure.REAUTHENTICATE,failure.reason)
            assertEquals(if(stage==0)0 else 1,f.calls.size)
        }
    }

    @Test fun malformedOversizedOrStaleLayerRepliesCannotReachCallerOrExtendTheAccessLease() {
        val f=AdminControlFixture();val session=f.login();val deadline=session.accessUntilElapsedMs
        val p=proposal(f);val request=AdminLayerControl.saveDraft(0,p,Identity.random())
        val valid=saved(f,p)
        val cases=listOf(f.reply(valid.replace("\"id\":\"synthetic-draft\"","\"id\":\"other\"")),
            f.reply("[]"),f.reply(valid.replace("\"revision\":1,","\"revision\":1,\"revision\":1,")),
            f.reply(" ".repeat(524_289)),f.reply(valid,headers=mapOf("content-type" to listOf("text/html"))),
            f.reply(valid,headers=mapOf("date" to listOf(AdminAuthFixture.date(f.oauth.wall-60_000)))))
        for(reply in cases) {
            val before=f.calls.size;f.handler={reply}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.layerAction(request,session,IdentityScope())}
            assertEquals(before+1,f.calls.size);assertEquals(deadline,session.accessUntilElapsedMs)
        }
    }
}
