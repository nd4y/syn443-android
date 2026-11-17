package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.Signature
import java.util.Base64

/** Generated signed discovery/OIDC/DPoP only. The peer is an owned fake;
 * no network, account, device, durable pending record or publication is changed. */
class AdminOperationProtocolTest {
    private class Fixture {
        data class Call(val method:String,val url:String,val headers:Map<String,String>,val body:ByteArray?,val max:Int)
        val oauth=AdminAuthFixture()
        val device="synthetic-device"
        private val offline=AdminControlFixture.ec()
        private val anchor=TrustAnchor("synthetic-operation-root",Base64.getEncoder().encodeToString(offline.public.encoded),1)
        private val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"synthetic-operation-service",
            "https://device-id.example.invalid/realms/device","syn443-android","https://device-api.example.invalid",
            mapOf("synthetic-online" to Base64.getEncoder().encodeToString(AdminControlFixture.ec().public.encoded)),
            oauth.wall/1000,oauth.wall/1000,oauth.wall/1000+3600,adminBootstrap=oauth.metadata)
        private fun ticket(value:ServiceDescriptor,key:KeyPair=offline,root:TrustAnchor=anchor):AdminDiscovery {
            val header="""{"alg":"ES256","kid":"${root.id}","typ":"syn443-bootstrap+jws"}"""
            val payload=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(value)))
            val input=Identity.encode(header.toByteArray())+"."+Identity.encode(payload.toByteArray())
            val signature=Signature.getInstance("SHA256withECDSA").run {initSign(key.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            val raw=input+"."+Identity.encode(Identity.derToRaw(signature))
            val floor=BootstrapTrust.descriptor(raw,root,ServiceFloor(),oauth.wall/1000).second
            val expected=Bootstrap(value.serviceId,value.issuer,value.clientId,value.apiOrigin,value.roots.toMap())
            return checkNotNull(BootstrapTrust.adminDiscovery(raw,root,floor,expected,oauth.wall/1000))
        }
        var discovery:AdminDiscovery?=ticket(descriptor)
        fun changedDiscovery(root:Boolean):AdminDiscovery {
            val next=descriptor.copy(revision=2)
            if(!root)return ticket(next)
            val pair=AdminControlFixture.ec()
            return ticket(next,pair,TrustAnchor("synthetic-replacement-root",Base64.getEncoder().encodeToString(pair.public.encoded),1))
        }
        var signHook:(()->Unit)?=null
        var signatures=0
        private val key=object:ProofKey {
            override val publicKey=oauth.key.publicKey
            override fun sign(input:ByteArray)=oauth.key.sign(input).also {signatures++;signHook?.invoke()}
        }
        val calls=mutableListOf<Call>()
        var handler:(Call)->Reply={reply("{}",400)}
        private val exchange=IdentityExchange {method,url,headers,body,scope,max->
            if(url in setOf(oauth.metadata.apiOrigin+AdminOperationReconcile.PATH,oauth.metadata.apiOrigin+AdminControl.PATH)) {
                val call=Call(method,url,headers.toMap(),body?.copyOf(),max);calls+=call;handler(call)
            }else oauth.exchange.request(method,url,headers,body,scope,max)
        }
        val client=AdminProtocol.fromDiscovery({discovery},key,exchange,{oauth.boot},{oauth.elapsed})
        private val pending=client.newPending(7)
        init {oauth.handler={call->if(call.url.endsWith("/token"))oauth.tokens(idChanges=mapOf("nonce" to JsonPrimitive(pending.nonce))) else oauth.normal(call)}}
        fun login():AdminSession {
            val issuer=client.discover(IdentityScope())
            return client.exchangeCallback(AdminBootstrap.CALLBACK+"?"+Identity.form(linkedMapOf(
                "code" to "synthetic-code","state" to pending.state,"iss" to oauth.metadata.issuer)),pending,7,issuer,IdentityScope())
        }
        fun proposal(blob:Int=0)=AdminLayerControl.proposal("""{"draftId":"synthetic-draft","draftRevision":1,"targetKind":"device","targetId":"$device","mode":"wifi","approvalUntilMs":${oauth.wall+600_000},"bundles":[{"device":"$device","baseRevision":1,"baseHash":"${"a".repeat(64)}","layers":[{"id":"$device","kind":"device","priority":0,"revision":1,"changes":[{"path":"/blob","operation":"set","value":"${"x".repeat(blob)}"}],"permissions":[]}]}]}""")
        fun original(version:Int=2,id:String=Identity.random(),blob:Int=0)=AdminLayerControl.saveDraft(0,proposal(blob),id,version)
        fun request(session:AdminSession,original:AdminLayerRequest=original(),intent:AdminOperationIntent=AdminOperationIntent.LOOKUP)=
            AdminOperationReconcile.request(original,client.layerActor(session),oauth.metadata.apiOrigin,Identity.random(),intent)
        fun wire(request:AdminOperationRequest,outcome:AdminOperationOutcome=AdminOperationOutcome.RECORDED,
            recorded:Long=if(outcome==AdminOperationOutcome.UNKNOWN)0 else oauth.wall,job:String?=null):String {
            val absent=outcome in setOf(AdminOperationOutcome.UNKNOWN,AdminOperationOutcome.NO_EFFECT)
            return """{"version":1,"actor":"${request.actor}","action":"${request.original.action.wire}","requestId":"${request.original.requestId}","bodyHash":"${request.originalBodyHash}","targetKind":"${request.targetKind}","targetId":"${request.targetId}","outcome":"${outcome.name}","recordedAtMs":$recorded,"effectKind":"${if(absent)"" else request.effectKind}","effectId":"${if(absent)"" else request.effectId}","effectRevision":${if(absent)0 else request.effectRevision}${job?.let {",\"job\":$it"}?:""}}"""
        }
        fun reply(raw:String,status:Int=200,headers:Map<String,List<String>> = emptyMap(),at:Long=oauth.wall)=
            Reply(status,mapOf("content-type" to listOf("application/json"),"date" to listOf(AdminAuthFixture.date(at)))+headers,raw.toByteArray(Charsets.UTF_8))
        fun claims(call:Call)=Identity.objectJSON(Policy.utf8(Policy.decode64(call.headers.getValue("DPoP").split('.')[1])))
    }
    private fun verifyProof(f:Fixture,call:Fixture.Call,session:AdminSession,request:AdminOperationRequest) {
        assertEquals("POST",call.method);assertEquals(f.oauth.metadata.apiOrigin+AdminOperationReconcile.PATH,call.url)
        assertEquals(setOf("Content-Type","Cache-Control","Authorization","DPoP"),call.headers.keys)
        assertEquals("application/json",call.headers["Content-Type"]);assertEquals("no-store",call.headers["Cache-Control"])
        assertEquals("DPoP "+session.accessToken,call.headers["Authorization"]);assertEquals(1_048_576,call.max)
        assertArrayEquals(request.bodyBytes(),call.body)
        val parts=call.headers.getValue("DPoP").split('.')
        val header=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[0])))
        assertEquals(setOf("alg","typ","jwk"),header.keys);assertEquals("ES256",header.getValue("alg").jsonPrimitive.content)
        assertEquals("dpop+jwt",header.getValue("typ").jsonPrimitive.content);assertEquals(Identity.jwk(f.oauth.key.publicKey),header["jwk"])
        val claims=f.claims(call)
        assertEquals(setOf("htm","htu","iat","jti","ath","req_hash"),claims.keys)
        assertEquals(call.url,claims.getValue("htu").jsonPrimitive.content);assertEquals("POST",claims.getValue("htm").jsonPrimitive.content)
        assertEquals(Identity.hash(checkNotNull(call.body)),claims.getValue("req_hash").jsonPrimitive.content)
        assertEquals(Identity.hash(session.accessToken.toByteArray(Charsets.US_ASCII)),claims.getValue("ath").jsonPrimitive.content)
        assertTrue(AdminIdentity.digest(claims.getValue("jti").jsonPrimitive.content));assertFalse("nonce" in claims)
        val signature=Policy.decode64(parts[2]);assertEquals(64,signature.size)
        fun integer(value:ByteArray):ByteArray {val n=BigInteger(1,value).toByteArray();return byteArrayOf(2,n.size.toByte())+n}
        val values=integer(signature.copyOfRange(0,32))+integer(signature.copyOfRange(32,64))
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(f.oauth.key.publicKey);update((parts[0]+"."+parts[1]).toByteArray(Charsets.US_ASCII))
            verify(byteArrayOf(0x30,values.size.toByte())+values)
        })
    }

    @Test fun reconciliationSignsOnlyFixedUriTokenOuterBytesAndExactOwnedOriginal() {
        val f=Fixture();val session=f.login();val original=f.original();val exact=original.bodyBytes()
        val request=f.request(session,original,AdminOperationIntent.SEAL_IF_ABSENT);val body=request.bodyBytes()
        original.bodyBytes().fill(0);request.bodyBytes().fill(0);request.original.bodyBytes().fill(0)
        f.handler={f.reply(f.wire(request,AdminOperationOutcome.NO_EFFECT))}
        val oauth=f.oauth.calls.size;val receipt=f.client.operationReconcile(request,session,IdentityScope())
        assertEquals(AdminOperationOutcome.NO_EFFECT,receipt.outcome);assertEquals(original.requestId,receipt.requestId)
        assertEquals(request.originalBodyHash,receipt.bodyHash);assertEquals(request.actor,receipt.actor)
        assertEquals(Identity.hash((f.oauth.metadata.issuer+"\u0000"+session.subject).toByteArray(Charsets.UTF_8)),receipt.actor)
        assertEquals("",receipt.effectId);assertEquals(0L,receipt.effectRevision);assertNull(receipt.job)
        val outer=AdminLayerJson.parse(Policy.utf8(body)).jsonObject
        assertEquals(setOf("version","requestId","intent","originalBody64"),outer.keys)
        assertEquals(request.requestId,outer.getValue("requestId").jsonPrimitive.content)
        assertArrayEquals(exact,Policy.decode64(outer.getValue("originalBody64").jsonPrimitive.content))
        assertArrayEquals(exact,request.original.bodyBytes());assertArrayEquals(body,request.bodyBytes())
        assertTrue(request.original.expected.replayOnly);verifyProof(f,f.calls.single(),session,request)
        assertEquals(oauth,f.oauth.calls.size);assertTrue(session.available())
        for(value in listOf(request,request.original,receipt))assertFalse(value.toString().contains("synthetic-draft"))
        val signed=f.signatures;val calls=f.calls.size
        for(foreign in listOf(AdminOperationReconcile.request(original,Identity.hash("other actor".toByteArray()),f.oauth.metadata.apiOrigin,Identity.random(),AdminOperationIntent.LOOKUP),
            AdminOperationReconcile.request(original,request.actor,"https://other-admin.example.invalid",Identity.random(),AdminOperationIntent.LOOKUP))) {
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.operationReconcile(foreign,session,IdentityScope())}
        }
        val other=Fixture();val foreign=other.login()
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.operationReconcile(request,foreign,IdentityScope())}
        assertEquals(signed,f.signatures);assertEquals(calls,f.calls.size);assertEquals(oauth,f.oauth.calls.size)
    }

    @Test fun fullOriginalUsesScopedCanonicalProofBoundsWithoutChangingOrdinaryIdentityLimits() {
        val f=Fixture();val session=f.login();val id=Identity.random()
        val empty=f.original(id=id).bodyBytes().size
        val original=f.original(id=id,blob=262_144-empty);assertEquals(262_144,original.bodyBytes().size)
        val request=f.request(session,original);val body=request.bodyBytes()
        assertTrue(body.size>262_144 && body.size<350_000);assertEquals(524_288,AdminOperationReconcile.MAX_REQUEST_BYTES)
        assertEquals(1_048_576,request.maxReplyBytes)
        f.handler={f.reply(f.wire(request))}
        val received=f.client.operationReconcile(request,session,IdentityScope())
        assertEquals(AdminOperationOutcome.RECORDED,received.outcome);verifyProof(f,f.calls.single(),session,request)
        val wrapper=AdminLayerJson.reconciliationDocument(Policy.utf8(body)).root.jsonObject
        assertArrayEquals(original.bodyBytes(),Policy.decode64(wrapper.getValue("originalBody64").jsonPrimitive.content))
        val signed=f.signatures;val calls=f.calls.size
        var ordinarySigns=0
        val ordinarySign:(ByteArray)->ByteArray={input->ordinarySigns++;f.oauth.key.sign(input)}
        assertThrows(IllegalArgumentException::class.java) {
            Identity.proof(f.oauth.key.publicKey,ordinarySign,"POST",f.oauth.metadata.apiOrigin+"/ordinary",f.oauth.wall/1000,
                token=session.accessToken,body=ByteArray(8193))
        }
        assertThrows(IllegalArgumentException::class.java) {
            Identity.proof(f.oauth.key.publicKey,ordinarySign,"POST",request.uri,f.oauth.wall/1000,
                token=session.accessToken,body=ByteArray(360_449),maxBody=360_449)
        }
        assertThrows(IllegalArgumentException::class.java) {
            Identity.proof(f.oauth.key.publicKey,ordinarySign,"POST",request.uri,f.oauth.wall/1000,token="x".repeat(16_385))
        }
        assertEquals(0,ordinarySigns);assertEquals(signed,f.signatures);assertEquals(calls,f.calls.size)
    }

    @Test fun httpDenialsAndNonceChallengesNeverRetryDispatchOrManufactureAnOperationReceipt() {
        val f=Fixture();val session=f.login();val request=f.request(session);val pending=request.original.bodyBytes()
        val oauth=f.oauth.calls.size;val deadline=session.accessUntilElapsedMs
        val cases=listOf(Triple(404,"catalog_unavailable",AdminFailure.TRANSPORT),Triple(405,"catalog_unavailable",AdminFailure.TRANSPORT),
            Triple(400,"catalog_invalid",AdminFailure.INVALID_CONFIGURATION),Triple(403,"catalog_denied",AdminFailure.ACCESS_DENIED),
            Triple(403,"catalog_reauthentication_required",AdminFailure.REAUTHENTICATE),Triple(409,"catalog_revision_conflict",AdminFailure.CONFLICT),
            Triple(429,"catalog_quota",AdminFailure.LIMITED),Triple(401,"catalog_denied",AdminFailure.REAUTHENTICATE),
            Triple(500,"catalog_unavailable",AdminFailure.TRANSPORT),Triple(503,"catalog_unavailable",AdminFailure.TRANSPORT),
            Triple(400,"catalog_denied",AdminFailure.INVALID_REPLY),Triple(409,"catalog_invalid",AdminFailure.INVALID_REPLY),
            Triple(429,"catalog_denied",AdminFailure.INVALID_REPLY),Triple(302,"catalog_denied",AdminFailure.INVALID_REPLY))
        for((status,code,failure) in cases) {
            val calls=f.calls.size;val signed=f.signatures
            f.handler={f.reply("""{"code":"$code"}""",status,mapOf("dpop-nonce" to listOf("synthetic-reconcile-nonce")),at=f.oauth.wall+10_000)}
            AdminAuthFixture.failure(failure){f.client.operationReconcile(request,session,IdentityScope())}
            assertEquals(calls+1,f.calls.size);assertEquals(signed+1,f.signatures);assertEquals(oauth,f.oauth.calls.size)
            assertEquals(deadline,session.accessUntilElapsedMs);assertTrue(session.available());assertArrayEquals(pending,request.original.bodyBytes())
            verifyProof(f,f.calls.last(),session,request)
        }
        // A rejected response's later Date must not become an accepted floor.
        f.handler={f.reply(f.wire(request))}
        assertEquals(AdminOperationOutcome.RECORDED,f.client.operationReconcile(request,session,IdentityScope()).outcome)
        assertTrue(f.calls.all {it.url.endsWith(AdminOperationReconcile.PATH)})
    }

    @Test fun changedSignedSourceRootAndAccountDuringSigningOrReplyCannotPublishAReceiptOrClock() {
        for(stage in 0..1)for(change in 0..2) {
            val f=Fixture();val session=f.login();val request=f.request(session);val before=checkNotNull(f.discovery)
            val changed=if(change<2)f.changedDiscovery(change==1)else null
            if(changed!=null)assertNotEquals(before.binding,changed.binding)
            val oauth=f.oauth.calls.size;val deadline=session.accessUntilElapsedMs
            fun revoke() {if(change==2)f.client.logout(session) else f.discovery=changed}
            if(stage==0)f.signHook=::revoke
            f.handler={if(stage==1)revoke();f.reply(f.wire(request),at=f.oauth.wall+10_000)}
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.operationReconcile(request,session,IdentityScope())}
            assertEquals(if(stage==0)0 else 1,f.calls.size);assertEquals(oauth,f.oauth.calls.size)
            assertEquals(deadline,session.accessUntilElapsedMs)
            if(change==2)assertFalse(session.available()) else {
                // Restoring this isolated source value checks only that the
                // rejected response did not publish a future trusted clock.
                f.discovery=before;f.signHook=null;f.handler={f.reply(f.wire(request))}
                assertEquals(AdminOperationOutcome.RECORDED,f.client.operationReconcile(request,session,IdentityScope()).outcome)
                assertTrue(session.available())
            }
        }
    }

    @Test fun bootClockAndCancellationFenceSigningDispatchAndCompletedReplies() {
        for(mode in 0..10) {
            val f=Fixture();val session=f.login();val scope=IdentityScope();val request=f.request(session)
            val signed=f.signatures;val oauth=f.oauth.calls.size
            when(mode) {
                0->scope.cancel()
                1->f.oauth.boot++
                2->f.oauth.elapsed--
                3->f.oauth.elapsed=session.accessUntilElapsedMs
                4->f.signHook={scope.cancel()}
                5->f.signHook={f.oauth.boot++}
                6->f.signHook={f.oauth.elapsed+=20_001}
                7->f.signHook={f.oauth.elapsed--}
            }
            f.handler={
                when(mode){8->scope.cancel();9->f.oauth.boot++;10->f.oauth.elapsed+=20_001}
                f.reply(f.wire(request))
            }
            val expected=when(mode){0,4,8->AdminFailure.CANCELLED;1,2,3,9->AdminFailure.REAUTHENTICATE;else->AdminFailure.INVALID_REPLY}
            AdminAuthFixture.failure(expected){f.client.operationReconcile(request,session,scope)}
            assertEquals(if(mode>=8)1 else 0,f.calls.size);assertEquals(signed+if(mode>=4)1 else 0,f.signatures)
            assertEquals(oauth,f.oauth.calls.size);assertTrue(session.available())
        }
    }

    @Test fun malformedForeignAndUnboundRepliesNeverMintNoEffectOrAdvanceAcceptedTime() {
        val f=Fixture();val session=f.login();val request=f.request(session);val valid=f.wire(request)
        val deadline=session.accessUntilElapsedMs;val pending=request.original.bodyBytes()
        val invalid=listOf(valid.replace(request.actor,Identity.hash("foreign".toByteArray())),
            valid.replace(request.originalBodyHash,"b".repeat(64)),valid.replace(request.original.requestId,request.requestId),
            valid.replace("\"targetId\":\"${f.device}\"","\"targetId\":\"foreign-device\""),
            valid.replace("\"effectRevision\":1","\"effectRevision\":2"),
            valid.replace("\"version\":1","\"version\":1,\"version\":1"),
            valid.replace("\"outcome\":\"RECORDED\"","\"outcome\":null"),
            valid.dropLast(1)+",\"unknown\":true}",f.wire(request,recorded=f.oauth.wall+100_000),"[]","{}","", " ".repeat(1_048_577))
        for(raw in invalid) {
            val calls=f.calls.size;f.handler={f.reply(raw,at=f.oauth.wall+10_000)}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.operationReconcile(request,session,IdentityScope())}
            assertEquals(calls+1,f.calls.size);assertEquals(deadline,session.accessUntilElapsedMs);assertArrayEquals(pending,request.original.bodyBytes())
        }
        for(headers in listOf(mapOf("content-type" to listOf("text/html")),mapOf("date" to listOf(AdminAuthFixture.date(f.oauth.wall+40_000))))) {
            f.handler={f.reply(valid,headers=headers)}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.operationReconcile(request,session,IdentityScope())}
        }
        for(name in listOf("date","content-type")) {
            val value=if(name=="date")AdminAuthFixture.date(f.oauth.wall)else "application/json"
            f.handler={f.reply(valid,headers=mapOf(name to listOf(value,value)))}
            AdminAuthFixture.failure(AdminFailure.TRANSPORT){f.client.operationReconcile(request,session,IdentityScope())}
        }
        f.handler={f.reply(valid).let {it.copy(body=it.body+byteArrayOf(0xff.toByte()))}}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.operationReconcile(request,session,IdentityScope())}
        val old=f.request(session,f.original(version=1))
        f.handler={f.reply(f.wire(old,AdminOperationOutcome.NO_EFFECT),at=f.oauth.wall+10_000)}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.operationReconcile(old,session,IdentityScope())}
        f.handler={f.reply(f.wire(old,AdminOperationOutcome.UNKNOWN))}
        assertEquals(AdminOperationOutcome.UNKNOWN,f.client.operationReconcile(old,session,IdentityScope()).outcome)
        assertEquals(deadline,session.accessUntilElapsedMs);assertTrue(session.available());assertArrayEquals(pending,request.original.bodyBytes())
    }

    @Test fun largeEscapedJobRemainsMetadataAndCannotRenewPreviewActivationOrOrdinaryTransportLimits() {
        val f=Fixture();val session=f.login();val actor=f.client.layerActor(session)
        val original=AdminLayerControl.preview(f.proposal(),actor,f.oauth.metadata.apiOrigin,Identity.random(),2)
        val request=f.request(session,original);val rawResult="\""+"\\u003c".repeat(99_000)+"\""
        val job="""{"id":"${request.effectId}","state":"ready","result":$rawResult}"""
        val wire=f.wire(request,job=job);assertTrue(wire.toByteArray().size>524_288 && wire.toByteArray().size<1_048_576)
        val deadline=session.accessUntilElapsedMs;val lease=session.sessionUntilElapsedMs;val oauth=f.oauth.calls.size
        f.handler={f.reply(wire)}
        val receipt=f.client.operationReconcile(request,session,IdentityScope());val queue=checkNotNull(receipt.job)
        assertEquals(AdminOperationJobState.READY,queue.state);assertEquals(rawResult,queue.rawResultJson())
        assertEquals(request.effectId,queue.id);assertEquals(AdminLayerAction.PREVIEW,receipt.action)
        assertEquals(AdminOperationOutcome.RECORDED,receipt.outcome);assertTrue(request.original.expected.replayOnly)
        assertEquals(deadline,session.accessUntilElapsedMs);assertEquals(lease,session.sessionUntilElapsedMs)
        assertEquals(oauth,f.oauth.calls.size);verifyProof(f,f.calls.single(),session,request)
        assertEquals("AdminOperationJob([redacted])",queue.toString());assertEquals("AdminOperationReceipt([redacted])",receipt.toString())
        val ordinary=AdminLayerControl.listDrafts("device",f.device,Identity.random())
        f.handler={f.reply("""{"targetKind":"device","targetId":"${f.device}","drafts":[]}""")}
        assertTrue(f.client.layerAction(ordinary,session,IdentityScope()) is AdminLayerDraftList)
        assertEquals(524_288,f.calls.last().max);assertEquals(f.oauth.metadata.apiOrigin+AdminControl.PATH,f.calls.last().url)
        f.handler={f.reply(" ".repeat(524_289))}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.layerAction(ordinary,session,IdentityScope())}
        val token=Fixture()
        token.oauth.handler={call->if(call.url.endsWith("/token"))token.oauth.reply(text=" ".repeat(65_537))else token.oauth.normal(call)}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){token.login()}
        assertEquals(1_048_576,request.maxReplyBytes);assertEquals(deadline,session.accessUntilElapsedMs)
    }
}
