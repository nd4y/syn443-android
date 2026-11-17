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

/** Actual signed discovery/OIDC/DPoP owners with a bounded fake HTTP peer.
 * This value-only read never owns a device, pending journal, grant or publisher. */
class AdminOperationVersionTest {
    private class Fixture {
        data class Call(val method:String,val url:String,val headers:Map<String,String>,val body:ByteArray?,val max:Int)
        val oauth=AdminAuthFixture()
        private val offline=AdminControlFixture.ec()
        private val anchor=TrustAnchor("synthetic-version-root",Base64.getEncoder().encodeToString(offline.public.encoded),1)
        private val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"synthetic-version-service",
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
            return ticket(next,pair,TrustAnchor("synthetic-next-root",Base64.getEncoder().encodeToString(pair.public.encoded),1))
        }
        var signatures=0
        var signHook:(()->Unit)?=null
        private val key=object:ProofKey {
            override val publicKey=oauth.key.publicKey
            override fun sign(input:ByteArray)=oauth.key.sign(input).also {signatures++;signHook?.invoke()}
        }
        val calls=mutableListOf<Call>()
        var handler:(Call)->Reply={reply("""{"version":1,"configurationRequestVersion":1}""")}
        private val exchange=IdentityExchange {method,url,headers,body,scope,max->
            if(url==oauth.metadata.apiOrigin+AdminControl.PATH) {
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
        fun reply(raw:String,status:Int=200,headers:Map<String,List<String>> = emptyMap(),at:Long=oauth.wall)=
            Reply(status,mapOf("content-type" to listOf("application/json"),"date" to listOf(AdminAuthFixture.date(at)))+headers,raw.toByteArray(Charsets.UTF_8))
        fun claims(call:Call)=Identity.objectJSON(Policy.utf8(Policy.decode64(call.headers.getValue("DPoP").split('.')[1])))
        fun proposal()=AdminLayerControl.proposal("""{"draftId":"synthetic-draft","draftRevision":1,"targetKind":"device","targetId":"synthetic-device","mode":"wifi","approvalUntilMs":${oauth.wall+600_000},"bundles":[{"device":"synthetic-device","baseRevision":1,"baseHash":"${"a".repeat(64)}","layers":[{"id":"synthetic-device","kind":"device","priority":0,"revision":1,"changes":[],"permissions":[]}]}]}""")
    }
    private fun verify(f:Fixture,call:Fixture.Call,session:AdminSession) {
        assertEquals("POST",call.method);assertEquals(f.oauth.metadata.apiOrigin+AdminControl.PATH,call.url)
        assertEquals(setOf("Content-Type","Cache-Control","Authorization","DPoP"),call.headers.keys)
        assertEquals("application/json",call.headers["Content-Type"]);assertEquals("no-store",call.headers["Cache-Control"])
        assertEquals("DPoP "+session.accessToken,call.headers["Authorization"]);assertEquals(4096,call.max)
        val body=checkNotNull(call.body);assertTrue(body.size in 1..8192)
        val request=Identity.objectJSON(Policy.utf8(body))
        assertEquals(setOf("version","action","requestId","payload"),request.keys)
        assertEquals(JsonPrimitive(1),request["version"]);assertEquals(JsonPrimitive("configuration.protocol.get"),request["action"])
        assertTrue(AdminIdentity.digest(request.getValue("requestId").jsonPrimitive.content));assertEquals(buildJsonObject {},request["payload"])
        assertEquals(Canonical.encode(request),Policy.utf8(body))
        val parts=call.headers.getValue("DPoP").split('.')
        val header=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[0])))
        assertEquals(setOf("alg","typ","jwk"),header.keys);assertEquals(JsonPrimitive("ES256"),header["alg"])
        assertEquals(JsonPrimitive("dpop+jwt"),header["typ"]);assertEquals(Identity.jwk(f.oauth.key.publicKey),header["jwk"])
        val claims=f.claims(call)
        assertEquals(setOf("htm","htu","iat","jti","ath","req_hash"),claims.keys)
        assertEquals(JsonPrimitive("POST"),claims["htm"]);assertEquals(JsonPrimitive(call.url),claims["htu"])
        assertEquals(JsonPrimitive(Identity.hash(body)),claims["req_hash"])
        assertEquals(JsonPrimitive(Identity.hash(session.accessToken.toByteArray(Charsets.US_ASCII))),claims["ath"])
        assertTrue(AdminIdentity.digest(claims.getValue("jti").jsonPrimitive.content));assertFalse("nonce" in claims)
        val raw=Policy.decode64(parts[2]);assertEquals(64,raw.size)
        fun integer(value:ByteArray):ByteArray {val n=BigInteger(1,value).toByteArray();return byteArrayOf(2,n.size.toByte())+n}
        val integers=integer(raw.copyOfRange(0,32))+integer(raw.copyOfRange(32,64))
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(f.oauth.key.publicKey);update((parts[0]+"."+parts[1]).toByteArray(Charsets.US_ASCII))
            verify(byteArrayOf(0x30,integers.size.toByte())+integers)
        })
    }

    @Test fun protocolVersionReadUsesOnlyCurrentSignedControlOriginAndVerifiableOneShotProof() {
        val f=Fixture();val session=f.login();val oauth=f.oauth.calls.size
        val access=session.accessUntilElapsedMs;val lease=session.sessionUntilElapsedMs
        for(version in listOf(1,2)) {
            val before=f.calls.size
            f.handler={f.reply("""{"version":1,"configurationRequestVersion":$version}""")}
            assertEquals(version,f.client.configurationRequestVersion(session,IdentityScope()))
            assertEquals(before+1,f.calls.size);verify(f,f.calls.last(),session)
            assertEquals(access,session.accessUntilElapsedMs);assertEquals(lease,session.sessionUntilElapsedMs);assertTrue(session.available())
        }
        assertEquals(oauth,f.oauth.calls.size)
        val requests=f.calls.map {Identity.objectJSON(Policy.utf8(checkNotNull(it.body))).getValue("requestId")}
        assertEquals(2,requests.toSet().size);assertNotEquals(f.claims(f.calls[0])["jti"],f.claims(f.calls[1])["jti"])
        f.handler={f.reply("""{"version":1,"configurationRequestVersion":2}""",at=f.oauth.wall+10_000)}
        assertEquals(2,f.client.configurationRequestVersion(session,IdentityScope()))
        f.handler={f.reply("""{"version":1,"configurationRequestVersion":1}""")}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.configurationRequestVersion(session,IdentityScope())}
        assertEquals(access,session.accessUntilElapsedMs);assertEquals(lease,session.sessionUntilElapsedMs)
    }

    @Test fun closedVersionReplyRejectsNumbersShapeUtf8AndHeadersWithoutPublishingRejectedClock() {
        val f=Fixture();val session=f.login();val valid="""{"version":1,"configurationRequestVersion":2}"""
        val bad=mutableListOf("", "[]", "{}", valid+"{}",valid.dropLast(1)+",\"unknown\":true}",
            valid.replace("\"version\":1","\"Version\":1"),valid.replace("\"version\":1","\"version\":1,\"version\":1"),
            valid.replace("\"configurationRequestVersion\":2","\"configurationRequestVersion\":2,\"configurationRequestVersion\":2"),
            valid.replace("\"version\":1","\"version\":1.0"))
        for(number in listOf("0","3","-1","2.0","2e0","\"2\"","true","null","9007199254740992"))
            bad+=valid.replace("\"configurationRequestVersion\":2","\"configurationRequestVersion\":"+number)
        val access=session.accessUntilElapsedMs;val lease=session.sessionUntilElapsedMs;val oauth=f.oauth.calls.size
        for(raw in bad) {
            val before=f.calls.size;f.handler={f.reply(raw,at=f.oauth.wall+10_000)}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.configurationRequestVersion(session,IdentityScope())}
            assertEquals(before+1,f.calls.size)
        }
        for(reply in listOf(f.reply(valid,headers=mapOf("content-type" to listOf("text/html"))),
            f.reply(valid).let {it.copy(headers=it.headers-"content-type")},
            f.reply(valid).let {it.copy(headers=it.headers-"date")},
            f.reply(valid).let {it.copy(body=it.body+byteArrayOf(0xff.toByte()))},
            f.reply(valid,at=f.oauth.wall+40_000))) {
            f.handler={reply};AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.configurationRequestVersion(session,IdentityScope())}
        }
        for(name in listOf("date","content-type")) {
            val value=if(name=="date")AdminAuthFixture.date(f.oauth.wall)else "application/json"
            f.handler={f.reply(valid,headers=mapOf(name to listOf(value,value)))}
            AdminAuthFixture.failure(AdminFailure.TRANSPORT){f.client.configurationRequestVersion(session,IdentityScope())}
        }
        val exact=valid+" ".repeat(4096-valid.toByteArray().size)
        f.handler={f.reply(exact)};assertEquals(2,f.client.configurationRequestVersion(session,IdentityScope()))
        f.handler={f.reply(exact+" ")};AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.configurationRequestVersion(session,IdentityScope())}
        f.handler={f.reply(valid)};assertEquals(2,f.client.configurationRequestVersion(session,IdentityScope()))
        val iat=f.claims(f.calls.first()).getValue("iat")
        assertTrue(f.calls.all {f.claims(it).getValue("iat")==iat})
        assertEquals(access,session.accessUntilElapsedMs);assertEquals(lease,session.sessionUntilElapsedMs)
        assertEquals(oauth,f.oauth.calls.size);assertTrue(session.available())
    }

    @Test fun onlyExplicitOldUnsupportedRoutesReturnOneWithoutAuthorityOrClockPromotion() {
        val f=Fixture();val session=f.login();val oauth=f.oauth.calls.size
        val access=session.accessUntilElapsedMs;val lease=session.sessionUntilElapsedMs
        val replies=listOf(f.reply("old route",404,headers=mapOf("date" to listOf("untrusted"))),
            f.reply("<html>unsupported</html>",405,headers=mapOf("content-type" to listOf("text/html"))),
            f.reply("""{"code":"catalog_invalid"}""",400,at=f.oauth.wall+600_000))
        for(reply in replies) {
            val before=f.calls.size;f.handler={reply}
            assertEquals(1,f.client.configurationRequestVersion(session,IdentityScope()))
            assertEquals(before+1,f.calls.size);verify(f,f.calls.last(),session)
            assertEquals(access,session.accessUntilElapsedMs);assertEquals(lease,session.sessionUntilElapsedMs)
        }
        f.handler={f.reply("""{"version":1,"configurationRequestVersion":1}""")}
        assertEquals(1,f.client.configurationRequestVersion(session,IdentityScope()))
        assertTrue(f.calls.all {f.claims(it)["iat"]==f.claims(f.calls.first())["iat"]})
        assertTrue(session.available());assertEquals(oauth,f.oauth.calls.size)
        val actor=f.client.layerActor(session);val before=f.calls.size
        assertEquals(Identity.hash((f.oauth.metadata.issuer+"\u0000"+session.subject).toByteArray()),actor)
        assertEquals(before,f.calls.size)
    }

    @Test fun deniedMfaQuotaTransientMalformedAndNonceRepliesNeverFallbackOrRetry() {
        val f=Fixture();val session=f.login();val oauth=f.oauth.calls.size
        val cases=listOf(Triple(401,"catalog_denied",AdminFailure.REAUTHENTICATE),
            Triple(403,"catalog_reauthentication_required",AdminFailure.REAUTHENTICATE),
            Triple(403,"catalog_denied",AdminFailure.ACCESS_DENIED),Triple(429,"catalog_quota",AdminFailure.LIMITED),
            Triple(503,"catalog_unavailable",AdminFailure.TRANSPORT),Triple(409,"catalog_revision_conflict",AdminFailure.CONFLICT),
            Triple(400,"catalog_revision_conflict",AdminFailure.INVALID_REPLY),Triple(429,"catalog_denied",AdminFailure.INVALID_REPLY),
            Triple(302,"catalog_invalid",AdminFailure.INVALID_REPLY))
        for((status,code,reason) in cases) {
            val before=f.calls.size;f.handler={f.reply("""{"code":"$code"}""",status)}
            AdminAuthFixture.failure(reason){f.client.configurationRequestVersion(session,IdentityScope())}
            assertEquals(before+1,f.calls.size)
        }
        val malformed=listOf(f.reply("""{"code":"catalog_invalid","extra":true}""",400),
            f.reply("""{"code":"catalog_invalid"}""",400,headers=mapOf("content-type" to listOf("text/html"))),
            f.reply("""{"code":"catalog_invalid","code":"catalog_invalid"}""",400),
            f.reply("""{"version":1,"configurationRequestVersion":2}""",headers=mapOf("dpop-nonce" to listOf("synthetic-nonce"))),
            f.reply("old route",404,headers=mapOf("DPoP-Nonce" to listOf("synthetic-nonce"))),
            f.reply("""{"code":"catalog_invalid"}""",400,headers=mapOf("dpop-nonce" to listOf(""))))
        for(reply in malformed) {
            val before=f.calls.size;f.handler={reply}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.configurationRequestVersion(session,IdentityScope())}
            assertEquals(before+1,f.calls.size)
        }
        for(reason in listOf(DeliveryFailure.TRANSPORT,DeliveryFailure.CANCELLED)) {
            val before=f.calls.size;f.handler={throw DeliveryException(reason)}
            AdminAuthFixture.failure(if(reason==DeliveryFailure.CANCELLED)AdminFailure.CANCELLED else AdminFailure.TRANSPORT) {
                f.client.configurationRequestVersion(session,IdentityScope())
            }
            assertEquals(before+1,f.calls.size)
        }
        assertEquals(oauth,f.oauth.calls.size);assertTrue(session.available());assertTrue(f.calls.all {"nonce" !in f.claims(it)})
    }

    @Test fun sourceRootAccountBootClockAndCancellationFenceBothSidesOfSingleDispatch() {
        for(mode in 0..12) {
            val f=Fixture();val session=f.login();val scope=IdentityScope()
            val oauth=f.oauth.calls.size;val signed=f.signatures
            when(mode) {
                0->scope.cancel()
                1->f.discovery=null
                2->f.discovery=f.changedDiscovery(true)
                3->f.discovery=f.changedDiscovery(false)
                4->f.signHook={scope.cancel()}
                5->f.signHook={f.oauth.boot++}
                6->f.signHook={f.oauth.elapsed+=20_001}
                7->f.signHook={f.oauth.elapsed--}
                11->f.signHook={f.discovery=f.changedDiscovery(true)}
                12->f.signHook={f.discovery=null}
            }
            f.handler={
                when(mode){8->scope.cancel();9->f.oauth.boot++;10->f.oauth.elapsed+=20_001}
                f.reply("""{"version":1,"configurationRequestVersion":2}""")
            }
            val reason=when(mode){0,4,8->AdminFailure.CANCELLED;1,2,3,9,11,12->AdminFailure.REAUTHENTICATE;else->AdminFailure.INVALID_REPLY}
            AdminAuthFixture.failure(reason){f.client.configurationRequestVersion(session,scope)}
            assertEquals(if(mode in 8..10)1 else 0,f.calls.size)
            assertEquals(signed+if(mode>=4)1 else 0,f.signatures);assertEquals(oauth,f.oauth.calls.size);assertTrue(session.available())
        }
        val f=Fixture();val session=f.login();val other=Fixture();val foreign=other.login();val signed=f.signatures
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.configurationRequestVersion(foreign,IdentityScope())}
        assertTrue(f.calls.isEmpty());assertEquals(signed,f.signatures)
        f.oauth.elapsed=session.accessUntilElapsedMs
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.configurationRequestVersion(session,IdentityScope())}
        assertTrue(f.calls.isEmpty());assertEquals(signed,f.signatures)
    }

    @Test fun eachNewMutationReadsAgainWithoutCachingOrRewritingAnyStoredVersionOneOperation() {
        val f=Fixture();val session=f.login();val actor=f.client.layerActor(session);val origin=f.oauth.metadata.apiOrigin
        val proposal=f.proposal();val requestId=Identity.random()
        val original=AdminLayerControl.saveDraft(0,proposal,requestId)
        val exact=original.bodyBytes();val context=AdminLayerControl.replayContext(original,actor,origin)
        val access=session.accessUntilElapsedMs;val lease=session.sessionUntilElapsedMs;val oauth=f.oauth.calls.size
        for(version in listOf(1,2,1)) {
            f.handler={f.reply("""{"version":1,"configurationRequestVersion":$version}""")}
            val selected=f.client.configurationRequestVersion(session,IdentityScope());assertEquals(version,selected)
            val new=AdminLayerControl.saveDraft(0,proposal,Identity.random(),selected)
            assertEquals(JsonPrimitive(version),AdminLayerJson.parse(new.wireJson()).jsonObject["version"])
            assertArrayEquals(exact,original.bodyBytes());assertArrayEquals(context,AdminLayerControl.replayContext(original,actor,origin))
            val restored=AdminLayerControl.restoreRequest(exact,context,proposal.wireJson(),actor,origin)
            assertTrue(restored.expected.replayOnly);assertArrayEquals(exact,restored.bodyBytes())
            assertEquals(JsonPrimitive(1),AdminLayerJson.parse(restored.wireJson()).jsonObject["version"])
            assertArrayEquals(exact,AdminLayerControl.saveDraft(0,proposal,requestId).bodyBytes())
        }
        assertEquals(3,f.calls.size)
        f.handler={throw DeliveryException(DeliveryFailure.TRANSPORT)}
        AdminAuthFixture.failure(AdminFailure.TRANSPORT){f.client.configurationRequestVersion(session,IdentityScope())}
        assertEquals(4,f.calls.size);assertArrayEquals(exact,original.bodyBytes());assertArrayEquals(context,AdminLayerControl.replayContext(original,actor,origin))
        assertEquals(access,session.accessUntilElapsedMs);assertEquals(lease,session.sessionUntilElapsedMs)
        assertEquals(oauth,f.oauth.calls.size);assertTrue(session.available());f.calls.forEach {verify(f,it,session)}
    }
}
