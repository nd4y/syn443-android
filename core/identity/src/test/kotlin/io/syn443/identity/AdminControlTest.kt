package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class AdminControlTest {
    @Test fun threeReadActionsBindExactSignedOriginBodyAccessTokenAndFreshDpopProofs() {
        val f=AdminControlFixture();val session=f.login();val oauth=f.oauth.calls.size
        val page=f.client.listDevices("",session,IdentityScope())
        assertEquals(f.lastWire,page.wireJson());assertEquals(f.device,page.devices.single().device)
        assertEquals(4L,page.devices.single().policyRevision);assertEquals(2L,page.devices.single().desiredRevision)
        val report=page.devices.single().report
        assertEquals("reported",report.state);assertEquals(4L,report.policyRevision);assertEquals(4L,report.activePolicyRevision)
        assertEquals("committed",report.outcome);assertTrue(report.receivedAtMs>0)
        val config=f.client.deviceConfiguration(f.device,session,IdentityScope())
        assertEquals(f.lastWire,config.wireJson());assertEquals("wifi",config.mode);assertEquals(2L,config.revision)
        assertEquals(4L,config.policyRevision);assertEquals("assigned",config.state);assertEquals("matches_desired",config.publicationSource)
        assertEquals("reported",checkNotNull(config.activation).state)
        val runtime=f.client.deviceRuntime(f.device,session,IdentityScope())
        assertEquals(f.lastWire,runtime.wireJson());assertEquals("recent",runtime.state)
        val runtimeReport=checkNotNull(runtime.report)
        assertEquals("online",runtimeReport.sample.phase);assertTrue(runtimeReport.receivedAtMs>0)
        f.client.listDevices("",session,IdentityScope())
        assertEquals(listOf("configuration.devices.list","configuration.inventory.get","configuration.runtime.get","configuration.devices.list"),
            f.calls.map {Identity.objectJSON(checkNotNull(it.body).decodeToString()).getValue("action").jsonPrimitive.content})
        f.calls.forEach {f.verify(it,session)}
        assertEquals(f.calls.size,f.calls.map {Identity.objectJSON(checkNotNull(it.body).decodeToString()).getValue("requestId").jsonPrimitive.content}.toSet().size)
        assertEquals(f.calls.size,f.calls.map {f.claims(it).getValue("jti").jsonPrimitive.content}.toSet().size)
        assertEquals(oauth,f.oauth.calls.size);assertTrue(session.available())
        assertThrows(UnsupportedOperationException::class.java){(page.devices as MutableList<*>).clear()}
        for(view in listOf(page,page.devices.single(),report,config,runtime,checkNotNull(runtime.report))) {
            assertFalse(view.toString().contains(f.device));assertTrue(view.toString().contains("[redacted]"))
        }
    }
    @Test fun paginationRequiresAtMostThirtyTwoUniqueOrderedDevicesAndExactContinuation() {
        val f=AdminControlFixture();val session=f.login()
        val ids=(0 until 32).map {"synthetic-"+it.toString().padStart(2,'0')}
        f.handler={f.reply(f.page(ids,ids.last()))}
        assertEquals(32,f.client.listDevices("",session,IdentityScope()).devices.size)
        f.handler={f.reply(f.page(emptyList()))}
        assertTrue(f.client.listDevices(ids.last(),session,IdentityScope()).devices.isEmpty())
        val invalid=listOf(f.page(ids+"synthetic-32"),f.page(listOf("b","a")),f.page(listOf("a","a")),
            f.page(listOf("a"),"a"),f.page(ids,"foreign"),f.page(listOf("bad/id")),f.page(listOf("a")))
        for((index,wire) in invalid.withIndex()) {
            f.handler={f.reply(wire)}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.listDevices(if(index==6)"z" else "",session,IdentityScope())}
        }
        val count=f.calls.size
        for(invalidId in listOf("bad/id","x".repeat(65),"a?b","a\n")) {
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.listDevices(invalidId,session,IdentityScope())}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.deviceRuntime(invalidId,session,IdentityScope())}
        }
        assertEquals(count,f.calls.size)
    }
    @Test fun deviceSearchBindsLiteralPrefixAndCursorInTheSignedBodyAndRejectsForeignRows() {
        val f=AdminControlFixture()
        val session=f.login()
        val prefix="Z_A"
        f.handler={f.reply(f.page(ids=listOf("z_a-02","z_a-03")))}
        val page=f.client.listDevices("z_a-01",session,IdentityScope(),prefix)
        assertEquals(listOf("z_a-02","z_a-03"),page.devices.map {it.device})
        f.verify(f.calls.single(),session,"z_a-01",prefix)
        f.handler={f.reply(f.page(ids=listOf("zBa")))}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY) {f.client.listDevices("",session,IdentityScope(),prefix)}
        val before=f.calls.size
        listOf("%","x.y","x".repeat(65),"А").forEach {
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY) {f.client.listDevices("",session,IdentityScope(),it)}
        }
        assertEquals(before,f.calls.size)
    }
    @Test fun configurationPreservesTheEntireUtf8ReplyAndRejectsMismatchedOuterMetadata() {
        val f=AdminControlFixture();val session=f.login()
        val original=" \n"+f.configuration()+"\n "
        f.handler={f.reply(original)}
        val result=f.client.deviceConfiguration(f.device,session,IdentityScope())
        assertEquals(original,result.wireJson());assertTrue(result.wireJson().contains("синтетика"))
        assertTrue(result.wireJson().contains("opaqueNested"))
        for(changes in listOf(mapOf("device" to JsonPrimitive("foreign-device")),mapOf("currentRevision" to JsonPrimitive(3)),
            mapOf("revision" to JsonPrimitive(-1)),mapOf("hash" to JsonPrimitive("unsafe")),
            mapOf("historical" to JsonPrimitive(true)),mapOf("effective" to JsonNull),mapOf("unknown" to JsonPrimitive(true)))) {
            f.handler={f.reply(f.changed(f.configuration(),changes))}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.deviceConfiguration(f.device,session,IdentityScope())}
        }
        f.handler={f.reply(f.unassigned())}
        assertEquals("unassigned",f.client.deviceConfiguration(f.device,session,IdentityScope()).state)
        f.handler={f.reply(f.changed(f.configuration(),mapOf("state" to JsonPrimitive("expired"))))}
        assertEquals("expired",f.client.deviceConfiguration(f.device,session,IdentityScope()).state)
        f.handler={f.reply(f.page(report=JsonObject(f.activation()+mapOf("state" to JsonPrimitive("historical"),
            "policyRevision" to JsonPrimitive(9),"activePolicyRevision" to JsonPrimitive(9)))))}
        assertEquals(9L,f.client.listDevices("",session,IdentityScope()).devices.single().report.policyRevision)
        f.handler={f.reply(f.page(report=buildJsonObject {put("state","awaiting_report");put("activePolicyRevision",0)}))}
        assertEquals("awaiting_report",f.client.listDevices("",session,IdentityScope()).devices.single().report.state)
    }
    @Test fun runtimeReadsValidateRequestedIdentityReportClockAndRecentStaleNoneSemantics() {
        val f=AdminControlFixture();val session=f.login()
        f.handler={f.reply(f.runtime("none"))}
        assertNull(f.client.deviceRuntime(f.device,session,IdentityScope()).report)
        f.handler={f.reply(f.runtime("stale"))}
        assertEquals("stale",f.client.deviceRuntime(f.device,session,IdentityScope()).state)
        for(wire in listOf(f.changed(f.runtime(),mapOf("device" to JsonPrimitive("foreign"))),
            f.changed(f.runtime(),mapOf("state" to JsonPrimitive("none"))),
            f.changed(f.runtime("none"),mapOf("state" to JsonPrimitive("recent"))),
            f.changed(f.runtime(),mapOf("report" to JsonNull)),
            f.runtime(reportChanges=mapOf("sampledAtMs" to JsonPrimitive(f.oauth.wall+31_000))),
            f.runtime(reportChanges=mapOf("engineKnown" to JsonPrimitive(false))),
            f.runtime(reportChanges=mapOf("sequence" to JsonPrimitive("1"))),
            f.changed(f.runtime(),mapOf("observedAtMs" to JsonPrimitive(f.oauth.wall+60_000))))) {
            f.handler={f.reply(wire)}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.deviceRuntime(f.device,session,IdentityScope())}
        }
    }
    @Test fun expiredAccessCannotUseAnOtherwiseLiveRefreshFamilyOrStartAHiddenRefresh() {
        val f=AdminControlFixture(lifetime=2_000_000);val session=f.login();val oauth=f.oauth.calls.size
        f.oauth.elapsed=session.accessUntilElapsedMs
        assertTrue(session.sessionUntilElapsedMs>f.oauth.elapsed);assertTrue(session.available())
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.listDevices("",session,IdentityScope())}
        assertTrue(f.calls.isEmpty());assertEquals(oauth,f.oauth.calls.size)
        f.oauth.elapsed=session.sessionUntilElapsedMs
        AdminAuthFixture.failure(AdminFailure.SESSION_EXPIRED){f.client.deviceConfiguration(f.device,session,IdentityScope())}
        assertTrue(f.calls.isEmpty())
    }
    @Test fun foreignKeyBootClockLogoutConsumedAndUnguardedOwnersCannotSendControlRequests() {
        for(mode in 0..5) {
            val f=AdminControlFixture();val session=f.login()
            when(mode) {
                0->f.publicOverride=AdminControlFixture.ec().public as ECPublicKey
                1->f.oauth.boot++
                2->f.oauth.elapsed--
                3->f.client.logout(session)
                4->assertTrue(session.consume())
                5->{f.oauth.elapsed=session.accessUntilElapsedMs-1000;f.signHook={f.oauth.elapsed=session.accessUntilElapsedMs}}
            }
            AdminAuthFixture.failure(if(mode==0)AdminFailure.INVALID_REPLY else AdminFailure.REAUTHENTICATE) {
                f.client.deviceRuntime(f.device,session,IdentityScope())
            }
            assertTrue(f.calls.isEmpty())
        }
        val f=AdminControlFixture();val session=f.login();val foreign=AdminControlFixture()
        foreign.client.discover(IdentityScope())
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){foreign.client.listDevices("",session,IdentityScope())}
        assertTrue(foreign.calls.isEmpty())
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.oauth.client.listDevices("",session,IdentityScope())}
        assertTrue(f.calls.isEmpty())
    }
    @Test fun revokedTrustDuringSigningOrResponseCannotDispatchOrPublishARead() {
        val f=AdminControlFixture();val session=f.login();f.signHook={f.enabled=false}
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.deviceRuntime(f.device,session,IdentityScope())}
        assertTrue(f.calls.isEmpty());assertTrue(session.available())
        val late=AdminControlFixture();val current=late.login()
        late.handler={late.reply(late.runtime()).also {late.enabled=false}}
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){late.client.deviceRuntime(late.device,current,IdentityScope())}
        assertEquals(1,late.calls.size);assertTrue(current.available())
    }
    @Test fun cancellationAndLogoutDuringReadNeverPublishDataOrConsumeRefreshOwnership() {
        val f=AdminControlFixture();val session=f.login();val signed=f.signatures
        val cancelled=IdentityScope().apply {cancel()}
        AdminAuthFixture.failure(AdminFailure.CANCELLED){f.client.listDevices("",session,cancelled)}
        assertTrue(f.calls.isEmpty());assertEquals(signed,f.signatures);assertTrue(session.available())
        val late=IdentityScope();f.handler={f.reply(f.runtime()).also {late.cancel()}}
        AdminAuthFixture.failure(AdminFailure.CANCELLED){f.client.deviceRuntime(f.device,session,late)}
        assertTrue(session.available())
        f.handler={f.reply(f.runtime()).also {f.client.logout(session)}}
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.deviceRuntime(f.device,session,IdentityScope())}
        assertFalse(session.available())
    }
    @Test fun finiteServerErrorsAndDpopNonceChallengesNeverRetryOrRotateTokens() {
        val f=AdminControlFixture();val session=f.login();val oauth=f.oauth.calls.size
        for((status,reason) in listOf(401 to AdminFailure.REAUTHENTICATE,403 to AdminFailure.ACCESS_DENIED,
            503 to AdminFailure.TRANSPORT,400 to AdminFailure.INVALID_REPLY,302 to AdminFailure.INVALID_REPLY,429 to AdminFailure.INVALID_REPLY)) {
            val count=f.calls.size
            f.handler={f.reply("""{"error":"use_dpop_nonce"}""",status,mapOf("dpop-nonce" to listOf("synthetic-control-nonce")))}
            AdminAuthFixture.failure(reason){f.client.listDevices("",session,IdentityScope())}
            assertEquals(count+1,f.calls.size);assertTrue(session.available());assertEquals(oauth,f.oauth.calls.size)
        }
        f.handler={throw DeliveryException(DeliveryFailure.TRANSPORT)}
        AdminAuthFixture.failure(AdminFailure.TRANSPORT){f.client.listDevices("",session,IdentityScope())}
        assertTrue(session.available())
    }
    @Test fun replyBoundsDuplicateJsonWrongContentAndStaleDatesCannotReachThePrivateMailbox() {
        val f=AdminControlFixture();val session=f.login()
        val cases=listOf(f.reply("x".repeat(32_769)),f.reply(""),f.reply("[]"),
            f.reply("""{"devices":[],"devices":[],"next":"","observedAtMs":${f.oauth.wall}}"""),
            f.reply(f.page(),headers=mapOf("content-type" to listOf("text/html"))),
            f.reply(f.page(),at=f.oauth.wall-60_000))
        for(reply in cases) {
            f.handler={reply}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.listDevices("",session,IdentityScope())}
        }
        f.handler={f.reply("x".repeat(524_289))}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.deviceConfiguration(f.device,session,IdentityScope())}
        f.handler={f.reply("x".repeat(4097))}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.deviceRuntime(f.device,session,IdentityScope())}
    }
    @Test fun newApiClockCanRejectAccessButCannotExtendLeaseOrRollBackItsAcceptedFloor() {
        val f=AdminControlFixture();val session=f.login();val deadline=session.accessUntilElapsedMs
        f.oauth.elapsed=deadline-5000
        f.handler={f.reply(f.page(),at=f.oauth.wall+10_000)}
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.listDevices("",session,IdentityScope())}
        assertEquals(deadline,session.accessUntilElapsedMs);assertTrue(session.available())
        val stable=AdminControlFixture();val current=stable.login()
        stable.handler={stable.reply(stable.page(),at=stable.oauth.wall+10_000)}
        stable.client.listDevices("",current,IdentityScope())
        stable.handler={stable.reply(stable.page())}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){stable.client.listDevices("",current,IdentityScope())}
        assertTrue(current.available())
        val known=AdminControlFixture();val previous=known.login()
        known.oauth.elapsed=previous.accessUntilElapsedMs-20_000
        known.handler={known.reply(known.page(),at=known.oauth.wall+10_000)}
        known.client.listDevices("",previous,IdentityScope())
        known.oauth.elapsed+=10_000
        val calls=known.calls.size
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){known.client.listDevices("",previous,IdentityScope())}
        assertEquals(calls,known.calls.size);assertTrue(previous.available())
    }
    @Test fun configurationInventoryAcceptsWideLayersAnd4096EffectiveOriginsWithoutTruncation() {
        val f=AdminControlFixture();val session=f.login();val base=Identity.objectJSON(f.configuration())
        // Go-shaped layer/permission/origin data; this exercises the actual authenticated reader, not publication compilation.
        fun wide(width:Int):String {
            val origin=buildJsonObject {put("layerId","t");put("kind","template");put("revision",1)}
            fun path(index:Int)=if(width>512)"/s/g${index/256}/k${index%256}" else "/s/k$index"
            val settings=if(width>512)buildJsonObject {
                for(group in 0 until (width+255)/256)put("g$group",buildJsonObject {
                    for(index in group*256 until minOf(width,(group+1)*256))put("k${index%256}",index)
                })
            } else buildJsonObject {repeat(width){put("k$it",it)}}
            val changes=if(width>512)JsonArray(listOf(buildJsonObject {put("path","/s");put("operation","set");put("value",settings)}))
                else JsonArray((0 until width).map {buildJsonObject {put("path",path(it));put("operation","set");put("value",it)}})
            val permissions=(0 until minOf(width,256)).map {buildJsonObject {put("path",path(it));put("mode","locked")}}
            val layer=buildJsonObject {
                put("id","t");put("kind","template");put("priority",0);put("revision",1)
                put("changes",changes);put("permissions",JsonArray(permissions))
            }
            val effective=buildJsonObject {
                put("document",buildJsonObject {put("s",settings)})
                put("fields",buildJsonObject {repeat(width){put(path(it),origin)}})
                put("restrictions",JsonArray(permissions.map {buildJsonObject {put("permission",it);put("origin",origin)}}))
            }
            return Canonical.encode(JsonObject(base+mapOf("layers" to JsonArray(listOf(layer)),"effective" to effective)))
        }
        for(width in listOf(129,256,4096)) {
            val wire=wide(width)
            assertTrue(wire.toByteArray(Charsets.UTF_8).size<=524_288)
            assertThrows(Exception::class.java){Canonical.parse(wire)}
            f.handler={f.reply(wire)}
            val result=f.client.deviceConfiguration(f.device,session,IdentityScope())
            assertEquals(wire,result.wireJson());assertEquals(f.device,result.device)
            val tree=AdminControlJson.parse(result.wireJson()).jsonObject
            assertEquals(width,tree.getValue("effective").jsonObject.getValue("fields").jsonObject.size)
            val returnedLayer=tree.getValue("layers").jsonArray.single().jsonObject
            assertEquals(if(width>512)1 else width,returnedLayer.getValue("changes").jsonArray.size)
            assertEquals(minOf(width,256),returnedLayer.getValue("permissions").jsonArray.size)
            f.verify(f.calls.last(),session)
        }
        val overflow=wide(4097);assertTrue(overflow.toByteArray(Charsets.UTF_8).size<=524_288)
        f.handler={f.reply(overflow)}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.deviceConfiguration(f.device,session,IdentityScope())}
        assertTrue(session.available())
    }
    @Test fun configurationJsonKeepsExactBoundsGrammarAndUnrelatedParserLimits() {
        fun members(count:Int)= (0 until count).joinToString(",","{","}"){"\"k$it\":0"}
        fun items(count:Int)=(0 until count).joinToString(",","[","]"){"0"}
        assertEquals(512,AdminControlJson.parse(members(512)).jsonObject.size)
        assertEquals(512,AdminControlJson.parse(items(512)).jsonArray.size)
        for(invalid in listOf(members(513),items(513)))assertThrows(Exception::class.java){AdminControlJson.parse(invalid)}
        val origin="""{"layerId":"t","kind":"template","revision":1}"""
        fun origins(count:Int)=(0 until count).joinToString(",","{","}"){"\"/s/k$it\":$origin"}
        val fields=origins(4096);val exact="""{"effective":{"fields":$fields}}"""
        assertEquals(4096,AdminControlJson.parse(exact).jsonObject.getValue("effective").jsonObject.getValue("fields").jsonObject.size)
        for(invalid in listOf("""{"effective":{"fields":${origins(4097)}}}""", """{"x":$exact}""",
            """{"effective":{"x":{"fields":$fields}}}""", """{"effective":{"fields":{"nested":$fields}}}""",
            """{"effective":[{"fields":$fields}]}""", """{"Effective":{"fields":$fields}}""", "[$exact]")) {
            assertThrows(Exception::class.java){AdminControlJson.parse(invalid)}
        }
        val ordinaryObject=members(65);val ordinaryArray="""{"items":${items(129)}}"""
        for(wide in listOf(ordinaryObject,ordinaryArray)) {
            assertNotNull(AdminControl.objectReply(wide,AdminControl.Read.CONFIGURATION))
            assertThrows(Exception::class.java){Canonical.parse(wide)}
            for(read in listOf(AdminControl.Read.DEVICES,AdminControl.Read.RUNTIME)) {
                assertThrows(Exception::class.java){AdminControl.objectReply(wide,read)}
            }
        }
        val depth24="[".repeat(24)+"0"+"]".repeat(24)
        assertEquals(Canonical.parse(depth24),AdminControlJson.parse(depth24))
        assertThrows(Exception::class.java){AdminControlJson.parse("[$depth24]")}
        val whitespace="{}".padEnd(524_288,' ')
        assertEquals(0,AdminControlJson.parse(whitespace).jsonObject.size)
        assertThrows(Exception::class.java){AdminControlJson.parse(whitespace+" ")}
        val unicode="{\"s\":\""+"é".repeat((524_288-8)/2)+"\"}"
        assertEquals(524_288,unicode.toByteArray(Charsets.UTF_8).size)
        assertEquals(Canonical.parse(unicode),AdminControlJson.parse(unicode))
        assertThrows(Exception::class.java){AdminControlJson.parse(unicode.dropLast(2)+"é\"}")}
        val profile=Canonical.encode(buildJsonObject {
            put("values",JsonArray(listOf(JsonPrimitive(true),JsonPrimitive(false),JsonNull,JsonPrimitive(0),
                JsonPrimitive(9_007_199_254_740_991L),JsonPrimitive(-9_007_199_254_740_991L))))
            put("control",0.toChar().toString());put("pair",String(charArrayOf(0xd83d.toChar(),0xde00.toChar())))
            put("escaped","\\\"")
        })
        assertEquals(Canonical.parse(profile),AdminControlJson.parse(profile))
        assertEquals(Canonical.parse("-0"),AdminControlJson.parse("-0"))
        val invalid=listOf("", "{}{}", "{} true", "[1,]", "{\"a\":1,}", "01", "-01", "+1", "1.0", "1e0", "NaN", "Infinity",
            "9007199254740992", "-9007199254740992", "9".repeat(100), "-", "\"unterminated", "\"\\", "tru", "fals", "nul",
            "{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}", "{\"s\":\"\\uD800\"}", "{\"s\":\"\\uDC00\"}",
            "{\"s\":\"\\x\"}", "{\"s\":\"\\u00\"}", "{\"s\":\"\n\"}", "{\"s\":\""+0xd800.toChar()+"\"}", "{\"s\":\""+0xdc00.toChar()+"\"}")
        for(raw in invalid) {
            assertThrows(Exception::class.java){Canonical.parse(raw)}
            assertThrows(Exception::class.java){AdminControlJson.parse(raw)}
        }
    }
}

/** Generated signed discovery/JWTs and injected transport. No live browser, server ACL or device evidence. */
internal class AdminControlFixture(lifetime:Long=3600) {
    data class Call(val method:String,val url:String,val headers:Map<String,String>,val body:ByteArray?,val max:Int)
    val oauth=AdminAuthFixture()
    val device="synthetic-device"
    private val offline=ec()
    private val anchor=TrustAnchor("synthetic-control-root",Base64.getEncoder().encodeToString(offline.public.encoded),1)
    private val online=Base64.getEncoder().encodeToString(ec().public.encoded)
    private val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"synthetic-service",
        "https://device-id.example.invalid/realms/device","syn443-android","https://device-api.example.invalid",
        mapOf("synthetic-online" to online),oauth.wall/1000,oauth.wall/1000,oauth.wall/1000+lifetime,adminBootstrap=oauth.metadata)
    private val raw=run {
        val header="""{"alg":"ES256","kid":"${anchor.id}","typ":"syn443-bootstrap+jws"}"""
        val payload=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(descriptor)))
        val input=Identity.encode(header.toByteArray())+"."+Identity.encode(payload.toByteArray())
        val signature=Signature.getInstance("SHA256withECDSA").run {initSign(offline.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
        input+"."+Identity.encode(Identity.derToRaw(signature))
    }
    private val floor=BootstrapTrust.descriptor(raw,anchor,ServiceFloor(),oauth.wall/1000).second
    private val expected=Bootstrap(descriptor.serviceId,descriptor.issuer,descriptor.clientId,descriptor.apiOrigin,descriptor.roots)
    var enabled=true
    var publicOverride:ECPublicKey?=null
    var signHook:(()->Unit)?=null
    var signatures=0
    private val key=object:ProofKey {
        override val publicKey:ECPublicKey get()=publicOverride?:oauth.key.publicKey
        override fun sign(input:ByteArray)=oauth.key.sign(input).also {signatures++;signHook?.invoke()}
    }
    val calls=mutableListOf<Call>()
    var lastWire=""
    var handler:(Call)->Reply={call->
        val action=Identity.objectJSON(checkNotNull(call.body).decodeToString()).getValue("action").jsonPrimitive.content
        reply(when(action){"configuration.devices.list"->page();"configuration.inventory.get"->configuration();else->runtime()})
    }
    private val exchange=IdentityExchange {method,url,headers,body,scope,max->
        if(url==oauth.metadata.apiOrigin+AdminControl.PATH) {
            val call=Call(method,url,headers.toMap(),body?.copyOf(),max);calls+=call
            handler(call).also {lastWire=it.body.decodeToString()}
        } else oauth.exchange.request(method,url,headers,body,scope,max)
    }
    val client=AdminProtocol.fromDiscovery({if(enabled)BootstrapTrust.adminDiscovery(raw,anchor,floor,expected,oauth.wall/1000) else null},
        key,exchange,{oauth.boot},{oauth.elapsed})
    private val pending=client.newPending(7)
    init {oauth.handler={call->if(call.url.endsWith("/token"))oauth.tokens(idChanges=mapOf("nonce" to JsonPrimitive(pending.nonce))) else oauth.normal(call)}}
    fun login():AdminSession {
        val issuer=client.discover(IdentityScope())
        return client.exchangeCallback(AdminBootstrap.CALLBACK+"?"+Identity.form(linkedMapOf(
            "code" to "synthetic-code","state" to pending.state,"iss" to oauth.metadata.issuer)),pending,7,issuer,IdentityScope())
    }
    fun claims(call:Call)=Identity.objectJSON(Policy.utf8(Policy.decode64(call.headers.getValue("DPoP").split('.')[1])))
    fun verify(call:Call,session:AdminSession,after:String="",prefix:String="") {
        assertEquals("POST",call.method);assertEquals(oauth.metadata.apiOrigin+AdminControl.PATH,call.url)
        assertEquals("application/json",call.headers["Content-Type"]);assertEquals("DPoP "+session.accessToken,call.headers["Authorization"])
        assertFalse(call.headers.keys.any {it.equals("origin",true)})
        val body=checkNotNull(call.body);val envelope=Identity.objectJSON(body.decodeToString())
        assertEquals(setOf("version","requestId","action","payload"),envelope.keys)
        assertEquals(1,envelope.getValue("version").jsonPrimitive.int);assertTrue(AdminIdentity.digest(envelope.getValue("requestId").jsonPrimitive.content))
        val action=envelope.getValue("action").jsonPrimitive.content
        val payload=envelope.getValue("payload").jsonObject
        val expected=buildJsonObject {
            if(action=="configuration.devices.list") {
                put("after",after)
                if(prefix.isNotEmpty())put("prefix",prefix)
            } else put("id",device)
        }
        assertEquals(expected,payload)
        assertEquals(if(action=="configuration.devices.list")32_768 else if(action=="configuration.inventory.get")524_288 else 4096,call.max)
        val raw=call.headers.getValue("DPoP").split('.')
        val header=Identity.objectJSON(Policy.utf8(Policy.decode64(raw[0])))
        assertEquals(setOf("alg","typ","jwk"),header.keys);assertEquals("ES256",header.getValue("alg").jsonPrimitive.content)
        assertEquals("dpop+jwt",header.getValue("typ").jsonPrimitive.content)
        assertEquals(Identity.jwk(oauth.key.publicKey),header["jwk"])
        val proof=claims(call)
        assertEquals(call.url,proof.getValue("htu").jsonPrimitive.content);assertEquals("POST",proof.getValue("htm").jsonPrimitive.content)
        assertEquals(Identity.hash(body),proof.getValue("req_hash").jsonPrimitive.content)
        assertEquals(Identity.hash(session.accessToken.toByteArray(Charsets.US_ASCII)),proof.getValue("ath").jsonPrimitive.content)
        assertFalse("nonce" in proof);assertTrue(AdminIdentity.digest(proof.getValue("jti").jsonPrimitive.content))
        assertTrue(proof.getValue("iat").jsonPrimitive.long in (oauth.wall/1000-30)..(oauth.wall/1000+30))
        val signature=Policy.decode64(raw[2]);assertEquals(64,signature.size)
        fun integer(bytes:ByteArray):ByteArray {val value=BigInteger(1,bytes).toByteArray();return byteArrayOf(2,value.size.toByte())+value}
        val values=integer(signature.copyOfRange(0,32))+integer(signature.copyOfRange(32,64))
        assertTrue(Signature.getInstance("SHA256withECDSA").run {initVerify(oauth.key.publicKey);update((raw[0]+"."+raw[1]).toByteArray(Charsets.US_ASCII));verify(byteArrayOf(0x30,values.size.toByte())+values)})
    }
    fun changed(raw:String,fields:Map<String,JsonElement>)=Canonical.encode(JsonObject(Identity.objectJSON(raw)+fields))
    fun activation()=buildJsonObject {
        put("state","reported");put("policyRevision",4);put("outcome","committed");put("activePolicyRevision",4);put("receivedAtMs",oauth.wall-500)
    }
    fun page(ids:List<String> = listOf(device),next:String="",report:JsonObject=activation())=Canonical.encode(buildJsonObject {
        put("devices",JsonArray(ids.map {buildJsonObject {put("device",it);put("policyRevision",4);put("desiredRevision",2);put("report",report)}}))
        put("next",next);put("observedAtMs",oauth.wall)
    })
    fun configuration()=Canonical.encode(buildJsonObject {
        put("device",device);put("owner","synthetic-owner");put("state","assigned");put("revision",2);put("hash","a".repeat(64))
        put("policyRevision",4);put("mode","wifi");put("approvalUntilMs",oauth.wall+600_000);put("currentRevision",2)
        put("publicationSource","matches_desired");put("activation",activation())
        put("layers",JsonArray(listOf(buildJsonObject {
            put("id","synthetic-layer");put("kind","device");put("priority",0);put("revision",1)
            put("changes",JsonArray(listOf(buildJsonObject {
                put("path","/display");put("operation","set");put("value",buildJsonObject {put("opaqueNested",buildJsonObject {put("label","синтетика")})})
            })));put("permissions",JsonArray(emptyList()))
        })))
        put("effective",buildJsonObject {put("document",buildJsonObject {put("opaqueNested","retained")});put("fields",buildJsonObject {});put("restrictions",JsonArray(emptyList()))})
        put("issuedSettings",buildJsonObject {put("revision",4);put("opaqueNested","retained")})
    })
    fun unassigned()=Canonical.encode(buildJsonObject {
        put("device",device);put("owner","synthetic-owner");put("state","unassigned");put("revision",0);put("hash","")
        put("policyRevision",0);put("mode","");put("approvalUntilMs",0);put("layers",JsonArray(emptyList()));put("currentRevision",0)
        put("publicationSource","not_issued");put("activation",buildJsonObject {put("state","not_issued");put("activePolicyRevision",0)})
    })
    fun runtime(state:String="recent",reportChanges:Map<String,JsonElement> = emptyMap()):String=Canonical.encode(buildJsonObject {
        put("device",device);put("observedAtMs",oauth.wall);put("state",state)
        if(state!="none")put("report",JsonObject(buildJsonObject {
            val age=if(state=="stale")200_000 else 1000
            put("version",1);put("sequence",9);put("build",86);put("phase","online");put("policyRevision",4)
            put("engineKnown",true);put("engineActive",true);put("network","wifi");put("sampledAtMs",oauth.wall-age);put("receivedAtMs",oauth.wall-age+500)
        }+reportChanges))
    })
    fun reply(wire:String,status:Int=200,headers:Map<String,List<String>> = emptyMap(),at:Long=oauth.wall)=
        Reply(status,mapOf("content-type" to listOf("application/json"),"date" to listOf(AdminAuthFixture.date(at)))+headers,wire.toByteArray(Charsets.UTF_8))
    companion object {
        fun ec()=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
    }
}
