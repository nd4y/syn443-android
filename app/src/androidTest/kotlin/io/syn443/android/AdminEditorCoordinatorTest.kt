package io.syn443.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.admin.*
import io.syn443.android.vpn.*
import io.syn443.identity.*
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.Closeable
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Real isolated AES/AtomicFile plus signed synthetic OIDC/DPoP/core protocol.
 * Synthetic server receipts prove coordinator handling, not live ACL/MFA,
 * actual server publication, browser authentication or VPN activation. */
class AdminEditorCoordinatorTest {
    private class Fixture(sharedStorage:Fixture?=null):Closeable {
        val context=ApplicationProvider.getApplicationContext<Context>()
        val namespace:String=sharedStorage?.namespace ?:"admin-editor-test-"+UUID.randomUUID().toString().replace("-","")
        val alias:String=sharedStorage?.alias ?:"syn443-admin-editor-test-"+Identity.random()
        private val ownsStorage=sharedStorage==null
        val directory=File(context.noBackupFilesDir,namespace)
        val executor=Executors.newSingleThreadExecutor()
        val busy=AtomicBoolean()
        var now=1000L
        var boot=4
        var enabled=true
        var queuePreview=false
        var queuePublish=false
        var desiredRevision=2L
        var loseNext=false
        var revokeNext=false
        var failList=false
        var rejectPreview=""
        var device="device-a"
        val owner=Identity.hash("synthetic-device-owner".toByteArray())
        val baseHash="a".repeat(64)
        val calls=mutableListOf<AdminLayerAction>()
        val requestedDevices=mutableListOf<String>()
        val sent=mutableListOf<Pair<String,ByteArray>>()
        val originals=mutableMapOf<String,Pair<String,String>>()
        val terminals=mutableMapOf<String,String>()
        var saved:JSONObject?=null
        private val offline=ec()
        private val online=ec()
        private val proof=ec()
        private val metadata=AdminBootstrap("https://coordinator-id.example.invalid/realms/control",AdminBootstrap.CLIENT_ID,AdminBootstrap.AUDIENCE,
            "https://coordinator-api.example.invalid",AdminBootstrap.ASSURANCE_ACR)
        private val anchor=TrustAnchor("coordinator-root",Base64.getEncoder().encodeToString(offline.public.encoded),1)
        private val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"coordinator-service",
            "https://device-id.example.invalid/realms/device","syn443-android","https://device-api.example.invalid",
            mapOf("online" to Base64.getEncoder().encodeToString(online.public.encoded)),WALL/1000,WALL/1000,WALL/1000+86_400,adminBootstrap=metadata)
        private val manifest=signManifest(descriptor,anchor,offline)
        private val floor=BootstrapTrust.descriptor(manifest,anchor,ServiceFloor(),WALL/1000).second
        private val projected=Bootstrap(descriptor.serviceId,descriptor.issuer,descriptor.clientId,descriptor.apiOrigin,descriptor.roots)
        private lateinit var protocol:AdminProtocol
        private lateinit var session:AdminSession
        private lateinit var pending:AdminPending
        private var subject="synthetic-admin"
        private var loginGeneration=0L
        var coordinator:AdminEditorCoordinator
        val wall get()=WALL+now-1000
        val key=object:ProofKey {
            override val publicKey=proof.public as ECPublicKey
            override fun sign(input:ByteArray)=Signature.getInstance("SHA256withECDSA").run {initSign(proof.private);update(input);sign()}
        }
        val access=object:AdminEditorCoordinator.Access {
            override fun check(){if(!enabled)throw AdminException(AdminFailure.REAUTHENTICATE)}
            override fun ownership()=protocol.layerOwnership(session)
            override fun reviewDeadline(preview:AdminLayerPreview)=protocol.layerReviewDeadline(preview,session)
            override fun action(request:AdminLayerRequest):AdminLayerReply {
                calls+=request.action
                return protocol.layerAction(request,session,IdentityScope())
            }
        }
        init {
            assumeTrue(BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
            coordinator=newCoordinator()
            worker {
                protocol=AdminProtocol.fromDiscovery({if(enabled)BootstrapTrust.adminDiscovery(manifest,anchor,floor,projected,wall/1000) else null},key,
                    IdentityExchange {method,url,headers,body,_,_->
                        assertTrue(headers.keys.none {it.equals("Origin",true)})
                        if(url==metadata.apiOrigin+"/v1/control/action") {
                            assertEquals("POST",method);assertTrue(headers.getValue("Authorization").startsWith("DPoP "))
                            val raw=checkNotNull(body);val claims=Canonical.parse(Policy.utf8(Policy.decode64(headers.getValue("DPoP").split('.')[1]))).jsonObject
                            assertEquals(Identity.hash(raw),claims.getValue("req_hash").jsonPrimitive.content)
                            val result=control(Policy.utf8(raw))
                            if(revokeNext){revokeNext=false;enabled=false}
                            if(loseNext){loseNext=false;throw AdminException(AdminFailure.TRANSPORT)}
                            reply(result)
                        } else when {
                            url.endsWith("/.well-known/openid-configuration")->reply(Canonical.encode(buildJsonObject {
                                val base=metadata.issuer+"/protocol/openid-connect"
                                put("issuer",metadata.issuer);put("authorization_endpoint",base+"/auth");put("token_endpoint",base+"/token");put("jwks_uri",base+"/certs")
                                put("id_token_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("RS256"))))
                                put("dpop_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("ES256"))))
                                put("code_challenge_methods_supported",JsonArray(listOf(JsonPrimitive("S256"))))
                            }))
                            url.endsWith("/certs")->reply(Canonical.encode(buildJsonObject {put("keys",JsonArray(listOf(buildJsonObject {
                                put("kty","RSA");put("kid","coordinator-rsa");put("use","sig");put("alg","RS256");put("n",unsigned((rsa.public as RSAPublicKey).modulus));put("e","AQAB")
                            })))}))
                            url.endsWith("/token")->tokens()
                            else->throw AssertionError("unexpected synthetic origin/path")
                        }
                    },{boot},{now})
                authenticate()
            }
        }
        fun newCoordinator()=AdminEditorCoordinator({store()},{boot},{now})
        fun store()=AdminEditorStore.isolatedForTest(context,namespace,alias)
        fun <T> worker(action:()->T):T {
            check(busy.compareAndSet(false,true))
            return executor.submit<T> {try {action()}finally {busy.set(false)}}.get(30,TimeUnit.SECONDS)
        }
        fun run(kind:AdminEditorCoordinator.Kind,model:AdminEditorModel?=null,pages:List<String> = emptyList(),binding:String?=null,revision:Long?=null):AdminEditorModel=worker {
            coordinator.execute(AdminEditorCoordinator.Command(kind,model?.device?:device,binding?:model?.documentBinding?:"",revision?:model?.localRevision?:0,
                pages,model?.reviewBinding?:"",model?.reviewDeadlineElapsed?:0),access)
        }
        fun record()=worker {val o=protocol.layerOwnership(session);checkNotNull(store().recoverOwned(o.serviceHash,o.actor))}
        private fun authenticate() {
            val issuer=protocol.discover(IdentityScope());loginGeneration++
            pending=protocol.newPending(loginGeneration);protocol.authorization(pending,loginGeneration)
            session=protocol.exchangeCallback(AdminBootstrap.CALLBACK+"?"+Identity.form(linkedMapOf("code" to "synthetic-code","state" to pending.state,"iss" to metadata.issuer)),
                pending,loginGeneration,issuer,IdentityScope())
        }
        fun loginAs(nextSubject:String)=worker {
            protocol.logout(session);subject=nextSubject;authenticate()
            coordinator=newCoordinator() // Production retirement replaces its RAM coordinator too.
        }
        private fun tokens():Reply {
            fun jwt(id:Boolean):String {
                val payload=buildJsonObject {
                    put("iss",metadata.issuer);put("sub",subject);put("aud",if(id)AdminBootstrap.CLIENT_ID else AdminBootstrap.AUDIENCE);put("azp",AdminBootstrap.CLIENT_ID)
                    put("iat",wall/1000);put("exp",wall/1000+300);put("jti",Identity.random())
                    if(id){put("nonce",pending.nonce);put("auth_time",wall/1000)}else {put("scope",AdminBootstrap.SCOPE);put("cnf",buildJsonObject {put("jkt",Identity.thumbprint(key.publicKey))})}
                }
                val input=Identity.encode("""{"alg":"RS256","kid":"coordinator-rsa","typ":"JWT"}""".toByteArray())+"."+Identity.encode(Canonical.encode(payload).toByteArray())
                return input+"."+Identity.encode(Signature.getInstance("SHA256withRSA").run {initSign(rsa.private);update(input.toByteArray(Charsets.US_ASCII));sign()})
            }
            return reply(Canonical.encode(buildJsonObject {put("token_type","DPoP");put("access_token",jwt(false));put("refresh_token",Identity.random());put("id_token",jwt(true))
                put("expires_in",300);put("refresh_expires_in",86_400);put("scope",AdminBootstrap.SCOPE)}))
        }
        private fun reply(text:String)=Reply(200,mapOf("content-type" to listOf("application/json"),"date" to listOf(date(wall))),text.toByteArray(Charsets.UTF_8))
        private fun inventory()="""{"device":"$device","owner":"$owner","state":"assigned","revision":$desiredRevision,"hash":"$baseHash","policyRevision":0,"mode":"wifi","approvalUntilMs":${WALL+3_600_000},"layers":[{"id":"template-a","kind":"template","priority":0,"revision":1,"changes":[{"path":"/schemaVersion","operation":"set","value":1}],"permissions":[{"path":"/schemaVersion","mode":"free"}]},{"id":"$device","kind":"device","priority":0,"revision":1,"changes":[],"permissions":[]}],"effective":{"document":{"schemaVersion":1},"fields":{"/schemaVersion":{"layerId":"template-a","kind":"template","revision":1}},"restrictions":[]},"currentRevision":$desiredRevision}"""
        private fun ready(request:JSONObject):String {
            val p=request.getJSONObject("payload").getJSONObject("proposal");val o=protocol.layerOwnership(session);val id=Identity.hash((o.actor+"\u0000"+request.getString("requestId")).toByteArray())
            val b=p.getJSONArray("bundles").getJSONObject(0)
            val v=JSONObject().put("schemaVersion",1).put("origin",o.apiOrigin).put("actor",o.actor).put("requestId",request.getString("requestId"))
                .put("draftId",p.getString("draftId")).put("draftRevision",p.getLong("draftRevision")).put("draftHash","c".repeat(64))
                .put("targetKind","device").put("targetId",device).put("mode",p.getString("mode")).put("dependencyHash","d".repeat(64)).put("effectiveHash","e".repeat(64))
                .put("recipients",JSONArray().put(JSONObject().put("owner",owner).put("device",device).put("thumbprint",Identity.hash("phone-key".toByteArray()))
                    .put("grantHash",Identity.hash("grant".toByteArray())).put("baseRevision",b.getLong("baseRevision")).put("baseHash",b.getString("baseHash")).put("capabilitiesHash","b".repeat(64))))
                .put("issuedAtMs",wall).put("expiresAtMs",wall+120_000)
            val message=Identity.encode("""{"alg":"ES256","typ":"syn443-configuration-preview+jws","kid":"synthetic-preview"}""".toByteArray())+"."+Identity.encode(v.toString().toByteArray())
            val ticket=message+"."+Identity.encode(Identity.derToRaw(Signature.getInstance("SHA256withECDSA").run {initSign(offline.private);update(message.toByteArray(Charsets.US_ASCII));sign()}))
            return JSONObject().put("id",id).put("state","ready").put("result",JSONObject().put("previewId",id).put("ticket",ticket).put("preview",v)).toString()
        }
        private fun control(raw:String):String {
            val request=JSONObject(raw);val action=request.getString("action");val id=request.getString("requestId");val payload=request.getJSONObject("payload")
            if(action in setOf("configuration.inventory.get","configuration.history.get"))requestedDevices+=payload.getString("id")
            val mutation=action in setOf("configuration.layers.draft.put","configuration.layers.draft.discard","configuration.preview.request","configuration.publish")
            if(mutation) {
                val o=protocol.layerOwnership(session);val durable=checkNotNull(store().recoverOwned(o.serviceHash,o.actor)).pending
                assertNotNull("mutation escaped durable preparation",durable);assertEquals(id,durable!!.requestId);assertArrayEquals(raw.toByteArray(Charsets.UTF_8),durable.body)
                sent+=id to raw.toByteArray(Charsets.UTF_8)
                originals[id]?.let {assertEquals(Identity.hash(raw.toByteArray()),it.first);return it.second}
            }
            val result=when(action) {
                "configuration.inventory.get"->inventory()
                "configuration.history.get"->inventory().replace("\"revision\":$desiredRevision","\"revision\":${payload.getLong("revision")}").dropLast(1)+",\"historical\":true}"
                "configuration.layers.drafts.list"->{if(failList)throw AdminException(AdminFailure.ACCESS_DENIED)
                    JSONObject().put("targetKind","device").put("targetId",device).put("drafts",JSONArray().also {rows->saved?.let {rows.put(JSONObject().put("id",it.getString("id")).put("revision",it.getLong("revision")).put("savedAtMs",it.getLong("savedAtMs")))}}).toString()}
                "configuration.layers.draft.get"->checkNotNull(saved).toString()
                "configuration.layers.draft.put"->{val d=payload.getJSONObject("draft");assertEquals(saved?.getLong("revision")?:0,d.getLong("revision"))
                    saved=JSONObject(d.toString()).put("revision",d.getLong("revision")+1).put("savedAtMs",wall);checkNotNull(saved).toString()}
                "configuration.preview.request"->{val normal=ready(request);val v=JSONObject(normal);val job=v.getString("id")
                    val terminal=if(rejectPreview.isEmpty())normal else JSONObject().put("id",job).put("state","rejected").put("error",rejectPreview).toString();terminals[job]=terminal
                    if(queuePreview)JSONObject().put("id",job).put("state","queued").toString() else terminal}
                "configuration.publish"->{val owned=protocol.layerOwnership(session);val job=Identity.hash((owned.actor+"\u0000"+id).toByteArray())
                    desiredRevision++;val terminal=JSONObject().put("id",job).put("state","published").put("result",JSONObject().put("heads",JSONArray().put(JSONObject().put("device",device).put("revision",desiredRevision).put("hash","c".repeat(64))))).toString()
                    terminals[job]=terminal;if(queuePublish)JSONObject().put("id",job).put("state","queued").toString() else terminal}
                "configuration.request.get"->checkNotNull(terminals[payload.getString("id")])
                else->throw AssertionError("unexpected fixed action")
            }
            if(mutation)originals[id]=Identity.hash(raw.toByteArray()) to result
            return result
        }
        override fun close() {
            check(!busy.get()) {"actual_worker_not_confirmed_idle"}
            try {worker {
                protocol.logout(session)
                if(ownsStorage) {
                    KeyStore.getInstance("AndroidKeyStore").apply {load(null)}.deleteEntry(alias)
                    directory.listFiles()?.forEach {file->check(file.name in setOf("editor.bin","editor.bin.bak","editor.bin.new"));check(file.isFile && file.delete())}
                    check(!directory.exists() || directory.delete())
                }
            }}finally {executor.shutdown();check(executor.awaitTermination(5,TimeUnit.SECONDS))}
        }
    }
    companion object {
        private const val WALL=1_800_000_000_000L
        private val rsa:KeyPair by lazy {KeyPairGenerator.getInstance("RSA").apply {initialize(2048)}.generateKeyPair()}
        private fun ec()=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private fun unsigned(value:BigInteger)=Identity.encode(value.toByteArray().let {if(it[0]==0.toByte())it.copyOfRange(1,it.size) else it})
        private fun date(value:Long)=DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'",Locale.US).withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(value))
        private fun signManifest(value:ServiceDescriptor,anchor:TrustAnchor,key:KeyPair):String {
            val header=Canonical.encode(buildJsonObject {put("alg","ES256");put("kid",anchor.id);put("typ","syn443-bootstrap+jws")})
            val input=Identity.encode(header.toByteArray())+"."+Identity.encode(Canonical.encode(Canonical.parse(Canonical.json.encodeToString(value))).toByteArray())
            return input+"."+Identity.encode(Identity.derToRaw(Signature.getInstance("SHA256withECDSA").run {initSign(key.private);update(input.toByteArray(Charsets.US_ASCII));sign()}))
        }
    }

    @Test fun actualEncryptedEditorCompletesExplicitSavePreviewPublishWithFourRevisionDomainsSeparate() {
        Fixture().use {f->
            var m=f.run(AdminEditorCoordinator.Kind.OPEN);assertEquals(AdminEditorPhase.EDITING,m.phase);assertEquals(1L,m.privateDraftRevision);assertEquals(2L,m.desiredHeadRevision)
            val before=m.pages.joinToString("")
            val candidate=before.replace("\"changes\":[],\"permissions\":[]","\"changes\":[{\"path\":\"/schemaVersion\",\"operation\":\"set\",\"value\":1}],\"permissions\":[]")
            assertNotEquals(before,candidate)
            m=f.run(AdminEditorCoordinator.Kind.SAVE_LOCAL,m,listOf(candidate));assertEquals(AdminEditorPhase.LOCAL_DIRTY,m.phase)
            m=f.run(AdminEditorCoordinator.Kind.SAVE_DRAFT,m);assertEquals(AdminEditorPhase.EDITING,m.phase);assertEquals(1L,m.privateDraftRevision);assertNull(f.record().pending)
            assertEquals(2L,checkNotNull(f.saved).getJSONObject("proposal").getJSONArray("bundles").getJSONObject(0).getJSONArray("layers").getJSONObject(1).getLong("revision"))
            m=f.run(AdminEditorCoordinator.Kind.PREVIEW,m);assertEquals(AdminEditorPhase.REVIEW,m.phase);assertTrue(m.reviewBinding.isNotEmpty());assertTrue(m.reviewDeadlineElapsed>f.now)
            val beforePublish=f.sent.size;m=f.run(AdminEditorCoordinator.Kind.PUBLISH,m);assertEquals(AdminEditorPhase.PUBLISHED,m.phase);assertTrue(m.readOnly);assertEquals(beforePublish+1,f.sent.size);assertNull(f.record().pending)
            assertEquals(3L,m.desiredHeadRevision);assertEquals(3L,f.desiredRevision)
            assertTrue(f.sent.all {it.second.size<=262_144})
        }
    }
    @Test fun freshQueuedJobsNeedExplicitPollAndOriginalReviewBindingBeforePublication() {
        Fixture().use {f->
            f.queuePreview=true;var m=f.run(AdminEditorCoordinator.Kind.OPEN);m=f.run(AdminEditorCoordinator.Kind.PREVIEW,m)
            assertEquals(AdminEditorPhase.UNCERTAIN,m.phase);val count=f.calls.size;f.worker {f.coordinator.snapshot(f.access)};assertEquals(count,f.calls.size)
            m=f.run(AdminEditorCoordinator.Kind.POLL,m);assertEquals(AdminEditorPhase.REVIEW,m.phase)
            val sent=f.sent.size
            val denied=f.worker {f.coordinator.execute(AdminEditorCoordinator.Command(AdminEditorCoordinator.Kind.PUBLISH,m.device,m.documentBinding,m.localRevision,
                reviewBinding="foreign",reviewDeadline=m.reviewDeadlineElapsed),f.access)}
            assertNotEquals(AdminEditorPhase.PUBLISHED,denied.phase);assertEquals(sent,f.sent.size)
            m=f.run(AdminEditorCoordinator.Kind.PREVIEW,denied);assertEquals(AdminEditorPhase.UNCERTAIN,m.phase);m=f.run(AdminEditorCoordinator.Kind.POLL,m)
            f.now=m.reviewDeadlineElapsed+1
            val expired=f.run(AdminEditorCoordinator.Kind.PUBLISH,m);assertNotEquals(AdminEditorPhase.PUBLISHED,expired.phase);assertEquals(sent+1,f.sent.size)
        }
    }
    @Test fun processRecreationRecoversPendingWithoutSendingAndRestoredReadyRequiresNewPreview() {
        Fixture().use {f->
            var m=f.run(AdminEditorCoordinator.Kind.OPEN);f.loseNext=true;m=f.run(AdminEditorCoordinator.Kind.PREVIEW,m)
            assertEquals(AdminEditorPhase.UNCERTAIN,m.phase);val original=f.record().pending!!;val count=f.calls.size
            f.coordinator=f.newCoordinator();m=f.run(AdminEditorCoordinator.Kind.OPEN);assertEquals(AdminEditorPhase.UNCERTAIN,m.phase);assertEquals(count,f.calls.size)
            m=f.run(AdminEditorCoordinator.Kind.POLL,m);assertEquals(AdminEditorPhase.LOCAL_DIRTY,m.phase);assertEquals("",m.reviewBinding);assertNull(f.record().pending)
            assertEquals(original.requestId,f.sent.single().first)
            m=f.run(AdminEditorCoordinator.Kind.PREVIEW,m);assertEquals(AdminEditorPhase.REVIEW,m.phase)
        }
    }
    @Test fun uncertainDraftSaveReplaysExactBodyIdAndNeverInventsAJobOrSavedCas() {
        Fixture().use {f->
            var m=f.run(AdminEditorCoordinator.Kind.OPEN);f.loseNext=true;m=f.run(AdminEditorCoordinator.Kind.SAVE_DRAFT,m)
            assertEquals(AdminEditorPhase.UNCERTAIN,m.phase);val first=f.sent.single();assertNotNull(f.record().pending)
            val count=f.calls.size;m=f.run(AdminEditorCoordinator.Kind.POLL,m);assertEquals(AdminEditorPhase.UNCERTAIN,m.phase);assertEquals(count,f.calls.size)
            m=f.run(AdminEditorCoordinator.Kind.RETRY_EXACT,m);assertEquals(AdminEditorPhase.EDITING,m.phase);assertEquals(1L,m.privateDraftRevision)
            assertEquals(first.first,f.sent.last().first);assertArrayEquals(first.second,f.sent.last().second);assertNull(f.record().pending)
        }
    }
    @Test fun invalidLocalTextAndStaleUiCasStayEncryptedWithoutMutationAndSurrogatePagesStayWhole() {
        Fixture().use {f->
            val original=f.run(AdminEditorCoordinator.Kind.OPEN);val raw="x".repeat(8191)+"\uD83D\uDE00"+"tail"
            val inputPages=listOf(raw.substring(0,8191),raw.substring(8191))
            assertTrue(inputPages.all {it.length<=8192 && !it.last().isHighSurrogate() && !it.first().isLowSurrogate()})
            var m=f.run(AdminEditorCoordinator.Kind.SAVE_LOCAL,original,inputPages);assertEquals(AdminEditorPhase.LOCAL_DIRTY,m.phase)
            assertEquals(raw,m.pages.joinToString(""));assertEquals(2,m.pages.size);assertTrue(m.pages.all {it.length<=8192 && !it.last().isHighSurrogate() && !it.first().isLowSurrogate()})
            assertEquals(inputPages,m.pages)
            val count=f.sent.size;m=f.run(AdminEditorCoordinator.Kind.PREVIEW,m);assertEquals(AdminEditorPhase.LOCAL_DIRTY,m.phase);assertEquals(count,f.sent.size)
            val stale=f.run(AdminEditorCoordinator.Kind.SAVE_LOCAL,original,listOf("stale"));assertEquals(AdminEditorPhase.CONFLICT,stale.phase)
            assertEquals(raw,f.record().proposal.toString(Charsets.UTF_8))
            var failure:Exception?=null
            InstrumentationRegistry.getInstrumentation().runOnMainSync {try {f.coordinator.snapshot(f.access)}catch(e:Exception){failure=e}}
            assertTrue(failure is AdminEditorStorageException)
        }
    }
    @Test fun accessRevokedAfterDispatchKeepsDurablePendingAndDoesNotFollowAnotherAuthority() {
        Fixture().use {f->
            var m=f.run(AdminEditorCoordinator.Kind.OPEN);f.revokeNext=true;m=f.run(AdminEditorCoordinator.Kind.PREVIEW,m)
            assertEquals(AdminEditorPhase.NEEDS_REAUTH,m.phase);assertTrue(m.pages.isEmpty());assertEquals(1,f.sent.size)
            f.enabled=true
            assertNotNull(f.record().pending)
            f.coordinator=f.newCoordinator();m=f.run(AdminEditorCoordinator.Kind.OPEN);assertEquals(AdminEditorPhase.UNCERTAIN,m.phase)
            val count=f.sent.size;m=f.run(AdminEditorCoordinator.Kind.CLOSE,m);assertEquals(AdminEditorPhase.UNCERTAIN,m.phase);assertEquals(count,f.sent.size)
        }
        for(closed in listOf(false,true))Fixture().use {f->
            val opened=f.run(AdminEditorCoordinator.Kind.OPEN);val original=f.record()
            if(closed)f.run(AdminEditorCoordinator.Kind.CLOSE,opened)
            val before=File(f.directory,"editor.bin").readBytes()
            val previousReads=f.requestedDevices.size
            f.loginAs("synthetic-second-admin")
            f.device="device-b"
            val next=f.run(AdminEditorCoordinator.Kind.OPEN)
            if(closed) {
                assertEquals(AdminEditorPhase.EDITING,next.phase);val replacement=f.record()
                assertEquals(original.owner.serviceHash,replacement.owner.serviceHash);assertNotEquals(original.owner.actor,replacement.owner.actor)
                assertNotEquals(original.owner.draftId,replacement.owner.draftId);assertTrue(replacement.revision>original.revision+1)
                assertEquals("device-b",replacement.owner.deviceId)
            } else {
                assertEquals(AdminEditorPhase.UNAVAILABLE,next.phase);assertEquals("ACCESS_DENIED",next.error)
                assertTrue(next.pages.isEmpty());assertTrue(next.parents.isEmpty());assertEquals(0L,next.localRevision)
                assertArrayEquals(before,File(f.directory,"editor.bin").readBytes())
                f.worker {assertEquals(original,f.store().load(original.owner))}
            }
            assertEquals(listOf("device-b"),f.requestedDevices.drop(previousReads))
            assertTrue(f.sent.isEmpty()) // Inventory is an authorized read; no mutation escaped.
        }
        for(closed in listOf(false,true))Fixture().use {originalService->
            val opened=originalService.run(AdminEditorCoordinator.Kind.OPEN);val original=originalService.record()
            if(closed)originalService.run(AdminEditorCoordinator.Kind.CLOSE,opened)
            val before=File(originalService.directory,"editor.bin").readBytes()
            // A separately signed service/root binding shares only this test's
            // exact AES namespace. The outer owner alone performs file cleanup.
            Fixture(sharedStorage=originalService).use {nextService->
                nextService.device="device-b"
                val next=nextService.run(AdminEditorCoordinator.Kind.OPEN)
                if(closed) {
                    assertEquals(AdminEditorPhase.EDITING,next.phase);val replacement=nextService.record()
                    assertNotEquals(original.owner.serviceHash,replacement.owner.serviceHash);assertEquals(original.owner.actor,replacement.owner.actor)
                    assertTrue(replacement.revision>original.revision+1)
                    assertEquals("device-b",replacement.owner.deviceId)
                } else {
                    assertEquals(AdminEditorPhase.UNAVAILABLE,next.phase);assertEquals("ACCESS_DENIED",next.error)
                    assertTrue(next.pages.isEmpty());assertTrue(next.parents.isEmpty());assertEquals(0L,next.localRevision)
                    assertArrayEquals(before,File(originalService.directory,"editor.bin").readBytes())
                    originalService.worker {assertEquals(original,originalService.store().load(original.owner))}
                }
                assertEquals(listOf("device-b"),nextService.requestedDevices)
                assertTrue(nextService.sent.isEmpty())
            }
        }
    }
    @Test fun compareAndChangedHeadRebaseFailClosedWithoutFlatteningOrDroppingPrivateEdits() {
        Fixture().use {f->
            var m=f.run(AdminEditorCoordinator.Kind.OPEN);val before=f.record().proposal
            f.desiredRevision=3;m=f.run(AdminEditorCoordinator.Kind.COMPARE,m);assertEquals(AdminEditorPhase.CONFLICT,m.phase)
            m=f.run(AdminEditorCoordinator.Kind.REBASE,m);assertEquals(AdminEditorPhase.LIMITED,m.phase);assertEquals("REBASE_REQUIRED",m.error)
            assertArrayEquals(before,f.record().proposal);assertTrue(f.sent.isEmpty())
            m=f.run(AdminEditorCoordinator.Kind.CLOSE,m);assertEquals(AdminEditorPhase.INVENTORY,m.phase);assertTrue(m.pages.isEmpty())
        }
    }
    @Test fun recoveredPrivateDraftCasRequiresCompleteListAndCheckedGetRatherThanLocalRevisionGuess() {
        Fixture().use {f->
            var m=f.run(AdminEditorCoordinator.Kind.OPEN);m=f.run(AdminEditorCoordinator.Kind.SAVE_DRAFT,m)
            assertEquals(1L,m.privateDraftRevision)
            f.coordinator=f.newCoordinator();f.failList=true;m=f.run(AdminEditorCoordinator.Kind.OPEN);assertEquals(AdminEditorPhase.UNAVAILABLE,m.phase)
            val sent=f.sent.size;assertEquals(1,sent)
            f.failList=false;m=f.run(AdminEditorCoordinator.Kind.OPEN);assertEquals(AdminEditorPhase.EDITING,m.phase)
            assertTrue(f.calls.contains(AdminLayerAction.DRAFT_LIST));assertTrue(f.calls.contains(AdminLayerAction.DRAFT_GET))
            m=f.run(AdminEditorCoordinator.Kind.SAVE_DRAFT,m);assertEquals(2L,m.privateDraftRevision);assertEquals(sent+1,f.sent.size)
        }
    }
    @Test fun verifiedServerTerminalErrorsResolveExactPendingAndExposeOnlyFiniteUppercaseCodes() {
        for((wire,code,expected) in listOf(Triple("configuration_conflict","CONFIGURATION_CONFLICT",AdminEditorPhase.CONFLICT),
            Triple("configuration_denied","ACCESS_DENIED",AdminEditorPhase.LOCAL_DIRTY))) {
            Fixture().use {f->
                var m=f.run(AdminEditorCoordinator.Kind.OPEN);val before=f.record().proposal;f.rejectPreview=wire
                m=f.run(AdminEditorCoordinator.Kind.PREVIEW,m)
                assertEquals(expected,m.phase);assertEquals(code,m.error);assertNull(f.record().pending)
                assertArrayEquals(before,f.record().proposal);assertEquals("",m.reviewBinding);assertEquals(1,f.sent.size)
            }
        }
    }
    @Test fun rollbackAndCorruptEncryptedRecoveryCannotWriteSendOrReplaceTheUnknownOwner() {
        Fixture().use {f->
            val m=f.run(AdminEditorCoordinator.Kind.OPEN);val file=File(f.directory,"editor.bin");val before=file.readBytes()
            f.now=999
            val denied=f.run(AdminEditorCoordinator.Kind.SAVE_LOCAL,m,listOf("must not persist"))
            assertEquals(AdminEditorPhase.NEEDS_REAUTH,denied.phase);assertArrayEquals(before,file.readBytes());assertTrue(f.sent.isEmpty())
        }
        Fixture().use {f->
            f.run(AdminEditorCoordinator.Kind.OPEN);val file=File(f.directory,"editor.bin")
            val corrupt=f.worker {file.readBytes().also {it[it.lastIndex]=(it.last().toInt() xor 1).toByte();file.writeBytes(it)}}
            val count=f.calls.size;f.coordinator=f.newCoordinator()
            val denied=f.run(AdminEditorCoordinator.Kind.OPEN)
            assertEquals(AdminEditorPhase.UNAVAILABLE,denied.phase);assertEquals("STORAGE_CORRUPT",denied.error)
            assertTrue(denied.pages.isEmpty());assertEquals(count,f.calls.size);assertArrayEquals(corrupt,file.readBytes())
        }
    }
}
