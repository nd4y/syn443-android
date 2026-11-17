package io.syn443.android

import android.content.Context
import androidx.core.net.toUri
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
class AdminOperationCoordinatorTest {
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
        var protocolVersion=2
        var versionQueries=0
        var loseBefore=false
        var outcome=AdminOperationOutcome.UNKNOWN
        var jobState:String?=null
        var reconcileFailure:AdminFailure?=null
        var checkFailure:AdminFailure?=null
        var beforeReconcile:((AdminOperationRequest)->Unit)?=null
        var afterReconcile:((AdminOperationRequest)->Unit)?=null
        val reconciliation=mutableListOf<AdminOperationRequest>()
        var queuePreview=false
        var queuePublish=false
        var desiredRevision=2L
        var loseNext=false
        var revokeNext=false
        var failList=false
        var rejectPreview=""
        var remoteOwnValue:Int?=null
        var afterInventory:(()->Unit)?=null
        private val inventories=mutableMapOf<Long,String>()
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
            override fun check(){checkFailure?.let {throw AdminException(it)};if(!enabled)throw AdminException(AdminFailure.REAUTHENTICATE)}
            override fun configurationRequestVersion():Int {versionQueries++;return protocolVersion}
            override fun reconcile(request:AdminOperationRequest):AdminOperationReceipt {
                val observed=protocol.layerOwnership(session).time
                reconciliation+=request
                beforeReconcile?.invoke(request)
                reconcileFailure?.let {throw AdminException(it)}
                val receipt=AdminOperationReconcile.parseReply(request,receipt(request),observed)
                afterReconcile?.invoke(request)
                return receipt
            }
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
                            if(loseBefore && JSONObject(Policy.utf8(raw)).getString("action") in setOf("configuration.layers.draft.put","configuration.preview.request","configuration.publish")) {
                                loseBefore=false;throw AdminException(AdminFailure.TRANSPORT)
                            }
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
        fun run(kind:AdminEditorCoordinator.Kind,model:AdminEditorModel?=null,pages:List<String> = emptyList(),binding:String?=null,revision:Long?=null,comparisonBinding:String=""):AdminEditorModel=worker {
            coordinator.execute(AdminEditorCoordinator.Command(kind,model?.device?:device,binding?:model?.documentBinding?:"",revision?:model?.localRevision?:0,
                pages,model?.reviewBinding?:"",model?.reviewDeadlineElapsed?:0,comparisonBinding,model?.operationBinding?:""),access)
        }
        fun compare(kind:AdminEditorCoordinator.ComparisonKind,model:AdminEditorModel,current:AdminComparisonModel?=null,
            section:AdminComparisonSection=current?.section?:AdminComparisonSection.CONFLICTS,offset:Int=0,row:String="",
            side:AdminComparisonSide=AdminComparisonSide.BASE,page:Int=0,choice:String="",binding:String?=null)=worker {
            coordinator.comparison(AdminEditorCoordinator.ComparisonCommand(kind,model.device,model.documentBinding,model.localRevision,
                binding?:current?.binding?:"",section,offset,row,side,page,choice),access)
        }
        fun record()=worker {val o=protocol.layerOwnership(session);checkNotNull(store().recoverOwned(o.serviceHash,o.actor))}
        fun rawRecord(owner:AdminEditorOwner)=worker {store().load(owner)}
        fun vpnWitness():String {
            fun read(method:String)=JSONObject(checkNotNull(context.contentResolver.call("content://io.syn443.control".toUri(),method,null,null)).getString("json"))
            val state=read("status");val login=read("auth-status")
            return JSONObject().put("desiredOn",state.getBoolean("desiredOn")).put("generation",state.getLong("generation"))
                .put("configRevision",state.optString("configRevision")).put("method",login.optString("method")).toString()
        }
        fun uncertain(kind:AdminEditorCoordinator.Kind=AdminEditorCoordinator.Kind.SAVE_DRAFT,version:Int=2,applied:Boolean=false):AdminEditorModel {
            protocolVersion=version
            var model=run(AdminEditorCoordinator.Kind.OPEN)
            if(kind==AdminEditorCoordinator.Kind.PUBLISH)model=run(AdminEditorCoordinator.Kind.PREVIEW,model)
            if(applied)loseNext=true else loseBefore=true
            model=run(kind,model)
            assertEquals(AdminEditorPhase.UNCERTAIN,model.phase);assertNotNull(record().pending)
            assertTrue(model.operationBinding.isNotEmpty());assertFalse(model.canSeal)
            return model
        }
        private fun receipt(request:AdminOperationRequest):String {
            val envelope=JSONObject(request.original.wireJson());val payload=envelope.getJSONObject("payload")
            val action=request.original.action
            val draft=action in setOf(AdminLayerAction.DRAFT_PUT,AdminLayerAction.DRAFT_DISCARD)
            val effectId=if(draft)if(action==AdminLayerAction.DRAFT_PUT)payload.getJSONObject("draft").getString("id") else payload.getString("id")
                else Identity.hash((request.actor+"\u0000"+request.original.requestId).toByteArray(Charsets.UTF_8))
            val effectRevision=if(!draft)0L else if(action==AdminLayerAction.DRAFT_PUT)payload.getJSONObject("draft").getLong("revision")+1 else payload.getLong("revision")
            val absent=outcome in setOf(AdminOperationOutcome.UNKNOWN,AdminOperationOutcome.NO_EFFECT)
            val result=JSONObject().put("version",1).put("actor",request.actor).put("action",action.wire)
                .put("requestId",request.original.requestId).put("bodyHash",request.originalBodyHash)
                .put("targetKind","device").put("targetId",device).put("outcome",outcome.name)
                .put("recordedAtMs",if(outcome==AdminOperationOutcome.UNKNOWN)0 else wall)
                .put("effectKind",if(absent)"" else if(draft)"draft" else "job").put("effectId",if(absent)"" else effectId)
                .put("effectRevision",if(absent)0 else effectRevision)
            if(outcome==AdminOperationOutcome.RECORDED && !draft) {
                val job=jobState?.let {state->JSONObject().put("id",effectId).put("state",state).also {
                    if(state in setOf("rejected","expired","cancelled"))it.put("error",if(state=="rejected")"configuration_conflict" else "deadline_or_retry_limit")
                }} ?:JSONObject(checkNotNull(terminals[effectId]))
                result.put("job",job)
            }
            return result.toString()
        }
        fun replacePendingFromActualStore(request:AdminOperationRequest):AdminEditorRecord {
            val owned=protocol.layerOwnership(session);val current=checkNotNull(store().recoverOwned(owned.serviceHash,owned.actor));val pending=checkNotNull(current.pending)
            val cleared=store().resolve(current,pending.requestId,pending.bodySha256,current.proposal)
            val replacement=AdminLayerControl.saveDraft(0,AdminLayerControl.proposal(Policy.utf8(cleared.proposal)),Identity.random(),2)
            check(replacement.requestId!=request.original.requestId)
            return store().preparePending(cleared,"layers.draft.put",replacement.requestId,replacement.bodyBytes(),
                AdminLayerControl.replayContext(replacement,owned.actor,owned.apiOrigin))
        }
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
        private fun inventory():String {
            val ownRevision=if(remoteOwnValue==null)1 else 2
            val ownChanges=remoteOwnValue?.let {"""[{"path":"/schemaVersion","operation":"set","value":$it}]"""}?:"[]"
            val origin=if(remoteOwnValue==null)"""{"layerId":"template-a","kind":"template","revision":1}""" else """{"layerId":"$device","kind":"device","revision":$ownRevision}"""
            val raw="""{"device":"$device","owner":"$owner","state":"assigned","revision":$desiredRevision,"hash":"$baseHash","policyRevision":0,"mode":"wifi","approvalUntilMs":${WALL+3_600_000},"layers":[{"id":"template-a","kind":"template","priority":0,"revision":1,"changes":[{"path":"/schemaVersion","operation":"set","value":1}],"permissions":[{"path":"/schemaVersion","mode":"free"}]},{"id":"$device","kind":"device","priority":0,"revision":$ownRevision,"changes":$ownChanges,"permissions":[]}],"effective":{"document":{"schemaVersion":${remoteOwnValue?:1}},"fields":{"/schemaVersion":$origin},"restrictions":[{"permission":{"path":"/schemaVersion","mode":"free"},"origin":{"layerId":"template-a","kind":"template","revision":1}}]},"currentRevision":$desiredRevision}"""
            inventories.putIfAbsent(desiredRevision,raw)
            return raw
        }
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
                "configuration.inventory.get"->inventory().also {afterInventory?.invoke()}
                "configuration.history.get"->{val captured=checkNotNull(inventories[payload.getLong("revision")]);captured.dropLast(1)+",\"historical\":true}"}
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


    private fun assertPendingEquals(expected:AdminEditorRecord,actual:AdminEditorRecord) {
        assertEquals(expected,actual);assertArrayEquals(expected.proposal,actual.proposal)
        val a=checkNotNull(expected.pending);val b=checkNotNull(actual.pending)
        assertEquals(a.requestId,b.requestId);assertEquals(a.bodySha256,b.bodySha256)
        assertArrayEquals(a.body,b.body);assertArrayEquals(a.replayContext,b.replayContext)
    }
    @Test fun unknownVersionTwoKeepsExactEncryptedDebtAndOnlyMatchingLookupArmsExplicitSeal() {
        Fixture().use {f->
            var model=f.uncertain();val retained=f.record();val sent=f.sent.size
            val premature=f.run(AdminEditorCoordinator.Kind.SEAL_PENDING,model)
            assertEquals("OUTCOME_CHECK_REQUIRED",premature.error);assertTrue(f.reconciliation.isEmpty());assertFalse(premature.canSeal)
            model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,premature)
            assertEquals("UNKNOWN",model.operationOutcome);assertEquals("OUTCOME_UNKNOWN",model.error);assertTrue(model.canSeal)
            assertEquals(AdminOperationIntent.LOOKUP,f.reconciliation.single().intent);assertEquals(sent,f.sent.size)
            assertPendingEquals(retained,f.record())
            val count=f.reconciliation.size;f.worker {f.coordinator.snapshot(f.access)};assertEquals(count,f.reconciliation.size)
            val rejected=f.worker {f.coordinator.execute(AdminEditorCoordinator.Command(AdminEditorCoordinator.Kind.SEAL_PENDING,
                model.device,model.documentBinding,model.localRevision,operationBinding=Identity.random()),f.access)}
            assertEquals("CONFLICT",rejected.error);assertEquals(count,f.reconciliation.size);assertPendingEquals(retained,f.record())
            f.worker {f.coordinator=f.newCoordinator()}
            model=f.run(AdminEditorCoordinator.Kind.OPEN)
            assertFalse(model.canSeal);assertTrue(model.operationOutcome.isEmpty());assertPendingEquals(retained,f.record())
            model=f.run(AdminEditorCoordinator.Kind.SEAL_PENDING,model)
            assertEquals("OUTCOME_CHECK_REQUIRED",model.error);assertEquals(count,f.reconciliation.size)
        }
    }
    @Test fun explicitVersionTwoNoEffectClearsOnlyMatchingDebtThenReadsCurrentHeadAndCompleteDraftState() {
        for(changed in listOf(false,true))Fixture().use {f->
            var model=f.uncertain();val retained=f.record()
            model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model);assertTrue(model.canSeal)
            f.outcome=AdminOperationOutcome.NO_EFFECT;if(changed)f.desiredRevision=3
            val before=f.calls.size;model=f.run(AdminEditorCoordinator.Kind.SEAL_PENDING,model)
            assertEquals(AdminOperationIntent.SEAL_IF_ABSENT,f.reconciliation.last().intent)
            assertEquals("NO_EFFECT",model.operationOutcome);assertNull(f.record().pending)
            assertArrayEquals(retained.proposal,f.record().proposal);assertFalse(model.canSeal)
            assertEquals(listOf(AdminLayerAction.INVENTORY,AdminLayerAction.DRAFT_LIST),f.calls.drop(before).take(2))
            assertEquals(if(changed)AdminEditorPhase.CONFLICT else AdminEditorPhase.LOCAL_DIRTY,model.phase)
            assertTrue(model.reviewBinding.isEmpty());assertEquals(0L,model.reviewDeadlineElapsed)
        }
    }
    @Test fun versionOneUnknownNeverAdvertisesOrSendsSealAndCannotAcceptNoEffect() {
        Fixture().use {f->
            var model=f.uncertain(version=1);val retained=f.record()
            model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model);assertEquals("UNKNOWN",model.operationOutcome);assertFalse(model.canSeal)
            val count=f.reconciliation.size;model=f.run(AdminEditorCoordinator.Kind.SEAL_PENDING,model)
            assertEquals(count,f.reconciliation.size);assertEquals("OUTCOME_CHECK_REQUIRED",model.error)
            f.outcome=AdminOperationOutcome.NO_EFFECT;model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model)
            assertEquals("INVALID_REPLY",model.error);assertFalse(model.canSeal);assertPendingEquals(retained,f.record())
        }
    }
    @Test fun recordedDraftAcknowledgementPreservesLocalTextAndRequiresFreshHeadDraftReadbackIncludingConflict() {
        for(changed in listOf(false,true))Fixture().use {f->
            var model=f.uncertain(applied=true);val retained=f.record();assertNotNull(f.saved)
            f.outcome=AdminOperationOutcome.RECORDED;if(changed)f.desiredRevision=3
            val before=f.calls.size;model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model)
            assertNull(f.record().pending);assertArrayEquals(retained.proposal,f.record().proposal)
            assertEquals(listOf(AdminLayerAction.INVENTORY,AdminLayerAction.DRAFT_LIST,AdminLayerAction.DRAFT_GET),f.calls.drop(before).take(3))
            assertEquals(if(changed)AdminEditorPhase.CONFLICT else AdminEditorPhase.LOCAL_DIRTY,model.phase)
            assertEquals("RECORDED",model.operationOutcome);assertTrue(model.reviewBinding.isEmpty());assertFalse(model.canSeal)
        }
    }
    @Test fun recordedQueuedAndRunningRemainExactPendingWithoutAutomaticPollRetryOrPreview() {
        for(state in listOf("queued","running"))Fixture().use {f->
            var model=f.uncertain(AdminEditorCoordinator.Kind.PREVIEW,applied=true);val retained=f.record();val sent=f.sent.size
            f.outcome=AdminOperationOutcome.RECORDED;f.jobState=state
            model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model)
            assertEquals(AdminEditorPhase.UNCERTAIN,model.phase);assertEquals("BUSY",model.error);assertFalse(model.canSeal)
            assertPendingEquals(retained,f.record());assertEquals(sent,f.sent.size);assertTrue(model.reviewBinding.isEmpty())
            val count=f.reconciliation.size;f.worker {f.coordinator.snapshot(f.access)};assertEquals(count,f.reconciliation.size)
        }
    }
    @Test fun historicalReadyAndLaterPollCannotMintReviewAndRequireExplicitNewPreviewBeforePublish() {
        for(queued in listOf(false,true))Fixture().use {f->
            var model=f.uncertain(AdminEditorCoordinator.Kind.PREVIEW,applied=true)
            f.outcome=AdminOperationOutcome.RECORDED;if(queued)f.jobState="queued"
            model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model)
            if(queued)model=f.run(AdminEditorCoordinator.Kind.POLL,model)
            assertNull(f.record().pending);assertEquals(AdminEditorPhase.LOCAL_DIRTY,model.phase);assertEquals("REVIEW_REQUIRED",model.error)
            assertTrue(model.reviewBinding.isEmpty());assertEquals(0L,model.reviewDeadlineElapsed)
            val mutations=f.sent.size;val queries=f.versionQueries
            val denied=f.run(AdminEditorCoordinator.Kind.PUBLISH,model)
            assertNotEquals(AdminEditorPhase.PUBLISHED,denied.phase);assertEquals(mutations,f.sent.size);assertEquals(queries,f.versionQueries)
            model=f.run(AdminEditorCoordinator.Kind.PREVIEW,denied)
            assertEquals(AdminEditorPhase.REVIEW,model.phase);assertTrue(model.reviewBinding.isNotEmpty());assertEquals(queries+1,f.versionQueries)
        }
    }
    @Test fun recordedPublishedAcknowledgesOnlyDesiredHeadWithoutAnotherMutationOrVpnActivation() {
        Fixture().use {f->
            val vpnBefore=f.vpnWitness()
            var model=f.uncertain(AdminEditorCoordinator.Kind.PUBLISH,applied=true);val mutations=f.sent.size
            f.outcome=AdminOperationOutcome.RECORDED
            model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model)
            assertEquals(AdminEditorPhase.PUBLISHED,model.phase);assertEquals(3L,model.desiredHeadRevision);assertTrue(model.readOnly)
            assertNull(f.record().pending);assertEquals(mutations,f.sent.size);assertTrue(model.reviewBinding.isEmpty())
            assertTrue(f.sent.all {(_,body)->JSONObject(Policy.utf8(body)).getString("action") in setOf("configuration.preview.request","configuration.publish")})
            // This coordinator owns no VPN interface or activation action; the
            // result is desired-head metadata, not a connected/runtime receipt.
            assertEquals(listOf(AdminOperationIntent.LOOKUP),f.reconciliation.map {it.intent})
            assertEquals(vpnBefore,f.vpnWitness())
        }
    }
    @Test fun unavailableLegacyAndRejectedHistoricalResultsNeverTurnUnknownPayloadIntoFreshGrant() {
        for(case in listOf("unavailable","legacy","rejected","expired","cancelled"))Fixture().use {f->
            var model=f.uncertain(AdminEditorCoordinator.Kind.PREVIEW,applied=true);val retained=f.record()
            f.outcome=if(case=="unavailable")AdminOperationOutcome.RECORDED_RESULT_UNAVAILABLE else AdminOperationOutcome.RECORDED
            f.jobState=when(case){"legacy"->"applied";"unavailable"->null;else->case}
            model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model)
            assertFalse(model.canSeal);assertTrue(model.reviewBinding.isEmpty());assertNotEquals(AdminEditorPhase.REVIEW,model.phase)
            if(case in setOf("unavailable","legacy")){assertEquals(AdminEditorPhase.UNCERTAIN,model.phase);assertEquals("RESULT_UNAVAILABLE",model.error);assertPendingEquals(retained,f.record())}
            else {assertNull(f.record().pending);assertArrayEquals(retained.proposal,f.record().proposal);assertNotEquals(AdminEditorPhase.PUBLISHED,model.phase)
                if(case in setOf("expired","cancelled"))assertEquals("REVIEW_EXPIRED",model.error)
            }
        }
        for(failure in listOf(AdminFailure.TRANSPORT,AdminFailure.ACCESS_DENIED))Fixture().use {f->
            val model=f.uncertain();val retained=f.record();f.reconcileFailure=failure
            val rejected=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model)
            assertEquals(AdminEditorPhase.UNCERTAIN,rejected.phase);assertEquals(failure.name,rejected.error)
            assertFalse(rejected.canSeal);assertPendingEquals(retained,f.record())
        }
    }
    @Test fun cancellationRootBootLeaseAndConcurrentStoreReplacementFenceReceiptsBeforeAndAfterRpc() {
        for(after in listOf(false,true))for(kind in listOf("cancel","root","boot","lease"))Fixture().use {f->
            val model=f.uncertain();val retained=f.record();f.outcome=AdminOperationOutcome.NO_EFFECT
            val invalidate:()->Unit={when(kind) {
                "cancel"->f.checkFailure=AdminFailure.CANCELLED
                "root"->f.enabled=false
                "boot"->f.boot++
                else->f.now+=8*60*60*1000L
            }
            }
            if(after)f.afterReconcile={invalidate()} else invalidate()
            val rejected=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model)
            assertEquals(if(after)1 else 0,f.reconciliation.size);assertEquals(AdminEditorPhase.NEEDS_REAUTH,rejected.phase)
            assertFalse(rejected.canSeal);assertTrue(rejected.reviewBinding.isEmpty());assertPendingEquals(retained,f.rawRecord(retained.owner))
        }
        for(during in listOf(false,true))Fixture().use {f->
            val model=f.uncertain();val retained=f.record();f.outcome=AdminOperationOutcome.NO_EFFECT
            var replacement:AdminEditorRecord?=null
            if(during)f.beforeReconcile={request->replacement=f.replacePendingFromActualStore(request)}
            else f.worker {
                val owned=f.access.ownership();val pending=checkNotNull(retained.pending)
                val original=AdminLayerControl.restoreRequest(pending.body,pending.replayContext,Policy.utf8(retained.proposal),owned.actor,owned.apiOrigin)
                val request=AdminOperationReconcile.request(original,owned.actor,owned.apiOrigin,Identity.random(),AdminOperationIntent.LOOKUP)
                replacement=f.replacePendingFromActualStore(request)
            }
            val rejected=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model)
            assertEquals(if(during)1 else 0,f.reconciliation.size)
            assertEquals("COMPARISON_STALE",rejected.error);assertNotNull(replacement)
            assertPendingEquals(checkNotNull(replacement),f.rawRecord(retained.owner))
            assertNotEquals(retained.pending!!.requestId,replacement!!.pending!!.requestId)
        }
    }
    @Test fun freshSavePreviewPublishProbeVersionButHistoricalRetryPollAndReconcileKeepOriginalVersionBytes() {
        Fixture().use {f->
            var model=f.run(AdminEditorCoordinator.Kind.OPEN);assertEquals(0,f.versionQueries)
            model=f.run(AdminEditorCoordinator.Kind.SAVE_DRAFT,model);assertEquals(1,f.versionQueries)
            model=f.run(AdminEditorCoordinator.Kind.PREVIEW,model);assertEquals(2,f.versionQueries)
            f.loseNext=true;model=f.run(AdminEditorCoordinator.Kind.PUBLISH,model);assertEquals(3,f.versionQueries)
            val retained=f.record();assertEquals(2,JSONObject(Policy.utf8(retained.pending!!.body)).getInt("version"))
            f.protocolVersion=1
            model=f.run(AdminEditorCoordinator.Kind.CHECK_OUTCOME,model);assertEquals(3,f.versionQueries);assertPendingEquals(retained,f.record())
            model=f.run(AdminEditorCoordinator.Kind.RETRY_EXACT,model);assertEquals(3,f.versionQueries)
            assertEquals(AdminEditorPhase.PUBLISHED,model.phase);assertArrayEquals(retained.pending!!.body,f.sent.last().second)
        }
        Fixture().use {f->
            f.queuePreview=true;var model=f.run(AdminEditorCoordinator.Kind.OPEN);model=f.run(AdminEditorCoordinator.Kind.PREVIEW,model)
            assertEquals(1,f.versionQueries);f.protocolVersion=1
            model=f.run(AdminEditorCoordinator.Kind.POLL,model);assertEquals(AdminEditorPhase.REVIEW,model.phase);assertEquals(1,f.versionQueries)
        }
    }
}
