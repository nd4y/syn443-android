package io.syn443.android

import android.content.Context
import androidx.core.net.toUri
import androidx.test.core.app.ApplicationProvider
import io.syn443.android.vpn.*
import io.syn443.android.admin.*
import io.syn443.identity.*
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.json.JSONObject
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.Closeable
import java.io.File
import java.math.BigInteger
import java.net.URI
import java.net.URLDecoder
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Collections
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Actual isolated controller, signed synthetic OAuth/DPoP and AES outbox.
 * These barriers prove dispatch admission, not live server publication or VPN activation. */
class AdminPublishDispatchDeadlineTest {
    private class Gate {
        val entered=CountDownLatch(1)
        val release=CountDownLatch(1)
        fun hold() {entered.countDown();check(release.await(20,TimeUnit.SECONDS)) {"fixture_gate_deadline"}}
        fun reached()=assertTrue("actual worker did not reach the owned barrier",entered.await(15,TimeUnit.SECONDS))
    }
    private class Call(val method:String,val url:String,val headers:Map<String,String>,val body:ByteArray?) {
        override fun toString()="SyntheticAdminCall([redacted])"
    }
    private class Fixture(autoStart:Boolean=true):Closeable {
        val context=ApplicationProvider.getApplicationContext<Context>()
        val namespace="test-controller-"+UUID.randomUUID().toString().replace("-","").take(24)
        val aes="syn443-admin-store-test-"+Identity.random()
        private val editorNamespace="admin-editor-test-"+UUID.randomUUID().toString().replace("-","")
        private val editorAlias="syn443-admin-editor-test-"+Identity.random()
        private val editorDirectory=File(context.noBackupFilesDir,editorNamespace)
        val directory=File(context.noBackupFilesDir,"admin-login/$namespace")
        val file=File(directory,"owner.bin")
        private val worker=ThreadPoolExecutor(1,1,30,TimeUnit.SECONDS,ArrayBlockingQueue(1))
        private val offline=ec()
        private val online=ec()
        val anchor=TrustAnchor("controller-offline",Base64.getEncoder().encodeToString(offline.public.encoded),1)
        val metadata=AdminBootstrap("https://controller-id.example.invalid/realms/admin",AdminBootstrap.CLIENT_ID,
            AdminBootstrap.AUDIENCE,"https://controller-api.example.invalid",AdminBootstrap.ASSURANCE_ACR)
        val oidc=metadata.issuer+"/protocol/openid-connect"
        val device="synthetic-device"
        @Volatile var elapsed=1000L
        @Volatile var boot=7
        @Volatile var enabled=true
        @Volatile var deviceBinding=Identity.hash("synthetic-device-context-one".toByteArray())
        @Volatile var onSource:(()->Unit)?=null
        @Volatile var onExchange:((Call)->Reply)?=null
        @Volatile var onMetadata:(()->AdminDeviceContext?)?=null
        val metadataCalls=AtomicInteger()
        private val calls=Collections.synchronizedList(mutableListOf<Call>())
        private val gates=Collections.synchronizedList(mutableListOf<Gate>())
        private val aliases=Collections.synchronizedSet(mutableSetOf<String>())
        private val proofIDs=mutableSetOf<String>()
        private val usedRefresh=mutableSetOf<String>()
        private val verifierFailure=AtomicReference<AssertionError?>()
        private var savedBrowser=emptyMap<String,String>()
        private var currentRefresh=""
        private var currentAccess=""
        private var thumbprint=""
        private var subject="synthetic-admin"
        private var tokenNumber=0
        val wall:Long get()=NOW+elapsed-1000
        private val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"controller-service",
            "https://device-id.example.invalid/realms/device","syn443-android","https://device-api.example.invalid",
            mapOf("online" to Base64.getEncoder().encodeToString(online.public.encoded)),NOW/1000,NOW/1000,NOW/1000+86_400,
            adminBootstrap=metadata)
        private val manifest=signManifest(descriptor,anchor,offline)
        private val floor=BootstrapTrust.descriptor(manifest,anchor,ServiceFloor(),NOW/1000).second
        private val projected=Bootstrap(descriptor.serviceId,descriptor.issuer,descriptor.clientId,descriptor.apiOrigin,
            descriptor.roots.toMap(),controlPanelOrigin=descriptor.controlPanelOrigin)
        private var vpnBefore:JSONObject?=null
        private val sentinelAlias=DeviceKey.newAlias()
        private var sentinelPublic:ByteArray?=null
        private var active:AdminController?=null
        val controller:AdminController get()=checkNotNull(active)
        init {
            assumeTrue(BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
            try {
                vpnBefore=vpnSnapshot()
                sentinelPublic=onWorker {DeviceKey.create(sentinelAlias).publicKey.encoded}
                if(autoStart)createController()
            }catch(error:Throwable) {
                try {close()}catch(cleanup:Throwable) {error.addSuppressed(cleanup)}
                throw error
            }
        }
        fun <T> onWorker(action:()->T):T=worker.submit<T> {action()}.get(25,TimeUnit.SECONDS)
        fun journal()=AdminKeyJournal.isolatedForTest(context,namespace,aes)
        fun record()=onWorker {journal().read().also {if(it.alias.isNotEmpty())aliases+=it.alias}}
        fun createController() {
            check(active==null)
            active=AdminController.isolatedForTest(context,namespace,aes,{
                try {
                    onSource?.invoke()
                    if(!enabled)null else BootstrapTrust.adminDiscovery(manifest,anchor,floor,projected,wall/1000)
                        ?.let {AdminDeviceContext(deviceBinding,it)}
                }catch(error:AssertionError) {verifierFailure.compareAndSet(null,error);throw error}
            },IdentityExchange {method,url,headers,body,_,maxBody->
                val call=Call(method,url,headers.toMap(),body?.copyOf());calls+=call
                try {
                    assertFalse(headers.keys.any {it.equals("Origin",true)})
                    if(method=="POST")verifyProof(call)
                    val reply=onExchange?.invoke(call) ?:normal(call)
                    // Oversize replies are deliberately permitted only for explicit negative cases.
                    assertTrue(maxBody in 1..524_288)
                    reply
                }catch(error:AssertionError) {verifierFailure.compareAndSet(null,error);throw error}
            },{boot},{elapsed},refreshDiscovery={metadataCalls.incrementAndGet();onMetadata?.invoke()},editorStore={store()})
            idle()
        }
        fun verifiedContext()=checkNotNull(BootstrapTrust.adminDiscovery(manifest,anchor,floor,projected,wall/1000))
            .let {AdminDeviceContext(deviceBinding,it)}
        fun trustFingerprint()=Identity.hash(Canonical.encode(buildJsonObject {
            put("root",anchor.spki);put("epoch",anchor.epoch);put("service",floor.serviceId);put("revision",floor.revision)
            put("floor",floor.hash);put("ordinary",Identity.bootstrapAuthority(projected))
        }).toByteArray())
        fun assertNoAdminReservation() {
            assertEquals(AdminKeyRecord(),record());assertFalse(directory.exists());assertFalse(file.exists())
            onWorker {assertFalse(keyStore().containsAlias(aes))}
        }
        fun restart() {assertTrue(controller.shutdownForTest());active=null;createController()}
        fun snapshot()=controller.status()
        fun gen()=snapshot().getLong("generation")
        fun idle() {
            await { !controller.status().getBoolean("busy") }
            verifierFailure.get()?.let {throw AssertionError("synthetic signature/transport verification failed",it)}
        }
        fun phase(expected:String) {idle();assertEquals(expected,snapshot().getString("phase"))}
        fun gate()=Gate().also {gates+=it}
        fun callCount()=synchronized(calls) {calls.size}
        fun tokenCalls()=synchronized(calls) {calls.count {it.url==oidc+"/token"}}
        fun controlCalls()=synchronized(calls) {calls.count {it.url==metadata.apiOrigin+"/v1/control/action"}}
        fun refreshCalls()=synchronized(calls) {calls.count {it.url==oidc+"/token" && parameters(checkNotNull(it.body).toString(Charsets.UTF_8))["grant_type"]=="refresh_token"}}
        fun openBrowser():AdminController.BrowserResult {
            assertTrue(controller.start(gen()));phase("BROWSER");record()
            return handoff()
        }
        fun handoff():AdminController.BrowserResult {
            val id=id();assertTrue(controller.prepareBrowser(id,gen()));idle()
            val result=controller.browserResult(id,gen());assertEquals("done",result.state)
            assertNotNull(result.url);savedBrowser=parameters(checkNotNull(URI(result.url).rawQuery))
            assertEquals(AdminBootstrap.CLIENT_ID,savedBrowser["client_id"])
            assertEquals(AdminBootstrap.CALLBACK,savedBrowser["redirect_uri"])
            assertEquals("300",savedBrowser["max_age"])
            assertEquals("gone",controller.browserResult(id,gen()).state)
            return result
        }
        fun callback(error:String?=null,state:String=savedBrowser.getValue("state"))=AdminBootstrap.CALLBACK+"?"+Identity.form(linkedMapOf(
            "state" to state,"iss" to metadata.issuer)+(if(error==null)mapOf("code" to "synthetic-code") else mapOf("error" to error)))
        fun login() {openBrowser();assertTrue(controller.callback(callback()));phase("AUTHENTICATED");record()}
        fun read(kind:String="devices",target:String=if(kind=="devices")"" else device):AdminController.ReadResult {
            val id=id();assertTrue(controller.readStart(id,gen(),kind,target));idle();return controller.readResult(id,gen())
        }
        fun seed(phase:AdminKeyPhase):AdminKeyRecord=onWorker {
            val journal=journal();val initial=journal.read();val alias=AdminKey.newAlias().also {aliases+=it}
            var next=journal.commit(initial,initial.copy(revision=1,generation=1,phase=AdminKeyPhase.RESERVED,alias=alias))
            assertNotNull(AdminKey.createIfCurrent(alias) {journal.read()==next})
            if(phase in setOf(AdminKeyPhase.BROWSER,AdminKeyPhase.AUTHENTICATED)) {
                next=journal.commit(next,next.copy(revision=next.revision+1,phase=AdminKeyPhase.BROWSER))
                if(phase==AdminKeyPhase.AUTHENTICATED)next=journal.commit(next,next.copy(revision=next.revision+1,phase=phase))
            } else if(phase==AdminKeyPhase.RETIRING)next=journal.commit(next,next.copy(revision=next.revision+1,generation=2,phase=phase))
            next
        }
        fun signedOutKeyAbsent(alias:String)=onWorker {assertFalse(keyStore().containsAlias(alias))}
        fun vpnSnapshot():JSONObject {
            fun read(method:String)=JSONObject(checkNotNull(context.contentResolver.call("content://io.syn443.control".toUri(),method,null,null)).getString("json"))
            val state=read("status");val auth=read("auth-status")
            return JSONObject().put("desiredOn",state.getBoolean("desiredOn")).put("generation",state.getLong("generation"))
                .put("configRevision",state.optString("configRevision")).put("telemetryEnabled",auth.optBoolean("telemetryEnabled"))
                .put("method",auth.optString("method"))
        }
        fun assertVpnPreserved() {
            assertEquals(checkNotNull(vpnBefore).toString(),vpnSnapshot().toString())
            onWorker {assertArrayEquals(checkNotNull(sentinelPublic),DeviceKey.open(sentinelAlias).publicKey.encoded)}
        }
        private fun verifyProof(call:Call) {
            val raw=call.headers.getValue("DPoP");val parts=raw.split('.');assertEquals(3,parts.size)
            val header=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[0])))
            assertEquals("ES256",header.getValue("alg").jsonPrimitive.content)
            assertEquals("dpop+jwt",header.getValue("typ").jsonPrimitive.content)
            val jwk=header.getValue("jwk").jsonObject
            assertEquals(setOf("kty","crv","x","y"),jwk.keys);assertEquals("EC",jwk.getValue("kty").jsonPrimitive.content)
            assertEquals("P-256",jwk.getValue("crv").jsonPrimitive.content)
            val key=KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(
                BigInteger(1,Policy.decode64(jwk.getValue("x").jsonPrimitive.content)),
                BigInteger(1,Policy.decode64(jwk.getValue("y").jsonPrimitive.content))),Identity.ecParameters)) as ECPublicKey
            assertTrue(Signature.getInstance("SHA256withECDSA").run {
                initVerify(key);update((parts[0]+"."+parts[1]).toByteArray(Charsets.US_ASCII));verify(der(Policy.decode64(parts[2])))
            })
            val claims=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[1])))
            assertEquals("POST",claims.getValue("htm").jsonPrimitive.content);assertEquals(call.url,claims.getValue("htu").jsonPrimitive.content)
            assertTrue(kotlin.math.abs(claims.getValue("iat").jsonPrimitive.long-wall/1000)<=30)
            assertTrue(proofIDs.add(claims.getValue("jti").jsonPrimitive.content))
            val actualThumb=Identity.thumbprint(key)
            val reserved=onWorker {journal().read().also {if(it.alias.isNotEmpty())aliases+=it.alias}}
            assertTrue(reserved.alias.isNotEmpty())
            assertTrue(actualThumb==onWorker {Identity.thumbprint(AdminKey.open(reserved.alias).publicKey)})
            if(call.url==oidc+"/token") {
                assertFalse("ath" in claims);assertFalse("req_hash" in claims)
                thumbprint=actualThumb
                val fields=parameters(checkNotNull(call.body).toString(Charsets.UTF_8))
                assertEquals(AdminBootstrap.CLIENT_ID,fields["client_id"])
                if(fields["grant_type"]=="authorization_code") {
                    assertEquals(AdminBootstrap.CALLBACK,fields["redirect_uri"])
                    assertTrue(savedBrowser.getValue("dpop_jkt")==actualThumb)
                    assertTrue(savedBrowser.getValue("code_challenge")==Identity.hash(fields.getValue("code_verifier").toByteArray(Charsets.US_ASCII)))
                    assertEquals("synthetic-code",fields["code"])
                } else {
                    assertEquals("refresh_token",fields["grant_type"])
                    val refresh=fields.getValue("refresh_token");assertTrue(refresh==currentRefresh && usedRefresh.add(refresh))
                }
            } else {
                assertEquals(metadata.apiOrigin+"/v1/control/action",call.url)
                assertTrue(call.headers.getValue("Authorization")=="DPoP $currentAccess")
                assertTrue(claims.getValue("ath").jsonPrimitive.content==Identity.hash(currentAccess.toByteArray(Charsets.US_ASCII)))
                assertTrue(claims.getValue("req_hash").jsonPrimitive.content==Identity.hash(checkNotNull(call.body)))
                assertFalse("nonce" in claims)
            }
        }
        fun normal(call:Call):Reply=when(call.url) {
            metadata.issuer+"/.well-known/openid-configuration"->reply(Canonical.encode(buildJsonObject {
                put("issuer",metadata.issuer);put("authorization_endpoint",oidc+"/auth");put("token_endpoint",oidc+"/token");put("jwks_uri",oidc+"/certs")
                put("id_token_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("RS256"))))
                put("dpop_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("ES256"))))
                put("code_challenge_methods_supported",JsonArray(listOf(JsonPrimitive("S256"))))
            }))
            oidc+"/certs"->reply(Canonical.encode(buildJsonObject {put("keys",JsonArray(listOf(buildJsonObject {
                put("kty","RSA");put("kid","controller-rsa");put("use","sig");put("alg","RS256")
                put("n",unsigned((rsa.public as RSAPublicKey).modulus));put("e","AQAB")
            })))}))
            oidc+"/token"->tokens()
            metadata.apiOrigin+"/v1/control/action"-> {
                val request=Identity.objectJSON(checkNotNull(call.body).toString(Charsets.UTF_8))
                assertEquals(setOf("version","action","requestId","payload"),request.keys)
                assertEquals(1,request.getValue("version").jsonPrimitive.int)
                reply(control(JSONObject(Policy.utf8(checkNotNull(call.body)))))
            }
            else->throw AssertionError("foreign HTTP origin/path")
        }
        private val actor get()=Identity.hash((metadata.issuer+"\u0000"+subject).toByteArray(Charsets.UTF_8))
        private val baseHash="a".repeat(64)
        fun store()=AdminEditorStore.isolatedForTest(context,editorNamespace,editorAlias)
        fun editorRecord():AdminEditorRecord?=onWorker {store().recoverOwned(verifiedContext().discovery.binding,actor)}
        fun publishCalls()=synchronized(calls) {calls.count {call->call.url==metadata.apiOrigin+"/v1/control/action" &&
            JSONObject(Policy.utf8(checkNotNull(call.body))).getString("action")=="configuration.publish"}}
        fun publishedBody()=synchronized(calls) {checkNotNull(calls.single {call->call.url==metadata.apiOrigin+"/v1/control/action" &&
            JSONObject(Policy.utf8(checkNotNull(call.body))).getString("action")=="configuration.publish"}.body).copyOf()}
        fun command(kind:AdminEditorCoordinator.Kind,model:AdminEditorModel)=AdminEditorCoordinator.Command(kind,model.device,
            model.documentBinding,model.localRevision,reviewBinding=model.reviewBinding,reviewDeadline=model.reviewDeadlineElapsed)
        fun editor(kind:AdminEditorCoordinator.Kind,model:AdminEditorModel?=null):AdminEditorModel {
            val operation=id();val cmd=if(model==null)AdminEditorCoordinator.Command(kind,device) else command(kind,model)
            assertTrue(controller.editorStart(operation,gen(),cmd));idle()
            val result=controller.readResult(operation,gen());assertEquals("done",result.state)
            return onWorker {AdminEditorWire.decode(result.bodyBytes())}
        }
        fun review():AdminEditorModel {
            val opened=editor(AdminEditorCoordinator.Kind.OPEN);assertEquals(AdminEditorPhase.EDITING,opened.phase)
            val reviewed=editor(AdminEditorCoordinator.Kind.PREVIEW,opened);assertEquals(AdminEditorPhase.REVIEW,reviewed.phase)
            assertTrue(reviewed.reviewDeadlineElapsed>elapsed);assertNull(editorRecord()!!.pending)
            return reviewed
        }
        private fun inventory()="""{"device":"$device","owner":"${Identity.hash("synthetic-owner".toByteArray())}","state":"assigned","revision":2,"hash":"$baseHash","policyRevision":0,"mode":"wifi","approvalUntilMs":${NOW+3_600_000},"layers":[{"id":"template-a","kind":"template","priority":0,"revision":1,"changes":[{"path":"/schemaVersion","operation":"set","value":1}],"permissions":[{"path":"/schemaVersion","mode":"free"}]},{"id":"$device","kind":"device","priority":0,"revision":1,"changes":[],"permissions":[]}],"effective":{"document":{"schemaVersion":1},"fields":{"/schemaVersion":{"layerId":"template-a","kind":"template","revision":1}},"restrictions":[{"permission":{"path":"/schemaVersion","mode":"free"},"origin":{"layerId":"template-a","kind":"template","revision":1}}]},"currentRevision":2}"""
        private fun ready(request:JSONObject):String {
            val proposal=request.getJSONObject("payload").getJSONObject("proposal")
            val bundle=proposal.getJSONArray("bundles").getJSONObject(0)
            val job=Identity.hash((actor+"\u0000"+request.getString("requestId")).toByteArray())
            val preview=JSONObject().put("schemaVersion",1).put("origin",metadata.apiOrigin).put("actor",actor)
                .put("requestId",request.getString("requestId")).put("draftId",proposal.getString("draftId"))
                .put("draftRevision",proposal.getLong("draftRevision")).put("draftHash","c".repeat(64))
                .put("targetKind","device").put("targetId",device).put("mode",proposal.getString("mode"))
                .put("dependencyHash","d".repeat(64)).put("effectiveHash","e".repeat(64))
                .put("recipients",JSONArray().put(JSONObject().put("owner",Identity.hash("synthetic-owner".toByteArray()))
                    .put("device",device).put("thumbprint",Identity.hash("synthetic-phone-key".toByteArray()))
                    .put("grantHash",Identity.hash("synthetic-grant".toByteArray())).put("baseRevision",bundle.getLong("baseRevision"))
                    .put("baseHash",bundle.getString("baseHash")).put("capabilitiesHash","b".repeat(64))))
                .put("issuedAtMs",wall).put("expiresAtMs",wall+120_000)
            val header="""{"alg":"ES256","typ":"syn443-configuration-preview+jws","kid":"synthetic-preview"}"""
            val input=Identity.encode(header.toByteArray())+"."+Identity.encode(preview.toString().toByteArray())
            val ticket=input+"."+Identity.encode(Identity.derToRaw(Signature.getInstance("SHA256withECDSA").run {
                initSign(offline.private);update(input.toByteArray(Charsets.US_ASCII));sign()
            }))
            return JSONObject().put("id",job).put("state","ready").put("result",JSONObject().put("previewId",job)
                .put("ticket",ticket).put("preview",preview)).toString()
        }
        private fun control(request:JSONObject):String=when(request.getString("action")) {
            "configuration.protocol.get"->"""{"version":1,"configurationRequestVersion":1}"""
            "configuration.inventory.get"->inventory()
            "configuration.layers.drafts.list"->"""{"targetKind":"device","targetId":"$device","drafts":[]}"""
            "configuration.preview.request","configuration.publish"->{
                val record=checkNotNull(editorRecord());val pending=checkNotNull(record.pending)
                assertEquals(request.getString("requestId"),pending.requestId)
                assertEquals(request.toString(),JSONObject(Policy.utf8(pending.body)).toString())
                if(request.getString("action")=="configuration.preview.request")ready(request) else
                    JSONObject().put("id",Identity.hash((actor+"\u0000"+request.getString("requestId")).toByteArray()))
                        .put("state","published").put("result",JSONObject().put("heads",JSONArray().put(JSONObject()
                            .put("device",device).put("revision",3).put("hash","c".repeat(64))))).toString()
            }
            else->throw AssertionError("unexpected fixed editor action")
        }
        fun tokens():Reply {
            tokenNumber++
            fun jwt(id:Boolean):String {
                val body=buildJsonObject {
                    put("iss",metadata.issuer);put("sub",subject);put("aud",if(id)AdminBootstrap.CLIENT_ID else AdminBootstrap.AUDIENCE)
                    put("azp",AdminBootstrap.CLIENT_ID);put("iat",wall/1000);put("exp",wall/1000+300);put("jti","synthetic-$tokenNumber-${Identity.random()}")
                    if(id) {put("nonce",savedBrowser.getValue("nonce"));put("auth_time",wall/1000)}
                    else {put("scope",AdminBootstrap.SCOPE);put("cnf",buildJsonObject {put("jkt",thumbprint)})}
                }
                val header=Identity.encode("""{"alg":"RS256","kid":"controller-rsa","typ":"JWT"}""".toByteArray())
                val input=header+"."+Identity.encode(Canonical.encode(body).toByteArray())
                return input+"."+Identity.encode(Signature.getInstance("SHA256withRSA").run {
                    initSign(rsa.private);update(input.toByteArray(Charsets.US_ASCII));sign()
                })
            }
            currentAccess=jwt(false);currentRefresh=Identity.random()
            return reply(Canonical.encode(buildJsonObject {
                put("token_type","DPoP");put("access_token",currentAccess);put("refresh_token",currentRefresh)
                put("expires_in",300);put("refresh_expires_in",86_400);put("scope",AdminBootstrap.SCOPE);put("id_token",jwt(true))
            }))
        }
        fun reply(text:String="{}",status:Int=200)=Reply(status,mapOf("content-type" to listOf("application/json"),
            "date" to listOf(date(wall))),text.toByteArray(Charsets.UTF_8))
        override fun close() {
            synchronized(gates) {gates.forEach {it.release.countDown()}}
            var canErase=active==null
            try {
                active?.let {owned ->
                    owned.logout(owned.status().getLong("generation"))
                    await { !owned.status().getBoolean("busy") }
                    assertTrue(owned.shutdownForTest())
                    canErase=true
                }
                assertVpnPreserved()
            }finally {
                // Never erase keys/journal beneath a worker whose actual exit is unknown.
                // A failed fixture remains isolated under its exact random namespace.
                check(canErase) {"fixture_owner_not_stopped_state_preserved"}
                try {onWorker {
                    try {journal().read().alias.takeIf {it.isNotEmpty()}?.let {aliases+=it}}catch(_:AdminKeyStorageException) {}
                    synchronized(aliases) {aliases.forEach(AdminKey::deleteOwned)}
                    DeviceKey.deleteOwned(sentinelAlias);keyStore().deleteEntry(aes);keyStore().deleteEntry(editorAlias)
                    editorDirectory.listFiles()?.forEach {entry ->
                        check(entry.name in setOf("editor.bin","editor.bin.bak","editor.bin.new"));check(entry.isFile && entry.delete())
                    }
                    check(!editorDirectory.exists() || editorDirectory.delete())
                    directory.listFiles()?.forEach {entry ->
                        check(entry.name in setOf("owner.bin","owner.bin.bak","owner.bin.new"));check(entry.delete())
                    }
                    check(!directory.exists() || directory.delete())
                }}finally {worker.shutdownNow();assertTrue(worker.awaitTermination(5,TimeUnit.SECONDS))}
            }
        }
    }
    companion object {
        private const val NOW=1_800_000_000_000L
        private val rsa:KeyPair by lazy {KeyPairGenerator.getInstance("RSA").apply {initialize(2048)}.generateKeyPair()}
        private fun ec()=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private fun keyStore()=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        private fun id()=UUID.randomUUID().toString().replace("-","")
        private fun unsigned(value:BigInteger)=Identity.encode(value.toByteArray().let {if(it[0]==0.toByte())it.copyOfRange(1,it.size) else it})
        private fun parameters(raw:String)=raw.split('&').associate {entry ->val pair=entry.split('=',limit=2)
            URLDecoder.decode(pair[0],"UTF-8") to URLDecoder.decode(pair[1],"UTF-8")}
        private fun date(value:Long)=DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'",Locale.US)
            .withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(value))
        private fun der(raw:ByteArray):ByteArray {
            require(raw.size==64)
            fun integer(bytes:ByteArray):ByteArray {val value=BigInteger(1,bytes).toByteArray();return byteArrayOf(2,value.size.toByte())+value}
            val body=integer(raw.copyOfRange(0,32))+integer(raw.copyOfRange(32,64))
            return byteArrayOf(0x30,body.size.toByte())+body
        }
        private fun signManifest(value:ServiceDescriptor,anchor:TrustAnchor,key:KeyPair):String {
            val header=Canonical.encode(buildJsonObject {put("alg","ES256");put("kid",anchor.id);put("typ","syn443-bootstrap+jws")})
            val body=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(value)))
            val input=Identity.encode(header.toByteArray())+"."+Identity.encode(body.toByteArray())
            val signature=Signature.getInstance("SHA256withECDSA").run {initSign(key.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            return input+"."+Identity.encode(Identity.derToRaw(signature))
        }
        private fun await(predicate:()->Boolean) {
            val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(20)
            while(System.nanoTime()<deadline) {if(predicate())return;Thread.sleep(50)}
            throw AssertionError("bounded controller completion deadline")
        }
    }


    @Test fun currentReviewDispatchesOnlyAfterActualEncryptedPendingAndRetainsOrdinaryOwner() {
        Fixture().use {f->
            f.login();val review=f.review()
            val result=f.editor(AdminEditorCoordinator.Kind.PUBLISH,review)
            assertEquals(AdminEditorPhase.PUBLISHED,result.phase);assertEquals(3L,result.desiredHeadRevision)
            assertEquals(1,f.publishCalls());assertNull(f.editorRecord()!!.pending)
            f.phase("AUTHENTICATED");f.assertVpnPreserved()
        }
    }
    @Test fun originalReviewExpiryAtAdmissionAndBootChangeCannotDispatchFreshPublication() {
        Fixture().use {f->
            f.login();val review=f.review();val calls=f.controlCalls()
            f.elapsed=review.reviewDeadlineElapsed
            assertFalse(f.controller.editorStart(id(),f.gen(),f.command(AdminEditorCoordinator.Kind.PUBLISH,review)))
            assertEquals(calls,f.controlCalls());assertEquals(0,f.publishCalls());assertNull(f.editorRecord()!!.pending)
            f.phase("AUTHENTICATED")
        }
        Fixture().use {f->
            f.login();val review=f.review();f.boot++
            assertTrue(f.controller.editorStart(id(),f.gen(),f.command(AdminEditorCoordinator.Kind.PUBLISH,review)));f.idle()
            assertEquals(0,f.publishCalls());assertNull(f.editorRecord()!!.pending)
            assertEquals("REAUTHENTICATE",f.snapshot().getString("phase"));f.assertVpnPreserved()
        }
    }
    @Test fun reviewDeadlineAfterActualJournalCommitKeepsExactPendingAndRejectsLateHttpWithoutPolling() {
        Fixture().use {f->
            f.login();val review=f.review();val gate=f.gate();val once=AtomicBoolean()
            f.elapsed=review.reviewDeadlineElapsed-200
            f.onSource={if(f.editorRecord()?.pending?.action=="publish" && once.compareAndSet(false,true))gate.hold()}
            val operation=id();val generation=f.gen()
            assertTrue(f.controller.editorStart(operation,generation,f.command(AdminEditorCoordinator.Kind.PUBLISH,review)))
            gate.reached()
            val committed=checkNotNull(f.editorRecord());val pending=checkNotNull(committed.pending)
            assertEquals("publish",pending.action);assertEquals(0,f.publishCalls())
            f.elapsed=review.reviewDeadlineElapsed
            // No result poll is needed to expire the active owner; a second
            // command cannot replace the still-blocked actual worker.
            assertTrue(f.snapshot().getBoolean("busy"))
            assertFalse(f.controller.editorStart(id(),generation,f.command(AdminEditorCoordinator.Kind.POLL,review)))
            gate.release.countDown();f.idle();f.onSource=null
            assertEquals(0,f.publishCalls());assertEquals(committed,f.editorRecord())
            assertArrayEquals(pending.body,checkNotNull(f.editorRecord()!!.pending).body)
            assertArrayEquals(pending.replayContext,checkNotNull(f.editorRecord()!!.pending).replayContext)
            assertEquals("gone",f.controller.readResult(operation,generation).state)
            f.phase("AUTHENTICATED");f.assertVpnPreserved()
            // Historical debt remains explicit: OPEN sends no mutation and
            // cannot manufacture another preview or change pending bytes.
            val reopened=f.editor(AdminEditorCoordinator.Kind.OPEN)
            assertEquals(AdminEditorPhase.UNCERTAIN,reopened.phase);assertEquals(0,f.publishCalls())
            assertEquals(committed,f.editorRecord())
            // An explicit historical exact retry uses its own ordinary
            // operation mailbox, never an invented fresh review deadline.
            val retried=f.editor(AdminEditorCoordinator.Kind.RETRY_EXACT,reopened)
            assertEquals(AdminEditorPhase.PUBLISHED,retried.phase);assertEquals(1,f.publishCalls())
            assertArrayEquals(pending.body,f.publishedBody())
            assertNull(f.editorRecord()!!.pending);f.phase("AUTHENTICATED")
        }
    }
}
