package io.syn443.android

import android.content.Context
import androidx.core.net.toUri
import androidx.test.core.app.ApplicationProvider
import io.syn443.android.vpn.*
import io.syn443.identity.*
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.json.JSONObject
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
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Signed synthetic authority with real isolated Keystore/journal/controller workers. Never changes VPN intent. */
class AdminControllerTest {
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
            },{boot},{elapsed},refreshDiscovery={metadataCalls.incrementAndGet();onMetadata?.invoke()})
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
                when(request.getValue("action").jsonPrimitive.content) {
                    "configuration.devices.list"->reply("""{"devices":[{"device":"$device","policyRevision":0,"desiredRevision":0,"report":{"state":"not_issued","activePolicyRevision":0}}],"next":"","observedAtMs":$wall}""")
                    "configuration.inventory.get"->reply("""{"device":"$device","owner":"synthetic-owner","state":"unassigned","revision":0,"hash":"","policyRevision":0,"mode":"","approvalUntilMs":0,"layers":[],"currentRevision":0,"publicationSource":"not_issued"}""")
                    "configuration.runtime.get"->reply("""{"device":"$device","observedAtMs":$wall,"state":"none"}""")
                    else->throw AssertionError("arbitrary control action escaped the typed API")
                }
            }
            else->throw AssertionError("foreign HTTP origin/path")
        }
        fun tokens():Reply {
            tokenNumber++
            fun jwt(id:Boolean):String {
                val body=buildJsonObject {
                    put("iss",metadata.issuer);put("sub",subject);put("aud",if(id)AdminBootstrap.CLIENT_ID else AdminBootstrap.AUDIENCE)
                    put("azp",AdminBootstrap.CLIENT_ID);put("iat",wall/1000);put("exp",wall/1000+300);put("jti","synthetic-$tokenNumber-${Identity.random()}")
                    if(id)put("nonce",savedBrowser.getValue("nonce"))
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
                    DeviceKey.deleteOwned(sentinelAlias);keyStore().deleteEntry(aes)
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

    @Test fun signedAdminLoginAndThreePrivateReadsKeepDeviceVpnAndPublicStatusUnchanged() {
        Fixture().use {f ->
            val handoff=f.openBrowser();assertEquals(f.elapsed+5000,handoff.expiresAtElapsedMs)
            val reserved=f.record();assertEquals(AdminKeyPhase.BROWSER,reserved.phase)
            assertTrue(f.onWorker {keyStore().containsAlias(reserved.alias)})
            assertTrue(f.controller.callback(f.callback()));f.phase("AUTHENTICATED")
            assertEquals(AdminKeyPhase.AUTHENTICATED,f.record().phase)
            for(kind in listOf("devices","configuration","runtime")) {
                val result=f.read(kind);assertEquals("done",result.state)
                val bytes=result.bodyBytes();assertTrue(bytes.isNotEmpty());bytes.fill(0)
                assertFalse(result.bodyBytes().all {it==0.toByte()})
                assertFalse(result.toString().contains(f.device))
            }
            assertEquals(3,f.controlCalls());assertEquals(1,f.tokenCalls())
            val status=f.snapshot();assertEquals(setOf("generation","phase","busy","reason"),status.keys().asSequence().toSet())
            assertFalse(status.toString().contains(f.metadata.issuer));assertFalse(status.toString().contains(reserved.alias))
            f.assertVpnPreserved()
        }
    }
    @Test fun foreignCallbackPreservesUnusedAttemptWhileDenialAndCodeReplayNeverReuseCredentials() {
        Fixture().use {f ->
            f.openBrowser();val reserved=f.record();val before=f.tokenCalls()
            assertTrue(f.controller.callback(f.callback(state=Identity.random())));f.phase("BROWSER")
            assertEquals(before,f.tokenCalls());assertEquals(reserved,f.record())
            f.handoff();val raw=f.callback();assertTrue(f.controller.callback(raw));f.phase("AUTHENTICATED")
            assertFalse(f.controller.callback(raw));assertEquals(before+1,f.tokenCalls())
        }
        Fixture().use {f ->
            f.openBrowser();val alias=f.record().alias;val count=f.tokenCalls()
            assertTrue(f.controller.callback(f.callback(error="access_denied")));f.phase("REAUTHENTICATE")
            assertEquals(count,f.tokenCalls());assertEquals(AdminKeyPhase.SIGNED_OUT,f.record().phase);f.signedOutKeyAbsent(alias)
            assertFalse(f.controller.callback(f.callback()));assertEquals(count,f.tokenCalls())
        }
    }
    @Test fun revokedContextAfterRealSignedCodeDispatchCannotPublishLateSessionOrAdmitAnotherOwner() {
        for(changeDevice in listOf(false,true))Fixture().use {f ->
            f.openBrowser();val alias=f.record().alias;val gate=f.gate()
            f.onExchange={call ->f.normal(call).also {if(call.url==f.oidc+"/token")gate.hold()}}
            assertTrue(f.controller.callback(f.callback()));gate.reached()
            if(changeDevice)f.deviceBinding=Identity.hash("synthetic-reauth-context-two".toByteArray()) else f.enabled=false
            assertTrue(f.snapshot().getBoolean("busy"));assertFalse(f.controller.start(f.gen()))
            gate.release.countDown();f.phase("REAUTHENTICATE")
            assertEquals(1,f.tokenCalls());assertEquals(AdminKeyPhase.SIGNED_OUT,f.record().phase);f.signedOutKeyAbsent(alias)
            assertFalse(f.controller.readStart(id(),f.gen(),"devices",""))
        }
    }
    @Test fun logoutDuringBlockedRotatingRefreshRetainsBusyUntilActualExitAndRejectsItsLatePair() {
        Fixture().use {f ->
            f.login();val before=f.record();f.elapsed=275_000;val gate=f.gate()
            f.onExchange={call ->f.normal(call).also {if(call.url==f.oidc+"/token")gate.hold()}}
            val op=id();assertTrue(f.controller.readStart(op,f.gen(),"devices",""));gate.reached()
            val generation=f.gen();val calls=f.callCount();assertTrue(f.controller.logout(generation))
            assertTrue(f.snapshot().getBoolean("busy"));assertFalse(f.controller.shutdownForTest())
            assertFalse(f.controller.start(generation));assertFalse(f.controller.readStart(id(),generation,"devices",""))
            assertEquals(calls,f.callCount());assertEquals(before,f.record())
            assertEquals("gone",f.controller.readResult(op,generation).state);f.assertVpnPreserved()
            gate.release.countDown();f.phase("SIGNED_OUT")
            assertEquals(1,f.refreshCalls());assertEquals(0,f.controlCalls());f.signedOutKeyAbsent(before.alias)
            assertEquals(before.generation+1,f.gen())
        }
    }
    @Test fun exactReadCancellationAndMailboxExpiryNeverReleaseABlockedOwnerOrRetireAValidSession() {
        Fixture().use {f ->
            f.login();val owned=f.record();val gate=f.gate()
            f.onExchange={call ->f.normal(call).also {if(call.url==f.metadata.apiOrigin+"/v1/control/action")gate.hold()}}
            val op=id();val gen=f.gen();assertTrue(f.controller.readStart(op,gen,"devices",""));gate.reached()
            assertFalse(f.controller.readCancel(id(),gen));assertFalse(f.controller.readCancel(op,gen+1))
            assertEquals("pending",f.controller.readResult(op,gen).state)
            assertTrue(f.controller.readCancel(op,gen));assertEquals("gone",f.controller.readResult(op,gen).state)
            assertTrue(f.snapshot().getBoolean("busy"));assertFalse(f.controller.readStart(id(),gen,"devices",""))
            gate.release.countDown();f.phase("AUTHENTICATED");assertEquals(owned,f.record())
            f.onExchange=null;assertEquals("done",f.read().state)
            val expiredGate=f.gate();f.onExchange={call ->f.normal(call).also {if(call.url==f.metadata.apiOrigin+"/v1/control/action")expiredGate.hold()}}
            val expiring=id();assertTrue(f.controller.readStart(expiring,gen,"devices",""));expiredGate.reached()
            f.elapsed+=60_001;assertEquals("gone",f.controller.readResult(expiring,gen).state)
            assertTrue(f.snapshot().getBoolean("busy"));assertFalse(f.controller.readStart(id(),gen,"devices",""))
            expiredGate.release.countDown();f.phase("AUTHENTICATED");assertEquals(owned,f.record())
            f.onExchange={call ->if(call.url==f.metadata.apiOrigin+"/v1/control/action")f.reply(" ".repeat(524_289)) else f.normal(call)}
            val oversized=f.read("configuration");assertEquals("failed",oversized.state);assertTrue(oversized.bodyBytes().isEmpty())
            f.phase("AUTHENTICATED");assertEquals(owned,f.record());f.onExchange=null
            assertFalse(f.controller.readStart(id(),gen,"configuration","x".repeat(65)))
        }
    }
    @Test fun recreatedReservedBrowserAuthenticatedAndRetiringRecordsRequireFreshOwnedKeyRetirement() {
        for(phase in listOf(AdminKeyPhase.RESERVED,AdminKeyPhase.BROWSER,AdminKeyPhase.AUTHENTICATED,AdminKeyPhase.RETIRING))Fixture(false).use {f ->
            val seeded=f.seed(phase);val raw=f.file.readBytes();assertFalse(raw.toString(Charsets.ISO_8859_1).contains(seeded.alias))
            f.createController();f.phase("REAUTHENTICATE")
            assertEquals("PROCESS_RECREATED",f.snapshot().getString("reason"));assertEquals(AdminKeyPhase.SIGNED_OUT,f.record().phase)
            f.signedOutKeyAbsent(seeded.alias);assertEquals(0,f.callCount())
            assertFalse(f.controller.callback(AdminBootstrap.CALLBACK+"?code=old"))
            f.login();assertNotEquals(seeded.alias,f.record().alias)
        }
        Fixture().use {f ->
            f.login();val previous=f.record();val tokens=f.tokenCalls()
            f.restart();f.phase("REAUTHENTICATE");f.signedOutKeyAbsent(previous.alias)
            assertFalse(f.controller.readStart(id(),f.gen(),"devices",""));assertEquals(tokens,f.tokenCalls())
            f.login();assertNotEquals(previous.alias,f.record().alias);assertEquals(0,f.refreshCalls())
        }
    }
    @Test fun corruptOrMissingAdminAesKeyNeverResetsTheJournalOrCreatesANewOwner() {
        for(missing in listOf(false,true))Fixture(false).use {f ->
            val seeded=f.seed(AdminKeyPhase.BROWSER)
            if(missing)f.onWorker {keyStore().deleteEntry(f.aes)}
            else f.file.writeBytes(f.file.readBytes().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})
            val saved=f.file.readBytes();f.createController();f.phase("UNAVAILABLE")
            assertFalse(f.controller.start(f.gen()));assertEquals(0,f.callCount());assertArrayEquals(saved,f.file.readBytes())
            assertTrue(f.onWorker {keyStore().containsAlias(seeded.alias)})
        }
    }
    @Test fun dueRefreshRotatesOnceWhileUncertainDeliveryCannotReplayTheOldPair() {
        Fixture().use {f ->
            f.login();f.elapsed=275_000;assertEquals("done",f.read().state)
            assertEquals(1,f.refreshCalls());assertEquals(1,f.controlCalls());assertEquals("done",f.read().state)
            assertEquals(1,f.refreshCalls());f.phase("AUTHENTICATED")
        }
        Fixture().use {f ->
            f.login();val owned=f.record();f.elapsed=275_000
            f.onExchange={call ->if(call.url==f.oidc+"/token") {f.normal(call);throw DeliveryException(DeliveryFailure.TRANSPORT)} else f.normal(call)}
            f.read();f.phase("REAUTHENTICATE");assertEquals(1,f.refreshCalls());assertEquals(0,f.controlCalls())
            val count=f.callCount();assertFalse(f.controller.readStart(id(),f.gen(),"devices",""));assertEquals(count,f.callCount())
            f.signedOutKeyAbsent(owned.alias)
        }
    }
    @Test fun readDenialAndTransportFailurePreserveValidSessionButUnauthorizedReadRetiresIt() {
        Fixture().use {f ->
            f.login();val owned=f.record()
            for(code in listOf(403,503,-1)) {
                f.onExchange={call ->if(call.url==f.metadata.apiOrigin+"/v1/control/action") {
                    if(code<0)throw DeliveryException(DeliveryFailure.TRANSPORT) else f.reply(status=code)
                } else f.normal(call)}
                val result=f.read();assertEquals("failed",result.state)
                assertEquals(if(code==403)"ACCESS_DENIED" else "TRANSPORT",result.reason)
                f.phase("AUTHENTICATED");assertEquals(owned,f.record());assertEquals(0,f.refreshCalls())
            }
            f.onExchange=null;assertEquals("done",f.read().state)
            f.onExchange={call ->if(call.url==f.metadata.apiOrigin+"/v1/control/action")f.reply(status=401) else f.normal(call)}
            f.read();f.phase("REAUTHENTICATE");f.signedOutKeyAbsent(owned.alias)
        }
    }
    @Test fun browserHandoffsExpireConsumeOnceAndCancelOnlyTheirBlockedFreshAuthorization() {
        Fixture().use {f ->
            f.openBrowser();val before=f.record();val expiring=id();assertTrue(f.controller.prepareBrowser(expiring,f.gen()));f.idle()
            f.elapsed+=5000;assertEquals("gone",f.controller.browserResult(expiring,f.gen()).state)
            val gate=f.gate();f.onSource={gate.hold()}
            val cancelled=id();assertTrue(f.controller.prepareBrowser(cancelled,f.gen()));gate.reached()
            assertFalse(f.controller.browserCancel(id(),f.gen()));assertFalse(f.controller.browserCancel(cancelled,f.gen()+1))
            assertTrue(f.controller.browserCancel(cancelled,f.gen()));assertEquals("gone",f.controller.browserResult(cancelled,f.gen()).state)
            assertTrue(f.snapshot().getBoolean("busy"));assertFalse(f.controller.prepareBrowser(id(),f.gen()))
            f.onSource=null;gate.release.countDown();f.phase("BROWSER");assertEquals(before,f.record())
            f.handoff();assertTrue(f.controller.callback(f.callback()));f.phase("AUTHENTICATED")
        }
        Fixture().use {f ->
            f.openBrowser();val gate=f.gate();f.onSource={gate.hold()}
            val op=id();assertTrue(f.controller.prepareBrowser(op,f.gen()));gate.reached();f.enabled=false
            f.onSource=null;gate.release.countDown();f.phase("REAUTHENTICATE")
            assertNull(f.controller.browserResult(op,f.gen()).url);assertEquals(0,f.tokenCalls())
        }
    }
    @Test fun bootClockRollbackAndNewDeviceContextCannotBorrowAnAuthenticatedOwner() {
        for(change in 0..2)Fixture().use {f ->
            f.login();val alias=f.record().alias;val calls=f.controlCalls()
            when(change) {0->f.boot++;1->f.elapsed=999;else->f.deviceBinding=Identity.hash("reauthentication-revision-changed".toByteArray())}
            f.read();f.phase("REAUTHENTICATE");assertEquals(calls,f.controlCalls());f.signedOutKeyAbsent(alias)
        }
    }
    @Test fun cancelledPublicationOfAnAlreadyReturnedRefreshRetiresItsConsumedFamilyImmediately() {
        Fixture().use {f ->
            f.login();val owned=f.record();f.elapsed=275_000
            val gate=f.gate();val sourceReads=AtomicInteger();var delivered=false
            f.onExchange={call ->f.normal(call).also {if(call.url==f.oidc+"/token")delivered=true}}
            f.onSource={if(delivered && sourceReads.incrementAndGet()==4) {
                // Controller post-HTTP admission, then core post-HTTP and post-JWT
                // checks run first. The fourth read is after refresh returned,
                // before the controller publishes its rotation.
                assertTrue(Thread.currentThread().stackTrace.none {it.className.startsWith("io.syn443.identity.AdminProtocol")})
                gate.hold()
            }}
            val gen=f.gen();val op=id();assertTrue(f.controller.readStart(op,gen,"devices",""));gate.reached()
            assertTrue(f.controller.readCancel(op,gen));assertTrue(f.snapshot().getBoolean("busy"))
            f.onSource=null;gate.release.countDown();f.phase("REAUTHENTICATE")
            assertEquals(1,f.refreshCalls());assertEquals(0,f.controlCalls());f.signedOutKeyAbsent(owned.alias)
            assertEquals(AdminKeyPhase.SIGNED_OUT,f.record().phase)
            assertFalse(f.controller.readStart(id(),f.gen(),"devices",""))
        }
    }
    @Test fun missingMetadataWaitsForFreshVerifiedSourceBeforeReservingAnAdminKey() {
        Fixture().use {f ->
            f.enabled=false;val trust=f.trustFingerprint();val gate=f.gate()
            f.onMetadata={
                val captured=f.verifiedContext()
                gate.hold();f.enabled=true;captured
            }
            assertTrue(f.controller.start(f.gen()));gate.reached()
            assertTrue(f.snapshot().getBoolean("busy"));f.assertNoAdminReservation()
            assertEquals(0,f.callCount());assertEquals(0,f.tokenCalls());assertEquals(1,f.metadataCalls.get())
            assertFalse(f.controller.start(f.gen()));f.assertVpnPreserved()
            gate.release.countDown();f.phase("BROWSER")
            val owner=f.record();assertEquals(1L,owner.generation);assertEquals(AdminKeyPhase.BROWSER,owner.phase)
            assertTrue(f.onWorker {keyStore().containsAlias(owner.alias)})
            assertEquals(2,f.callCount());assertEquals(1,f.metadataCalls.get());assertEquals(trust,f.trustFingerprint())
            f.handoff();assertTrue(f.controller.callback(f.callback()));f.phase("AUTHENTICATED")
            assertEquals(1,f.tokenCalls());assertEquals(trust,f.trustFingerprint())
        }
        Fixture().use {f ->
            f.enabled=false
            // A genuine descriptor/ticket returned by the loader is still not a
            // published current source. Raw fetched bytes would establish even less.
            f.onMetadata={f.verifiedContext()}
            assertTrue(f.controller.start(f.gen()));f.phase("REAUTHENTICATE")
            f.assertNoAdminReservation();assertEquals(1,f.metadataCalls.get());assertEquals(0,f.callCount())
            assertFalse(f.controller.readStart(id(),f.gen(),"devices",""))
        }
    }
    @Test fun failedInvalidOrAbsentMetadataCannotCreateKeysSessionsOrAutomaticRetries() {
        for(kind in 0..2)Fixture().use {f ->
            f.enabled=false;val trust=f.trustFingerprint()
            f.onMetadata=when(kind) {
                0->null
                1->({throw AdminException(AdminFailure.INVALID_REPLY)})
                else->({throw DeliveryException(DeliveryFailure.TLS)})
            }
            assertTrue(f.controller.start(f.gen()));f.phase("REAUTHENTICATE")
            assertEquals(1,f.metadataCalls.get());assertEquals(0,f.callCount());assertEquals(0,f.tokenCalls())
            f.assertNoAdminReservation();assertEquals(trust,f.trustFingerprint());f.assertVpnPreserved()
            repeat(4) {assertFalse(f.snapshot().getBoolean("busy"));assertEquals("REAUTHENTICATE",f.snapshot().getString("phase"))}
            assertFalse(f.controller.prepareBrowser(id(),f.gen()));assertFalse(f.controller.callback(AdminBootstrap.CALLBACK+"?code=untrusted"))
            assertFalse(f.controller.readStart(id(),f.gen(),"devices",""))
            assertEquals(1,f.metadataCalls.get());assertEquals(0,f.callCount());assertEquals(trust,f.trustFingerprint())
        }
    }
    @Test fun logoutOrChangedContextDuringMetadataLoadCannotPublishALateAdminOwner() {
        for(logout in listOf(true,false))Fixture().use {f ->
            f.enabled=false;val trust=f.trustFingerprint();val gate=f.gate()
            f.onMetadata={
                val captured=f.verifiedContext()
                gate.hold();f.enabled=true;captured
            }
            val gen=f.gen();assertTrue(f.controller.start(gen));gate.reached();f.assertNoAdminReservation()
            if(logout)assertTrue(f.controller.logout(gen))
            else f.deviceBinding=Identity.hash("changed-while-owned-metadata-was-loading".toByteArray())
            assertTrue(f.snapshot().getBoolean("busy"));assertFalse(f.controller.shutdownForTest())
            assertFalse(f.controller.start(gen));assertFalse(f.controller.prepareBrowser(id(),gen))
            assertEquals(0,f.callCount());assertEquals(1,f.metadataCalls.get());f.assertVpnPreserved()
            gate.release.countDown();f.phase(if(logout)"SIGNED_OUT" else "REAUTHENTICATE")
            f.assertNoAdminReservation();assertEquals(gen,f.gen())
            assertEquals(1,f.metadataCalls.get());assertEquals(0,f.callCount());assertEquals(0,f.tokenCalls())
            assertNull(f.controller.browserResult(id(),f.gen()).url);assertEquals(trust,f.trustFingerprint())
        }
    }
}
