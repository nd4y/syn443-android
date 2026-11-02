package io.syn443.android

import android.content.Context
import android.os.SystemClock
import androidx.core.net.toUri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.syn443.android.vpn.DeviceKey
import io.syn443.android.vpn.LoginController
import io.syn443.android.vpn.LoginJournal
import io.syn443.android.vpn.LoginStorageException
import io.syn443.android.vpn.ManagedOverlayStorage
import io.syn443.android.vpn.OverlayVault
import io.syn443.identity.*
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import io.syn443.policy.Payload
import io.syn443.policy.Gate
import io.syn443.policy.Check
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.math.BigInteger
import java.net.URLDecoder
import java.security.KeyFactory
import java.security.KeyPairGenerator
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
import java.util.Locale
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Actual Android controller/journal/Keystore with synthetic, cryptographically checked replies. */
@RunWith(AndroidJUnit4::class)
class LoginControllerTest {
    private class Server:IdentityExchange {
        private val rsa=KeyPairGenerator.getInstance("RSA").apply {initialize(2048)}.generateKeyPair()
        private val root=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val bootstrap=Bootstrap("synthetic","https://id.example.invalid/realms/test","test","https://api.example.invalid",
            mapOf("root" to Base64.getEncoder().encodeToString(root.public.encoded)))
        @Volatile var authorization=""
        @Volatile var dropEnrollment=false
        @Volatile var holdEnrollment=false
        @Volatile var holdRevoke=false
        @Volatile var policyReady=false
        @Volatile var foreignPolicyKey=false
        @Volatile var overlayPolicy=false
        @Volatile var managedOverlayPolicy=false
        @Volatile var managedTag="home"
        @Volatile var badOverlayGrant=false
        @Volatile var dropOverlayFetch=false
        @Volatile var overlayFetchStatus=200
        @Volatile var overlayTimeAdvanceMs=0L
        @Volatile var holdOverlayFetch=false
        @Volatile var dropOverlayConsume=false
        var beforeOverlayFetch:(()->Unit)?=null
        val overlayFetchEntered=CountDownLatch(1);val releaseOverlayFetch=CountDownLatch(1)
        var overlayReference=Identity.random()
        val overlaySetupValue=UUID.randomUUID().toString()
        val overlayFetchBodies=mutableListOf<String>();val overlayConsumeBodies=mutableListOf<String>()
        fun overlayBinding(thumb:String)=OverlayCredentialBinding(OverlayAddress(bootstrap.serviceId,LoginRecovery.ownerTag(bootstrap,"synthetic-owner"),sessions.getValue(thumb).deviceId,
            "home","netbird","fixture-resource","fixture-network",1,"https://overlay.example.invalid"),thumb,overlayReference,1,0,now()+3_600_000)
        private fun managedEngine(thumb:String):String {
            val b=overlayBinding(thumb);val a=b.address
            return org.json.JSONObject().put("outbounds",org.json.JSONArray().put(org.json.JSONObject().put("type","netbird").put("tag",managedTag)
                .put("management_url",a.managementURL).put("managed",org.json.JSONObject().put("overlayId",a.overlayId).put("resourceId",a.resourceId)
                    .put("networkId",a.networkId).put("identityEpoch",a.identityEpoch).put("setupReference",b.reference).put("setupVersion",b.version))))
                .put("route",org.json.JSONObject().put("final",managedTag)).toString()
        }
        private fun overlayReply(thumb:String,request:ByteArray,consume:Boolean):Reply {
            val session=sessions.getValue(thumb);val b=overlayBinding(thumb)
            val operation=Identity.objectJSON(request.toString(Charsets.UTF_8))
            check(operation.keys==setOf("operationId","namespace","reference","version"))
            check(operation.getValue("namespace").jsonPrimitive.content==ManagedOverlay.namespace(b.address))
            if(consume) {
                overlayConsumeBodies+=request.toString(Charsets.UTF_8)
                if(dropOverlayConsume)throw java.io.IOException("synthetic lost overlay consumption ACK")
                return reply(text="""{"consumed":true}""",timeMs=now()+overlayTimeAdvanceMs)
            }
            check(operation.getValue("reference").jsonPrimitive.content==b.reference && operation.getValue("version").jsonPrimitive.long==b.version)
            beforeOverlayFetch?.invoke();overlayFetchBodies+=request.toString(Charsets.UTF_8);overlayFetchEntered.countDown()
            if(dropOverlayFetch)throw DeliveryException(DeliveryFailure.TRANSPORT)
            if(overlayFetchStatus!=200)return reply(status=overlayFetchStatus)
            if(holdOverlayFetch)check(releaseOverlayFetch.await(10,TimeUnit.SECONDS))
            val a=b.address
            val issued=now()+overlayTimeAdvanceMs
            val payload=buildJsonObject {
                put("schemaVersion",1);put("audience","syn443-overlay-credential")
                putJsonObject("address") {
                    put("serviceId",a.serviceId);put("ownerTag",a.ownerTag);put("deviceId",session.deviceId);put("overlayId",a.overlayId)
                    put("provider",a.provider);put("resourceId",a.resourceId);put("networkId",a.networkId);put("identityEpoch",a.identityEpoch);put("managementURL",a.managementURL)
                }
                put("keyThumbprint",if(badOverlayGrant)Identity.random() else thumb);put("reference",b.reference);put("version",b.version);put("securityEpoch",b.securityEpoch)
                put("kind","netbird.setup-key");put("issuedAtMs",issued);put("notBeforeMs",issued);put("expiresMs",issued+300_000);put("value",overlaySetupValue)
            }
            val input=Identity.encode("""{"alg":"ES256","kid":"root","typ":"syn443-overlay-credential+jws"}""".toByteArray())+"."+Identity.encode(Canonical.encode(payload).toByteArray())
            val envelope=input+"."+Identity.encode(Identity.derToRaw(Signature.getInstance("SHA256withECDSA").run {initSign(root.private);update(input.toByteArray());sign()}))
            return reply(text=Canonical.encode(buildJsonObject{put("consumed",false);put("envelope",envelope)}),timeMs=issued)
        }
        @Volatile var policyRevision=1L
        @Volatile var engineTag="direct"
        @Volatile var policyStatus=200
        @Volatile var policyProblem="test_failure"
        @Volatile var shortAccess=false
        @Volatile var dropRefresh=false
        @Volatile var chatStatus=200
        val enrollmentEntered=CountDownLatch(1);val release=CountDownLatch(1)
        val revokeEntered=CountDownLatch(1);val releaseRevoke=CountDownLatch(1)
        val receipts=linkedMapOf<String,String>();val enrollBodies=mutableListOf<String>();val paths=mutableListOf<String>()
        val activeKeys=mutableSetOf<String>()
        val sessions=mutableMapOf<String,DeviceSession>()
        val refreshBodies=mutableListOf<String>()
        private val refreshReceipts=mutableMapOf<String,Pair<String,String>>()
        private val policies=mutableMapOf<String,String>()
        private fun now()=System.currentTimeMillis()/1000*1000
        private fun reply(status:Int=200,text:String="{}",timeMs:Long=now())=Reply(status,mapOf(
            "content-type" to listOf("application/json; charset=utf-8"),
            "date" to listOf(DateTimeFormatter.ofPattern("EEE, dd MMM uuuu HH:mm:ss 'GMT'",Locale.US).withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(timeMs)))),text.toByteArray())
        private fun jwt(id:Boolean,thumb:String):String {
            val claims=buildJsonObject {
                put("iss",bootstrap.issuer);put("sub","synthetic-owner");put("aud",if(id)bootstrap.clientId else "syn443-api")
                put("azp",bootstrap.clientId);put("iat",now()/1000);put("exp",now()/1000+300)
                if(id)put("nonce",checkNotNull(authorization.toUri().getQueryParameter("nonce"))) else putJsonObject("cnf") {put("jkt",thumb)}
            }
            val input=Identity.encode("""{"alg":"RS256","kid":"test","typ":"JWT"}""".toByteArray())+"."+Identity.encode(Canonical.encode(claims).toByteArray())
            return input+"."+Identity.encode(Signature.getInstance("SHA256withRSA").run {initSign(rsa.private);update(input.toByteArray());sign()})
        }
        private fun checkedProof(method:String,url:String,headers:Map<String,String>,body:ByteArray?):String {
            val parts=headers.getValue("DPoP").split('.')
            val header=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[0])));val jwk=header.getValue("jwk").jsonObject
            val key=KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(
                BigInteger(1,Policy.decode64(jwk.getValue("x").jsonPrimitive.content)),BigInteger(1,Policy.decode64(jwk.getValue("y").jsonPrimitive.content))),Identity.ecParameters)) as ECPublicKey
            val raw=Policy.decode64(parts[2]);require(raw.size==64)
            val r=BigInteger(1,raw.copyOfRange(0,32)).toByteArray();val s=BigInteger(1,raw.copyOfRange(32,64)).toByteArray()
            val der=byteArrayOf(0x30,(r.size+s.size+4).toByte(),2,r.size.toByte())+r+byteArrayOf(2,s.size.toByte())+s
            check(Signature.getInstance("SHA256withECDSA").run {initVerify(key);update((parts[0]+"."+parts[1]).toByteArray());verify(der)})
            val claims=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[1])))
            check(claims.getValue("htu").jsonPrimitive.content==url && claims.getValue("htm").jsonPrimitive.content==method)
            headers["Authorization"]?.let {
                check(it.startsWith("DPoP ") && claims.getValue("ath").jsonPrimitive.content==Identity.hash(it.removePrefix("DPoP ").toByteArray()))
                if(body!=null)check(claims.getValue("req_hash").jsonPrimitive.content==Identity.hash(body))
                else check("req_hash" !in claims)
            }
            return Identity.thumbprint(key)
        }
        override fun request(method:String,url:String,headers:Map<String,String>,body:ByteArray?,scope:BoundedHttp.Scope,maxBody:Int):Reply {
            paths.add(java.net.URI(url).path)
            if(url.endsWith("openid-configuration"))return reply(text=Canonical.encode(buildJsonObject {
                put("issuer",bootstrap.issuer);put("authorization_endpoint",bootstrap.issuer+"/protocol/openid-connect/auth")
                put("token_endpoint",bootstrap.issuer+"/protocol/openid-connect/token");put("jwks_uri",bootstrap.issuer+"/protocol/openid-connect/certs")
                put("id_token_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("RS256"))))
                put("dpop_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("ES256"))))
                put("code_challenge_methods_supported",JsonArray(listOf(JsonPrimitive("S256"))))
            }))
            if(url.endsWith("/certs"))return reply(text=Canonical.encode(buildJsonObject {putJsonArray("keys") {add(buildJsonObject {
                val key=rsa.public as RSAPublicKey;val bytes=key.modulus.toByteArray().dropWhile {it==0.toByte()}.toByteArray()
                put("kid","test");put("kty","RSA");put("alg","RS256");put("use","sig");put("n",Identity.encode(bytes));put("e","AQAB")
            })}}))
            val thumb=checkedProof(method,url,headers,body)
            if(java.net.URI(url).path.startsWith("/v1/device/overlay/")) {
                check(headers.getValue("Authorization")=="DPoP "+sessions.getValue(thumb).accessToken)
                return overlayReply(thumb,checkNotNull(body),url.endsWith("/consume"))
            }
            if(java.net.URI(url).path.startsWith("/v1/chat/")) {
                check(headers.getValue("Authorization")=="DPoP "+sessions.getValue(thumb).accessToken)
                return reply(chatStatus,"""{"admin":false}""")
            }
            if(url.endsWith("/token")) {
                val form=checkNotNull(body).toString(Charsets.UTF_8).split('&').associate {row->val p=row.split('=',limit=2);p[0] to URLDecoder.decode(p[1],"UTF-8")}
                check(Identity.hash(form.getValue("code_verifier").toByteArray())==authorization.toUri().getQueryParameter("code_challenge"))
                check(thumb==authorization.toUri().getQueryParameter("dpop_jkt"))
                return reply(text=Canonical.encode(buildJsonObject {put("token_type","DPoP");put("id_token",jwt(true,thumb));put("access_token",jwt(false,thumb));put("expires_in",300)}))
            }
            if(url.endsWith("/devices/enroll")) {
                val text=checkNotNull(body).toString(Charsets.UTF_8);enrollBodies.add(text)
                check(Identity.hash(Canonical.encode(Identity.objectJSON(text).getValue("key")).toByteArray())==thumb)
                val response=receipts.getOrPut(text) {
                    activeKeys.add(thumb)
                    val session=DeviceSession(Identity.random(),Identity.random(),Identity.random(),now()+(if(shortAccess)10_000 else 590_000),now()+86_000_000,0,Identity.random())
                    sessions[thumb]=session;Canonical.json.encodeToString(session)
                }
                enrollmentEntered.countDown()
                if(holdEnrollment)check(release.await(10,TimeUnit.SECONDS))
                if(dropEnrollment) {dropEnrollment=false;throw DeliveryException(DeliveryFailure.TRANSPORT)}
                return reply(text=response)
            }
            if(url.endsWith("/device/session/refresh")) {
                val text=checkNotNull(body).toString(Charsets.UTF_8);refreshBodies.add(text)
                val oldToken=headers.getValue("Authorization").removePrefix("DPoP ")
                val receipt=refreshReceipts.getOrPut(text) {
                    val old=sessions.getValue(thumb);check(oldToken==old.refreshToken)
                    val next=old.copy(accessToken=Identity.random(),refreshToken=Identity.random(),accessUntilMs=now()+590_000,
                        generation=old.generation+1,nonce=Identity.random())
                    sessions[thumb]=next;oldToken to Canonical.json.encodeToString(next)
                }
                check(receipt.first==oldToken)
                if(dropRefresh) {dropRefresh=false;throw DeliveryException(DeliveryFailure.TRANSPORT)}
                return reply(text=receipt.second)
            }
            if(url.endsWith("/device/policy")) {
                if(policyStatus!=200)return reply(policyStatus,org.json.JSONObject().put("code",policyProblem).toString())
                if(!policyReady)return reply(202,"""{"code":"provisioning_pending"}""")
                val session=sessions.getValue(thumb);check(headers.getValue("Authorization")=="DPoP "+session.accessToken)
                val envelope=policies.getOrPut(thumb+foreignPolicyKey+policyRevision) {
                    val engine=if(managedOverlayPolicy)managedEngine(thumb) else if(overlayPolicy)"""{"outbounds":[{"type":"netbird","tag":"overlay","management_url":"https://overlay.example.invalid"}],"route":{"final":"overlay"}}"""
                        else """{"outbounds":[{"type":"direct","tag":"$engineTag"}],"route":{"final":"$engineTag"}}"""
                    val payload=Payload(2,policyRevision,0,0,session.deviceId,"syn443-device",now(),now(),now()+30_000,now()+3_600_000,
                        IdentityOperation.requiredCapabilities+(if(managedOverlayPolicy)listOf("overlay.credentials.v1") else emptyList()),"m1-local-v1",Identity.encode(engine.toByteArray()),Policy.hash(engine),
                        Gate(30,false,listOf(Check("internet","https_204","https://health.example.org/generate_204"))),
                        keyThumbprint=if(foreignPolicyKey)Identity.random() else thumb)
                    val input=Identity.encode("""{"alg":"ES256","kid":"root","typ":"syn443-policy+jws"}""".toByteArray())+"."+
                        Identity.encode(Canonical.encode(Canonical.parse(Policy.json.encodeToString(payload))).toByteArray())
                    input+"."+Identity.encode(Identity.derToRaw(Signature.getInstance("SHA256withECDSA").run {initSign(root.private);update(input.toByteArray());sign()}))
                }
                val response=reply(text=envelope)
                return response.copy(headers=response.headers+mapOf("content-type" to listOf("application/jose")))
            }
            if(url.endsWith("/identity/devices/revoke")) {
                Identity.objectJSON(checkNotNull(body).toString(Charsets.UTF_8)).getValue("thumbprints").jsonArray.forEach {activeKeys.remove(it.jsonPrimitive.content)}
                return reply(204,"")
            }
            if(url.endsWith("/device/revoke")) {
                revokeEntered.countDown()
                if(holdRevoke)check(releaseRevoke.await(10,TimeUnit.SECONDS))
                activeKeys.remove(thumb);return reply(204,"")
            }
            error("unexpected synthetic endpoint")
        }
    }
    private val context=ApplicationProvider.getApplicationContext<Context>()
    private fun until(predicate:()->Boolean) {
        val end=SystemClock.elapsedRealtime()+20_000
        while(!predicate()) {check(SystemClock.elapsedRealtime()<end) {"isolated login timed out"};Thread.sleep(50)}
    }
    private inner class Fixture(val server:Server=Server(),val beforeQueue:(()->Unit)?=null) {
        val namespace="test-"+UUID.randomUUID().toString()
        var controller=LoginController.isolatedForTest(context,namespace,server,beforeQueue)
        val journal=LoginJournal(context,namespace)
        fun idle()=until {!controller.status().getBoolean("busy")}
        fun begin():String {
            val generation=journal.snapshot().generation;controller.start(generation);idle()
            check(controller.status().getBoolean("browserReady"));server.authorization=controller.browserUrl(generation+1)
            val state=checkNotNull(server.authorization.toUri().getQueryParameter("state"))
            return Identity.callback+"?"+Identity.form(mapOf("state" to state,"iss" to server.bootstrap.issuer,"code" to "synthetic-code"))
        }
        fun restart() {idle();controller.shutdownTest();controller=LoginController.isolatedForTest(context,namespace,server,beforeQueue);controller.recover();idle()}
        fun cleanup() {
            server.release.countDown();server.releaseRevoke.countDown();server.releaseOverlayFetch.countDown();controller.cancel();idle();check(journal.snapshot().phase==LoginPhase.SIGNED_OUT)
            controller.shutdownTest();check(File(context.noBackupFilesDir,"login/$namespace").deleteRecursively())
            val bootstrap=File(context.noBackupFilesDir,"$namespace-bootstrap.json")
            android.util.AtomicFile(bootstrap).delete()
            check(listOf(bootstrap,File(bootstrap.path+".bak"),File(bootstrap.path+".new")).none {it.exists()})
        }
    }
    private fun fixture(beforeQueue:(()->Unit)?=null,block:(Fixture)->Unit) {
        check(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        context.contentResolver.call("content://io.syn443.control".toUri(),"disconnect",null,null)
        until {
            val raw=context.contentResolver.call("content://io.syn443.control".toUri(),"status",null,null)?.getString("json")
            raw!=null && org.json.JSONObject(raw).let {!it.optBoolean("desiredOn") && !it.optBoolean("engineActive")}
        }
        val f=Fixture(beforeQueue=beforeQueue)
        var failure:Throwable?=null
        try {
            f.controller.configure(Canonical.json.encodeToString(f.server.bootstrap));f.idle()
            check(f.controller.status().getBoolean("configured")) {"isolated bootstrap was not committed"}
            block(f)
        } catch(e:Throwable) {failure=e;throw e}
        finally {try {f.cleanup()} catch(e:Throwable) {if(failure==null)throw e else failure.addSuppressed(e)}}
    }
    @Test fun pendingPollFencesStaleGenerationAndCannotReviveLogout() {
        val pause=AtomicBoolean();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        fixture(beforeQueue={if(pause.compareAndSet(true,false)) {entered.countDown();check(release.await(5,TimeUnit.SECONDS))}}) {f->
            f.controller.callback(f.begin());f.idle()
            val generation=f.journal.snapshot().generation
            assertEquals(LoginPhase.PROVISIONING,f.journal.snapshot().phase)
            assertFalse(f.controller.pollProvisioning(generation+1));assertFalse(f.controller.pollProvisioning(generation))
            val requests=f.server.paths.count {it=="/v1/device/policy"}
            val caller=java.util.concurrent.Executors.newSingleThreadExecutor()
            try {
                pause.set(true)
                val polling=caller.submit {until {f.controller.pollProvisioning(generation)}}
                assertTrue(entered.await(12,TimeUnit.SECONDS));assertTrue(f.controller.status().getBoolean("busy"))
                assertFalse(f.controller.pollProvisioning(generation))
                f.controller.cancel();release.countDown();polling.get(10,TimeUnit.SECONDS);f.idle()
                assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
                assertFalse(f.controller.pollProvisioning(generation))
                assertEquals(requests,f.server.paths.count {it=="/v1/device/policy"})
            } finally {release.countDown();caller.shutdownNow()}
        }
    }
    @Test fun acceptedCommandIsBusyBeforeExecutorAdmissionAndCancellationDrainsItExactlyOnce() {
        val pause=java.util.concurrent.atomic.AtomicBoolean()
        val entered=CountDownLatch(1);val release=CountDownLatch(1)
        fixture(beforeQueue={if(pause.get()) {entered.countDown();check(release.await(5,TimeUnit.SECONDS))}}) {f->
            val caller=java.util.concurrent.Executors.newSingleThreadExecutor()
            try {
                pause.set(true);val accepted=caller.submit {f.controller.start(0)}
                assertTrue(entered.await(3,TimeUnit.SECONDS))
                assertTrue(f.controller.status().getBoolean("busy"))
                assertThrows(IllegalArgumentException::class.java) {f.controller.start(0)}
                f.controller.cancel();assertTrue(f.controller.status().getBoolean("busy"))
                pause.set(false);release.countDown();accepted.get(3,TimeUnit.SECONDS);f.idle()
                assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
                assertEquals(0L,f.journal.snapshot().generation)
                assertFalse(f.controller.status().getBoolean("busy"));assertFalse(f.controller.status().getBoolean("browserReady"))
                // A cancelled pre-queue command does not poison the next admitted generation.
                f.begin();assertEquals(LoginPhase.BROWSER,f.journal.snapshot().phase)
            } finally {pause.set(false);release.countDown();caller.shutdownNow()}
        }
    }
    @Test fun fullQueueAndDiscardedCommandsCannotRemainBusyOrRunAfterCancellation() = fixture {f->
        f.server.holdEnrollment=true;f.controller.callback(f.begin())
        assertTrue(f.server.enrollmentEntered.await(10,TimeUnit.SECONDS))
        val generation=f.journal.snapshot().generation
        f.controller.retry(generation)
        assertThrows(java.util.concurrent.RejectedExecutionException::class.java) {f.controller.retry(generation)}
        assertTrue(f.controller.status().getBoolean("busy"))
        f.controller.cancel();f.server.holdEnrollment=false;f.server.release.countDown();f.idle()
        assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
        assertEquals(1,f.server.enrollBodies.size);assertFalse(f.controller.status().getBoolean("busy"))
        f.controller.callback(f.begin());f.idle()
        assertEquals(LoginPhase.PROVISIONING,f.journal.snapshot().phase)
        assertTrue(f.journal.snapshot().tombstones.isEmpty());assertEquals(1,f.server.activeKeys.size)
    }
    @Test fun actualControllerRegistersOnceAcrossRestartAndRevokesBeforeDeletingItsKey() = fixture {f->
        f.controller.callback(f.begin());f.idle()
        val s=f.journal.snapshot();assertEquals(LoginPhase.PROVISIONING,s.phase);assertEquals(1,f.server.receipts.size)
        assertFalse(f.controller.allowsConnect())
        f.restart();assertEquals(s,f.journal.snapshot());assertEquals(1,f.server.enrollBodies.size)
        f.controller.cancel();f.idle()
        assertTrue(f.server.activeKeys.isEmpty());assertTrue(f.journal.snapshot().tombstones.isEmpty())
        assertThrows(IllegalStateException::class.java) {DeviceKey.open(s.keyAlias)}
    }
    @Test fun expiredPublicationReceiptRequiresReauthenticationInsteadOfPermanentProvisioning()=fixture {f->
        f.server.policyStatus=409;f.server.policyProblem="reauthentication_required"
        f.controller.callback(f.begin());f.idle()
        val current=f.journal.snapshot();assertEquals(LoginPhase.NEEDS_REAUTH,current.phase)
        assertFalse(f.controller.pollProvisioning(current.generation))
        assertFalse(f.controller.allowsConnect());assertFalse(f.controller.status().getBoolean("busy"))
    }
    @Test fun chatReplyIsPrivateAndDenialDoesNotWithdrawAssignedPolicy()=fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val before=f.journal.snapshot();val id="a".repeat(32)
        assertTrue(f.controller.chatStart(id,before.generation,"self","{}"));f.idle()
        assertEquals("done",f.controller.chatResult(id,before.generation).getString("state"))
        assertEquals("gone",f.controller.chatResult(id,before.generation+1).getString("state"))
        assertFalse(f.controller.status().toString().contains("admin"))
        f.server.chatStatus=403
        assertTrue(f.controller.chatStart("b".repeat(32),before.generation,"inbox","{}"));f.idle()
        assertEquals("ACCESS_DENIED",f.controller.chatResult("b".repeat(32),before.generation).getString("reason"))
        assertEquals(LoginPhase.POLICY_CACHED,f.journal.snapshot().phase)
        assertEquals(before.generation,f.journal.snapshot().generation)
        assertNotNull(f.controller.assignedRuntime.read(f.journal.snapshot()).candidate)
        f.controller.cancel();f.idle()
        assertEquals("gone",f.controller.chatResult(id,before.generation).getString("state"))
    }
    @Test fun chatResumesPersistedRefreshAfterTransportLossWithoutManualLogin()=fixture {f->
        f.server.policyReady=true;f.server.shortAccess=true
        f.controller.callback(f.begin());f.idle();val initial=f.journal.snapshot()
        f.server.dropRefresh=true;f.restart();val uncertain=f.journal.snapshot()
        assertEquals(LoginPhase.REFRESHING,uncertain.phase)
        val id="e".repeat(32)
        assertFalse(f.controller.chatStart(id,uncertain.generation+1,"self","{}"))
        assertTrue(f.controller.chatStart(id,uncertain.generation,"self","{}"));f.idle()
        assertEquals("done",f.controller.chatResult(id,uncertain.generation).getString("state"))
        val resumed=f.journal.snapshot();assertEquals(LoginPhase.POLICY_CACHED,resumed.phase)
        assertEquals(initial.policyHash,resumed.policyHash);assertEquals(initial.keyAlias,resumed.keyAlias)
        assertEquals(2,f.server.refreshBodies.size);assertEquals(f.server.refreshBodies[0],f.server.refreshBodies[1])
        assertEquals(1,f.server.enrollBodies.size);assertEquals(1L,resumed.sessionGeneration)
    }
    @Test fun chatCannotResumeRefreshFromAnObsoleteBootOrBypassRecoveryAdmission()=fixture {f->
        f.server.policyReady=true;f.server.shortAccess=true
        f.controller.callback(f.begin());f.idle();f.server.dropRefresh=true;f.restart()
        val uncertain=f.journal.snapshot();assertEquals(LoginPhase.REFRESHING,uncertain.phase)
        val stale=uncertain.copy(operationBoot=uncertain.operationBoot+1,revision=uncertain.revision+1)
        f.journal.commit(uncertain,stale)
        val paths=f.server.paths.size;val id="f".repeat(32)
        assertTrue(f.controller.chatStart(id,stale.generation,"self","{}"));f.idle()
        assertEquals("REAUTHENTICATE",f.controller.chatResult(id,stale.generation).getString("reason"))
        assertEquals(LoginPhase.NEEDS_REAUTH,f.journal.snapshot().phase)
        assertEquals(paths,f.server.paths.size)
    }
    @Test fun cancelledQueuedChatNeverTransmitsAndDoesNotPoisonNextRequest() {
        val pause=AtomicBoolean();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        fixture(beforeQueue={if(pause.compareAndSet(true,false)) {entered.countDown();check(release.await(5,TimeUnit.SECONDS))}}) {f->
            f.controller.callback(f.begin());f.idle();val generation=f.journal.snapshot().generation
            val caller=java.util.concurrent.Executors.newSingleThreadExecutor();val id="c".repeat(32)
            try {
                pause.set(true);val request=caller.submit<Boolean> {f.controller.chatStart(id,generation,"send","{}")}
                assertTrue(entered.await(3,TimeUnit.SECONDS));f.controller.chatCancel(id)
                release.countDown();assertTrue(request.get(3,TimeUnit.SECONDS));f.idle()
                assertFalse(f.server.paths.any {it.startsWith("/v1/chat/")})
                assertEquals("gone",f.controller.chatResult(id,generation).getString("state"))
                assertTrue(f.controller.chatStart("d".repeat(32),generation,"self","{}"));f.idle()
                assertEquals("done",f.controller.chatResult("d".repeat(32),generation).getString("state"))
            } finally {release.countDown();caller.shutdownNow()}
        }
    }
    @Test fun verifiedAssignmentPersistsAcrossControllerDeathAndIsErasedOnLogout() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val current=f.journal.snapshot();assertEquals(LoginPhase.POLICY_CACHED,current.phase)
        val value=checkNotNull(f.journal.readAssignment(current))
        val protected=LoginPayload.decode(f.journal.readProtected(current),current)
        assertEquals(current.policyHash,Assignments.receipt(value,current,protected,protected.session!!.time.boot,SystemClock.elapsedRealtime()))
        assertTrue(f.controller.allowsConnect()) // Explicit Connect is possible; fetch never turns it on.
        val view=f.controller.status().getJSONObject("assignedPolicy")
        assertEquals("prepared",view.getString("phase"));assertTrue(view.getBoolean("candidateValidated"));assertFalse(view.getBoolean("runtimeAuthorized"))
        assertThrows(IllegalStateException::class.java) {f.controller.assignedRuntime.config(current)}
        f.restart();assertEquals(current.generation,f.journal.snapshot().generation);assertEquals(1,f.server.enrollBodies.size)
        assertEquals(value.journal,f.journal.readAssignment(f.journal.snapshot())!!.journal)
        assertTrue(f.controller.status().getJSONObject("assignedPolicy").getBoolean("candidateValidated"))
        f.controller.cancel();assertEquals("unavailable",f.controller.status().getJSONObject("assignedPolicy").getString("phase"));f.idle()
        assertFalse(File(context.noBackupFilesDir,"login/${f.namespace}/assignment.bin").exists())
        assertTrue(f.server.activeKeys.isEmpty());assertTrue(f.journal.snapshot().tombstones.isEmpty())
    }
    @Test fun managedOverlayWithoutItsCredentialNamespaceCannotBecomeARuntimeCandidate() = fixture {f->
        f.server.policyReady=true;f.server.overlayPolicy=true;f.controller.callback(f.begin());f.idle()
        val s=f.journal.snapshot();assertEquals(LoginPhase.POLICY_CACHED,s.phase)
        val view=f.controller.status().getJSONObject("assignedPolicy")
        assertFalse(view.getBoolean("candidateValidated"));assertFalse(view.getBoolean("runtimeAuthorized"))
        assertThrows(IllegalStateException::class.java) {f.controller.assignedRuntime.config(s)}
    }
    @Test fun persistedOverlayClaimsSurviveRestartAndRetireBeforeDeviceKey()=fixture{f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val before=f.journal.snapshot()
        val binding=OverlayCredentialBinding(OverlayAddress(f.server.bootstrap.serviceId,before.ownerTag,before.deviceId,"home","netbird","resource","tenant",1,"https://mesh.example.invalid"),before.thumbprint,Identity.random(),1,0,1_800_000_120_000L)
        val owned=ManagedOverlay.namespace(binding.address)
        val claimed=f.journal.commit(before,LoginRecovery.claimOverlay(before,before.generation,owned))
        val vault=OverlayVault(context,owned,{true},{0},f.namespace);vault.reserve(binding,claimed.generation)
        val storage=ManagedOverlayStorage(context,f.namespace);val directory=storage.directory(owned);check(directory.mkdirs())
        val evidence=Identity.hash("synthetic public SDK key proof".toByteArray())
        File(directory,"syn443-managed-identity.json").writeText("""{"schemaVersion":1,"namespace":"$owned","initialized":true,"identityEvidence":"$evidence"}""")
        val sdk=File(directory,"config.json").apply{writeText("synthetic owned SDK state")}
        try {
            f.restart();assertEquals(listOf(owned),f.journal.snapshot().overlayNamespaces)
            java.io.RandomAccessFile(File(context.noBackupFilesDir,"engine-owner.lock"),"rw").use{file->file.channel.lock().use{
                val started=SystemClock.elapsedRealtime();f.controller.cancel()
                assertTrue(SystemClock.elapsedRealtime()-started<1000)
                assertEquals(listOf(owned),f.journal.snapshot().retiringOverlays)
                Thread.sleep(150);assertTrue(sdk.isFile)
                assertTrue(java.security.KeyStore.getInstance("AndroidKeyStore").apply{load(null)}.containsAlias(before.keyAlias))
            }}
            f.idle();assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
            assertFalse(directory.exists());assertNull(vault.snapshot())
            assertFalse(java.security.KeyStore.getInstance("AndroidKeyStore").apply{load(null)}.containsAlias(before.keyAlias))
        } finally {
            if(directory.exists()){sdk.delete();File(directory,"syn443-managed-identity.json").delete();directory.delete()}
            directory.parentFile?.delete();directory.parentFile?.parentFile?.delete()
        }
    }
    @Test fun unreadableOwnedOverlayKeepsLogoutPendingUntilTheSameCleanupCanResume()=fixture{f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val before=f.journal.snapshot();val owned="managed-netbird/"+Identity.random()
        f.journal.commit(before,LoginRecovery.claimOverlay(before,before.generation,owned))
        val storage=ManagedOverlayStorage(context,f.namespace);val directory=storage.directory(owned);check(directory.mkdirs())
        val manifest=File(directory,"syn443-managed-identity.json").apply{writeText("corrupt")}
        val sdk=File(directory,"config.json").apply{writeText("preserve until ownership is readable")}
        try {
            f.controller.cancel();f.idle()
            assertEquals(LoginPhase.RETIRING,f.journal.snapshot().phase);assertEquals(listOf(owned),f.journal.snapshot().retiringOverlays)
            assertTrue(sdk.isFile);assertTrue(java.security.KeyStore.getInstance("AndroidKeyStore").apply{load(null)}.containsAlias(before.keyAlias))
            manifest.writeText("""{"schemaVersion":1,"namespace":"$owned","initialized":false,"identityEvidence":""}""")
            f.controller.recover();f.idle()
            assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase);assertFalse(directory.exists())
        } finally {
            if(directory.exists()){sdk.delete();manifest.delete();directory.delete()}
            directory.parentFile?.delete();directory.parentFile?.parentFile?.delete()
        }
    }
    @Test fun assignedRuntimeViewIsWorkerPreparedAndCannotOutliveLogout() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val s=f.journal.snapshot();val p=LoginPayload.decode(f.journal.readProtected(s),s)
        val state=checkNotNull(f.journal.readAssignment(s));val boot=p.session!!.time.boot
        val applying=Assignments.begin(state,s,p,listOf(false),boot,SystemClock.elapsedRealtime())
        val runtime=f.controller.assignedRuntime
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().runOnMainSync {
            assertThrows(IllegalStateException::class.java) {runtime.prepare(s,p,applying)}
        }
        val prepared=runtime.prepare(s,p,applying);runtime.publish(prepared)
        val raw=runtime.config(s);val deadline=runtime.leaseDeadline(s,Policy.hash(raw))
        assertTrue(deadline>SystemClock.elapsedRealtime())
        assertTrue(runtime.status(s).getBoolean("runtimeAuthorized"))
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().runOnMainSync {
            assertEquals(raw,runtime.config(s)) // Already verified; reads do no Keystore/disk work.
        }
        assertThrows(IllegalArgumentException::class.java) {runtime.leaseDeadline(s,Policy.hash("different"))}
        assertThrows(IllegalArgumentException::class.java) {runtime.config(s.copy(generation=s.generation+1))}
        f.controller.cancel();f.idle()
        assertThrows(IllegalStateException::class.java) {runtime.config(s)}
        assertFalse(runtime.status(f.journal.snapshot()).getBoolean("runtimeAuthorized"))
    }
    @Test fun assignedActivationPersistsBeforeUseAndCommitsAcrossControllerRestart() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val ticket=f.controller.assignmentTicket();val s=f.journal.snapshot()
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().runOnMainSync {
            assertTrue(f.controller.beginAssignment(ticket,listOf(false)))
        }
        f.idle();assertEquals("applying",f.journal.readAssignment(s)!!.journal.phase)
        val config=f.controller.assignedRuntime.config(s)
        assertTrue(f.controller.finishAssignment(ticket,listOf(true),true));f.idle()
        val committed=f.journal.readAssignment(s)!!;assertEquals("committed",committed.journal.phase)
        assertEquals(committed.journal.active,committed.journal.lastGood)
        f.restart();assertEquals(config,f.controller.assignedRuntime.config(f.journal.snapshot()))
        assertEquals("committed",f.journal.readAssignment(f.journal.snapshot())!!.journal.phase)
        assertTrue(f.controller.allowsConnect())
    }
    @Test fun assignedFailedReplacementRollsBackAndRejectsStaleActivationResults() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val first=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(first,listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(first,listOf(true),true));f.idle()
        val config=f.controller.assignedRuntime.config(f.journal.snapshot())
        f.server.policyRevision=2;f.server.engineTag="replacement"
        f.controller.retry(f.journal.snapshot().generation);f.idle();val second=f.controller.assignmentTicket()
        assertNotEquals(first,second)
        assertTrue(f.controller.beginAssignment(first,listOf(true)));f.idle()
        assertEquals("prepared",f.journal.readAssignment(f.journal.snapshot())!!.journal.phase)
        assertEquals(config,f.controller.assignedRuntime.config(f.journal.snapshot()))
        assertTrue(f.controller.beginAssignment(second,listOf(true)));f.idle()
        assertNotEquals(config,f.controller.assignedRuntime.config(f.journal.snapshot()))
        assertTrue(f.controller.finishAssignment(second,listOf(false),true));f.idle()
        val failed=f.journal.readAssignment(f.journal.snapshot())!!
        assertEquals("rolled_back",failed.journal.phase);assertEquals(listOf(2L),failed.journal.failedRevisions)
        assertEquals(config,f.controller.assignedRuntime.config(f.journal.snapshot()))
        f.server.policyRevision=3;f.controller.retry(f.journal.snapshot().generation);f.idle()
        assertEquals(failed.journal,f.journal.readAssignment(f.journal.snapshot())!!.journal)
        assertEquals(config,f.controller.assignedRuntime.config(f.journal.snapshot()))
    }
    @Test fun assignedFinishRechecksLocalProofAfterEncryptedPreparation() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val ticket=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(ticket,listOf(false)));f.idle()
        val applying=f.journal.readAssignment(f.journal.snapshot())!!
        val checks=java.util.concurrent.atomic.AtomicInteger()
        assertTrue(f.controller.finishAssignment(ticket,listOf(true),true) {checks.incrementAndGet()==1})
        f.idle()
        assertEquals(2,checks.get())
        assertEquals(applying.journal,f.journal.readAssignment(f.journal.snapshot())!!.journal)
        assertTrue(f.controller.finishAssignment(ticket,listOf(true),true) {true});f.idle()
        assertEquals("committed",f.journal.readAssignment(f.journal.snapshot())!!.journal.phase)
    }
    @Test fun assignedInterruptedActivationIsPoisonedBeforeRecoveryCanPublishIt() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val ticket=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(ticket,listOf(false)));f.idle()
        assertTrue(f.controller.status().getJSONObject("assignedPolicy").getBoolean("runtimeAuthorized"))
        f.restart();val state=f.journal.readAssignment(f.journal.snapshot())!!
        assertEquals("rolled_back",state.journal.phase);assertEquals("interrupted_activation",state.journal.reason)
        assertEquals(listOf(1L),state.journal.failedRevisions)
        assertFalse(f.controller.status().getJSONObject("assignedPolicy").getBoolean("runtimeAuthorized"))
        assertTrue(f.controller.finishAssignment(ticket,listOf(true),true));f.idle()
        assertEquals(state.journal,f.journal.readAssignment(f.journal.snapshot())!!.journal)
        assertThrows(IllegalStateException::class.java) {f.controller.assignedRuntime.config(f.journal.snapshot())}
    }
    @Test fun assignedAbortAndLogoutFenceAcceptedButNotYetQueuedTransitions() {
        val admission=CountDownLatch(1);val release=CountDownLatch(1);val pause=AtomicBoolean(false)
        fixture(beforeQueue={if(pause.compareAndSet(true,false)) {admission.countDown();check(release.await(10,TimeUnit.SECONDS))}}) {f->
            f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
            val ticket=f.controller.assignmentTicket()
            assertTrue(f.controller.beginAssignment(ticket,listOf(false)));f.idle()
            pause.set(true)
            val caller=java.util.concurrent.Executors.newSingleThreadExecutor()
            val accepted=caller.submit<Boolean> {f.controller.abortAssignment(ticket,"native_activation_failed")}
            try {
                assertTrue(admission.await(10,TimeUnit.SECONDS))
                assertFalse(f.controller.status().getJSONObject("assignedPolicy").getBoolean("runtimeAuthorized"))
                assertFalse(f.controller.finishAssignment(ticket,listOf(true),true))
                f.server.holdRevoke=true;f.controller.cancel()
                assertTrue(f.server.revokeEntered.await(10,TimeUnit.SECONDS))
                // Retirement occupies the worker; this current-generation retry fills its queue.
                f.controller.retry(f.journal.snapshot().generation)
                release.countDown();assertTrue(accepted.get(5,TimeUnit.SECONDS))
                assertTrue(f.controller.status().getBoolean("busy"))
            } finally {release.countDown();f.server.releaseRevoke.countDown();caller.shutdownNow()}
            f.idle()
            assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
            assertFalse(File(context.noBackupFilesDir,"login/${f.namespace}/assignment.bin").exists())
            assertTrue(f.controller.finishAssignment(ticket,listOf(true),true));f.idle()
            assertFalse(File(context.noBackupFilesDir,"login/${f.namespace}/assignment.bin").exists())
        }
    }
    @Test fun assignedTransportOutageRetainsLeaseButConfirmedDenialWithdrawsIt() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val ticket=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(ticket,listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(ticket,listOf(true),true));f.idle()
        val config=f.controller.assignedRuntime.config(f.journal.snapshot())
        f.server.policyStatus=503;f.controller.retry(f.journal.snapshot().generation);f.idle()
        assertEquals(config,f.controller.assignedRuntime.config(f.journal.snapshot()));assertTrue(f.controller.allowsConnect())
        f.server.policyStatus=403;f.controller.retry(f.journal.snapshot().generation);f.idle()
        assertEquals(LoginPhase.NEEDS_REAUTH,f.journal.snapshot().phase);assertFalse(f.controller.allowsConnect())
        assertFalse(f.controller.status().getJSONObject("assignedPolicy").getBoolean("runtimeAuthorized"))
    }
    @Test fun withdrawnOrUnreadableAssignmentRejectsRuntimeCommandsWithoutCrashing() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val policies=io.syn443.android.vpn.RuntimePolicies(context) {f.controller}
        assertEquals("prepared",policies.read().journal.phase)
        // No running signed candidate exists yet. A managed client must not use
        // an unrelated default endpoint or the unapproved candidate as health.
        assertTrue(runCatching {policies.internetChecks("foreign")}.isFailure)
        val ticket=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(ticket,listOf(false)));f.idle()
        val applying=policies.read()
        val candidate=checkNotNull(policies.allowed(applying.journal.candidate,applying))
        assertEquals(candidate.payload.activation.checks.filter {it.required && it.type=="https_204"},policies.internetChecks(candidate.payload.contentHash))
        assertTrue(runCatching {policies.internetChecks("foreign")}.isFailure)
        assertTrue(f.controller.finishAssignment(f.controller.assignmentTicket(),listOf(true),true));f.idle()
        assertEquals(candidate.payload.activation.checks.filter {it.required && it.type=="https_204"},policies.internetChecks(candidate.payload.contentHash))
        f.controller.assignedRuntime.clear()
        assertTrue(runCatching {policies.internetChecks(candidate.payload.contentHash)}.isFailure)
        assertTrue(policies.managed());assertEquals("blocked",policies.read().journal.phase)
        assertFalse(policies.begin(listOf(false)));assertFalse(policies.finish(listOf(true),true))
        assertFalse(policies.rollback("native_activation_failed"))
        var localRead=false
        assertTrue(runCatching {policies.config {localRead=true;"{}"}}.isFailure);assertFalse(localRead)
        val file=File(context.noBackupFilesDir,"login/${f.namespace}/intent.json");val original=file.readBytes()
        try {
            file.writeText("corrupt public intent")
            assertTrue(policies.managed());assertEquals("blocked",policies.read().journal.phase)
            assertFalse(policies.begin(listOf(false)));assertFalse(policies.finish(listOf(true),true))
            assertFalse(policies.rollback("native_activation_failed"));assertFalse(policies.refreshAssigned(true))
        } finally {file.writeBytes(original)}
    }
    @Test fun logoutCannotAcknowledgeRetirementWhileTheNativeOwnerLockIsHeld() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val alias=f.journal.snapshot().keyAlias
        java.io.RandomAccessFile(File(context.noBackupFilesDir,"engine-owner.lock"),"rw").use {file->
            file.channel.lock().use {
                f.controller.cancel();Thread.sleep(250)
                assertEquals(LoginPhase.RETIRING,f.journal.snapshot().phase)
                assertTrue(f.controller.status().getBoolean("busy"));DeviceKey.open(alias)
            }
        }
        f.idle();assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
        assertThrows(IllegalStateException::class.java) {DeviceKey.open(alias)}
    }
    @Test fun wrongKeyAssignmentNeverGetsAReceiptOrUsableConfiguration() = fixture {f->
        f.server.policyReady=true;f.server.foreignPolicyKey=true
        f.controller.callback(f.begin());f.idle()
        val s=f.journal.snapshot();assertEquals(LoginPhase.PROVISIONING,s.phase);assertTrue(s.policyHash.isEmpty())
        assertNull(f.journal.readAssignment(s));assertFalse(f.controller.allowsConnect())
        assertEquals("INVALID_REPLY",f.controller.status().getString("reason"))
    }
    @Test fun rotatedSessionReplyLossRetriesItsPersistedOperationWithoutLosingThePolicy() = fixture {f->
        f.server.policyReady=true;f.server.shortAccess=true
        f.controller.callback(f.begin());f.idle();val first=f.journal.snapshot();assertEquals(LoginPhase.POLICY_CACHED,first.phase)
        f.server.dropRefresh=true;f.restart();val uncertain=f.journal.snapshot();assertEquals(LoginPhase.REFRESHING,uncertain.phase)
        f.restart();val resumed=f.journal.snapshot()
        assertEquals(LoginPhase.POLICY_CACHED,resumed.phase);assertEquals(1L,resumed.sessionGeneration)
        assertEquals(first.policyHash,resumed.policyHash);assertEquals(first.keyAlias,resumed.keyAlias)
        assertEquals(2,f.server.refreshBodies.size);assertEquals(f.server.refreshBodies[0],f.server.refreshBodies[1])
        assertEquals(1,f.server.enrollBodies.size);assertEquals(1L,f.server.sessions.getValue(resumed.thumbprint).generation)
    }
    @Test fun lostEnrollmentReplyRetriesExactPersistedBodyAndKeyAfterControllerRestart() = fixture {f->
        f.server.dropEnrollment=true;f.controller.callback(f.begin());f.idle()
        val uncertain=f.journal.snapshot();assertEquals(LoginPhase.ENROLLING,uncertain.phase)
        assertEquals(1,f.server.receipts.size);f.restart()
        val registered=f.journal.snapshot();assertEquals(LoginPhase.PROVISIONING,registered.phase)
        assertTrue(registered.keyAlias==uncertain.keyAlias && registered.generation==uncertain.generation)
        assertEquals(2,f.server.enrollBodies.size);assertTrue(f.server.enrollBodies[0]==f.server.enrollBodies[1]);assertEquals(1,f.server.receipts.size)
    }
    @Test fun cancelledCommittedEnrollmentCannotReturnAndFreshOwnerLoginCleansItsOrphan() = fixture {f->
        f.server.holdEnrollment=true;f.controller.callback(f.begin())
        assertTrue(f.server.enrollmentEntered.await(10,TimeUnit.SECONDS))
        val old=f.journal.snapshot();val started=SystemClock.elapsedRealtime();f.controller.cancel()
        assertTrue(SystemClock.elapsedRealtime()-started<3000)
        assertFalse(File(context.noBackupFilesDir,"login/${f.namespace}/protected.bin").exists())
        f.server.holdEnrollment=false;f.server.release.countDown();f.idle()
        assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase);assertEquals(1,f.journal.snapshot().tombstones.size)
        assertThrows(IllegalStateException::class.java) {DeviceKey.open(old.keyAlias)}
        f.controller.callback(f.begin());f.idle()
        assertEquals(LoginPhase.PROVISIONING,f.journal.snapshot().phase);assertTrue(f.journal.snapshot().tombstones.isEmpty())
        assertEquals(1,f.server.activeKeys.size)
        val cleanup=f.server.paths.indexOf("/v1/identity/devices/revoke");assertTrue(cleanup>0 && cleanup<f.server.paths.lastIndexOf("/v1/devices/enroll"))
    }
    @Test fun unreadableJournalStillCancelsNetworkAndRetiresTheOwnedPrivateKey() = fixture {f->
        f.server.holdEnrollment=true;f.controller.callback(f.begin())
        assertTrue(f.server.enrollmentEntered.await(10,TimeUnit.SECONDS))
        val old=f.journal.snapshot();val file=File(context.noBackupFilesDir,"login/${f.namespace}/intent.json")
        val original=file.readBytes()
        try {
            file.writeText("corrupt public intent")
            assertThrows(LoginStorageException::class.java) {f.controller.cancel()}
            f.server.release.countDown();f.idle()
            assertEquals("BLOCKED",f.controller.status().getString("phase"))
            assertThrows(IllegalStateException::class.java) {DeviceKey.open(old.keyAlias)}
        } finally {file.writeBytes(original);f.server.release.countDown()}
        // Restoring only public metadata cannot revive the deleted proof key or apply a late reply.
        assertEquals(LoginPhase.ENROLLING,f.journal.snapshot().phase)
        f.controller.cancel();f.idle()
        assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
        assertEquals(1,f.journal.snapshot().tombstones.size)
        assertFalse(File(context.noBackupFilesDir,"login/${f.namespace}/protected.bin").exists())
    }

    @Test fun managedControllerClaimsNamespaceBeforeFetchAndRestoresProtectedMaterialWithoutRefetch()=fixture{f->
        f.server.policyReady=true;f.server.managedOverlayPolicy=true
        f.server.beforeOverlayFetch={
            val login=f.journal.snapshot();val binding=f.server.overlayBinding(login.thumbprint)
            assertEquals(listOf(ManagedOverlay.namespace(binding.address)),login.overlayNamespaces)
            assertEquals(LoginPhase.POLICY_CACHED,login.phase)
        }
        f.controller.callback(f.begin());f.idle()
        val login=f.journal.snapshot();val view=f.controller.assignedRuntime.read(login)
        assertTrue(f.controller.status().getJSONObject("assignedPolicy").getBoolean("candidateValidated"))
        assertFalse(f.controller.status().getJSONObject("assignedPolicy").getBoolean("runtimeAuthorized"))
        val raw=view.candidate!!.engineConfig;assertFalse(raw.contains(f.server.overlaySetupValue))
        val rendered=org.json.JSONObject(f.controller.renderAssigned(raw,File(context.noBackupFilesDir,f.namespace)))
        val outbound=rendered.getJSONArray("outbounds").getJSONObject(0)
        assertEquals(f.server.overlaySetupValue,outbound.getString("setup_key"));assertFalse(outbound.has("managed"))
        assertEquals(ManagedOverlayStorage(context,f.namespace).directory(login.overlayNamespaces.single()).absolutePath,outbound.getString("state_directory"))
        assertEquals(1,f.server.overlayFetchBodies.size)
        f.restart();assertEquals(login.overlayNamespaces,f.journal.snapshot().overlayNamespaces)
        assertTrue(f.controller.status().getJSONObject("assignedPolicy").getBoolean("candidateValidated"))
        assertEquals(1,f.server.overlayFetchBodies.size)
        assertThrows(IllegalArgumentException::class.java){f.controller.renderAssigned(raw+" ",context.noBackupFilesDir)}
    }
    @Test fun managedControllerNativeReceiptErasesGrantAndRecoversKeylessWhileConsumptionIsOffline()=fixture{f->
        f.server.policyReady=true;f.server.managedOverlayPolicy=true;f.server.dropOverlayConsume=true
        f.controller.callback(f.begin());f.idle()
        assertTrue(f.controller.beginAssignment(f.controller.assignmentTicket(),listOf(false)));f.idle()
        val applying=f.controller.assignmentTicket();val login=f.journal.snapshot()
        val raw=f.controller.assignedRuntime.config(login);val hash=Policy.hash(raw);val owned=login.overlayNamespaces.single()
        val session=UUID.randomUUID().toString();f.controller.overlayStarting(session,hash)
        val evidence=Identity.random();val proof=org.json.JSONObject().put("namespace",owned).put("identityEvidence",evidence).toString()
        assertFalse(f.controller.overlayIdentity(UUID.randomUUID().toString(),hash,proof){true})
        assertFalse(f.controller.overlayIdentity(session,hash,proof){false})
        assertTrue(f.controller.overlayIdentity(session,hash,proof){true});f.idle()
        val vault=OverlayVault(context,owned,{true},{0},f.namespace)
        assertEquals(OverlayPhase.ERASED,vault.snapshot()!!.phase);assertEquals(evidence,vault.snapshot()!!.identityEvidence)
        assertFalse(f.controller.overlayHasSetup(hash));assertTrue(f.controller.overlayNeedsRotation(hash))
        val keyless=org.json.JSONObject(f.controller.renderAssigned(raw,File(context.noBackupFilesDir,f.namespace))).getJSONArray("outbounds").getJSONObject(0)
        assertFalse(keyless.has("setup_key"));assertEquals(owned,keyless.getString("managed_namespace"))
        assertTrue(f.controller.finishAssignment(applying,listOf(true),true));f.idle()
        assertNotNull(f.journal.readAssignment(f.journal.snapshot())!!.journal.active)
        f.server.dropOverlayConsume=false;f.controller.retry(f.journal.snapshot().generation);f.idle()
        assertEquals(OverlayPhase.ACKNOWLEDGED,vault.snapshot()!!.phase)
        assertTrue(f.server.overlayConsumeBodies.isNotEmpty());assertEquals(1,f.server.overlayConsumeBodies.toSet().size)
        assertEquals(1,f.server.overlayFetchBodies.size)
        f.server.policyStatus=503;f.restart()
        assertEquals(owned,f.journal.snapshot().overlayNamespaces.single())
        assertEquals(raw,f.controller.assignedRuntime.config(f.journal.snapshot()))
        assertFalse(org.json.JSONObject(f.controller.renderAssigned(raw,File(context.noBackupFilesDir,f.namespace))).getJSONArray("outbounds").getJSONObject(0).has("setup_key"))
        assertEquals(1,f.server.overlayFetchBodies.size)
    }
    @Test fun managedControllerLogoutFencesALateCredentialAndKeepsNoRuntimeMaterial()=fixture{f->
        f.server.policyReady=true;f.server.managedOverlayPolicy=true;f.server.holdOverlayFetch=true
        f.controller.callback(f.begin());assertTrue(f.server.overlayFetchEntered.await(12,TimeUnit.SECONDS))
        val login=f.journal.snapshot();assertEquals(1,login.overlayNamespaces.size)
        f.controller.cancel();f.server.releaseOverlayFetch.countDown();f.idle()
        assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
        assertFalse(f.controller.status().getJSONObject("assignedPolicy").getBoolean("runtimeAuthorized"))
        assertTrue(f.server.overlayConsumeBodies.isEmpty())
        assertNull(OverlayVault(context,login.overlayNamespaces.single(),{false},{Long.MAX_VALUE},f.namespace).snapshot())
        assertFalse(f.controller.overlayIdentity(UUID.randomUUID().toString(),"0".repeat(64),"{}"){true})
    }
    @Test fun managedControllerRejectsSignedWrongAddressAndRetriesTheSameReservedOperation()=fixture{f->
        f.server.policyReady=true;f.server.managedOverlayPolicy=true;f.server.badOverlayGrant=true
        f.controller.callback(f.begin());f.idle()
        val login=f.journal.snapshot();val owned=login.overlayNamespaces.single()
        val vault=OverlayVault(context,owned,{true},{0},f.namespace);val pending=vault.snapshot()!!
        assertEquals(OverlayPhase.RESERVED,pending.phase)
        assertTrue(f.controller.status().getJSONObject("assignedPolicy").getBoolean("candidateValidated"))
        val waitingRaw=f.controller.assignedRuntime.read(login).candidate!!.engineConfig
        val waiting=org.json.JSONObject(f.controller.renderAssigned(waitingRaw,context.noBackupFilesDir)).getJSONArray("outbounds").getJSONObject(0)
        assertTrue(waiting.getBoolean("credential_pending"));assertFalse(waiting.has("setup_key"))
        f.server.badOverlayGrant=false;f.controller.retry(login.generation);f.idle()
        assertEquals(pending.operation,vault.snapshot()!!.operation);assertEquals(OverlayPhase.ENROLLING,vault.snapshot()!!.phase)
        assertEquals(2,f.server.overlayFetchBodies.size);assertEquals(1,f.server.overlayFetchBodies.toSet().size)
        val raw=f.controller.assignedRuntime.read(f.journal.snapshot()).candidate!!.engineConfig
        f.controller.cancel();f.idle()
        assertThrows(IllegalArgumentException::class.java){f.controller.renderAssigned(raw,context.noBackupFilesDir)}
        assertTrue(f.server.overlayConsumeBodies.isEmpty())
    }

    @Test fun managedCredentialOutageKeepsBasePolicyAndRetriesSameOperationBeforeEnrollment()=fixture{f->
        f.server.policyReady=true;f.server.managedOverlayPolicy=true;f.server.dropOverlayFetch=true
        f.controller.callback(f.begin());f.idle()
        val login=f.journal.snapshot();val owned=login.overlayNamespaces.single()
        val record=OverlayVault(context,owned,{true},{0},f.namespace).snapshot()!!
        assertEquals(OverlayPhase.RESERVED,record.phase)
        val raw=f.controller.assignedRuntime.read(login).candidate!!.engineConfig;val hash=Policy.hash(raw)
        assertEquals("waiting",f.controller.overlayLaunchMode(hash));assertFalse(f.controller.overlayHasSetup(hash))
        val waiting=org.json.JSONObject(f.controller.renderAssigned(raw,File(context.noBackupFilesDir,f.namespace))).getJSONArray("outbounds").getJSONObject(0)
        assertTrue(waiting.getBoolean("credential_pending"));assertFalse(waiting.has("setup_key"))
        assertFalse(File(waiting.getString("state_directory")).exists())
        assertTrue(f.controller.beginAssignment(f.controller.assignmentTicket(),listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(f.controller.assignmentTicket(),listOf(true),true));f.idle()
        assertEquals(raw,f.controller.assignedRuntime.config(f.journal.snapshot()))
        val beforeTime=checkNotNull(f.journal.readAssignment(f.journal.snapshot())!!.time)
        f.server.dropOverlayFetch=false;f.server.overlayTimeAdvanceMs=2_000;f.controller.retry(login.generation);f.idle()
        assertEquals("enrolling",f.controller.overlayLaunchMode(hash));assertTrue(f.controller.overlayHasSetup(hash))
        assertEquals(record.operation,OverlayVault(context,owned,{true},{0},f.namespace).snapshot()!!.operation)
        val ready=org.json.JSONObject(f.controller.renderAssigned(raw,File(context.noBackupFilesDir,f.namespace))).getJSONArray("outbounds").getJSONObject(0)
        assertEquals(f.server.overlaySetupValue,ready.getString("setup_key"));assertFalse(ready.has("credential_pending"))
        assertEquals(2,f.server.overlayFetchBodies.size);assertEquals(1,f.server.overlayFetchBodies.toSet().size)
        val persisted=checkNotNull(f.journal.readAssignment(f.journal.snapshot())!!.time)
        assertTrue(persisted.window(persisted.boot,SystemClock.elapsedRealtime()).lowerMs>beforeTime.window(beforeTime.boot,SystemClock.elapsedRealtime()).lowerMs)
        f.restart();assertEquals("enrolling",f.controller.overlayLaunchMode(hash));assertEquals(2,f.server.overlayFetchBodies.size)
    }

    @Test fun managedGrantFailureNeverUsesAKeyAndAuthenticationDenialWithdrawsBaseAuthority() {
        for(code in listOf(202,400,409,429,503,401,403))fixture{f->
            f.server.policyReady=true;f.server.managedOverlayPolicy=true;f.server.overlayFetchStatus=code
            f.controller.callback(f.begin());f.idle()
            val login=f.journal.snapshot()
            if(code==401 || code==403) {
                assertFalse(f.controller.allowsConnect())
                assertFalse(f.controller.status().getJSONObject("assignedPolicy").getBoolean("runtimeAuthorized"))
                assertFalse(f.controller.status().getJSONObject("assignedPolicy").getBoolean("candidateValidated"))
            } else {
                val candidate=checkNotNull(f.controller.assignedRuntime.read(login).candidate)
                assertEquals("waiting",f.controller.overlayLaunchMode(candidate.payload.contentHash))
                assertFalse(f.controller.overlayHasSetup(candidate.payload.contentHash))
                val outbound=org.json.JSONObject(f.controller.renderAssigned(candidate.engineConfig,File(context.noBackupFilesDir,f.namespace))).getJSONArray("outbounds").getJSONObject(0)
                assertTrue(outbound.getBoolean("credential_pending"));assertFalse(outbound.has("setup_key"))
                assertEquals(OverlayPhase.RESERVED,OverlayVault(context,login.overlayNamespaces.single(),{true},{0},f.namespace).snapshot()!!.phase)
            }
            assertEquals(1,f.server.overlayFetchBodies.size);assertTrue(f.server.overlayConsumeBodies.isEmpty())
        }
    }

    @Test fun activePendingIdentityAndFreshCandidateNeverConsumeEachOthersGrant()=fixture{f->
        f.server.policyReady=true;f.server.managedOverlayPolicy=true
        f.controller.callback(f.begin());f.idle()
        assertTrue(f.controller.beginAssignment(f.controller.assignmentTicket(),listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(f.controller.assignmentTicket(),listOf(true),true));f.idle()
        val login=f.journal.snapshot();val old=f.controller.assignedRuntime.config(login);val oldHash=Policy.hash(old)
        val session=UUID.randomUUID().toString();f.controller.overlayStarting(session,oldHash)
        f.server.overlayReference=Identity.random();f.server.policyRevision=2;f.server.managedTag="renamed-home"
        f.controller.retry(login.generation);f.idle()
        assertEquals(1,f.server.overlayFetchBodies.size);assertTrue(f.server.overlayConsumeBodies.isEmpty())
        assertEquals(old,f.controller.assignedRuntime.config(f.journal.snapshot()))
        assertFalse(f.controller.status().getJSONObject("assignedPolicy").getBoolean("candidateValidated"))
        val proof=org.json.JSONObject().put("namespace",login.overlayNamespaces.single()).put("identityEvidence",Identity.random()).toString()
        assertTrue(f.controller.overlayIdentity(session,oldHash,proof){true});f.idle()
        assertTrue(f.controller.status().getJSONObject("assignedPolicy").getBoolean("candidateValidated"))
        val candidate=f.controller.assignedRuntime.read(f.journal.snapshot()).candidate!!
        assertNotEquals(oldHash,candidate.payload.contentHash);assertFalse(f.controller.overlayHasSetup(candidate.payload.contentHash))
        assertEquals(1,f.server.overlayFetchBodies.size)
        val outbound=org.json.JSONObject(f.controller.renderAssigned(candidate.engineConfig,File(context.noBackupFilesDir,f.namespace))).getJSONArray("outbounds").getJSONObject(0)
        assertFalse(outbound.has("setup_key"));assertEquals(login.overlayNamespaces.single(),outbound.getString("managed_namespace"))
    }
}
