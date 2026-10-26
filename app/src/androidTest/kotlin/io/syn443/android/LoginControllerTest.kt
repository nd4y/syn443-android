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
        @Volatile var policyReady=false
        @Volatile var foreignPolicyKey=false
        @Volatile var overlayPolicy=false
        @Volatile var shortAccess=false
        @Volatile var dropRefresh=false
        val enrollmentEntered=CountDownLatch(1);val release=CountDownLatch(1)
        val receipts=linkedMapOf<String,String>();val enrollBodies=mutableListOf<String>();val paths=mutableListOf<String>()
        val activeKeys=mutableSetOf<String>()
        val sessions=mutableMapOf<String,DeviceSession>()
        val refreshBodies=mutableListOf<String>()
        private val refreshReceipts=mutableMapOf<String,Pair<String,String>>()
        private val policies=mutableMapOf<String,String>()
        private fun now()=System.currentTimeMillis()/1000*1000
        private fun reply(status:Int=200,text:String="{}")=Reply(status,mapOf(
            "content-type" to listOf("application/json; charset=utf-8"),
            "date" to listOf(DateTimeFormatter.ofPattern("EEE, dd MMM uuuu HH:mm:ss 'GMT'",Locale.US).withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(now())))),text.toByteArray())
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
                if(!policyReady)return reply(202,"""{"code":"provisioning_pending"}""")
                val session=sessions.getValue(thumb);check(headers.getValue("Authorization")=="DPoP "+session.accessToken)
                val envelope=policies.getOrPut(thumb+foreignPolicyKey) {
                    val engine=if(overlayPolicy)"""{"outbounds":[{"type":"netbird","tag":"overlay","management_url":"https://overlay.example.invalid"}],"route":{"final":"overlay"}}"""
                        else """{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""
                    val payload=Payload(2,1,0,0,session.deviceId,"syn443-device",now(),now(),now()+30_000,now()+3_600_000,
                        IdentityOperation.requiredCapabilities,"m1-local-v1",Identity.encode(engine.toByteArray()),Policy.hash(engine),
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
            if(url.endsWith("/device/revoke")) {activeKeys.remove(thumb);return reply(204,"")}
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
            server.release.countDown();controller.cancel();idle();check(journal.snapshot().phase==LoginPhase.SIGNED_OUT)
            controller.shutdownTest();check(File(context.noBackupFilesDir,"login/$namespace").deleteRecursively())
            check(File(context.noBackupFilesDir,"$namespace-bootstrap.json").delete())
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
        try {f.controller.configure(Canonical.json.encodeToString(f.server.bootstrap));f.idle();block(f)} finally {f.cleanup()}
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
    @Test fun verifiedAssignmentPersistsAcrossControllerDeathAndIsErasedOnLogout() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val current=f.journal.snapshot();assertEquals(LoginPhase.POLICY_CACHED,current.phase)
        val value=checkNotNull(f.journal.readAssignment(current))
        val protected=LoginPayload.decode(f.journal.readProtected(current),current)
        assertEquals(current.policyHash,Assignments.receipt(value,current,protected,protected.session!!.time.boot,SystemClock.elapsedRealtime()))
        assertFalse(f.controller.allowsConnect()) // Native handoff is a separate acceptance gate.
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
}
