package io.syn443.android

import android.content.Context
import android.os.SystemClock
import androidx.core.net.toUri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.syn443.android.vpn.DeviceKey
import io.syn443.android.vpn.BootstrapTrustStore
import io.syn443.android.vpn.LoginController
import io.syn443.android.vpn.assignmentRefreshDue
import io.syn443.android.vpn.needsForegroundRenewal
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
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Actual Android controller/journal/Keystore with synthetic, cryptographically checked replies. */
@RunWith(AndroidJUnit4::class)
class LoginControllerTest {
    private class Server(controlPanelOrigin:String=""):IdentityExchange {
        private val rsa=KeyPairGenerator.getInstance("RSA").apply {initialize(2048)}.generateKeyPair()
        private val root=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val bootstrap=Bootstrap("synthetic","https://id.example.invalid/realms/test","test","https://api.example.invalid",
            mapOf("root" to Base64.getEncoder().encodeToString(root.public.encoded)),controlPanelOrigin=controlPanelOrigin)
        @Volatile var authorization=""
        @Volatile var dropEnrollment=false
        @Volatile var holdCapabilities=false
        @Volatile var dropCapabilityAck=false
        @Volatile var requireCapabilityApproval=false
        @Volatile var capabilityStatus=200
        val capabilityBodies=mutableListOf<String>()
        val capabilities=mutableMapOf<String,List<String>>()
        val capabilityVersions=mutableMapOf<String,Long>()
        @Volatile var holdEnrollment=false
        @Volatile var holdRevoke=false
        @Volatile var policyReady=false
        @Volatile var panelGrant=false
        @Volatile var panelStatus=200
        @Volatile var foreignPolicyKey=false
        @Volatile var overlayPolicy=false
        @Volatile var managedOverlayPolicy=false
        @Volatile var managedTag="home"
        @Volatile var badOverlayGrant=false
        @Volatile var dropOverlayFetch=false
        @Volatile var overlayFetchStatus=200
        @Volatile var overlayTimeAdvanceMs=0L
        @Volatile var policyTimeAdvanceMs=0L
        @Volatile var overlayCredentialLifetimeMs=300_000L
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
                put("kind","netbird.setup-key");put("issuedAtMs",issued);put("notBeforeMs",issued);put("expiresMs",issued+overlayCredentialLifetimeMs);put("value",overlaySetupValue)
            }
            val input=Identity.encode("""{"alg":"ES256","kid":"root","typ":"syn443-overlay-credential+jws"}""".toByteArray())+"."+Identity.encode(Canonical.encode(payload).toByteArray())
            val envelope=input+"."+Identity.encode(Identity.derToRaw(Signature.getInstance("SHA256withECDSA").run {initSign(root.private);update(input.toByteArray());sign()}))
            return reply(text=Canonical.encode(buildJsonObject{put("consumed",false);put("envelope",envelope)}),timeMs=issued)
        }
        @Volatile var policyRevision=1L
        @Volatile var policyLifetimeMs=3_600_000L
        @Volatile var activationStatus=204
        @Volatile var technicalTelemetry=false
        val activationReports=java.util.Collections.synchronizedList(mutableListOf<DeviceActivationReport>())
        @Volatile var engineTag="direct"
        @Volatile var policyStatus=200
        @Volatile var policyProblem="test_failure"
        @Volatile var shortAccess=false
        @Volatile var dropRefresh=false
        @Volatile var subject="synthetic-owner"
        @Volatile var replaceRegisteredDevice=false
        @Volatile var chatStatus=200
        val enrollmentEntered=CountDownLatch(1);val release=CountDownLatch(1)
        val revokeEntered=CountDownLatch(1);val releaseRevoke=CountDownLatch(1)
        val receipts=linkedMapOf<String,String>();val enrollBodies=mutableListOf<String>();val paths=mutableListOf<String>()
        val activeKeys=mutableSetOf<String>()
        val sessions=mutableMapOf<String,DeviceSession>()
        val refreshBodies=mutableListOf<String>()
        private val refreshReceipts=mutableMapOf<String,Pair<String,String>>()
        private val policies=mutableMapOf<String,String>()
        // The issuer, API and their signed policy share a wall clock in this fixture.
        @Volatile var clockAdvanceMs = 0L
        private fun now()=(System.currentTimeMillis()+clockAdvanceMs)/1000*1000
        private fun reply(status:Int=200,text:String="{}",timeMs:Long=now())=Reply(status,mapOf(
            "content-type" to listOf("application/json; charset=utf-8"),
            "date" to listOf(DateTimeFormatter.ofPattern("EEE, dd MMM uuuu HH:mm:ss 'GMT'",Locale.US).withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(timeMs)))),text.toByteArray())
        private fun jwt(id:Boolean,thumb:String):String {
            val claims=buildJsonObject {
                put("iss",bootstrap.issuer);put("sub",subject);put("aud",if(id)bootstrap.clientId else "syn443-api")
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
            if(java.net.URI(url).path in setOf("/v1/device/capabilities","/v1/devices/capabilities")) {
                if(url.endsWith("/device/capabilities"))check(headers.getValue("Authorization")=="DPoP "+sessions.getValue(thumb).accessToken)
                if(capabilityStatus!=200)return reply(capabilityStatus)
                val before=capabilities.getValue(thumb)
                if(method=="GET")return reply(text=Canonical.encode(buildJsonObject {
                    put("version",capabilityVersions[thumb]?:0);put("hash",CapabilityNegotiation.hash(before))
                    put("capabilities",JsonArray(before.map(::JsonPrimitive)));put("authorityHash",Identity.hash("fixture capability scope".toByteArray()))
                }))
                val raw=checkNotNull(body).toString(Charsets.UTF_8);capabilityBodies+=raw
                val input=Identity.objectJSON(raw);val wanted=input.getValue("capabilities").jsonArray.map {it.jsonPrimitive.content}
                if(!holdCapabilities && before.toSet()!=wanted.toSet()) {
                    check(input.getValue("previousHash").jsonPrimitive.content==CapabilityNegotiation.hash(before))
                    capabilities[thumb]=wanted;capabilityVersions[thumb]=(capabilityVersions[thumb]?:0)+1
                }
                if(dropCapabilityAck && !holdCapabilities) {dropCapabilityAck=false;throw DeliveryException(DeliveryFailure.TRANSPORT)}
                return reply(text=Canonical.encode(buildJsonObject {
                    put("requestId",input.getValue("requestId"));put("state",if(holdCapabilities)"queued" else "approved")
                    put("version",if(holdCapabilities)0 else capabilityVersions.getValue(thumb))
                    put("hash",if(holdCapabilities)"" else CapabilityNegotiation.hash(wanted))
                }))
            }
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
                val declared=Identity.objectJSON(text).getValue("capabilities").jsonArray.map {it.jsonPrimitive.content}
                if(requireCapabilityApproval && capabilities[thumb]?.toSet()?.let{it!=declared.toSet()}==true)
                    return reply(409,"""{"code":"capabilities_update_required"}""")
                val response=receipts.getOrPut(text) {
                    activeKeys.add(thumb)
                    capabilities[thumb]=declared
                    val device=sessions[thumb]?.deviceId?.takeUnless {replaceRegisteredDevice} ?: Identity.random()
                    val session=DeviceSession(device,Identity.random(),Identity.random(),now()+(if(shortAccess)10_000 else 590_000),now()+86_000_000,0,Identity.random())
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
            if(url.endsWith("/device/policy/status")) {
                check(method=="POST" && headers["Authorization"]=="DPoP "+sessions.getValue(thumb).accessToken)
                activationReports.add(Canonical.json.decodeFromString<DeviceActivationReport>(checkNotNull(body).toString(Charsets.UTF_8)))
                return reply(activationStatus,if(activationStatus==204)"" else "{}")
            }
            if(url.endsWith("/device/control-panel")) {
                val session=sessions.getValue(thumb)
                check(method=="GET" && body==null && headers["Authorization"]=="DPoP "+session.accessToken)
                return reply(panelStatus,"""{"schemaVersion":1,"untilMs":${if(panelGrant)now()+60_000 else 0}}""")
            }
            if(url.endsWith("/device/policy")) {
                if(policyStatus!=200)return reply(policyStatus,org.json.JSONObject().put("code",policyProblem).toString())
                if(!policyReady)return reply(202,"""{"code":"provisioning_pending"}""")
                val session=sessions.getValue(thumb);check(headers.getValue("Authorization")=="DPoP "+session.accessToken)
                val envelope=policies.getOrPut(thumb+foreignPolicyKey+policyRevision) {
                    val engine=if(managedOverlayPolicy)managedEngine(thumb) else if(overlayPolicy)"""{"outbounds":[{"type":"netbird","tag":"overlay","management_url":"https://overlay.example.invalid"}],"route":{"final":"overlay"}}"""
                        else """{"outbounds":[{"type":"direct","tag":"$engineTag"}],"route":{"final":"$engineTag"}}"""
                    val issued=now()
                    val payload=Payload(2,policyRevision,0,0,session.deviceId,"syn443-device",issued,issued,issued+minOf(30_000L,policyLifetimeMs),issued+policyLifetimeMs,
                        IdentityOperation.requiredCapabilities+(if(managedOverlayPolicy)listOf("overlay.credentials.v1") else emptyList()),"m1-local-v1",Identity.encode(engine.toByteArray()),Policy.hash(engine),
                        Gate(30,false,listOf(Check("internet","https_204","https://health.example.org/generate_204"))),
                        keyThumbprint=if(foreignPolicyKey)Identity.random() else thumb)
                    val input=Identity.encode("""{"alg":"ES256","kid":"root","typ":"syn443-policy+jws"}""".toByteArray())+"."+
                        Identity.encode(Canonical.encode(Canonical.parse(Policy.json.encodeToString(payload))).toByteArray())
                    input+"."+Identity.encode(Identity.derToRaw(Signature.getInstance("SHA256withECDSA").run {initSign(root.private);update(input.toByteArray());sign()}))
                }
                val response=reply(text=envelope,timeMs=now()+policyTimeAdvanceMs)
                return response.copy(headers=response.headers+mapOf("content-type" to listOf("application/jose"),
                    "x-syn443-telemetry" to listOf(if(technicalTelemetry)"1" else "0")))
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
    private inner class Fixture(val server:Server=Server(),val beforeQueue:(()->Unit)?=null,val reportVpnOn:(()->Boolean)?=null,
        val testTrustAnchor:TrustAnchor?=null,val monotonicMillis:()->Long=SystemClock::elapsedRealtime) {
        val namespace="test-"+UUID.randomUUID().toString()
        var controller=LoginController.isolatedForTest(context,namespace,server,beforeQueue,anchor=testTrustAnchor,reportVpnOn=reportVpnOn,monotonicMillis=monotonicMillis)
        val journal=LoginJournal(context,namespace)
        fun idle()=until {!controller.status().getBoolean("busy")}
        fun begin():String {
            val generation=journal.snapshot().generation;controller.start(generation);idle()
            check(controller.status().getBoolean("browserReady"));server.authorization=controller.browserUrl(generation+1)
            val state=checkNotNull(server.authorization.toUri().getQueryParameter("state"))
            return Identity.callback+"?"+Identity.form(mapOf("state" to state,"iss" to server.bootstrap.issuer,"code" to "synthetic-code"))
        }
        fun repeatLogin():String {
            val login=journal.snapshot()
            check(controller.startReauthentication(login.generation,login.revision));idle()
            return repeatCallback()
        }
        fun repeatCallback():String {
            server.authorization=controller.browserUrl(journal.snapshot().generation)
            val uri=server.authorization.toUri()
            check(uri.getQueryParameter("prompt")=="login")
            return Identity.callback+"?"+Identity.form(mapOf("state" to checkNotNull(uri.getQueryParameter("state")),
                "iss" to server.bootstrap.issuer,"code" to "synthetic-code"))
        }
        fun restart() {idle();controller.shutdownTest();controller=LoginController.isolatedForTest(context,namespace,server,beforeQueue,anchor=testTrustAnchor,reportVpnOn=reportVpnOn,monotonicMillis=monotonicMillis);controller.recover();idle()}
        fun legacyCache() {
            idle();controller.shutdownTest()
            val s=journal.snapshot();val p=LoginPayload.decode(journal.readProtected(s),s).copy(advertisedCapabilities=null)
            journal.prepare(s,p.encode()).use {prepared->journal.commit(s,LoginRecovery.capabilitiesRecorded(s,s.generation,prepared.hash),prepared)}
            server.capabilities[s.thumbprint]=IdentityOperation.requiredCapabilities
            server.capabilityVersions.remove(s.thumbprint)
            controller=LoginController.isolatedForTest(context,namespace,server,beforeQueue,anchor=testTrustAnchor,reportVpnOn=reportVpnOn,monotonicMillis=monotonicMillis)
        }
        fun cleanup() {
            server.release.countDown();server.releaseRevoke.countDown();server.releaseOverlayFetch.countDown();controller.cancel();idle();check(journal.snapshot().phase==LoginPhase.SIGNED_OUT)
            controller.shutdownTest();check(File(context.noBackupFilesDir,"login/$namespace").deleteRecursively())
            val bootstrap=File(context.noBackupFilesDir,"$namespace-bootstrap.json")
            android.util.AtomicFile(bootstrap).delete()
            check(listOf(bootstrap,File(bootstrap.path+".bak"),File(bootstrap.path+".new")).none {it.exists()})
            if(testTrustAnchor!=null) {
                val owned=Regex(Regex.escape("$namespace-trust")+"(?:-admin-[A-Za-z0-9_-]{43})?\\.bin(?:\\.bak|\\.new)?")
                val parent=context.noBackupFilesDir.canonicalFile
                context.noBackupFilesDir.listFiles().orEmpty().filter {it.isFile && owned.matches(it.name)}.forEach {
                    check(it.parentFile?.canonicalFile==parent && it.delete())
                }
                check(context.noBackupFilesDir.listFiles().orEmpty().none {it.isFile && owned.matches(it.name)})
            }
        }
    }
    private fun fixture(beforeQueue:(()->Unit)?=null,controlPanelOrigin:String="",reportVpnOn:(()->Boolean)?=null,
        testTrustAnchor:TrustAnchor?=null,monotonicMillis:()->Long=SystemClock::elapsedRealtime,block:(Fixture)->Unit) {
        check(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        context.contentResolver.call("content://io.syn443.control".toUri(),"disconnect",null,null)
        until {
            val raw=context.contentResolver.call("content://io.syn443.control".toUri(),"status",null,null)?.getString("json")
            raw!=null && org.json.JSONObject(raw).let {
                it.optString("phase")=="Off" && !it.optBoolean("desiredOn") &&
                    it.optBoolean("engineStateKnown") && !it.getBoolean("engineActive")
            }
        }
        val f=Fixture(server=Server(controlPanelOrigin),beforeQueue=beforeQueue,reportVpnOn=reportVpnOn,testTrustAnchor=testTrustAnchor,monotonicMillis=monotonicMillis)
        var failure:Throwable?=null
        try {
            f.controller.configure(Canonical.json.encodeToString(f.server.bootstrap));f.idle()
            val initialized = f.controller.status()
            check(initialized.getBoolean("configured")) {
                val reason = initialized.optString("reason").takeIf { it.matches(Regex("[A-Z_]{1,48}")) } ?: "UNCLASSIFIED"
                "isolated bootstrap was not committed; reason=$reason busy=${initialized.optBoolean("busy")}"
            }
            block(f)
        } catch(e:Throwable) {failure=e;throw e}
        finally {try {f.cleanup()} catch(e:Throwable) {if(failure==null)throw e else failure.addSuppressed(e)}}
    }
    @Test fun signedAdminDiscoveryContextPreservesDeviceIdentityAndFencesTrustAndReauthentication() {
        val offline=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val anchor=TrustAnchor("synthetic-admin-context-root",Base64.getEncoder().encodeToString(offline.public.encoded),1)
        fun signed(value:Any,root:TrustAnchor,key:java.security.KeyPair,type:String):String {
            val document=when(value) {
                is ServiceDescriptor->Canonical.json.encodeToString(value)
                is RootTransition->Canonical.json.encodeToString(value)
                else->error("unsupported synthetic signed object")
            }
            val header="""{"alg":"ES256","kid":"${root.id}","typ":"$type"}"""
            val input=Identity.encode(header.toByteArray(Charsets.US_ASCII))+"."+
                Identity.encode(Canonical.encode(Canonical.parse(document)).toByteArray(Charsets.UTF_8))
            val signature=Signature.getInstance("SHA256withECDSA").run {initSign(key.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            return input+"."+Identity.encode(Identity.derToRaw(signature))
        }
        fixture(testTrustAnchor=anchor) {f->
            val store=BootstrapTrustStore(context,f.namespace+"-trust",anchor)
            val meta=AdminBootstrap("https://admin-id.example.invalid/realms/control",AdminBootstrap.CLIENT_ID,
                AdminBootstrap.AUDIENCE,"https://admin-api.example.invalid",AdminBootstrap.ASSURANCE_ACR)
            val device=f.server.bootstrap
            fun descriptor(revision:Long,admin:AdminBootstrap?,bootstrap:Bootstrap=device,rootEpoch:Long=1):ServiceDescriptor {
                val now=System.currentTimeMillis()/1000
                return ServiceDescriptor(1,"syn443-client-bootstrap",rootEpoch,revision,bootstrap.serviceId,bootstrap.issuer,
                    bootstrap.clientId,bootstrap.apiOrigin,bootstrap.roots.toMap(),now,now,now+3600,
                    controlPanelOrigin=bootstrap.controlPanelOrigin,adminBootstrap=admin)
            }
            fun accept(value:ServiceDescriptor,root:TrustAnchor=anchor,key:java.security.KeyPair=offline)=
                store.acceptDefaultDescriptor(signed(value,root,key,"syn443-bootstrap+jws"))
            fun bytes():Map<String,ByteArray> {
                val directory=File(context.noBackupFilesDir,"login/${f.namespace}")
                return directory.listFiles().orEmpty().filter {it.isFile}.associate {it.name to it.readBytes()}
            }
            fun unchanged(before:Map<String,ByteArray>) {
                val after=bytes();assertEquals(before.keys,after.keys)
                before.forEach {(name,value)->assertTrue("owned device journal bytes changed",value.contentEquals(after.getValue(name)))}
            }
            assertNull(f.controller.adminDiscoveryContext())
            assertEquals(device,accept(descriptor(1,meta)))
            assertNotNull(store.adminDiscovery(device))
            assertNull(f.controller.adminDiscoveryContext())
            f.controller.callback(f.begin());f.idle()
            assertEquals(LoginPhase.PROVISIONING,f.journal.snapshot().phase)
            assertNotNull(store.adminDiscovery(device))
            assertNull(f.controller.adminDiscoveryContext())
            assertEquals(device,accept(descriptor(2,null)))
            f.server.policyReady=true;f.server.technicalTelemetry=true
            f.controller.retry(f.journal.snapshot().generation);f.idle()
            assertEquals(LoginPhase.POLICY_CACHED,f.journal.snapshot().phase)
            assertNull(f.controller.adminDiscoveryContext())
            assertTrue(f.controller.chooseTechnicalTelemetry(f.journal.snapshot().generation,true));f.idle()
            val before=f.journal.snapshot();val original=bytes();val paths=f.server.paths.toList()
            val protectedBody=f.journal.readProtected(before)
            val authority=Identity.bootstrapAuthority(LoginPayload.decode(protectedBody,before).bootstrap)
            val publicKey=DeviceKey.open(before.keyAlias).publicKey.encoded
            val consent=context.getSharedPreferences(f.namespace+"-consent",Context.MODE_PRIVATE).all.toMap()
            assertTrue(f.controller.status().getBoolean("telemetryEnabled"))
            assertEquals(device,accept(descriptor(3,meta)))
            val first=checkNotNull(f.controller.adminDiscoveryContext())
            assertEquals(meta,first.discovery.metadata)
            assertEquals(32,Policy.decode64(first.binding).size);assertEquals(32,Policy.decode64(first.discovery.binding).size)
            assertEquals(device,accept(descriptor(4,meta.copy(apiOrigin="https://other-admin-api.example.invalid"))))
            val changed=checkNotNull(f.controller.adminDiscoveryContext())
            assertEquals(first.binding,changed.binding);assertNotEquals(first.discovery.binding,changed.discovery.binding)
            assertEquals(before,f.journal.snapshot());unchanged(original)
            assertTrue("owned device payload changed",protectedBody==f.journal.readProtected(before))
            assertEquals(authority,f.journal.snapshot().authority)
            assertArrayEquals(publicKey,DeviceKey.open(before.keyAlias).publicKey.encoded)
            assertTrue("device consent changed",consent==context.getSharedPreferences(f.namespace+"-consent",Context.MODE_PRIVATE).all)
            assertEquals(paths,f.server.paths)
            assertFalse(first.toString().contains(first.binding))
            val publicStatus=f.controller.status().toString()
            assertFalse(publicStatus.contains(first.binding));assertFalse(publicStatus.contains(first.discovery.binding))
            assertFalse(publicStatus.contains(meta.issuer))
            accept(descriptor(5,meta,device.copy(apiOrigin="https://foreign-device-api.example.invalid")))
            assertNull(f.controller.adminDiscoveryContext());unchanged(original)
            assertEquals(device,accept(descriptor(6,meta)))
            val restored=checkNotNull(f.controller.adminDiscoveryContext())
            assertEquals(first.binding,restored.binding)
            assertEquals(before,f.journal.snapshot());unchanged(original);assertEquals(paths,f.server.paths)
            f.restart()
            val restarted=checkNotNull(f.controller.adminDiscoveryContext())
            assertEquals(restored.binding,restarted.binding);assertEquals(restored.discovery.binding,restarted.discovery.binding)
            val sameOwner=f.journal.snapshot()
            f.server.policyStatus=409;f.server.policyProblem="reauthentication_required"
            f.controller.retry(sameOwner.generation);f.idle()
            assertEquals(LoginPhase.NEEDS_REAUTH,f.journal.snapshot().phase);assertNull(f.controller.adminDiscoveryContext())
            val callback=f.repeatLogin()
            assertNull(f.controller.adminDiscoveryContext())
            f.server.policyStatus=200;f.controller.callback(callback);f.idle()
            val reauthenticated=f.journal.snapshot();assertEquals(LoginPhase.POLICY_CACHED,reauthenticated.phase)
            assertEquals(sameOwner.generation,reauthenticated.generation)
            assertTrue(reauthenticated.reauthRevision>sameOwner.reauthRevision)
            assertEquals(sameOwner.keyAlias,reauthenticated.keyAlias);assertEquals(sameOwner.thumbprint,reauthenticated.thumbprint)
            assertEquals(sameOwner.deviceId,reauthenticated.deviceId);assertEquals(sameOwner.authority,reauthenticated.authority)
            assertArrayEquals(publicKey,DeviceKey.open(reauthenticated.keyAlias).publicKey.encoded)
            val current=checkNotNull(f.controller.adminDiscoveryContext())
            assertNotEquals(restarted.binding,current.binding);assertEquals(restarted.discovery.binding,current.discovery.binding)
            val reauthBytes=bytes();val reauthPaths=f.server.paths.toList()
            val nextKey=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
            val next=TrustAnchor("synthetic-next-admin-root",Base64.getEncoder().encodeToString(nextKey.public.encoded),2)
            val now=System.currentTimeMillis()/1000
            val transition=RootTransition(1,"syn443-root-transition",anchor.id,next.id,next.spki,2,now,now,now+3600)
            store.rotate(Canonical.json.encodeToString(RootRotation(
                signed(transition,anchor,offline,"syn443-root-transition+jws"),signed(transition,next,nextKey,"syn443-root-transition+jws"))))
            assertNull(f.controller.adminDiscoveryContext())
            assertEquals(device,accept(descriptor(7,meta,rootEpoch=2),next,nextKey))
            val rotated=checkNotNull(f.controller.adminDiscoveryContext())
            assertEquals(current.binding,rotated.binding);assertNotEquals(current.discovery.binding,rotated.discovery.binding)
            assertEquals(device,accept(descriptor(8,null,rootEpoch=2),next,nextKey))
            assertNull(f.controller.adminDiscoveryContext())
            assertEquals(reauthenticated,f.journal.snapshot());unchanged(reauthBytes)
            assertEquals(reauthPaths,f.server.paths)
        }
    }
    @Test fun adminDiscoveryContextRejectsMainAndBinderNamedThreadsWithoutChangingDeviceState()=fixture {f->
        val before=f.journal.snapshot();val paths=f.server.paths.toList()
        assertNull(f.controller.adminDiscoveryContext()) // Actual instrumentation worker, not the main looper.
        assertNull(f.controller.adminBootstrapContext())
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().runOnMainSync {
            assertThrows(IllegalStateException::class.java){f.controller.adminDiscoveryContext()}
            assertThrows(IllegalStateException::class.java){f.controller.adminBootstrapContext()}
            assertThrows(IllegalStateException::class.java){f.controller.applyAdminDescriptor("unowned","not-a-manifest")}
        }
        val binder=java.util.concurrent.Executors.newSingleThreadExecutor {r->Thread(r,"Binder:synthetic-admin-context")}
        try {
            assertTrue(binder.submit<Boolean> {
                try {f.controller.adminDiscoveryContext();false}catch(_:IllegalStateException){true}
            }.get(5,TimeUnit.SECONDS))
            assertTrue(binder.submit<Boolean> {
                try {f.controller.adminBootstrapContext();false}catch(_:IllegalStateException){true}
            }.get(5,TimeUnit.SECONDS))
            assertTrue(binder.submit<Boolean> {
                try {f.controller.applyAdminDescriptor("unowned","not-a-manifest");false}catch(_:IllegalStateException){true}
            }.get(5,TimeUnit.SECONDS))
        } finally {binder.shutdownNow();check(binder.awaitTermination(5,TimeUnit.SECONDS))}
        assertEquals(before,f.journal.snapshot());assertEquals(paths,f.server.paths)
    }
    @Test fun adminDescriptorRefreshUsesOrdinaryContextWithoutMetadataAndRejectsCapturedReauthenticationBinding() {
        val offline=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val anchor=TrustAnchor("synthetic-admin-refresh-root",Base64.getEncoder().encodeToString(offline.public.encoded),1)
        fun signed(value:ServiceDescriptor):String {
            val header="""{"alg":"ES256","kid":"${anchor.id}","typ":"syn443-bootstrap+jws"}"""
            val input=Identity.encode(header.toByteArray(Charsets.US_ASCII))+"."+
                Identity.encode(Canonical.encode(Canonical.parse(Canonical.json.encodeToString(value))).toByteArray(Charsets.UTF_8))
            val signature=Signature.getInstance("SHA256withECDSA").run {initSign(offline.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            return input+"."+Identity.encode(Identity.derToRaw(signature))
        }
        fixture(testTrustAnchor=anchor) {f->
            assertNull(f.controller.adminBootstrapContext())
            f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
            assertEquals(LoginPhase.POLICY_CACHED,f.journal.snapshot().phase)
            val ordinary=checkNotNull(f.controller.adminBootstrapContext())
            assertEquals(f.server.bootstrap,ordinary.bootstrap);assertNull(f.controller.adminDiscoveryContext())
            val before=f.journal.snapshot();val publicKey=DeviceKey.open(before.keyAlias).publicKey.encoded
            val protectedBody=f.journal.readProtected(before);val authority=Identity.bootstrapAuthority(ordinary.bootstrap)
            val consent=context.getSharedPreferences(f.namespace+"-consent",Context.MODE_PRIVATE).all.toMap()
            fun deviceBytes()=File(context.noBackupFilesDir,"login/${f.namespace}").listFiles().orEmpty()
                .filter {it.isFile}.associate {it.name to it.readBytes()}
            fun unchangedDevice(bytes:Map<String,ByteArray>) {
                val current=deviceBytes();assertEquals(bytes.keys,current.keys)
                bytes.forEach {(name,value)->assertArrayEquals(name,value,current.getValue(name))}
            }
            val original=deviceBytes();val paths=f.server.paths.toList()
            val now=System.currentTimeMillis()/1000
            val bootstrap=ordinary.bootstrap
            val legacy=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,bootstrap.serviceId,bootstrap.issuer,
                bootstrap.clientId,bootstrap.apiOrigin,bootstrap.roots.toMap(),now,now,now+3600,
                controlPanelOrigin=bootstrap.controlPanelOrigin)
            val store=BootstrapTrustStore(context,f.namespace+"-trust",anchor)
            assertTrue(store.refreshAdminDescriptor(signed(legacy),bootstrap))
            val root=store.adaptiveAuthorityFingerprint()
            assertNull(f.controller.adminDiscoveryContext())
            assertEquals(ordinary.binding,checkNotNull(f.controller.adminBootstrapContext()).binding)
            val meta=AdminBootstrap("https://admin-id.example.invalid/realms/control",AdminBootstrap.CLIENT_ID,
                AdminBootstrap.AUDIENCE,"https://admin-api.example.invalid",AdminBootstrap.ASSURANCE_ACR)
            val raw=signed(legacy.copy(revision=2,adminBootstrap=meta))
            val applied=checkNotNull(f.controller.applyAdminDescriptor(ordinary.binding,raw))
            assertEquals(ordinary.binding,applied.binding);assertEquals(meta,applied.discovery.metadata)
            val trustFile=File(context.noBackupFilesDir,f.namespace+"-trust.bin")
            val committed=trustFile.readBytes()
            assertEquals(applied.discovery.binding,checkNotNull(f.controller.applyAdminDescriptor(ordinary.binding,raw)).discovery.binding)
            assertArrayEquals(committed,trustFile.readBytes())
            assertEquals(before,f.journal.snapshot());unchangedDevice(original)
            assertEquals(protectedBody,f.journal.readProtected(before));assertEquals(authority,f.journal.snapshot().authority)
            assertArrayEquals(publicKey,DeviceKey.open(before.keyAlias).publicKey.encoded)
            assertEquals(consent,context.getSharedPreferences(f.namespace+"-consent",Context.MODE_PRIVATE).all)
            assertEquals(paths,f.server.paths);assertEquals(root,store.adaptiveAuthorityFingerprint())
            fun trustBytes()=context.noBackupFilesDir.listFiles().orEmpty().filter {it.isFile &&
                (it.name.startsWith(f.namespace+"-trust.") || it.name.startsWith(f.namespace+"-trust-admin-"))}
                .associate {it.name to it.readBytes()}
            fun unchangedTrust(expected:Map<String,ByteArray>) {
                val current=trustBytes();assertEquals(expected.keys,current.keys)
                expected.forEach {(name,value)->assertArrayEquals(name,value,current.getValue(name))}
            }
            val trusted=trustBytes()
            assertNull(f.controller.applyAdminDescriptor(Identity.random(),signed(legacy.copy(revision=3,adminBootstrap=meta))))
            unchangedTrust(trusted)
            assertNull(f.controller.applyAdminDescriptor(ordinary.binding,signed(legacy.copy(revision=3))))
            assertNull(f.controller.adminDiscoveryContext())
            assertEquals(ordinary.binding,checkNotNull(f.controller.adminBootstrapContext()).binding)
            assertNotNull(f.controller.applyAdminDescriptor(ordinary.binding,signed(legacy.copy(revision=4,adminBootstrap=meta))))
            val sameOwner=f.journal.snapshot()
            f.server.policyStatus=409;f.server.policyProblem="reauthentication_required"
            f.controller.retry(sameOwner.generation);f.idle()
            assertEquals(LoginPhase.NEEDS_REAUTH,f.journal.snapshot().phase)
            val beforeReauth=trustBytes()
            assertNull(f.controller.adminBootstrapContext())
            assertNull(f.controller.applyAdminDescriptor(ordinary.binding,signed(legacy.copy(revision=5,adminBootstrap=meta))))
            unchangedTrust(beforeReauth)
            val callback=f.repeatLogin();assertNull(f.controller.adminBootstrapContext())
            f.server.policyStatus=200;f.controller.callback(callback);f.idle()
            val reauthenticated=f.journal.snapshot();val current=checkNotNull(f.controller.adminBootstrapContext())
            assertEquals(sameOwner.generation,reauthenticated.generation);assertTrue(reauthenticated.reauthRevision>sameOwner.reauthRevision)
            assertEquals(before.keyAlias,reauthenticated.keyAlias);assertEquals(before.thumbprint,reauthenticated.thumbprint)
            assertEquals(before.deviceId,reauthenticated.deviceId);assertEquals(authority,reauthenticated.authority)
            assertNotEquals(ordinary.binding,current.binding);assertEquals(bootstrap,current.bootstrap)
            val trustAfterReauth=trustBytes();val deviceAfterReauth=deviceBytes();val currentPaths=f.server.paths.toList()
            val next=signed(legacy.copy(revision=5,adminBootstrap=meta))
            assertNull(f.controller.applyAdminDescriptor(ordinary.binding,next));unchangedTrust(trustAfterReauth)
            assertNotNull(f.controller.applyAdminDescriptor(current.binding,next))
            assertEquals(reauthenticated,f.journal.snapshot());unchangedDevice(deviceAfterReauth)
            assertArrayEquals(publicKey,DeviceKey.open(reauthenticated.keyAlias).publicKey.encoded)
            assertEquals(root,store.adaptiveAuthorityFingerprint());assertEquals(currentPaths,f.server.paths)
            assertFalse(current.toString().contains(current.binding))
        }
    }
    @Test fun runtimeUploadNeedsExplicitConsentAndCannotBorrowAnArtificialVpnOnHint() {
        fixture(reportVpnOn={true}) {f->
            f.server.policyReady=true;f.server.technicalTelemetry=true
            f.controller.callback(f.begin());f.idle()
            val before=f.journal.snapshot()
            assertFalse(f.controller.syncRuntimeObservation())
            assertTrue(f.controller.chooseTechnicalTelemetry(before.generation,true))
            assertTrue(f.controller.syncRuntimeObservation());f.idle()
            // The real controller checkpoint is Off. A test hint alone cannot
            // acquire its VPN generation or issue a report through another owner.
            assertFalse(f.server.paths.any {it.endsWith("/device/runtime")})
            assertEquals(before,f.journal.snapshot())
            assertTrue(f.controller.chooseTechnicalTelemetry(before.generation,false));f.idle()
            assertFalse(f.controller.syncRuntimeObservation())
        }
    }
    @Test fun activationDeliveryUsesDurableDecisionAndCannotChangeLoginOnFailure() {
        val on=java.util.concurrent.atomic.AtomicBoolean()
        fixture(reportVpnOn=on::get) { f ->
            f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
            fun finish(baseline:Boolean,actual:Boolean):AssignmentState {
                val ticket=f.controller.assignmentTicket()
                assertTrue(f.controller.beginAssignment(ticket,listOf(baseline)));f.idle()
                assertTrue(f.controller.finishAssignment(ticket,listOf(actual),true));f.idle()
                return checkNotNull(f.journal.readAssignment(f.journal.snapshot()))
            }
            val first=finish(false,true);val original=f.journal.snapshot()
            assertFalse(f.controller.refreshAssignment(false))
            assertTrue(f.server.activationReports.isEmpty())
            on.set(true);f.server.activationStatus=403
            val reason=f.controller.status().getString("reason")
            assertTrue(f.controller.refreshAssignment(false));f.idle()
            assertEquals(listOf(first.activationReport),f.server.activationReports.toList())
            assertEquals(original,f.journal.snapshot())
            assertEquals(reason,f.controller.status().getString("reason"))
            assertFalse(f.controller.refreshAssignment(false))
            f.server.policyRevision=2;f.server.engineTag="replacement"
            f.controller.retry(original.generation);f.idle()
            val rollback=finish(true,false)
            assertEquals("rolled_back",rollback.journal.phase)
            f.server.activationStatus=204
            assertTrue(f.controller.refreshAssignment(false));f.idle()
            assertEquals(listOf(first.activationReport,rollback.activationReport),f.server.activationReports.toList())
            assertEquals(1L,checkNotNull(rollback.activationReport).activePolicyRevision)
            assertFalse(f.controller.refreshAssignment(false))
            assertEquals(rollback,f.journal.readAssignment(f.journal.snapshot()))
        }
    }
    @Test fun legacyCapabilityApprovalSurvivesRestartWithoutChangingAssignedPolicyOrDeviceIdentity()=fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle();val first=f.journal.snapshot()
        val assignment=checkNotNull(f.journal.readAssignment(first));f.legacyCache()
        f.server.holdCapabilities=true;f.controller.recover();f.idle()
        val pending=f.journal.snapshot();assertEquals("PENDING",f.controller.status().getString("reason"))
        assertEquals(first.policyHash,pending.policyHash);assertEquals(assignment,f.journal.readAssignment(pending))
        assertEquals(1,f.server.capabilityBodies.size);assertFalse(f.controller.pollProvisioning(pending.generation+1))
        f.server.holdCapabilities=false;f.restart();val after=f.journal.snapshot()
        assertEquals(LoginPhase.POLICY_CACHED,after.phase);assertEquals(first.policyHash,after.policyHash)
        assertEquals(first.deviceId,after.deviceId);assertEquals(first.keyAlias,after.keyAlias);assertEquals(first.generation,after.generation)
        assertEquals(f.server.capabilityBodies[0],f.server.capabilityBodies[1]);assertEquals(1,f.server.enrollBodies.size)
        val p=LoginPayload.decode(f.journal.readProtected(after),after)
        assertEquals(IdentityOperation.supportedCapabilities.sorted(),p.advertisedCapabilities)
        val posts=f.server.capabilityBodies.size;f.restart();assertEquals(posts,f.server.capabilityBodies.size)
    }
    @Test fun cachedPolicyRefreshUsesTheSignedDeadlineOrFiveMinuteLimit() {
        assertFalse(assignmentRefreshDue(150_000,150_000,false))
        assertFalse(assignmentRefreshDue(299_999,1,false))
        assertTrue(assignmentRefreshDue(300_000,600_000,false))
        assertTrue(assignmentRefreshDue(60_000,0,false))
        assertFalse(assignmentRefreshDue(29_999,-10_000,false))
        assertTrue(assignmentRefreshDue(30_000,null,false))
        assertFalse(assignmentRefreshDue(-1,null,true))
        assertFalse(assignmentRefreshDue(4_999,0,true))
        assertTrue(assignmentRefreshDue(5_000,600_000,true))
    }
    @Test fun foregroundPollRenewsExpiredCommittedPolicyWithoutStartingVpnOrChangingIdentity()=fixture {f->
        f.server.policyLifetimeMs=15_000
        f.server.policyReady=true
        f.controller.callback(f.begin());f.idle()
        val login=f.journal.snapshot()
        val ticket=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(ticket,listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(ticket,listOf(true),true));f.idle()
        assertTrue(f.controller.allowsConnect())
        assertFalse(f.controller.pollProvisioning(login.generation))
        assertFalse(f.controller.refreshAssignment(false,login.generation+1))
        assertFalse(f.controller.refreshAssignment(false,login.generation))
        until {!f.controller.allowsConnect()}
        val expired=f.controller.status()
        assertEquals("",expired.getString("reason"))
        val assignment=expired.getJSONObject("assignedPolicy")
        assertTrue(needsForegroundRenewal(expired.getString("phase"),"",assignment))
        assertFalse(needsForegroundRenewal("NEEDS_REAUTH","",assignment))
        assertFalse(needsForegroundRenewal("POLICY_CACHED","ACCESS_DENIED",assignment))
        assertFalse(f.controller.pollProvisioning(login.generation+1))
        val reads=f.server.paths.count {it.endsWith("/device/policy")}
        f.server.policyLifetimeMs=3_600_000L
        f.server.policyRevision=2
        assertTrue(f.controller.pollProvisioning(login.generation));f.idle()
        assertEquals(reads+1,f.server.paths.count {it.endsWith("/device/policy")})
        assertFalse(f.controller.pollProvisioning(login.generation))
        val renewed=f.controller.status().getJSONObject("assignedPolicy")
        assertTrue(renewed.getBoolean("runtimeAuthorized"))
        assertFalse(needsForegroundRenewal("POLICY_CACHED","",renewed))
        val fresh=f.journal.snapshot()
        assertEquals(login.generation,fresh.generation)
        assertEquals(login.keyAlias,fresh.keyAlias)
        assertEquals(login.deviceId,fresh.deviceId)
        val status=context.contentResolver.call("content://io.syn443.control".toUri(),"status",null,null)!!
        val vpn=org.json.JSONObject(status.getString("json")!!)
        assertEquals("Off",vpn.getString("phase"));assertFalse(vpn.getBoolean("desiredOn"))
    }
    @Test fun lostCapabilityAckAndUnavailableEndpointKeepCurrentAssignmentAndStopStillWins()=fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle();val first=f.journal.snapshot();f.legacyCache()
        f.server.capabilityStatus=503;f.controller.recover();f.idle()
        assertEquals("UNAVAILABLE",f.controller.status().getString("reason"));assertEquals(first.policyHash,f.journal.snapshot().policyHash)
        f.server.capabilityStatus=200;f.server.dropCapabilityAck=true;f.restart()
        assertEquals("TRANSPORT",f.controller.status().getString("reason"));assertEquals(1,f.server.capabilityBodies.size)
        f.restart();val after=f.journal.snapshot();assertEquals(first.policyHash,after.policyHash)
        assertEquals(1,f.server.capabilityBodies.size);assertEquals(first.deviceId,after.deviceId)
        val generation=after.generation;f.controller.cancel();f.idle()
        assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase);assertFalse(f.controller.pollProvisioning(generation))
    }
    @Test fun oldEnrollmentAckCreatesANewPersistedRequestAndPendingApprovalCanPoll()=fixture {f->
        f.server.dropEnrollment=true;f.controller.callback(f.begin());f.idle();f.controller.shutdownTest()
        val s=f.journal.snapshot();assertEquals(LoginPhase.ENROLLING,s.phase)
        val oldOp=IdentityOperation(s.operation!!.path,Canonical.encode(JsonObject(Identity.objectJSON(s.operation!!.body)+
            ("capabilities" to JsonArray(IdentityOperation.requiredCapabilities.map(::JsonPrimitive))))))
        f.journal.commit(s,s.copy(revision=s.revision+1,operation=oldOp))
        f.server.receipts.clear();f.server.enrollBodies.clear();f.server.capabilities.remove(s.thumbprint);f.server.capabilityVersions.remove(s.thumbprint)
        f.server.requireCapabilityApproval=true;f.server.holdCapabilities=true
        f.controller=LoginController.isolatedForTest(context,f.namespace,f.server,anchor=f.testTrustAnchor)
        f.controller.recover();f.idle();val pending=f.journal.snapshot()
        assertEquals(LoginPhase.ENROLLING,pending.phase);assertEquals("PENDING",f.controller.status().getString("reason"))
        assertEquals(oldOp.body,f.server.enrollBodies[0]);assertNotEquals(oldOp.body,pending.operation!!.body)
        assertEquals(pending.operation!!.body,f.server.enrollBodies[1]);assertEquals(s.keyAlias,pending.keyAlias)
        assertFalse(f.controller.pollProvisioning(pending.generation+1))
        f.server.holdCapabilities=false
        until {f.controller.pollProvisioning(pending.generation)};f.idle()
        val after=f.journal.snapshot();assertEquals(LoginPhase.PROVISIONING,after.phase)
        assertEquals(s.generation,after.generation);assertEquals(s.keyAlias,after.keyAlias)
        assertEquals(2,f.server.capabilityBodies.size);assertEquals(f.server.capabilityBodies[0],f.server.capabilityBodies[1])
        assertTrue(f.server.enrollBodies.drop(1).all{it==pending.operation!!.body})
    }
    @Test fun confirmedCapabilitiesSurviveRefreshAndCannotBecomePublicStatusMetadata()=fixture {f->
        f.server.policyReady=true;f.server.shortAccess=true;f.controller.callback(f.begin());f.idle();f.restart()
        val s=f.journal.snapshot();val p=LoginPayload.decode(f.journal.readProtected(s),s)
        assertEquals(1L,s.sessionGeneration);assertEquals(IdentityOperation.supportedCapabilities.sorted(),p.advertisedCapabilities)
        assertTrue(f.server.capabilityBodies.isEmpty())
        val status=f.controller.status().toString();assertFalse(status.contains("advertisedCapabilities"));assertFalse(status.contains("overlay.credentials.v1"))
    }
    @Test fun administrationEntryUsesTrustedMetadataAndCannotOutliveItsLoginGeneration()=fixture(controlPanelOrigin="https://control.example.invalid") {f->
        assertNull(f.controller.adminPanelUrl(f.journal.snapshot().generation))
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val generation=f.journal.snapshot().generation
        assertNull(f.controller.adminPanelUrl(generation))
        assertTrue(f.controller.pollAdminPanel(generation));f.idle()
        assertNull(f.controller.adminPanelUrl(generation))
        assertFalse(f.controller.pollAdminPanel(generation))
        f.server.panelGrant=true;f.restart()
        assertNull(f.controller.adminPanelUrl(generation))
        assertTrue(f.controller.pollAdminPanel(generation));f.idle()
        val login=f.journal.snapshot()
        val target="https://control.example.invalid/#device=${login.deviceId}"
        assertEquals(target,f.controller.adminPanelUrl(generation))
        val requests=f.server.paths.toList()
        assertEquals(target,f.controller.adminPanelUrl(generation))
        assertEquals(requests,f.server.paths)
        val status=f.controller.status().toString()
        assertFalse(status.contains(login.deviceId));assertFalse(status.contains("#device="))
        assertNull(f.controller.adminPanelUrl(generation+1))
        assertTrue(f.controller.status().getBoolean("controlPanelAvailable"))
        f.controller.cancel()
        assertNull(f.controller.adminPanelUrl(generation));f.idle()
        assertFalse(f.controller.status().optBoolean("controlPanelAvailable"))
    }
    @Test fun olderIdentityServerKeepsAdministrationHiddenWithoutChangingLogin()=fixture(controlPanelOrigin="https://control.example.invalid") {f->
        f.server.panelStatus=404;f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val login=f.journal.snapshot()
        assertTrue(f.controller.pollAdminPanel(login.generation));f.idle()
        assertNull(f.controller.adminPanelUrl(login.generation))
        assertEquals(login,f.journal.snapshot())
    }
    @Test fun cancelledPrequeuePanelDiscoveryCannotExposeOldGenerationTarget() {
        val pause=AtomicBoolean();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        fixture(beforeQueue={if(pause.compareAndSet(true,false)) {entered.countDown();check(release.await(5,TimeUnit.SECONDS))}},
            controlPanelOrigin="https://control.example.invalid") {f->
            f.server.policyReady=true;f.server.panelGrant=true;f.controller.callback(f.begin());f.idle()
            val generation=f.journal.snapshot().generation
            val requests=f.server.paths.count {it=="/v1/device/control-panel"}
            val caller=java.util.concurrent.Executors.newSingleThreadExecutor()
            try {
                pause.set(true)
                val polling=caller.submit<Boolean> {f.controller.pollAdminPanel(generation)}
                assertTrue(entered.await(3,TimeUnit.SECONDS))
                assertTrue(f.controller.status().getBoolean("busy"))
                assertNull(f.controller.adminPanelUrl(generation))
                f.controller.cancel()
                assertNull(f.controller.adminPanelUrl(generation))
                release.countDown();assertTrue(polling.get(5,TimeUnit.SECONDS));f.idle()
                assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
                assertNull(f.controller.adminPanelUrl(generation));assertNull(f.controller.adminPanelUrl(generation+1))
                assertEquals(requests,f.server.paths.count {it=="/v1/device/control-panel"})
            } finally {release.countDown();caller.shutdownNow();check(caller.awaitTermination(5,TimeUnit.SECONDS))}
        }
    }
    @Test fun legacyBootstrapDoesNotInventAnAdministrationAddress()=fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        assertNull(f.controller.adminPanelUrl(f.journal.snapshot().generation))
        assertFalse(f.controller.status().getBoolean("controlPanelAvailable"))
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
    @Test fun repeatKeycloakLoginKeepsDevicePolicyAndFencesPreviousResults()=fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val staged=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(staged,listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(staged,listOf(true),true));f.idle()
        val before=f.journal.snapshot()
        val oldTicket=f.controller.assignmentTicket()
        val config=f.controller.assignedRuntime.config(before)
        val oldSession=f.server.sessions.getValue(before.thumbprint)
        f.server.policyStatus=409;f.server.policyProblem="reauthentication_required"
        f.controller.retry(before.generation);f.idle()
        val expired=f.journal.snapshot()
        assertEquals(LoginPhase.NEEDS_REAUTH,expired.phase);assertFalse(f.controller.allowsConnect())
        val obsolete=f.repeatLogin()
        assertFalse(f.controller.startReauthentication(expired.generation,expired.revision))
        val selected=f.repeatLogin()
        val directory=File(context.noBackupFilesDir,"login/${f.namespace}")
        val ciphertext=File(directory,"protected.bin")
        val backup=File(directory,"protected.previous.bin")
        ciphertext.copyTo(backup)
        ciphertext.writeBytes(byteArrayOf(1,2,3)) // Interrupted before the new intent hash committed.
        f.restart()
        assertEquals(selected,f.repeatCallback())
        f.controller.callback(obsolete);f.idle()
        assertEquals(LoginPhase.BROWSER,f.journal.snapshot().phase)
        assertEquals(1,f.server.enrollBodies.size)
        f.server.policyStatus=200
        f.controller.callback(selected);f.idle()
        val after=f.journal.snapshot()
        assertEquals(LoginPhase.POLICY_CACHED,after.phase)
        assertEquals(before.keyAlias,after.keyAlias);assertEquals(before.thumbprint,after.thumbprint)
        assertEquals(before.deviceId,after.deviceId);assertEquals(before.ownerTag,after.ownerTag)
        assertEquals(before.generation,after.generation);assertEquals(before.policyHash,after.policyHash)
        assertEquals(config,f.controller.assignedRuntime.config(after))
        assertNotEquals(oldSession.accessToken,f.server.sessions.getValue(after.thumbprint).accessToken)
        assertEquals(setOf(before.thumbprint),f.server.activeKeys)
        assertEquals(2,f.server.enrollBodies.size);assertFalse(backup.exists())
        assertNotEquals(oldTicket,f.controller.assignmentTicket())
        assertTrue(f.controller.finishAssignment(oldTicket,listOf(false),false));f.idle()
        assertEquals(after,f.journal.snapshot());assertTrue(f.controller.allowsConnect())
    }
    @Test fun repeatKeycloakLoginRejectsWrongOwnerAndDifferentDevice()=fixture {f->
        f.server.policyStatus=409;f.server.policyProblem="reauthentication_required"
        f.controller.callback(f.begin());f.idle()
        val before=f.journal.snapshot()
        assertEquals(LoginPhase.NEEDS_REAUTH,before.phase)
        f.server.subject="another-synthetic-owner"
        f.controller.callback(f.repeatLogin());f.idle()
        assertEquals(1,f.server.enrollBodies.size)
        assertEquals(LoginPhase.NEEDS_REAUTH,f.journal.snapshot().phase)
        assertEquals("ACCESS_DENIED",f.controller.status().getString("reason"))
        f.server.subject="synthetic-owner";f.server.replaceRegisteredDevice=true
        f.controller.callback(f.repeatLogin());f.idle()
        val after=f.journal.snapshot()
        assertEquals(LoginPhase.NEEDS_REAUTH,after.phase);assertFalse(f.controller.allowsConnect())
        assertEquals(before.keyAlias,after.keyAlias);assertEquals(before.deviceId,after.deviceId)
        assertEquals(before.ownerTag,after.ownerTag);assertEquals(before.generation,after.generation)
        assertEquals(2,f.server.enrollBodies.size)
    }
    private fun Fixture.expireRefreshFamily(before:LoginIntent) {
        val original=LoginPayload.decode(journal.readProtected(before),before)
        val session=checkNotNull(original.session);val deadline=session.time.upperMs
        val expired=original.copy(session=session.copy(session=session.session.copy(
            accessUntilMs=deadline,refreshUntilMs=deadline)))
        journal.prepare(before,expired.encode()).use {prepared->
            journal.commit(before,LoginRecovery.capabilitiesRecorded(before,before.generation,prepared.hash),prepared)
        }
    }
    @Test fun expiredRefreshFamilyRequiresLoginWithoutContactingTheServer()=fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val before=f.journal.snapshot();assertEquals(LoginPhase.POLICY_CACHED,before.phase)
        f.expireRefreshFamily(before)
        val paths=f.server.paths.toList()
        f.restart()
        val after=f.journal.snapshot();assertEquals(LoginPhase.NEEDS_REAUTH,after.phase)
        assertEquals(before.deviceId,after.deviceId);assertEquals(before.keyAlias,after.keyAlias)
        assertEquals(before.generation,after.generation);assertEquals(paths,f.server.paths)
        assertEquals("SESSION_EXPIRED",f.controller.status().getString("reason"))
        assertFalse(f.controller.allowsConnect())
    }
    @Test fun expiredRefreshFamilyPreservesAnAuthorizedOfflinePolicy()=fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val ticket=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(ticket,listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(ticket,listOf(true),true));f.idle()
        val before=f.journal.snapshot()
        val config=f.controller.assignedRuntime.config(before)
        f.expireRefreshFamily(before)
        val paths=f.server.paths.toList()
        f.restart()
        val after=f.journal.snapshot();assertEquals(LoginPhase.POLICY_CACHED,after.phase)
        assertEquals(before.deviceId,after.deviceId);assertEquals(before.policyHash,after.policyHash)
        assertEquals(config,f.controller.assignedRuntime.config(after))
        assertEquals("SESSION_EXPIRED",f.controller.status().getString("reason"))
        assertEquals(paths,f.server.paths)
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
        val checked = checkNotNull(f.controller.assignedRuntime.allowed(s, committed.journal.lastGood)).payload
        fun assertLastGoodPair() {
            val pair = io.syn443.android.vpn.RuntimePolicies(context) { f.controller }.status().getJSONObject("lastKnownGoodPair")
            assertEquals(checked.revision, pair.getLong("configRevision"))
            assertEquals(checked.algorithmRevision, pair.getString("algorithmRevision"))
        }
        assertLastGoodPair()
        f.restart();assertEquals(config,f.controller.assignedRuntime.config(f.journal.snapshot()))
        assertLastGoodPair()
        assertEquals("committed",f.journal.readAssignment(f.journal.snapshot())!!.journal.phase)
        assertTrue(f.controller.allowsConnect())
    }
    @Test fun logoutAfterAccessExpiryRotatesOnlyInRamRevokesAndErasesTheProtectedSession()=fixture {f->
        f.server.policyReady=true;f.server.shortAccess=true;f.controller.callback(f.begin());f.idle()
        val s=f.journal.snapshot();val p=LoginPayload.decode(f.journal.readProtected(s),s);val session=checkNotNull(p.session)
        assertTrue(f.server.refreshBodies.isEmpty())
        val now=SystemClock.elapsedRealtime();val until=now+session.session.accessUntilMs-session.time.window(session.time.boot,now).upperMs+200
        while(SystemClock.elapsedRealtime()<until)Thread.sleep(50)
        f.controller.cancel();f.idle()
        val out=f.journal.snapshot();assertEquals(LoginPhase.SIGNED_OUT,out.phase)
        assertEquals(1,f.server.refreshBodies.size);assertEquals(1,f.server.enrollBodies.size)
        assertTrue(f.server.activeKeys.isEmpty());assertTrue(out.tombstones.isEmpty())
        assertFalse(File(context.noBackupFilesDir,"login/${f.namespace}/protected.bin").exists())
        assertFalse(File(context.noBackupFilesDir,"login/${f.namespace}/assignment.bin").exists())
    }
    @Test fun lostLogoutRefreshKeepsRecoveryTombstoneWithoutRestoringSecretsOrRetryingEnrollment()=fixture {f->
        f.server.shortAccess=true;f.controller.callback(f.begin());f.idle()
        val s=f.journal.snapshot();val p=LoginPayload.decode(f.journal.readProtected(s),s);val session=checkNotNull(p.session)
        val now=SystemClock.elapsedRealtime();val until=now+session.session.accessUntilMs-session.time.window(session.time.boot,now).upperMs+200
        while(SystemClock.elapsedRealtime()<until)Thread.sleep(50)
        f.server.dropRefresh=true;f.controller.cancel();f.idle()
        val out=f.journal.snapshot();assertEquals(LoginPhase.SIGNED_OUT,out.phase)
        assertEquals(1,f.server.refreshBodies.size);assertEquals(1,f.server.enrollBodies.size)
        assertEquals(setOf(s.thumbprint),f.server.activeKeys)
        assertTrue(out.tombstones.any {it.ownerTag==s.ownerTag && it.thumbprint==s.thumbprint})
        assertFalse(File(context.noBackupFilesDir,"login/${f.namespace}/protected.bin").exists())
    }
    @Test fun assignedLeaseRenewalPersistsWithoutNewActivationAndRetainsDeviceIdentityAcrossRestart() = fixture {f->
        f.server.policyReady=true;f.controller.callback(f.begin());f.idle()
        val ticket=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(ticket,listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(ticket,listOf(true),true));f.idle()
        val before=f.journal.snapshot();val previous=checkNotNull(f.journal.readAssignment(before))
        val config=f.controller.assignedRuntime.config(before)
        f.server.policyRevision=2;f.controller.retry(before.generation);f.idle()
        val after=f.journal.snapshot();val renewed=checkNotNull(f.journal.readAssignment(after))
        assertEquals(before.generation,after.generation);assertEquals(before.deviceId,after.deviceId)
        assertEquals(before.thumbprint,after.thumbprint);assertEquals(before.keyAlias,after.keyAlias)
        assertNotEquals(before.policyHash,after.policyHash)
        assertEquals("committed",renewed.journal.phase);assertNull(renewed.journal.candidate)
        assertEquals(previous.journal.activationGeneration,renewed.journal.activationGeneration)
        assertEquals(2L,renewed.journal.maxRevision);assertEquals(config,f.controller.assignedRuntime.config(after))
        assertTrue(f.controller.status().getJSONObject("assignedPolicy").getBoolean("runtimeAuthorized"))
        assertFalse(f.controller.status().getJSONObject("assignedPolicy").getBoolean("candidateValidated"))
        // A queued result from the old envelope cannot mutate the renewed journal.
        assertTrue(f.controller.finishAssignment(ticket,listOf(false),false));f.idle()
        assertEquals(renewed.journal,f.journal.readAssignment(f.journal.snapshot())!!.journal)
        f.restart();val restored=f.journal.snapshot()
        assertEquals(after.deviceId,restored.deviceId);assertEquals(after.thumbprint,restored.thumbprint)
        assertEquals(renewed.journal,f.journal.readAssignment(restored)!!.journal)
        assertEquals(config,f.controller.assignedRuntime.config(restored));assertTrue(f.controller.allowsConnect())
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
        assertTrue(policies.awaitingInitialPermit())
        assertThrows(IllegalStateException::class.java) { policies.config { "unassigned" } }
        // No running signed candidate exists yet. A managed client must not use
        // an unrelated default endpoint or the unapproved candidate as health.
        assertTrue(runCatching {policies.internetChecks("foreign")}.isFailure)
        val ticket=f.controller.assignmentTicket()
        assertTrue(f.controller.beginAssignment(ticket,listOf(false)));f.idle()
        val applying=policies.read()
        assertFalse(policies.awaitingInitialPermit())
        val candidate=checkNotNull(policies.allowed(applying.journal.candidate,applying))
        assertEquals(candidate.engineConfig, policies.config { error("local fallback must remain unavailable") })
        assertEquals(candidate.payload.activation.checks.filter {it.required && it.type=="https_204"},policies.internetChecks(candidate.payload.contentHash))
        assertTrue(runCatching {policies.internetChecks("foreign")}.isFailure)
        assertTrue(f.controller.finishAssignment(f.controller.assignmentTicket(),listOf(true),true));f.idle()
        assertEquals(candidate.payload.activation.checks.filter {it.required && it.type=="https_204"},policies.internetChecks(candidate.payload.contentHash))
        f.controller.assignedRuntime.clear()
        assertTrue(runCatching {policies.internetChecks(candidate.payload.contentHash)}.isFailure)
        assertTrue(policies.managed());assertEquals("blocked",policies.read().journal.phase)
        assertFalse(policies.awaitingInitialPermit())
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
    @Test fun expiredFirstBrowserLinkCanRenewOnceWithoutRetiringItsKey() {
        val at=AtomicLong(-1)
        fixture(monotonicMillis={at.get().takeIf { it>=0 } ?: SystemClock.elapsedRealtime()}) { f->
            val obsolete=f.begin()
            val first=f.journal.snapshot()
            val previousUrl=f.controller.browserUrl(first.generation)
            val pending=checkNotNull(LoginPayload.decode(f.journal.readProtected(first),first).pending)
            at.set(pending.startedElapsedMs+299_999)
            assertTrue(f.controller.status().getBoolean("browserReady"))
            assertFalse(f.controller.startReauthentication(first.generation,first.revision))
            at.set(pending.startedElapsedMs+300_000)
            assertFalse(f.controller.status().getBoolean("browserReady"))
            assertTrue(f.controller.status().getBoolean("browserExpired"))
            assertThrows(IllegalArgumentException::class.java) {f.controller.browserUrl(first.generation)}
            assertTrue(f.controller.startReauthentication(first.generation,first.revision));f.idle()
            val next=f.journal.snapshot()
            assertTrue(next.revision>first.revision)
            assertEquals(first.keyAlias,next.keyAlias)
            assertEquals(first.thumbprint,next.thumbprint)
            assertFalse(next.maybeRegistered)
            assertFalse(f.controller.startReauthentication(first.generation,first.revision))
            val fresh=f.controller.browserUrl(next.generation)
            assertNotEquals(previousUrl,fresh)
            f.controller.callback(obsolete);f.idle()
            assertEquals(next,f.journal.snapshot())
            assertEquals(fresh,f.controller.browserUrl(next.generation))
            assertTrue(f.server.enrollBodies.isEmpty())
            at.set(-1)
        }
    }

    @Test fun expiredRegisteredBrowserKeepsOriginalDeviceOnRenewedLogin() {
        val advance = AtomicLong(0)
        fixture(monotonicMillis = { SystemClock.elapsedRealtime() + advance.get() }) { f ->
            f.server.policyReady = true
            f.controller.callback(f.begin()); f.idle()
            val enrolled = f.journal.snapshot()
            assertEquals(LoginPhase.POLICY_CACHED, enrolled.phase)
            val publicKey = DeviceKey.open(enrolled.keyAlias).publicKey.encoded
            f.server.policyStatus = 409
            f.server.policyProblem = "reauthentication_required"
            f.controller.retry(enrolled.generation); f.idle()
            assertEquals(LoginPhase.NEEDS_REAUTH, f.journal.snapshot().phase)
            val obsolete = f.repeatLogin()
            val old = f.journal.snapshot()
            val pending = checkNotNull(LoginPayload.decode(f.journal.readProtected(old), old).pending)
            advance.set(300_000)
            f.server.clockAdvanceMs = advance.get()
            assertTrue(SystemClock.elapsedRealtime() + advance.get() >= pending.startedElapsedMs + 300_000)
            assertTrue(f.controller.status().getBoolean("browserExpired"))
            assertThrows(IllegalArgumentException::class.java) { f.controller.browserUrl(old.generation) }
            val fresh = f.repeatLogin()
            f.controller.callback(obsolete); f.idle()
            assertEquals(LoginPhase.BROWSER, f.journal.snapshot().phase)
            assertEquals(1, f.server.enrollBodies.size)
            f.server.policyStatus = 200
            // The previous policy's signed refresh deadline passed while the user was away.
            f.server.policyRevision++
            f.controller.callback(fresh); f.idle()
            val restored = f.journal.snapshot()
            assertEquals(LoginPhase.POLICY_CACHED, restored.phase)
            assertEquals(enrolled.deviceId, restored.deviceId)
            assertEquals(enrolled.keyAlias, restored.keyAlias)
            assertEquals(enrolled.generation, restored.generation)
            assertEquals(enrolled.thumbprint, restored.thumbprint)
            assertArrayEquals(publicKey, DeviceKey.open(restored.keyAlias).publicKey.encoded)
            assertEquals(2, f.server.enrollBodies.size)
        }
    }

    @Test fun staleReviewedLogoutCannotStopVpnOrRetireAnEnrolledDevice() = fixture {f->
        f.server.policyReady=true
        val callback=f.begin()
        val browser=f.journal.snapshot()
        assertFalse(f.controller.status().getBoolean("registrationMayExist"))
        f.controller.callback(callback)
        f.idle()
        val enrolled=f.journal.snapshot()
        assertEquals(LoginPhase.POLICY_CACHED,enrolled.phase)
        assertTrue(f.controller.status().getBoolean("registrationMayExist"))
        var stops=0
        assertFalse(f.controller.cancelReviewed(browser.generation,browser.revision) { stops++ })
        assertFalse(f.controller.cancelReviewed(enrolled.generation+1,enrolled.revision) { stops++ })
        assertEquals(0,stops)
        assertEquals(enrolled,f.journal.snapshot())
        assertEquals(enrolled.thumbprint,Identity.thumbprint(DeviceKey.open(enrolled.keyAlias).publicKey))
        assertTrue(f.controller.cancelReviewed(enrolled.generation,enrolled.revision) { stops++ })
        f.idle()
        assertFalse(f.controller.cancelReviewed(enrolled.generation,enrolled.revision) { stops++ })
        assertEquals(1,stops)
        assertEquals(LoginPhase.SIGNED_OUT,f.journal.snapshot().phase)
        assertThrows(IllegalStateException::class.java) { DeviceKey.open(enrolled.keyAlias) }
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
        assertEquals(1,f.server.overlayFetchBodies.size)
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

    @Test fun periodicManagedCredentialRetryUsesSameOperationWithoutFetchingPolicyOrBypassingBackoff()=fixture{f->
        f.server.policyReady=true;f.server.managedOverlayPolicy=true;f.server.dropOverlayFetch=true
        f.controller.callback(f.begin());f.idle()
        val login=f.journal.snapshot();val owned=login.overlayNamespaces.single()
        val operation=OverlayVault(context,owned,{true},{0},f.namespace).snapshot()!!.operation
        val raw=f.controller.assignedRuntime.read(login).candidate!!.engineConfig;val hash=Policy.hash(raw)
        assertTrue(f.controller.beginAssignment(f.controller.assignmentTicket(),listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(f.controller.assignmentTicket(),listOf(true),true));f.idle()
        val policyFetches=f.server.paths.count{it.endsWith("/device/policy")}
        assertEquals(1,f.server.overlayFetchBodies.size)
        f.server.dropOverlayFetch=false
        until{f.controller.refreshAssignment(false)};f.idle()
        assertEquals("enrolling",f.controller.overlayLaunchMode(hash))
        assertEquals(operation,OverlayVault(context,owned,{true},{0},f.namespace).snapshot()!!.operation)
        assertEquals(2,f.server.overlayFetchBodies.size);assertEquals(1,f.server.overlayFetchBodies.toSet().size)
        assertEquals(policyFetches,f.server.paths.count{it.endsWith("/device/policy")})
        assertFalse(f.controller.refreshAssignment(false));f.idle();assertEquals(2,f.server.overlayFetchBodies.size)
        f.controller.cancel();f.idle()
        assertFalse(f.controller.refreshAssignment(false));assertEquals(2,f.server.overlayFetchBodies.size)
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
    @Test fun interruptedManagedRegistrationExpiresIntoKeylessProbeUntilCurrentNativeProof()=fixture{f->
        f.server.policyReady=true;f.server.managedOverlayPolicy=true;f.server.overlayCredentialLifetimeMs=10_000
        f.controller.callback(f.begin());f.idle()
        assertTrue(f.controller.beginAssignment(f.controller.assignmentTicket(),listOf(false)));f.idle()
        assertTrue(f.controller.finishAssignment(f.controller.assignmentTicket(),listOf(true),true));f.idle()
        val login=f.journal.snapshot();val raw=f.controller.assignedRuntime.config(login);val hash=Policy.hash(raw)
        val owned=login.overlayNamespaces.single();val vault=OverlayVault(context,owned,{true},{0},f.namespace)
        val original=vault.snapshot()!!;assertEquals(OverlayPhase.ENROLLING,original.phase)
        f.server.policyTimeAdvanceMs=15_000;f.server.overlayTimeAdvanceMs=15_000
        f.controller.retry(login.generation);f.idle()
        assertEquals(OverlayPhase.RECONCILING,vault.snapshot()!!.phase);assertEquals(original.operation,vault.snapshot()!!.operation)
        assertEquals("reconciling",f.controller.overlayLaunchMode(hash));assertFalse(f.controller.overlayHasSetup(hash))
        val probe=org.json.JSONObject(f.controller.renderAssigned(raw,File(context.noBackupFilesDir,f.namespace))).getJSONArray("outbounds").getJSONObject(0)
        assertTrue(probe.getBoolean("recover_existing"));assertFalse(probe.has("setup_key"));assertEquals(1,f.server.overlayFetchBodies.size)
        val session=UUID.randomUUID().toString();f.controller.overlayStarting(session,hash)
        val proof=org.json.JSONObject().put("namespace",owned).put("identityEvidence",Identity.random()).toString()
        assertFalse(f.controller.overlayIdentity(session,hash,proof){false})
        assertTrue(f.controller.overlayIdentity(session,hash,proof){true});f.idle()
        assertEquals(OverlayPhase.ACKNOWLEDGED,vault.snapshot()!!.phase)
        assertEquals("keyless",f.controller.overlayLaunchMode(hash));assertEquals(1,f.server.overlayFetchBodies.size)
        val keyless=org.json.JSONObject(f.controller.renderAssigned(raw,File(context.noBackupFilesDir,f.namespace))).getJSONArray("outbounds").getJSONObject(0)
        assertFalse(keyless.has("setup_key"));assertFalse(keyless.has("recover_existing"))
        f.restart();assertEquals("keyless",f.controller.overlayLaunchMode(hash));assertEquals(1,f.server.overlayFetchBodies.size)
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
