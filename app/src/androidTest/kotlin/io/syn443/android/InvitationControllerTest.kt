package io.syn443.android

import android.content.Context
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.core.net.toUri
import io.syn443.android.vpn.*
import io.syn443.identity.*
import io.syn443.policy.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.math.BigInteger
import java.net.URLEncoder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
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
import java.util.concurrent.CopyOnWriteArrayList

class InvitationControllerTest {
    private class Server:IdentityExchange {
        private fun pair()=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private val root=pair();private val online=pair()
        val anchor=TrustAnchor("synthetic-installation",Base64.getEncoder().encodeToString(root.public.encoded),1)
        private val now=System.currentTimeMillis()/1000
        private val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"synthetic","https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",
            mapOf("online" to Base64.getEncoder().encodeToString(online.public.encoded)),now,now,now+3600)
        private val manifest=run {
            val header=Canonical.encode(buildJsonObject{put("alg","ES256");put("kid",anchor.id);put("typ","syn443-bootstrap+jws")})
            val text=Identity.encode(header.toByteArray())+"."+Identity.encode(Canonical.encode(Canonical.json.encodeToJsonElement(descriptor)).toByteArray())
            val der=Signature.getInstance("SHA256withECDSA").run{initSign(root.private);update(text.toByteArray());sign()}
            text+"."+Identity.encode(Identity.derToRaw(der))
        }
        val link="syn443://enroll/v1?service=synthetic&origin="+URLEncoder.encode(descriptor.apiOrigin,"UTF-8")+"&code="+Identity.random()+"&bootstrap="+URLEncoder.encode(manifest,"UTF-8")
        val state=InvitationState(Identity.random(),2,"pending_approval","123456",Identity.random(),"",now+600,Identity.random())
        val device=Identity.random();val access=Identity.random();val refresh=Identity.random()
        val paths=CopyOnWriteArrayList<String>()
        @Volatile var approved=false
        @Volatile var publicationError=""
        @Volatile var holdClaim=false
        @Volatile var completed=false
        val entered=CountDownLatch(1);val release=CountDownLatch(1)
        private fun reply(status:Int=200,text:String="{}")=Reply(status,mapOf("content-type" to listOf("application/json"),"date" to listOf(
            DateTimeFormatter.ofPattern("EEE, dd MMM uuuu HH:mm:ss 'GMT'",Locale.US).withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(System.currentTimeMillis()/1000*1000)))),text.toByteArray())
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
            if(body!=null)check(claims.getValue("req_hash").jsonPrimitive.content==Identity.hash(body))
            headers["Authorization"]?.let {
                check(it.startsWith("DPoP ") && claims.getValue("ath").jsonPrimitive.content==Identity.hash(it.removePrefix("DPoP ").toByteArray()))
                if(body!=null)check(claims.getValue("req_hash").jsonPrimitive.content==Identity.hash(body))
                else check("req_hash" !in claims)
            }
            return Identity.thumbprint(key)
        }

        override fun request(method:String,url:String,headers:Map<String,String>,body:ByteArray?,scope:BoundedHttp.Scope,maxBody:Int):Reply {
            val path=java.net.URI(url).path;paths.add(path)
            if(path=="/v1/invitations/time"){check(method=="GET" && body==null && "DPoP" !in headers && "Authorization" !in headers);return reply(text="""{"serviceId":"synthetic"}""")}
            checkedProof(method,url,headers,body)
            return when(path){
                "/v1/invitations/claim"->{
                    if(holdClaim){holdClaim=false;entered.countDown();check(release.await(10,TimeUnit.SECONDS))}
                    reply(text=Canonical.json.encodeToString(state.copy(error=publicationError)))
                }
                "/v1/invitations/status"->reply(text=Canonical.json.encodeToString(if(approved)state.copy(version=4,state="ready",deviceId=device)else state))
                "/v1/invitations/complete"->{
                    check(approved);completed=true
                    val time=System.currentTimeMillis()/1000*1000
                    val session=DeviceSession(device,access,refresh,time+590000,time+86000000,0,Identity.random())
                    reply(text=Canonical.encode(buildJsonObject{put("session",Canonical.json.encodeToJsonElement(session));put("ownerTag",state.ownerTag)}))
                }
                "/v1/device/policy"->{check(headers["Authorization"]=="DPoP $access");reply(202,"""{"code":"provisioning_pending"}""")}
                "/v1/device/revoke"->reply(204)
                "/v1/invitations/abandon"->reply(text="""{"revoked":true}""")
                else->error("unexpected identity endpoint")
            }
        }
    }
    private val context=ApplicationProvider.getApplicationContext<Context>()
    private fun until(predicate:()->Boolean){val deadline=SystemClock.elapsedRealtime()+15000;while(!predicate()){check(SystemClock.elapsedRealtime()<deadline);Thread.sleep(30)}}
    private fun fixture(block:(Server,LoginController,LoginJournal,String)->Unit){
        check(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        context.contentResolver.call("content://io.syn443.control".toUri(),"disconnect",null,null)
        until {val status=org.json.JSONObject(checkNotNull(context.contentResolver.call("content://io.syn443.control".toUri(),"status",null,null)?.getString("json")));!status.optBoolean("desiredOn")&&!status.optBoolean("engineActive")}
        val namespace="test-invite-"+UUID.randomUUID().toString().replace("-","").take(20)
        val server=Server();val controller=LoginController.isolatedForTest(context,namespace,server,anchor=server.anchor);val journal=LoginJournal(context,namespace)
        try {block(server,controller,journal,namespace)}finally{
            server.release.countDown();controller.cancel();until{!controller.status().getBoolean("busy")};check(journal.snapshot().phase==LoginPhase.SIGNED_OUT)
            controller.shutdownTest();File(context.noBackupFilesDir,"login/$namespace").deleteRecursively()
            android.util.AtomicFile(File(context.noBackupFilesDir,"$namespace-bootstrap.json")).delete()
            android.util.AtomicFile(File(context.noBackupFilesDir,"$namespace-trust.bin")).delete()
        }
    }
    @Test fun manualInvitationStaysLocalUntilConfirmationAndThenUsesOrdinarySession()=fixture {server,controller,journal,_->
        val id=UUID.randomUUID().toString().replace("-","")
        assertTrue(controller.previewInvitation(id,server.link));until{!controller.status().getBoolean("busy")}
        assertEquals("verified",controller.invitationPreview(id).getString("state"));assertTrue(server.paths.isEmpty())
        controller.startInvitation(id);until{!controller.status().getBoolean("busy")}
        val pending=journal.snapshot();assertEquals(LoginPhase.INVITING,pending.phase);assertEquals("123456",controller.status().getString("pairCode"));assertFalse(server.completed)
        server.approved=true;controller.retry(pending.generation);until{!controller.status().getBoolean("busy")}
        val registered=journal.snapshot();assertEquals(LoginPhase.PROVISIONING,registered.phase);assertEquals(server.device,registered.deviceId);assertTrue(server.completed)
        assertTrue("/v1/device/policy" in server.paths);assertTrue(server.paths.none{it.contains("openid")});assertFalse(controller.allowsConnect())
        controller.cancel();until{!controller.status().getBoolean("busy")};assertEquals(LoginPhase.SIGNED_OUT,journal.snapshot().phase)
        assertTrue("/v1/device/revoke" in server.paths);assertThrows(IllegalStateException::class.java){DeviceKey.open(registered.keyAlias)}
    }
    @Test fun cancelledClaimCannotCompleteOrResurrectItsRetiredKey()=fixture {server,controller,journal,_->
        val id=UUID.randomUUID().toString().replace("-","");assertTrue(controller.previewInvitation(id,server.link));until{!controller.status().getBoolean("busy")}
        server.holdClaim=true;controller.startInvitation(id);assertTrue(server.entered.await(10,TimeUnit.SECONDS))
        val pending=journal.snapshot();controller.cancel();server.release.countDown();until{!controller.status().getBoolean("busy")}
        assertEquals(LoginPhase.SIGNED_OUT,journal.snapshot().phase);assertFalse(server.completed)
        assertTrue("/v1/invitations/abandon" in server.paths);assertThrows(IllegalStateException::class.java){DeviceKey.open(pending.keyAlias)}
    }
    @Test fun signedServiceCanPrepareKeycloakWithoutClaimingTheInvitation()=fixture {server,controller,journal,_->
        val id=UUID.randomUUID().toString().replace("-","");assertTrue(controller.previewInvitation(id,server.link));until{!controller.status().getBoolean("busy")}
        controller.startInvitation(id,false);until{!controller.status().getBoolean("busy")}
        val state=journal.snapshot();assertEquals(LoginPhase.BROWSER,state.phase);assertEquals("oidc",state.method)
        assertTrue(controller.browserUrl(state.generation).startsWith("https://id.example.invalid/realms/test/protocol/openid-connect/auth?"))
        assertTrue(server.paths.isEmpty());assertFalse(server.completed)
    }

    @Test fun expiredManualApprovalRequiresActionInsteadOfPollingForever()=fixture {server,controller,journal,_->
        val id=UUID.randomUUID().toString().replace("-","");assertTrue(controller.previewInvitation(id,server.link));until{!controller.status().getBoolean("busy")}
        server.publicationError="reauthentication_required";controller.startInvitation(id);until{!controller.status().getBoolean("busy")}
        val state=journal.snapshot();assertEquals(LoginPhase.NEEDS_REAUTH,state.phase);assertFalse(controller.pollProvisioning(state.generation));assertFalse(server.completed)
    }

}
