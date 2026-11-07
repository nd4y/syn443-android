package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Locale

class InvitationProtocolTest {
    private class Fixture {
        val pair=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val key=object:ProofKey {
            override val publicKey=pair.public as ECPublicKey
            override fun sign(input:ByteArray)=Signature.getInstance("SHA256withECDSA").run {initSign(pair.private);update(input);sign()}
        }
        val bootstrap=Bootstrap("fixture","https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",
            mapOf("online" to Base64.getEncoder().encodeToString(pair.public.encoded)))
        val now=1_800_000_000_000L
        var boot=2;var elapsed=1000L
        val time=TrustedTime(boot,elapsed,now,now+1000)
        val state=InvitationState(Identity.random(),3,"pending_approval","123456",Identity.random(),"",now/1000+600,Identity.random())
        val ready=state.copy(version=4,state="ready",deviceId=Identity.random())
        val session=DeviceSession(ready.deviceId,Identity.random(),Identity.random(),now+590000,now+86000000,0,Identity.random())
        val operation=InvitationOperation.claim(Identity.random(),key.publicKey)
        var handler:(String,String,Map<String,String>,ByteArray?)->Reply={method,url,headers,body->
            assertFalse(headers.containsKey("Authorization"))
            if(method=="GET"){assertNull(body);json("""{"serviceId":"fixture"}""")}
            else {
                assertNotNull(body);val proof=Identity.objectJSON(String(Base64.getUrlDecoder().decode(headers.getValue("DPoP").split('.')[1]),Charsets.UTF_8))
                assertFalse(proof.containsKey("ath"));assertEquals(Identity.hash(body!!),proof.getValue("req_hash").jsonPrimitive.content)
                when(url.substringAfterLast('/')) {
                    "claim"->json(Canonical.json.encodeToString(state))
                    "status"->json(Canonical.json.encodeToString(ready))
                    "complete"->json(Canonical.encode(buildJsonObject{put("session",Canonical.json.encodeToJsonElement(session));put("ownerTag",state.ownerTag)}))
                    else->json("""{"revoked":true}""")
                }
            }
        }
        val client=InvitationProtocol(bootstrap,key,IdentityExchange {m,u,h,b,_,max->assertEquals(8192,max);handler(m,u,h,b)}, {boot},{elapsed})
        fun json(text:String,status:Int=200)=Reply(status,mapOf("content-type" to listOf("application/json"),"date" to listOf(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'",Locale.US).withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(now)))),text.toByteArray())
    }
    private fun error(reason:AuthFailure,block:()->Unit){try {block();fail("untrusted invitation reply accepted")}catch(e:AuthException){assertEquals(reason,e.reason)}}
    private fun invalid(block:()->Unit){try {block();fail("invalid invitation accepted")}catch(_:IllegalArgumentException){}catch(_:IllegalStateException){}}
    @Test fun manualClaimConfirmationAndCompletionConvergeOnNormalBoundSession(){
        val f=Fixture();val scope=IdentityScope();val time=f.client.time(scope)
        assertEquals(f.operation,Canonical.json.decodeFromString<InvitationOperation>(Canonical.json.encodeToString(f.operation)))
        val claimed=f.client.claim(f.operation,time,scope)
        val status=InvitationOperation.mutation("status",claimed.state.id)
        val ready=f.client.status(status,claimed,time,scope)
        val completion=InvitationOperation.mutation("complete",ready.state.id)
        val result=f.client.complete(completion,ready,time,scope)
        assertEquals(f.session,result.session.session);assertEquals(f.state.ownerTag,result.ownerTag)
        assertEquals(Identity.bootstrapAuthority(f.bootstrap),result.session.authority)
        assertEquals(Identity.thumbprint(f.key.publicKey),result.session.keyThumbprint)
        f.client.abandon(InvitationOperation.mutation("abandon",ready.state.id),ready,time,scope)
        for(value in listOf(f.operation,claimed,claimed.state,result,InvitationPending(f.operation,time,claimed,completion)))assertFalse(value.toString().contains(f.state.nonce))
    }
    @Test fun sameProtectedPendingCanResumeAndThenUseExistingLoginPolicyLifecycle(){
        val f=Fixture();val pending=InvitationPending(f.operation,f.time,InvitationReply(f.ready,f.time),InvitationOperation.mutation("complete",f.ready.id))
        val alias="syn443-dpop-"+Identity.random();val reserved=LoginRecovery.reserve(LoginIntent(),0,f.bootstrap,alias,"invite")
        val prepared=LoginRecovery.invitationPrepared(reserved,reserved.generation,Identity.thumbprint(f.key.publicKey),Identity.random())
        val completing=LoginRecovery.invitationProgress(prepared,prepared.generation,f.state.ownerTag,true,Identity.random())
        val payload=LoginPayload(f.bootstrap,invitation=pending)
        assertEquals(payload,LoginPayload.decode(payload.encode(),completing))
        assertFalse(LoginRecovery.cancel(prepared,prepared.generation).tombstones.any())
        assertEquals(LoginResume.RETRY_INVITATION,LoginRecovery.resume(completing,true,true,2,1000))
        val reply=f.client.complete(pending.completion!!,pending.reply!!,f.time,IdentityScope())
        val registered=LoginRecovery.invited(completing,completing.generation,reply,Identity.random())
        val sessionPayload=LoginPayload(f.bootstrap,session=reply.session);sessionPayload.requireBound(registered)
        val cached=LoginRecovery.policyCached(registered,registered.generation,Identity.random(),Identity.random())
        assertEquals(LoginPhase.POLICY_CACHED,cached.phase)
        val cancelled=LoginRecovery.cancel(completing,completing.generation)
        assertTrue(RegistrationTombstone(f.state.ownerTag,completing.thumbprint) in cancelled.tombstones)
        invalid {LoginRecovery.invited(prepared,prepared.generation,reply,Identity.random())}
        invalid {LoginRecovery.invitationProgress(completing,completing.generation,Identity.random(),true,Identity.random())}
        invalid {LoginRecovery.invitationProgress(completing,completing.generation,f.state.ownerTag,false,Identity.random())}
        invalid {LoginRecovery.prepared(reserved,reserved.generation,completing.thumbprint,Identity.random())}
        invalid {pending.validate(Identity.random())}
        invalid {payload.requireBound(prepared)}
        val waiting=InvitationPending(f.operation);waiting.validate(completing.thumbprint)
        assertEquals(waiting,Canonical.json.decodeFromString<InvitationPending>(Canonical.json.encodeToString(waiting)))
    }
    @Test fun stateSubstitutionClockRollbackAndNumericCoercionFailClosed(){
        val f=Fixture();val previous=InvitationReply(f.state,f.time);val status=InvitationOperation.mutation("status",f.state.id)
        for(state in listOf(f.ready.copy(id=Identity.random()),f.ready.copy(nonce=Identity.random()),f.ready.copy(ownerTag=Identity.random()),f.ready.copy(pairCode="654321"),f.ready.copy(version=2),f.ready.copy(expires=f.state.expires+1))){
            f.handler={_,_,_,_->f.json(Canonical.json.encodeToString(state))};error(AuthFailure.INVALID_REPLY){f.client.status(status,previous,f.time,IdentityScope())}
        }
        f.handler={_,_,_,_->f.json(Canonical.json.encodeToString(f.state).replace(JsonPrimitive("version").toString()+":3",JsonPrimitive("version").toString()+":"+JsonPrimitive("3").toString()))}
        error(AuthFailure.INVALID_REPLY){f.client.claim(f.operation,f.time,IdentityScope())}
        f.handler={_,_,_,_->f.json("""{"serviceId":"other"}""")};error(AuthFailure.INVALID_REPLY){f.client.time(IdentityScope())}
        f.handler={_,_,_,_->f.json("""{"serviceId":"fixture"}""")};error(AuthFailure.INVALID_REPLY){f.client.time(IdentityScope(),f.time.copy(lowerMs=f.now+10000,upperMs=f.now+11000))}
        f.boot=3;assertEquals(3,f.client.time(IdentityScope(),f.time).boot)
    }
    @Test fun malformedOperationsStatesAndWrongKeyNeverReachNetwork(){
        val f=Fixture()
        invalid {InvitationOperation("/v1/invitations/unknown","{}")}
        invalid {InvitationOperation(f.operation.path,f.operation.body.replace(JsonPrimitive("code").toString(),JsonPrimitive("extra").toString()))}
        invalid {InvitationOperation.mutation("status","invalid")}
        invalid {InvitationOperation.mutation("unknown",f.state.id)}
        invalid {InvitationOperation(f.operation.path,"x".repeat(8193))}
        for(state in listOf(f.state.copy(id="invalid"),f.state.copy(version=1),f.state.copy(pairCode="bad"),f.state.copy(state="ready"),f.state.copy(error="private-error-text")))invalid {state.validate()}
        error(AuthFailure.INVALID_REPLY){f.client.claim(InvitationOperation.mutation("status",f.state.id),f.time,IdentityScope())}
        val previous=InvitationReply(f.ready,f.time)
        error(AuthFailure.INVALID_REPLY){f.client.complete(InvitationOperation.mutation("complete",Identity.random()),previous,f.time,IdentityScope())}
        error(AuthFailure.INVALID_REPLY){f.client.abandon(InvitationOperation.mutation("status",f.state.id),previous,f.time,IdentityScope())}
        invalid {InvitationPending(f.operation,reply=previous).validate(Identity.thumbprint(f.key.publicKey))}
    }
    @Test fun transportCancellationAndServerErrorsRemainDistinct(){
        val f=Fixture()
        for((status,reason) in listOf(202 to AuthFailure.PENDING,401 to AuthFailure.REAUTHENTICATE,403 to AuthFailure.ACCESS_DENIED,409 to AuthFailure.CONFLICT,429 to AuthFailure.THROTTLED,503 to AuthFailure.UNAVAILABLE,302 to AuthFailure.INVALID_REPLY)){
            f.handler={_,_,_,_->f.json("{}",status)};error(reason){f.client.claim(f.operation,f.time,IdentityScope())}
        }
        f.handler={_,_,_,_->throw DeliveryException(DeliveryFailure.DNS)};error(AuthFailure.TRANSPORT){f.client.time(IdentityScope())}
        val scope=IdentityScope();scope.cancel();error(AuthFailure.CANCELLED){f.client.time(scope)}
        f.handler={_,_,_,_->f.json("{}").copy(headers=mapOf("content-type" to listOf("text/html")))};error(AuthFailure.INVALID_REPLY){f.client.time(IdentityScope())}
        f.handler={_,_,_,_->f.json("""{"revoked":false}""")};error(AuthFailure.INVALID_REPLY){f.client.abandon(InvitationOperation.mutation("abandon",f.state.id),InvitationReply(f.state,f.time),f.time,IdentityScope())}
        f.handler={_,_,_,_->f.json("""{"session":{},"ownerTag":"wrong"}""")};error(AuthFailure.INVALID_REPLY){f.client.complete(InvitationOperation.mutation("complete",f.ready.id),InvitationReply(f.ready,f.time),f.time,IdentityScope())}
    }
}
