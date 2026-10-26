package io.syn443.identity

import io.syn443.policy.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Locale

class AuthProtocolTest {
    companion object {
        private const val now=1_800_000_000_000L
        private val ec=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private val rsa=KeyPairGenerator.getInstance("RSA").apply {initialize(2048)}.generateKeyPair()
        private val root=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private val pub=ec.public as ECPublicKey
        private val key=object:ProofKey {
            override val publicKey=pub
            override fun sign(input:ByteArray)=Signature.getInstance("SHA256withECDSA").run {initSign(ec.private);update(input);sign()}
        }
        private val b=Bootstrap("fixture","https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",
            mapOf("test-root" to Base64.getEncoder().encodeToString(root.public.encoded)))
        private val dateFormat=DateTimeFormatter.ofPattern("EEE, dd MMM uuuu HH:mm:ss 'GMT'",Locale.US).withZone(ZoneOffset.UTC)
        private fun date(ms:Long=now)=dateFormat.format(Instant.ofEpochMilli(ms))
        private fun raw(n:BigInteger)=n.toByteArray().let {if(it.first()==0.toByte())it.drop(1).toByteArray() else it}
        private fun jwks()=Canonical.encode(buildJsonObject {putJsonArray("keys") {add(buildJsonObject {
            val r=rsa.public as RSAPublicKey;put("kid","fixture");put("kty","RSA");put("alg","RS256");put("use","sig")
            put("n",Identity.encode(raw(r.modulus)));put("e","AQAB")
        })}})
        private fun jwt(p:Pending,id:Boolean):String {
            val claims=buildJsonObject {
                put("iss",b.issuer);put("sub","fixture-subject");put("aud",if(id)b.clientId else "syn443-api");put("azp",b.clientId)
                put("iat",now/1000);put("exp",now/1000+300)
                if(id)put("nonce",p.nonce) else putJsonObject("cnf") {put("jkt",p.thumbprint)}
            }
            val input=Identity.encode("""{"alg":"RS256","kid":"fixture","typ":"JWT"}""".toByteArray())+"."+Identity.encode(Canonical.encode(claims).toByteArray())
            return input+"."+Identity.encode(Signature.getInstance("SHA256withRSA").run {initSign(rsa.private);update(input.toByteArray());sign()})
        }
        private fun json(status:Int=200,text:String="{}",extra:Map<String,String> = emptyMap(),time:Long=now)=Reply(status,
            (mapOf("content-type" to "application/json; charset=utf-8","date" to date(time))+extra).mapValues {listOf(it.value)},text.toByteArray())
        private fun session(generation:Long=0,device:String=Identity.hash("fixture-device".toByteArray()),refreshUntil:Long=now+86_000_000)=DeviceSession(
            device,Identity.hash("access-$generation".toByteArray()),Identity.hash("refresh-$generation".toByteArray()),now+590_000,refreshUntil,generation,Identity.hash("nonce-$generation".toByteArray()))
        private fun sessionWire(s:DeviceSession=session())=Policy.json.encodeToString(s)
        private fun error(reason:AuthFailure,block:()->Unit) {try {block();fail("invalid protocol accepted")}catch(e:AuthException) {assertEquals(reason,e.reason);assertNull(e.cause)}}
        private fun invalid(block:()->Unit) {try {block();fail("invalid state accepted")}catch(_:IllegalArgumentException) {}}
    }
    private class Fixture {
        var elapsed=1000L;var boot=2
        val pending=Identity.newPending(7,Identity.thumbprint(pub),boot,elapsed)
        val requests=mutableListOf<String>()
        var handler:(String,String,Map<String,String>,ByteArray?,BoundedHttp.Scope,Int)->Reply={method,url,_,_,_,_->
            when {
                url.endsWith("openid-configuration")->json(text=Canonical.encode(buildJsonObject {
                    put("issuer",b.issuer);put("authorization_endpoint",b.issuer+"/protocol/openid-connect/auth")
                    put("token_endpoint",b.issuer+"/protocol/openid-connect/token");put("jwks_uri",b.issuer+"/protocol/openid-connect/certs")
                    put("id_token_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("RS256"))))
                    put("dpop_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("ES256"))))
                    put("code_challenge_methods_supported",JsonArray(listOf(JsonPrimitive("S256"))))
                }))
                url.endsWith("/certs")->json(text=jwks())
                url.endsWith("/token")->json(text=Canonical.encode(buildJsonObject {
                    put("token_type","DPoP");put("access_token",jwt(pending,false));put("id_token",jwt(pending,true));put("expires_in",300)
                }))
                method=="POST" && url.endsWith("/revoke")->json(204,text="")
                else->json(text=sessionWire())
            }
        }
        val client=AuthProtocol(b,key,IdentityExchange {m,u,h,body,scope,max->requests.add(u);handler(m,u,h,body,scope,max)}, {boot},{elapsed})
        fun time()=TrustedTime(boot,elapsed,now,now+1000)
        fun current(s:DeviceSession=session())=SessionReply(s,time(),client.authority,pending.thumbprint)
        fun user()=UserCredential(jwt(pending,false),"fixture-subject",pending.thumbprint,time(),client.authority)
        fun login(scope:IdentityScope=IdentityScope())=client.exchangeCode("fixture-code",pending,client.discover(scope),scope)
    }
    @Test fun trustedClockBoundsPrecisionRttDriftAndNeverUsesWallClock() {
        val a=TrustedTime.observe(date(),2,1000,2000)
        assertEquals(a,Policy.json.decodeFromString<TrustedTime>(Policy.json.encodeToString(a)))
        assertEquals(TimeWindow(now,now+2000),a.window(2,2000))
        val w=a.window(2,7000);assertEquals(now+4999,w.lowerMs);assertEquals(now+7001,w.upperMs)
        assertEquals(now/1000+6,a.proofSecond(2,7000))
        val next=TrustedTime.observe(date(now+5000),2,7000,8000,a)
        assertTrue(next.lowerMs>=a.window(2,8000).lowerMs)
    }
    @Test fun clockRejectsRebootRollbackStaleAnchorsAndMalformedDates() {
        val a=TrustedTime.observe(date(),2,1000,1000)
        invalid {a.window(3,2000)};invalid {a.window(2,999)};invalid {a.window(2,86_401_001)}
        invalid {TrustedTime.observe(date(),2,0,20_001)};invalid {TrustedTime.observe(date(),2,3,2)}
        invalid {TrustedTime.observe(date(now-60_000),2,1000,1000,a)}
        invalid {TrustedTime.observe(date(now+60_000),2,1000,1000,a)}
        invalid {TrustedTime.observe("Fri, 15 Jan 2027 08:00:00 +0100",2,0,1)}
        invalid {TrustedTime(2,0,0,1)};invalid {TrustedTime(2,0,now,now+51_001)}
        invalid {TrustedTime(2,0,now,now+51_000).proofSecond(2,0)}
    }
    @Test fun pinnedDiscoveryAndCodeExchangeVerifyActualRsaTokens() {
        val f=Fixture();val credential=f.login()
        assertEquals("fixture-subject",credential.subject);assertEquals(f.pending.thumbprint,credential.keyThumbprint)
        assertEquals(3,f.requests.size);assertFalse(credential.toString().contains(credential.accessToken))
        val original=f.handler
        f.handler={m,u,h,body,s,max->
            if(u.endsWith("/token")) {
                assertEquals("application/x-www-form-urlencoded",h["Content-Type"])
                assertTrue(body!!.toString(Charsets.UTF_8).contains("code_verifier="+f.pending.verifier))
                val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(h.getValue("DPoP").split('.')[1])))
                assertFalse(proof.containsKey("ath"));assertFalse(proof.containsKey("req_hash"))
            };original(m,u,h,body,s,max)
        };f.login()
    }
    @Test fun discoveryRejectsEndpointSubstitutionMissingAlgorithmsAndMalformedReplies() {
        val f=Fixture();val original=f.handler
        for(change in listOf<(String)->String>({it.replace("/certs","/elsewhere")},{it.replace("ES256","ES384")},{it.replace("S256","plain")},{it.replace("RS256","HS256")})) {
            f.handler={m,u,h,body,s,max->val r=original(m,u,h,body,s,max);r.copy(body=change(r.body.toString(Charsets.UTF_8)).toByteArray())}
            error(AuthFailure.INVALID_REPLY) {f.client.discover(IdentityScope())}
        }
        f.handler={_,_,_,_,_,_->json(text="{\"issuer\":\"a\",\"issuer\":\"b\"}")};error(AuthFailure.INVALID_REPLY) {f.client.discover(IdentityScope())}
        f.handler={_,_,_,_,_,_->json().copy(headers=emptyMap())};error(AuthFailure.INVALID_REPLY) {f.client.discover(IdentityScope())}
    }
    @Test fun oidcNonceChallengeIsOneRetryWithFreshProofAndSameCodeBody() {
        val f=Fixture();val issuer=f.client.discover(IdentityScope());val original=f.handler;var calls=0;var prior="";var bodyHash=""
        f.handler={m,u,h,body,s,max->
            if(u.endsWith("/token")) {
                calls++;val proof=h.getValue("DPoP");assertNotEquals(prior,proof);prior=proof
                val hash=Identity.hash(body!!);if(calls==1)bodyHash=hash else assertEquals(bodyHash,hash)
                if(calls==1)json(400,"""{"error":"use_dpop_nonce"}""",mapOf("dpop-nonce" to "fixture-issuer-nonce"))
                else {assertTrue(Policy.utf8(Policy.decode64(proof.split('.')[1])).contains("fixture-issuer-nonce"));original(m,u,h,body,s,max)}
            } else original(m,u,h,body,s,max)
        }
        f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope());assertEquals(2,calls)
        f.handler={_,_,_,_,_,_->json(401,"""{"error":"use_dpop_nonce"}""",mapOf("dpop-nonce" to "again"))}
        error(AuthFailure.REAUTHENTICATE) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
        f.handler={_,_,_,_,_,_->json(400,"""{"error":"use_dpop_nonce"}""")}
        error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
    }
    @Test fun tokenRepliesRequireDpopTypedExpiryIdentityAndFreshIssuerTime() {
        val f=Fixture();val issuer=f.client.discover(IdentityScope());val original=f.handler
        error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,IssuerState(issuer.keys,issuer.time,"another-service"),IdentityScope())}
        for(transform in listOf<(String)->String>({it.replace("DPoP","Bearer")},{it.replace("\"expires_in\":300","\"expires_in\":\"300\"")},{it.replace("\"expires_in\":300","\"expires_in\":601")},{it.replace(jwt(f.pending,true),jwt(f.pending,false))})) {
            f.handler={m,u,h,body,s,max->original(m,u,h,body,s,max).let {it.copy(body=transform(it.body.toString(Charsets.UTF_8)).toByteArray())}}
            error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
        }
        f.handler={m,u,h,body,s,max->original(m,u,h,body,s,max).copy(headers=mapOf("content-type" to listOf("application/json"),"date" to listOf(date(now-60_000))))}
        error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("",f.pending,issuer,IdentityScope())}
        f.elapsed+=300_000;error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
    }
    @Test fun enrollmentChallengesFreshProofsBindTheSamePersistedRawBody() {
        val f=Fixture();val op=IdentityOperation.enroll(pub);var prior="";var calls=0
        f.handler={m,u,h,body,_,_->
            assertEquals("POST",m);assertEquals(b.apiOrigin+op.path,u);assertEquals(op.body,body!!.toString(Charsets.UTF_8))
            assertEquals("application/json",h["Content-Type"]);val proof=h.getValue("DPoP");assertNotEquals(prior,proof);prior=proof
            val claims=Identity.objectJSON(Policy.utf8(Policy.decode64(proof.split('.')[1])))
            assertEquals(Identity.hash(body),claims.getValue("req_hash").jsonPrimitive.content)
            assertEquals(Identity.hash(f.user().accessToken.toByteArray()),claims.getValue("ath").jsonPrimitive.content)
            if(++calls==1)json(401,"""{"code":"use_dpop_nonce"}""",mapOf("dpop-nonce" to Identity.random())) else json(text=sessionWire())
        }
        val result=f.client.enroll(op,f.user(),IdentityScope());assertEquals(session(),result.session);assertEquals(2,calls)
        assertEquals("IdentityOperation([redacted])",op.toString());assertFalse(result.toString().contains(result.session.accessToken))
    }
    @Test fun serverNonceChallengeCannotLoopAndErrorCategoriesAreRedacted() {
        val f=Fixture();val op=IdentityOperation.enroll(pub)
        f.handler={_,_,_,_,_,_->json(401,"""{"code":"use_dpop_nonce"}""",mapOf("dpop-nonce" to "nonce"))}
        error(AuthFailure.REAUTHENTICATE) {f.client.enroll(op,f.user(),IdentityScope())};assertEquals(2,f.requests.size)
        for((code,reason) in listOf(202 to AuthFailure.PENDING,401 to AuthFailure.REAUTHENTICATE,403 to AuthFailure.ACCESS_DENIED,
            409 to AuthFailure.CONFLICT,429 to AuthFailure.THROTTLED,503 to AuthFailure.UNAVAILABLE,302 to AuthFailure.INVALID_REPLY)) {
            f.handler={_,_,_,_,_,_->json(code,"""{"code":"untrusted-text"}""")};error(reason) {f.client.enroll(op,f.user(),IdentityScope())}
        }
        f.handler={_,_,_,_,_,_->throw DeliveryException(DeliveryFailure.DNS)};error(AuthFailure.TRANSPORT) {f.client.enroll(op,f.user(),IdentityScope())}
    }
    @Test fun invalidSessionShapesTokensScalarTypesAndLifetimesCannotBeCached() {
        val f=Fixture();val op=IdentityOperation.enroll(pub);val s=session()
        for(wire in listOf(sessionWire(s.copy(accessToken="invalid")),sessionWire(s.copy(refreshToken=s.accessToken)),sessionWire(s.copy(generation=-1)),
            sessionWire(s.copy(accessUntilMs=now+1000)),sessionWire(s.copy(accessUntilMs=now+600_001)),sessionWire(s.copy(refreshUntilMs=now+86_400_001)),
            sessionWire(s.copy(refreshUntilMs=now+1000)),sessionWire().replace("\"generation\":0","\"generation\":\"0\""),sessionWire().dropLast(1)+",\"extra\":true}")) {
            f.handler={_,_,_,_,_,_->json(text=wire)};error(AuthFailure.INVALID_REPLY) {f.client.enroll(op,f.user(),IdentityScope())}
        }
        error(AuthFailure.INVALID_REPLY) {f.client.enroll(op,UserCredential("short","subject",f.pending.thumbprint,f.time(),f.client.authority),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.enroll(op,UserCredential(jwt(f.pending,false),"subject",Identity.random(),f.time(),f.client.authority),IdentityScope())}
    }
    @Test fun refreshRotatesOneGenerationWithoutExtendingAbsoluteGrantAndRevokeUsesAccess() {
        val f=Fixture();val previous=f.current();val refresh=IdentityOperation.refresh();val next=session(1)
        f.handler={_,u,h,body,_,_->
            if(u.endsWith("/refresh")) {assertEquals("DPoP "+previous.session.refreshToken,h["Authorization"]);assertEquals(refresh.body,body!!.toString(Charsets.UTF_8));json(text=sessionWire(next))}
            else {assertEquals("DPoP "+next.accessToken,h["Authorization"]);json(204,text="")}
        }
        error(AuthFailure.INVALID_REPLY) {f.client.refresh(refresh,previous.copy(authority="wrong"),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.policy(previous.copy(keyThumbprint=Identity.random()),IdentityScope())}
        assertEquals(previous,Policy.json.decodeFromString<SessionReply>(Policy.json.encodeToString(previous)))
        val result=f.client.refresh(refresh,previous,IdentityScope());assertEquals(next,result.session)
        f.client.revoke(IdentityOperation.revoke(),result,IdentityScope())
        for(bad in listOf(next.copy(generation=3),next.copy(deviceId=Identity.random()),next.copy(refreshUntilMs=next.refreshUntilMs-1),
            next.copy(accessToken=previous.session.accessToken),next.copy(refreshToken=previous.session.refreshToken),next.copy(nonce=previous.session.nonce))) {
            f.handler={_,_,_,_,_,_->json(text=sessionWire(bad))};error(AuthFailure.INVALID_REPLY) {f.client.refresh(refresh,previous,IdentityScope())}
        }
        f.elapsed+=86_000_001;error(AuthFailure.INVALID_REPLY) {f.client.refresh(refresh,previous,IdentityScope())}
    }
    @Test fun ownerCleanupNeedsFreshMatchingIdentityAndNeverReturnsASession() {
        val f=Fixture();val op=IdentityOperation.cleanup(listOf(Identity.random()))
        f.handler={m,u,h,body,_,_->assertEquals("POST",m);assertTrue(u.endsWith("/identity/devices/revoke"));assertEquals(op.body,body!!.toString(Charsets.UTF_8));assertTrue(h["Authorization"]!!.startsWith("DPoP "));json(204,text="")}
        assertEquals(now,f.client.cleanup(op,f.user(),IdentityScope()).lowerMs)
        error(AuthFailure.INVALID_REPLY) {f.client.cleanup(op,UserCredential(jwt(f.pending,false),"subject",f.pending.thumbprint,f.time(),"wrong"),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.cleanup(IdentityOperation.revoke(),f.user(),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.revoke(op,f.current(),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.refresh(op,f.current(),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.enroll(op,f.user(),IdentityScope())}
    }
    @Test fun operationsPreserveExactBodiesAndRejectUnboundedOrAmbiguousPersistence() {
        val a=IdentityOperation.enroll(pub);assertEquals(a,Policy.json.decodeFromString<IdentityOperation>(Policy.json.encodeToString(a)))
        assertNotEquals(a.body,IdentityOperation.enroll(pub).body)
        invalid {IdentityOperation("/elsewhere",a.body)};invalid {IdentityOperation(a.path," ".repeat(8193))}
        invalid {IdentityOperation(a.path,a.body.replace("P-256","P-384"))};invalid {IdentityOperation(a.path,a.body.replace("policy.keybound.v2","policy.unsupported"))}
        invalid {IdentityOperation(a.path,a.body.dropLast(1)+",\"requestId\":\"duplicate\"}")}
        invalid {IdentityOperation.cleanup(emptyList())};val t=Identity.random();invalid {IdentityOperation.cleanup(listOf(t,t))}
        invalid {IdentityOperation.cleanup(List(17){Identity.random()})};invalid {IdentityOperation.cleanup(listOf("invalid"))}
        invalid {IdentityOperation(IdentityOperation.revoke().path,"{\"requestId\":24}")}
        invalid {IdentityOperation(IdentityOperation.revoke().path,"{\"requestId\":\"short\"}")}
        invalid {IdentityOperation(IdentityOperation.revoke().path,IdentityOperation.revoke().body.dropLast(1)+",\"extra\":true}")}
        val f=Fixture();assertFalse(f.pending.toString().contains(f.pending.verifier));assertFalse(b.toString().contains(b.issuer))
        assertEquals("Callback([redacted])",Callback("sensitive-code",null).toString())
        assertEquals("UserIdentity([redacted])",UserIdentity("private-subject").toString())
        assertEquals("Reply(status=200, [redacted])",json(text="sensitive-body").toString())
    }
    @Test fun uncertainRefreshRetriesTheSameOperationAndCancelledEnrollmentCannotReturnACredential() {
        val f=Fixture();val previous=f.current();val op=IdentityOperation.refresh();var calls=0;var firstProof=""
        f.handler={_,_,headers,body,_,_->
            assertEquals(op.body,body!!.toString(Charsets.UTF_8))
            if(++calls==1) {firstProof=headers.getValue("DPoP");throw DeliveryException(DeliveryFailure.EOF)}
            assertNotEquals(firstProof,headers.getValue("DPoP"));json(text=sessionWire(session(1)))
        }
        error(AuthFailure.TRANSPORT) {f.client.refresh(op,previous,IdentityScope())}
        assertEquals(0L,previous.session.generation)
        assertEquals(1L,f.client.refresh(op,previous,IdentityScope()).session.generation);assertEquals(2,calls)
        val scope=IdentityScope();f.handler={_,_,_,_,_,_->scope.cancel();json(text=sessionWire())}
        error(AuthFailure.CANCELLED) {f.client.enroll(IdentityOperation.enroll(pub),f.user(),scope)}
    }
    @Test fun oneOperationSupportsSequentialChildrenButCancelRejectsLateAndFutureResults() {
        val f=Fixture();val scope=IdentityScope();f.login(scope);scope.cancel()
        error(AuthFailure.CANCELLED) {f.client.discover(scope)}
        val late=IdentityScope();f.handler={_,_,_,_,_,_->late.cancel();json()}
        error(AuthFailure.CANCELLED) {f.client.discover(late)}
        val active=IdentityScope();f.handler={_,_,_,_,child,_->active.cancel();child.active();json()}
        error(AuthFailure.CANCELLED) {f.client.discover(active)}
    }
    @Test fun policyRequiresJoseAndActualSignatureDeviceAndLocalKeyAtConservativeTime() {
        val f=Fixture();val s=session();val config="""{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""
        fun signed(device:String=s.deviceId,thumb:String=f.pending.thumbprint):String {
            val p=Payload(2,1,0,0,device,"syn443-device",now-1000,now-1000,now+300_000,now+600_000,
                IdentityOperation.requiredCapabilities,"m1-local-v1",Identity.encode(config.toByteArray()),Policy.hash(config),Gate(30,false,listOf(Check("internet","https_204","https://health.example.org/generate_204"))),keyThumbprint=thumb)
            val input=Identity.encode("""{"alg":"ES256","kid":"test-root","typ":"syn443-policy+jws"}""".toByteArray())+"."+Identity.encode(Canonical.encode(Canonical.parse(Policy.json.encodeToString(p))).toByteArray())
            return input+"."+Identity.encode(Signature.getInstance("SHA256withECDSAinP1363Format").run {initSign(root.private);update(input.toByteArray());sign()})
        }
        val valid=signed()
        f.handler={m,u,h,body,_,max->assertEquals("GET",m);assertEquals(b.apiOrigin+"/v1/device/policy",u);assertNull(body);assertEquals(524_288,max);assertTrue(h.containsKey("DPoP"));json(text=valid).copy(headers=mapOf("content-type" to listOf("application/jose"),"date" to listOf(date())))}
        val result=f.client.policy(f.current(),IdentityScope());assertEquals(valid,result.envelope);assertFalse(result.toString().contains(valid))
        val mutableRoots=b.roots.toMutableMap()
        val isolated=AuthProtocol(b.copy(roots=mutableRoots),key,IdentityExchange {m,u,h,body,scope,max->f.handler(m,u,h,body,scope,max)},{f.boot},{f.elapsed})
        mutableRoots.clear();assertEquals(valid,isolated.policy(f.current(),IdentityScope()).envelope)
        val original=f.handler
        for(wire in listOf(signed(thumb=Identity.random()),signed(device=Identity.random()),valid.dropLast(2)+"xx")) {
            f.handler={m,u,h,body,scope,max->original(m,u,h,body,scope,max).copy(body=wire.toByteArray())};error(AuthFailure.INVALID_REPLY) {f.client.policy(f.current(),IdentityScope())}
        }
        f.handler={_,_,_,_,_,_->json(text=valid)};error(AuthFailure.INVALID_REPLY) {f.client.policy(f.current(),IdentityScope())}
        val current=f.current();f.elapsed+=600_000;error(AuthFailure.INVALID_REPLY) {f.client.policy(current,IdentityScope())}
    }
}
