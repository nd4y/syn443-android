package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.net.URLDecoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

class AdminProtocolTest {
    @Test fun administrativeDiscoveryPinsKeycloakEndpointsAlgorithmsAndHttpsDateBeforeTokenDispatch() {
        val f=AdminAuthFixture();val state=f.client.discover(IdentityScope())
        assertEquals(listOf(f.metadata.issuer+"/.well-known/openid-configuration",f.base+"/certs"),f.calls.map {it.url})
        assertEquals(f.client.authority,state.authority);assertEquals(f.client.thumbprint,state.keyThumbprint)
        for(change in listOf<(String)->String>({it.replace(f.base+"/token","https://foreign.example.invalid/token")},
            {it.replace("RS256","HS256")},{it.replace("ES256","none")},{it.replace("S256","plain")},
            {it.replace(f.metadata.issuer,"https://foreign.example.invalid/realms/control")})) {
            val bad=AdminAuthFixture();bad.handler={call->bad.normal(call).let {it.copy(body=change(it.body.decodeToString()).toByteArray())}}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){bad.client.discover(IdentityScope())}
            assertEquals(1,bad.calls.size)
        }
    }
    @Test fun codeExchangeAndRefreshUseSeparatePkceDpopAndNeverExtendOriginalEightHourLease() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope())
        val first=f.client.exchangeCallback(f.callback(),f.pending,7,issuer,IdentityScope())
        val code=f.calls.last();val form=AdminAuthFixture.parameters(checkNotNull(code.body).decodeToString())
        assertEquals(AdminBootstrap.CALLBACK,form["redirect_uri"]);assertEquals(f.pending.verifier,form["code_verifier"])
        assertEquals(AdminBootstrap.CLIENT_ID,form["client_id"]);assertEquals("authorization_code",form["grant_type"])
        assertFalse(code.headers.containsKey("Authorization"));assertFalse(code.headers.containsKey("Origin"))
        assertEquals(f.base+"/token",f.proof(code).getValue("htu").jsonPrimitive.content)
        assertFalse("ath" in f.proof(code));assertFalse("nonce" in f.proof(code))
        assertTrue(first.sessionUntilElapsedMs<=f.pending.startedElapsedMs+28_800_000)
        val deadline=first.sessionUntilElapsedMs
        f.elapsed+=60_000
        val next=f.client.refresh(first,issuer,IdentityScope())
        assertEquals(deadline,next.sessionUntilElapsedMs);assertEquals(first.subject,next.subject)
        assertEquals(first.keyThumbprint,next.keyThumbprint);assertEquals(first.authority,next.authority)
        assertNotEquals(first.accessToken,next.accessToken);assertNotEquals(first.refreshToken,next.refreshToken)
        val refreshForm=AdminAuthFixture.parameters(checkNotNull(f.calls.last().body).decodeToString())
        assertEquals(setOf("grant_type","client_id","refresh_token"),refreshForm.keys)
        assertEquals(first.refreshToken,refreshForm["refresh_token"])
        val count=f.calls.size
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.refresh(first,issuer,IdentityScope())}
        assertEquals(count,f.calls.size)
        assertFalse(first.toString().contains(first.refreshToken));assertFalse(issuer.toString().contains(f.metadata.issuer))
    }
    @Test fun initialIdTokenRejectsMissingMalformedUnsafeAndStaleAuthenticationTimeDespiteFreshIssueTime() {
        val invalid=listOf<JsonElement?>(null,JsonNull,JsonPrimitive("1800000000"),JsonPrimitive(1800000000.0),
            JsonPrimitive(true),JsonPrimitive(0),JsonPrimitive(-1),JsonPrimitive(Long.MAX_VALUE),
            JsonPrimitive(Long.MAX_VALUE/1000+1),JsonPrimitive(AdminAuthFixture.NOW/1000-3600),
            JsonPrimitive(AdminAuthFixture.NOW/1000+31))
        for(authenticated in invalid) {
            val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope())
            f.handler={f.tokens(idChanges=authenticated?.let {mapOf("auth_time" to it)} ?: emptyMap(),
                includeAuthTime=authenticated!=null)}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY) {f.login(issuer)}
            assertTrue(f.pending.consumed.get());assertEquals(3,f.calls.size)
            assertEquals("authorization_code",AdminAuthFixture.parameters(checkNotNull(f.calls.last().body).decodeToString())["grant_type"])
            assertThrows(AdminException::class.java) {f.login(issuer)}
            assertEquals("a rejected consumed code cannot be retried",3,f.calls.size)
        }
    }
    @Test fun refreshKeepsOldAuthenticationTimeOptionalWithoutRenewingMfaOrTheOriginalSessionLease() {
        for(kind in 0..2) {
            val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val first=f.login(issuer)
            val deadline=first.sessionUntilElapsedMs
            f.elapsed+=360_000
            f.handler={when(kind) {
                0->f.tokens(includeId=false)
                1->f.tokens(includeAuthTime=false)
                else->f.tokens(idChanges=mapOf("auth_time" to JsonPrimitive(AdminAuthFixture.NOW/1000)))
            }}
            val next=f.client.refresh(first,issuer,IdentityScope())
            assertEquals(first.subject,next.subject);assertEquals(deadline,next.sessionUntilElapsedMs)
            assertFalse(first.available());assertTrue(next.available());assertEquals(4,f.calls.size)
            assertEquals(setOf("grant_type","client_id","refresh_token"),
                AdminAuthFixture.parameters(checkNotNull(f.calls.last().body).decodeToString()).keys)
        }
    }
    @Test fun catalogReauthenticationRequiresExactBoundedJsonAndNeverRetriesANonceOrWrongCode() {
        val exact="""{"code":"catalog_reauthentication_required"}"""
        val positives=listOf(exact,exact+"\n",exact+" ".repeat(128-exact.length))
        val invalid=listOf("""{"error":"catalog_reauthentication_required"}""", """{"code":"catalog_denied"}""",
            """{"error":"use_dpop_nonce"}""", """{"code":"catalog_reauthentication_required","extra":true}""",
            """{"code":"catalog_reauthentication_required","code":"catalog_reauthentication_required"}""",
            """{"code":"catalog_reauthentication_required","co\u0064e":"catalog_reauthentication_required"}""",
            """{"Code":"catalog_reauthentication_required"}""", """{"code":null}""", """{"code":true}""",
            """{"code":"CATALOG_REAUTHENTICATION_REQUIRED"}""",exact.dropLast(1),exact+" ".repeat(129-exact.length))
        for((raw,expected) in positives.map {it to AdminFailure.REAUTHENTICATE}+invalid.map {it to AdminFailure.ACCESS_DENIED}) {
            val f=AdminAuthFixture()
            f.handler={f.reply(403,raw,mapOf("dpop-nonce" to listOf("untrusted-no-retry")))}
            AdminAuthFixture.failure(expected) {f.client.discover(IdentityScope())}
            assertEquals(1,f.calls.size);assertFalse(f.pending.consumed.get())
        }
        for(headers in listOf(mapOf("content-type" to listOf("text/plain")),
            mapOf("content-type" to listOf("application/json","application/json")))) {
            val f=AdminAuthFixture();f.handler={f.reply(403,exact,headers)}
            AdminAuthFixture.failure(AdminFailure.ACCESS_DENIED) {f.client.discover(IdentityScope())}
            assertEquals(1,f.calls.size)
        }
        val malformed=AdminAuthFixture()
        malformed.handler={malformed.reply(403,exact).copy(body=byteArrayOf(0xc3.toByte(),0x28))}
        AdminAuthFixture.failure(AdminFailure.ACCESS_DENIED) {malformed.client.discover(IdentityScope())}
        assertEquals(1,malformed.calls.size)
    }
    @Test fun refreshAllowsMissingIdTokenButRejectsChangedSubjectNonceAudienceOrKey() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val first=f.login(issuer)
        f.handler={call->if(call.url.endsWith("/token"))f.tokens(includeId=false) else f.normal(call)}
        assertEquals(first.subject,f.client.refresh(first,issuer,IdentityScope()).subject)
        for(change in listOf<(AdminAuthFixture)->Reply>(
            {it.tokens(subject="foreign-user")},
            {it.tokens(idChanges=mapOf("nonce" to JsonPrimitive(Identity.random())))},
            {it.tokens(accessChanges=mapOf("aud" to JsonPrimitive("syn443-api")))},
            {it.tokens(accessChanges=mapOf("cnf" to buildJsonObject {put("jkt",Identity.random())}))})) {
            val bad=AdminAuthFixture();val state=bad.client.discover(IdentityScope());val old=bad.login(state)
            bad.handler={change(bad)}
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){bad.client.refresh(old,state,IdentityScope())}
            assertFalse(old.available())
        }
    }
    @Test fun optionalIdTokenAccessHashMustMatchBothInitialAndRotatedAccessTokens() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope())
        f.handler={f.tokens(includeAtHash=true)}
        val first=f.login(issuer)
        assertEquals(first.subject,f.client.refresh(first,issuer,IdentityScope()).subject)
        for(refresh in listOf(false,true)) {
            val bad=AdminAuthFixture();val state=bad.client.discover(IdentityScope())
            val previous=if(refresh)bad.login(state) else null
            bad.handler={bad.tokens(includeAtHash=true,idChanges=mapOf("at_hash" to JsonPrimitive(Identity.random())))}
            AdminAuthFixture.failure(if(refresh)AdminFailure.REAUTHENTICATE else AdminFailure.INVALID_REPLY) {
                if(previous==null)bad.login(state) else bad.client.refresh(previous,state,IdentityScope())
            }
        }
    }
    @Test fun refreshMustRotateItsPairAndCanOnlyShortenTheRemainingSessionLease() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val previous=f.login(issuer)
        f.handler={f.tokens().let {reply->reply.copy(body=Canonical.encode(JsonObject(
            Identity.objectJSON(reply.body.decodeToString())+mapOf("refresh_expires_in" to JsonPrimitive(120)))).toByteArray())}}
        val next=f.client.refresh(previous,issuer,IdentityScope())
        assertTrue(next.sessionUntilElapsedMs<previous.sessionUntilElapsedMs)
        assertTrue(next.sessionUntilElapsedMs<=f.elapsed+120_000)
        val bad=AdminAuthFixture();val state=bad.client.discover(IdentityScope());val old=bad.login(state)
        bad.handler={bad.tokens().let {reply->reply.copy(body=Canonical.encode(JsonObject(
            Identity.objectJSON(reply.body.decodeToString())+mapOf("refresh_token" to JsonPrimitive(old.refreshToken)))).toByteArray())}}
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){bad.client.refresh(old,state,IdentityScope())}
        assertFalse(old.available())
    }
    @Test fun signedTokenSubstitutionsCannotTurnDeviceAudienceOrForeignClaimsIntoAdminAuthority() {
        val changes=listOf<Pair<Boolean,Map<String,JsonElement>>>(
            false to mapOf("iss" to JsonPrimitive("https://device.example.invalid/realms/user")),
            false to mapOf("aud" to JsonPrimitive("syn443-api")),
            false to mapOf("aud" to JsonArray(listOf(JsonPrimitive(AdminBootstrap.AUDIENCE),JsonPrimitive("syn443-api")))),
            false to mapOf("azp" to JsonPrimitive("syn443-android")),
            false to mapOf("cnf" to buildJsonObject {put("jkt",Identity.random())}),
            false to mapOf("scope" to JsonPrimitive("openid")),
            false to mapOf("scope" to JsonPrimitive("openid syn443.control offline_access")),
            false to mapOf("scope" to JsonPrimitive("openid  syn443.control")),
            false to mapOf("sub" to JsonPrimitive("foreign")),
            false to mapOf("exp" to JsonPrimitive(AdminAuthFixture.NOW/1000+601)),
            false to mapOf("exp" to JsonPrimitive((AdminAuthFixture.NOW/1000+300).toString())),
            false to mapOf("iat" to JsonPrimitive(AdminAuthFixture.NOW/1000+31)),
            false to mapOf("nbf" to JsonPrimitive(AdminAuthFixture.NOW/1000+31)),
            true to mapOf("nonce" to JsonPrimitive(Identity.random())),
            true to mapOf("aud" to JsonPrimitive("syn443-android")),
            true to mapOf("azp" to JsonPrimitive("foreign-client")),
            true to mapOf("sub" to JsonPrimitive("foreign")))
        for((id,changed) in changes) {
            val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope())
            f.handler={f.tokens(idChanges=if(id)changed else emptyMap(),accessChanges=if(id)emptyMap() else changed)}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.login(issuer)}
            assertTrue(f.pending.consumed.get());assertEquals(3,f.calls.size)
        }
    }
    @Test fun tokenReplyTypesBoundsDuplicateJsonSignatureAndExpiryConsistencyAreRequired() {
        val transforms=listOf<(JsonObject)->JsonObject>(
            {JsonObject(it+mapOf("token_type" to JsonPrimitive("Bearer")))},
            {JsonObject(it+mapOf("expires_in" to JsonPrimitive("300")))},
            {JsonObject(it+mapOf("expires_in" to JsonPrimitive(601)))},
            {JsonObject(it+mapOf("expires_in" to JsonPrimitive(30)))},
            {JsonObject(it+mapOf("refresh_expires_in" to JsonPrimitive(0)))},
            {JsonObject(it+mapOf("refresh_expires_in" to JsonPrimitive(86_401)))},
            {JsonObject(it+mapOf("id_token" to JsonNull))},
            {JsonObject(it+mapOf("scope" to JsonPrimitive("openid")))},
            {JsonObject(it+mapOf("refresh_token" to JsonPrimitive("!".repeat(3000))))},
            {JsonObject(it+mapOf("access_token" to JsonPrimitive(it.getValue("access_token").jsonPrimitive.content+"x")))})
        for(transform in transforms) {
            val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope())
            f.handler={f.tokens().let {it.copy(body=Canonical.encode(transform(Identity.objectJSON(it.body.decodeToString()))).toByteArray())}}
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.login(issuer)}
        }
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope())
        f.handler={f.reply(text="""{"token_type":"DPoP","token_type":"DPoP"}""")}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.login(issuer)}
    }
    @Test fun issuerNonceChallengeIsOneRetryWithFreshProofAndIdenticalCodeRequest() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val bodies=mutableListOf<ByteArray>();val proofs=mutableListOf<String>()
        f.handler={call->
            bodies+=checkNotNull(call.body);proofs+=call.headers.getValue("DPoP")
            if(bodies.size==1)f.reply(400,"""{"error":"use_dpop_nonce"}""",mapOf("dpop-nonce" to listOf("issuer-nonce")))
            else {assertEquals("issuer-nonce",f.proof(call).getValue("nonce").jsonPrimitive.content);f.tokens()}
        }
        f.login(issuer)
        assertEquals(2,bodies.size);assertArrayEquals(bodies[0],bodies[1]);assertNotEquals(proofs[0],proofs[1])
        for(secondSuccess in listOf(false,true)) {
            val bad=AdminAuthFixture();val state=bad.client.discover(IdentityScope());var count=0
            bad.handler={count++;if(secondSuccess)bad.reply(text="{}") else bad.reply(401,"""{"error":"use_dpop_nonce"}""",mapOf("dpop-nonce" to listOf("again")))}
            AdminAuthFixture.failure(if(secondSuccess)AdminFailure.INVALID_REPLY else AdminFailure.REAUTHENTICATE){bad.login(state)}
            assertEquals(if(secondSuccess)1 else 2,count)
        }
    }
    @Test fun refreshNonceChallengeKeepsOneDispatchOwnerAndMissingOrStaleChallengeCannotRetry() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val old=f.login(issuer);var count=0;var body=""
        f.handler={call->
            count++;val raw=checkNotNull(call.body).decodeToString()
            if(count==1) {body=raw;f.reply(400,"""{"error":"use_dpop_nonce"}""",mapOf("dpop-nonce" to listOf("refresh-nonce")))}
            else {assertEquals(body,raw);assertEquals("refresh-nonce",f.proof(call).getValue("nonce").jsonPrimitive.content);f.tokens()}
        }
        f.client.refresh(old,issuer,IdentityScope());assertEquals(2,count)
        for(stale in listOf(false,true)) {
            val bad=AdminAuthFixture();val state=bad.client.discover(IdentityScope());val prior=bad.login(state)
            bad.handler={bad.reply(400,"""{"error":"use_dpop_nonce"}""",
                if(stale)mapOf("dpop-nonce" to listOf("nonce")) else emptyMap(),if(stale)AdminAuthFixture.NOW-60_000 else bad.wall)}
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){bad.client.refresh(prior,state,IdentityScope())}
            assertEquals(4,bad.calls.size)
        }
    }
    @Test fun uncertainRefreshTransportPermanentlyRetiresPairInsteadOfReplayingIt() {
        for(reason in listOf(DeliveryFailure.TRANSPORT,DeliveryFailure.EOF,DeliveryFailure.DEADLINE,DeliveryFailure.TLS)) {
            val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val old=f.login(issuer)
            f.handler={throw DeliveryException(reason)}
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.refresh(old,issuer,IdentityScope())}
            assertFalse(old.available());val count=f.calls.size
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.refresh(old,issuer,IdentityScope())}
            assertEquals(count,f.calls.size)
        }
    }
    @Test fun cancellationBeforeDispatchRetainsPairButLateCancellationRequiresNewAuthentication() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val old=f.login(issuer)
        val cancelled=IdentityScope().apply {cancel()};val before=f.calls.size
        AdminAuthFixture.failure(AdminFailure.CANCELLED){f.client.refresh(old,issuer,cancelled)}
        assertTrue(old.available());assertEquals(before,f.calls.size)
        val late=IdentityScope();f.handler={late.cancel();f.tokens()}
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.refresh(old,issuer,late)}
        assertFalse(old.available())
    }
    @Test fun callbackReplayGenerationBootAndDeadlineCannotDispatchAuthorizationCode() {
        for(mode in 0..4) {
            val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());var generation=7L
            when(mode) {0->generation++;1->f.boot++;2->f.elapsed+=300_000;3->f.elapsed--;4->f.login(issuer)}
            val count=f.calls.size
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.exchangeCallback(f.callback(),f.pending,generation,issuer,IdentityScope())}
            assertEquals(count,f.calls.size)
        }
    }
    @Test fun bootClockOrPendingExpiryDuringProofCannotDispatchExpiredCodeOrRefresh() {
        for(mode in 0..3) {
            val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope())
            if(mode==3)f.handler={f.tokens().let {reply->reply.copy(body=Canonical.encode(JsonObject(
                Identity.objectJSON(reply.body.decodeToString())+mapOf("refresh_expires_in" to JsonPrimitive(10)))).toByteArray())}}
            val previous=if(mode==0)null else f.login(issuer)
            val delaying=object:ProofKey {
                override val publicKey=f.key.publicKey
                override fun sign(input:ByteArray):ByteArray {
                    val signature=f.key.sign(input)
                    when(mode) {0->f.elapsed++;1->f.boot++;2->f.elapsed--;3->f.elapsed=checkNotNull(previous).sessionUntilElapsedMs}
                    return signature
                }
            }
            val guarded=AdminProtocol(f.identity,delaying,f.exchange,{f.boot},{f.elapsed})
            val p=guarded.newPending(7)
            if(mode==0)f.elapsed+=299_999
            val before=f.calls.size
            AdminAuthFixture.failure(if(mode==3)AdminFailure.SESSION_EXPIRED else AdminFailure.INVALID_REPLY) {
                if(previous==null)guarded.exchangeCallback(AdminBootstrap.CALLBACK+"?"+Identity.form(linkedMapOf(
                    "code" to "fixture-code","state" to p.state,"iss" to f.metadata.issuer)),p,7,issuer,IdentityScope())
                else guarded.refresh(previous,issuer,IdentityScope())
            }
            assertEquals(before,f.calls.size)
            if(previous!=null)assertTrue(previous.available())
        }
    }
    @Test fun issuerAndSessionCannotCrossAdministrativeAuthorityOrSeparateDpopKey() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val old=f.login(issuer)
        val foreign=AdminAuthFixture()
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){foreign.client.refresh(old,issuer,IdentityScope())}
        assertTrue(foreign.calls.isEmpty());assertTrue(old.available())
        val other=AdminProtocol(AdminIdentity(f.metadata,Identity.random()),f.key,f.exchange,{f.boot},{f.elapsed})
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){other.exchangeCallback(f.callback(),f.client.newPending(7),7,issuer,IdentityScope())}
        assertTrue(old.available())
    }
    @Test fun expiredSessionBootRollbackAndStaleHttpsDateCannotResurrectCredentials() {
        for(mode in 0..3) {
            val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val old=f.login(issuer);val before=f.calls.size
            when(mode) {0->f.elapsed=old.sessionUntilElapsedMs;1->f.boot++;2->f.elapsed--;3->f.handler={f.tokens().let {it.copy(headers=it.headers+mapOf("date" to listOf(AdminAuthFixture.date(f.wall-60_000))))}}}
            AdminAuthFixture.failure(when(mode){0->AdminFailure.SESSION_EXPIRED;3->AdminFailure.REAUTHENTICATE;else->AdminFailure.INVALID_REPLY}) {
                f.client.refresh(old,issuer,IdentityScope())
            }
            assertEquals(before+if(mode==3)1 else 0,f.calls.size)
        }
    }
    @Test fun concurrentRefreshHasOneOwnerAndLocalLogoutDoesNotCallServerOrDeviceIdentity() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val old=f.login(issuer)
        val entered=CountDownLatch(1);val release=CountDownLatch(1);val completed=CountDownLatch(1);val successes=AtomicInteger()
        f.handler={entered.countDown();check(release.await(2,TimeUnit.SECONDS));f.tokens()}
        val worker=thread {
            try {f.client.refresh(old,issuer,IdentityScope());successes.incrementAndGet()}
            finally {completed.countDown()}
        }
        try {
            assertTrue(entered.await(2,TimeUnit.SECONDS))
            val count=f.calls.size
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.refresh(old,issuer,IdentityScope())}
            assertEquals(count,f.calls.size)
        } finally {release.countDown();worker.join(2000)}
        assertTrue(completed.await(1,TimeUnit.SECONDS));assertEquals(1,successes.get())
        val count=f.calls.size;val logout=f.client.logout(old)
        assertEquals(old.authority,logout.authority);assertFalse(logout.toString().contains(old.refreshToken))
        assertEquals("AdminSessionFamily([redacted])",old.family.toString())
        assertEquals(count,f.calls.size)
    }
    @Test fun localLogoutClosesTheFamilyDuringInflightRefreshAndAcrossCompletedRotations() {
        val f=AdminAuthFixture();val issuer=f.client.discover(IdentityScope());val old=f.login(issuer)
        val entered=CountDownLatch(1);val release=CountDownLatch(1);val completed=CountDownLatch(1)
        val outcome=AtomicReference<Any>()
        f.handler={entered.countDown();check(release.await(2,TimeUnit.SECONDS));f.tokens()}
        val worker=thread {
            try {outcome.set(f.client.refresh(old,issuer,IdentityScope()))}
            catch(e:Exception){outcome.set(e)}
            finally {completed.countDown()}
        }
        try {
            assertTrue(entered.await(2,TimeUnit.SECONDS))
            val count=f.calls.size
            f.client.logout(old)
            assertEquals(count,f.calls.size)
            assertFalse(old.available())
        } finally {release.countDown();worker.join(2000)}
        assertTrue(completed.await(1,TimeUnit.SECONDS))
        assertTrue(outcome.get() is AdminException)
        assertEquals(AdminFailure.REAUTHENTICATE,(outcome.get() as AdminException).reason)
        val count=f.calls.size
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.refresh(old,issuer,IdentityScope())}
        assertEquals(count,f.calls.size)
        val other=AdminAuthFixture();val state=other.client.discover(IdentityScope());val first=other.login(state)
        val rotated=other.client.refresh(first,state,IdentityScope())
        other.client.logout(first)
        assertFalse(rotated.available())
        val before=other.calls.size
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){other.client.refresh(rotated,state,IdentityScope())}
        assertEquals(before,other.calls.size)
    }
    @Test fun cancelledOrRebootedDiscoveryAndMalformedKeysNeverReturnAdministrativeState() {
        val f=AdminAuthFixture();val cancelled=IdentityScope().apply {cancel()}
        AdminAuthFixture.failure(AdminFailure.CANCELLED){f.client.discover(cancelled)};assertTrue(f.calls.isEmpty())
        f.handler={call->f.normal(call).also {f.boot++}}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){f.client.discover(IdentityScope())}
        val bad=AdminAuthFixture();bad.handler={call->if(call.url.endsWith("/certs"))bad.reply(text="""{"keys":[]}""") else bad.normal(call)}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){bad.client.discover(IdentityScope())}
    }
}

/** Generated synthetic keys/tokens only; this exercises protocol checks, not a live IdP or browser. */
internal class AdminAuthFixture {
    data class Call(val method:String,val url:String,val headers:Map<String,String>,val body:ByteArray?)
    var boot=4
    var elapsed=1000L
    val wall:Long get()=NOW+elapsed-1000
    val metadata=AdminBootstrap("https://admin-id.example.invalid/realms/control",AdminBootstrap.CLIENT_ID,
        AdminBootstrap.AUDIENCE,"https://admin-api.example.invalid",AdminBootstrap.ASSURANCE_ACR)
    val binding=Identity.hash("synthetic-signed-service-binding".toByteArray())
    val identity=AdminIdentity(metadata,binding)
    private val ec=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
    val key=object:ProofKey {
        override val publicKey=ec.public as ECPublicKey
        override fun sign(input:ByteArray)=Signature.getInstance("SHA256withECDSA").run {initSign(ec.private);update(input);sign()}
    }
    val base=metadata.issuer+"/protocol/openid-connect"
    val calls=mutableListOf<Call>()
    var handler:(Call)->Reply={normal(it)}
    val exchange=IdentityExchange {method,url,headers,body,_,max->
        assertEquals(65_536,max);val call=Call(method,url,headers.toMap(),body?.copyOf());calls+=call;handler(call)
    }
    val client=AdminProtocol(identity,key,exchange,{boot},{elapsed})
    val pending=client.newPending(7)
    fun callback()=AdminBootstrap.CALLBACK+"?"+Identity.form(linkedMapOf("code" to "fixture-code","state" to pending.state,"iss" to metadata.issuer))
    fun login(issuer:AdminIssuerState)=client.exchangeCallback(callback(),pending,7,issuer,IdentityScope())
    fun proof(call:Call)=Identity.objectJSON(Policy.utf8(Policy.decode64(call.headers.getValue("DPoP").split('.')[1])))
    fun normal(call:Call):Reply=when(call.url) {
        metadata.issuer+"/.well-known/openid-configuration"->reply(text=Canonical.encode(buildJsonObject {
            put("issuer",metadata.issuer);put("authorization_endpoint",base+"/auth");put("token_endpoint",base+"/token");put("jwks_uri",base+"/certs")
            put("id_token_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("RS256"))))
            put("dpop_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("ES256"))))
            put("code_challenge_methods_supported",JsonArray(listOf(JsonPrimitive("S256"))))
        }))
        base+"/certs"->reply(text=Canonical.encode(buildJsonObject {put("keys",JsonArray(listOf(buildJsonObject {
            put("kty","RSA");put("kid","synthetic-rsa");put("use","sig");put("alg","RS256")
            put("n",unsigned((rsa.public as RSAPublicKey).modulus));put("e","AQAB")
        })))}))
        base+"/token"->tokens()
        else->error("Unexpected synthetic OAuth path")
    }
    fun tokens(subject:String="synthetic-user",includeId:Boolean=true,includeAtHash:Boolean=false,
        accessChanges:Map<String,JsonElement> = emptyMap(),idChanges:Map<String,JsonElement> = emptyMap(),includeAuthTime:Boolean=true):Reply {
        fun token(id:Boolean,accessHash:String?=null):String {
            val fields=buildJsonObject {
                put("iss",metadata.issuer);put("aud",if(id)AdminBootstrap.CLIENT_ID else AdminBootstrap.AUDIENCE)
                put("azp",AdminBootstrap.CLIENT_ID);put("sub",subject);put("iat",wall/1000);put("exp",wall/1000+300)
                put("jti",Identity.random())
                if(id) {
                    put("nonce",pending.nonce)
                    if(includeAuthTime)put("auth_time",wall/1000)
                    if(accessHash!=null)put("at_hash",accessHash)
                } else {
                    put("scope",AdminBootstrap.SCOPE);put("cnf",buildJsonObject {put("jkt",client.thumbprint)})
                }
            }
            val header=Identity.encode("""{"alg":"RS256","kid":"synthetic-rsa","typ":"JWT"}""".toByteArray())
            val payload=Identity.encode(Canonical.encode(JsonObject(fields+if(id)idChanges else accessChanges)).toByteArray())
            val input="$header.$payload"
            val signature=Signature.getInstance("SHA256withRSA").run {initSign(rsa.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            return input+"."+Identity.encode(signature)
        }
        val access=token(false)
        val accessHash=if(includeAtHash)Identity.encode(MessageDigest.getInstance("SHA-256").digest(access.toByteArray(Charsets.US_ASCII)).copyOfRange(0,16)) else null
        return reply(text=Canonical.encode(buildJsonObject {
            put("token_type","DPoP");put("access_token",access);put("refresh_token",Identity.random())
            put("expires_in",300);put("refresh_expires_in",86_400);put("scope",AdminBootstrap.SCOPE)
            if(includeId)put("id_token",token(true,accessHash))
        }))
    }
    fun reply(status:Int=200,text:String="{}",headers:Map<String,List<String>> = emptyMap(),at:Long=wall)=Reply(status,
        mapOf("content-type" to listOf("application/json"),"date" to listOf(date(at)))+headers,text.toByteArray())
    companion object {
        const val NOW=1_800_000_000_000L
        private val rsa:KeyPair=KeyPairGenerator.getInstance("RSA").apply {initialize(2048)}.generateKeyPair()
        private fun unsigned(value:BigInteger)=Identity.encode(value.toByteArray().let {if(it[0]==0.toByte())it.copyOfRange(1,it.size) else it})
        fun date(ms:Long)=DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'",Locale.US).withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(ms))
        fun parameters(raw:String)=raw.split('&').associate {val pair=it.split('=',limit=2);URLDecoder.decode(pair[0],"UTF-8") to URLDecoder.decode(pair[1],"UTF-8")}
        fun failure(reason:AdminFailure,block:()->Unit) {
            val thrown=assertThrows(AdminException::class.java,block)
            assertEquals(reason,thrown.reason);assertEquals(reason.name,thrown.message)
        }
    }
}
