package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Fixed synthetic transport, generated signatures and an unchanged existing root. No network/Android state. */
class AdminServiceDiscoveryTest {
    private class Fixture {
        val offline=key()
        val anchor=TrustAnchor("service-offline",Base64.getEncoder().encodeToString(offline.public.encoded),1)
        val now=1_800_000_000L
        val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"Synthetic-service_01",
            "https://device-id.example.invalid/realms/device","syn443-android","https://device-api.example.invalid:8443",
            mapOf("online" to Base64.getEncoder().encodeToString(key().public.encoded)),now,now,now+3600,
            adminBootstrap=AdminBootstrap("https://admin-id.example.invalid/realms/admin",AdminBootstrap.CLIENT_ID,
                AdminBootstrap.AUDIENCE,"https://admin-api.example.invalid",AdminBootstrap.ASSURANCE_ACR))
        val bootstrap=Bootstrap(descriptor.serviceId,descriptor.issuer,descriptor.clientId,descriptor.apiOrigin,descriptor.roots.toMap())
        val raw=sign(descriptor,anchor,offline)
        val target=bootstrap.apiOrigin+"/.well-known/syn443/bootstrap/"+bootstrap.serviceId
        var calls=0
        var child:BoundedHttp.Scope?=null
        var handler:()->Reply={reply(raw)}
        val exchange=IdentityExchange {method,url,headers,body,scope,maxBody->
            calls++;assertEquals("GET",method);assertEquals(target,url)
            assertEquals(mapOf("Accept" to "application/jose","Cache-Control" to "no-store"),headers)
            assertFalse(headers.keys.any {it.lowercase() in setOf("authorization","dpop","cookie","origin")})
            assertThrows(UnsupportedOperationException::class.java) {(headers as MutableMap<String,String>)["Origin"]="https://foreign.example.invalid"}
            assertNull(body);assertEquals(BootstrapTrust.MAX_MANIFEST,maxBody);scope.active();child=scope
            handler()
        }
        fun reader(bootstrap:Bootstrap=this.bootstrap)=AdminServiceDiscovery(bootstrap,exchange)
        fun reply(value:String=raw,status:Int=200,headers:Map<String,List<String>> = mapOf("content-type" to listOf("application/jose")))=
            Reply(status,headers,value.toByteArray(Charsets.UTF_8))
    }
    companion object {
        private fun key():KeyPair=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private fun sign(value:ServiceDescriptor,anchor:TrustAnchor,key:KeyPair):String {
            val header=Canonical.encode(buildJsonObject {put("alg","ES256");put("kid",anchor.id);put("typ","syn443-bootstrap+jws")})
            val input=Identity.encode(header.toByteArray())+"."+Identity.encode(Canonical.encode(Canonical.parse(Canonical.json.encodeToString(value))).toByteArray())
            val signature=Signature.getInstance("SHA256withECDSA").run {initSign(key.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            return input+"."+Identity.encode(Identity.derToRaw(signature))
        }
        private fun failure(reason:AdminFailure,action:()->Unit) {
            val error=assertThrows(AdminException::class.java,action)
            assertEquals(reason,error.reason);assertEquals(reason.name,error.message);assertNull(error.cause)
        }
    }
    @Test fun fixedOwnedBootstrapFetchesOneAnonymousJoseEnvelopeWithOneScopedChild() {
        val f=Fixture();val source=f.reader();val result=source.fetch(IdentityScope())
        assertEquals(f.raw,result.raw);assertEquals(1,f.calls)
        assertThrows(DeliveryException::class.java) {checkNotNull(f.child).active()}
        val first=f.child
        f.handler={f.reply(headers=mapOf("content-type" to listOf(" Application/JOSE "),"date" to listOf("untrusted-not-a-clock")))}
        assertEquals(f.raw,source.fetch(IdentityScope()).raw);assertEquals(2,f.calls);assertNotSame(first,f.child)
    }
    @Test fun completeSixKiBCompactEnvelopeFitsExactlyButEmptyAndOversizedBodiesFail() {
        val f=Fixture();val source=f.reader()
        // Syntax-only envelope at the transport bound; it is deliberately not a trusted descriptor.
        val exact="e30."+"A".repeat(6052)+"."+"A".repeat(87)
        assertEquals(6144,exact.toByteArray().size)
        f.handler={f.reply(exact)};assertEquals(exact,source.fetch(IdentityScope()).raw)
        for(body in listOf("",exact+"A")) {
            f.handler={f.reply(body)};val count=f.calls
            failure(AdminFailure.INVALID_REPLY) {source.fetch(IdentityScope())};assertEquals(count+1,f.calls)
        }
    }
    @Test fun invalidBootstrapOriginPathIdentifierRootsOrOperatorCaNeverDispatches() {
        val f=Fixture()
        val invalid=listOf(f.bootstrap.copy(serviceId="../service"),f.bootstrap.copy(serviceId="a%2fb"),f.bootstrap.copy(serviceId="a/b"),
            f.bootstrap.copy(serviceId="a\n"),f.bootstrap.copy(serviceId="x".repeat(65)),f.bootstrap.copy(clientId="unsafe/client"),
            f.bootstrap.copy(apiOrigin="http://device-api.example.invalid"),f.bootstrap.copy(apiOrigin="https://device-api.example.invalid/path"),
            f.bootstrap.copy(apiOrigin="https://device-api.example.invalid?x=1"),f.bootstrap.copy(apiOrigin="https://device-api.example.invalid#"),
            f.bootstrap.copy(apiOrigin="https://DEVICE-api.example.invalid"),f.bootstrap.copy(apiOrigin="https://device-api.example.invalid:443"),
            f.bootstrap.copy(issuer="https://device-id.example.invalid/realms/device/"),f.bootstrap.copy(roots=emptyMap()),
            f.bootstrap.copy(roots=mapOf("bad" to "not-a-public-spki")),
            f.bootstrap.copy(apiOrigin="https://127.0.0.1:8443",tlsCaDer="synthetic-operator-ca"))
        for(bootstrap in invalid)failure(AdminFailure.INVALID_REPLY) {f.reader(bootstrap)}
        assertEquals(0,f.calls)
    }
    @Test fun malformedCompactJwsUtf8OrJoseHeadersCannotBecomeManifestValues() {
        val f=Fixture();val source=f.reader()
        for(body in listOf(" "+f.raw,f.raw+"\n","é."+f.raw,"e30.e30","e30.e30.e30.e30",".e30.e30","e30..e30","e30.e30.",
            "e30=.e30.AA","e30.e30.A*","a.e30.AA","e30.e30.AB")) {
            f.handler={f.reply(body)};failure(AdminFailure.INVALID_REPLY) {source.fetch(IdentityScope())}
        }
        f.handler={Reply(200,mapOf("content-type" to listOf("application/jose")),byteArrayOf(0xc3.toByte(),0x28))}
        failure(AdminFailure.INVALID_REPLY) {source.fetch(IdentityScope())}
        for(headers in listOf(emptyMap(),mapOf("content-type" to listOf("application/json")),
            mapOf("content-type" to listOf("application/jose; charset=utf-8")),
            mapOf("content-type" to listOf("application/jose","application/jose")))) {
            f.handler={f.reply(headers=headers)};failure(AdminFailure.INVALID_REPLY) {source.fetch(IdentityScope())}
        }
    }
    @Test fun unavailableStatusesTransportFailuresAndNonceChallengesNeverRetryOrAuthenticate() {
        val f=Fixture();val source=f.reader()
        for(status in listOf(302,307,401,403,404,429,503)) {
            f.handler={f.reply("""{"error":"use_dpop_nonce"}""",status,mapOf("content-type" to listOf("application/json"),
                "dpop-nonce" to listOf("synthetic-nonce"),"location" to listOf("https://foreign.example.invalid")))}
            val count=f.calls;failure(AdminFailure.TRANSPORT) {source.fetch(IdentityScope())};assertEquals(count+1,f.calls)
        }
        for(reason in listOf(DeliveryFailure.CAPACITY,DeliveryFailure.DEADLINE,DeliveryFailure.DNS,DeliveryFailure.TLS,DeliveryFailure.EOF,DeliveryFailure.TRANSPORT)) {
            f.handler={throw DeliveryException(reason)};val count=f.calls
            failure(AdminFailure.TRANSPORT) {source.fetch(IdentityScope())};assertEquals(count+1,f.calls)
        }
    }
    @Test fun cancellationBeforeOrDuringResponsePreventsAValueAndKeepsTransportOwnershipBounded() {
        val f=Fixture();val source=f.reader();val stopped=IdentityScope().apply {cancel()}
        failure(AdminFailure.CANCELLED) {source.fetch(stopped)};assertEquals(0,f.calls)
        val scope=IdentityScope();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        val worker=Executors.newSingleThreadExecutor()
        try {
            f.handler={entered.countDown();check(release.await(10,TimeUnit.SECONDS));f.reply()}
            val result=worker.submit<AdminFailure?> {try {source.fetch(scope);null}catch(error:AdminException){error.reason}}
            assertTrue(entered.await(5,TimeUnit.SECONDS));scope.cancel();release.countDown()
            assertEquals(AdminFailure.CANCELLED,result.get(10,TimeUnit.SECONDS));assertEquals(1,f.calls)
            assertThrows(DeliveryException::class.java) {checkNotNull(f.child).active()}
            failure(AdminFailure.CANCELLED) {source.fetch(scope)};assertEquals(1,f.calls)
        }finally {release.countDown();worker.shutdownNow();assertTrue(worker.awaitTermination(5,TimeUnit.SECONDS))}
        val direct=IdentityScope();f.handler={f.reply().also {direct.cancel()}}
        failure(AdminFailure.CANCELLED) {source.fetch(direct)};assertEquals(2,f.calls)
    }
    @Test fun bootstrapAndReplyMutationCannotAlterOwnedTargetValueOrRedactedDiagnostics() {
        val f=Fixture();val roots=f.bootstrap.roots.toMutableMap();val source=f.reader(f.bootstrap.copy(roots=roots))
        roots.clear();val bytes=f.raw.toByteArray()
        f.handler={Reply(200,mapOf("content-type" to listOf("application/jose")),bytes)}
        val value=source.fetch(IdentityScope());bytes.fill(0)
        assertEquals(f.raw,value.raw);assertEquals("AdminServiceManifest([redacted])",value.toString())
        assertEquals("AdminServiceDiscovery([redacted])",source.toString())
        for(text in listOf(value.toString(),source.toString())) {
            assertFalse(text.contains(f.bootstrap.apiOrigin));assertFalse(text.contains(f.bootstrap.serviceId));assertFalse(text.contains(f.raw))
        }
    }
    @Test fun fetchedEnvelopeNeverReplacesTheExistingRootOrCommitsAdministrativeAuthority() {
        val f=Fixture();val existing=BootstrapTrust.descriptor(f.raw,f.anchor,ServiceFloor(),f.now).second
        val ordinary=f.reader().fetch(IdentityScope())
        assertNotNull(BootstrapTrust.adminDiscovery(ordinary.raw,f.anchor,existing,f.bootstrap,f.now))
        val foreign=key();val other=TrustAnchor("foreign-service-root",Base64.getEncoder().encodeToString(foreign.public.encoded),1)
        val replacement=sign(f.descriptor.copy(revision=2),other,foreign)
        f.handler={f.reply(replacement)}
        val value=f.reader().fetch(IdentityScope())
        assertEquals(replacement,value.raw)
        assertNull(BootstrapTrust.adminDiscovery(value.raw,f.anchor,existing,f.bootstrap,f.now))
        assertEquals(1L,existing.revision);assertEquals(f.descriptor.serviceId,existing.serviceId)
    }
}
