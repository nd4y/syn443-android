package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class AdminDiscoveryTest {
    @Test fun signedDiscoveryRequiresTheExactCommittedFloorAndFullDeviceProjection() {
        val f=AdminTicketFixture();val ticket=checkNotNull(f.ticket())
        assertEquals(f.oauth.metadata,ticket.metadata);assertTrue(AdminIdentity.digest(ticket.binding))
        assertEquals(ticket.binding,checkNotNull(f.ticket()).binding)
        assertNull(BootstrapTrust.adminDiscovery(f.raw,f.anchor,ServiceFloor(),f.expected,f.now))
        assertNull(BootstrapTrust.adminDiscovery(f.raw,f.anchor,f.floor.copy(hash=Identity.random()),f.expected,f.now))
        for(expected in listOf(f.expected.copy(serviceId="foreign-service"),
            f.expected.copy(issuer="https://other-device.example.invalid/realms/device"),
            f.expected.copy(clientId="other-device-client"),f.expected.copy(apiOrigin="https://other-device-api.example.invalid"),
            f.expected.copy(roots=mapOf("other-online" to f.online)),
            f.expected.copy(controlPanelOrigin="https://other-console.example.invalid"))) {
            assertNull(BootstrapTrust.adminDiscovery(f.raw,f.anchor,f.floor,expected,f.now))
        }
        val previousFloor=f.floor
        f.advance()
        assertNull(BootstrapTrust.adminDiscovery(f.raw,f.anchor,previousFloor,f.expected,f.now))
        assertNotNull(f.ticket())
        assertFalse(ticket.toString().contains(ticket.binding));assertFalse(ticket.toString().contains(ticket.metadata.issuer))
    }
    @Test fun metadataRevisionAndTrustRootBindDiscoveryWithoutChangingDeviceBootstrapAuthority() {
        val f=AdminTicketFixture();val initial=checkNotNull(f.ticket());val deviceAuthority=Identity.bootstrapAuthority(f.expected)
        f.advance(f.descriptor.copy(revision=2,adminBootstrap=f.oauth.metadata.copy(apiOrigin="https://new-admin-api.example.invalid")))
        val replaced=checkNotNull(f.ticket())
        assertNotEquals(initial.binding,replaced.binding);assertEquals(deviceAuthority,Identity.bootstrapAuthority(f.expected))
        val anchor=f.anchor.copy(lastTransition=Identity.random())
        val transitioned=checkNotNull(BootstrapTrust.adminDiscovery(f.raw,anchor,f.floor,f.expected,f.now))
        assertNotEquals(replaced.binding,transitioned.binding)
        val other=AdminTicketFixture.root()
        val otherAnchor=f.anchor.copy(id="other-offline-root",spki=Base64.getEncoder().encodeToString(other.public.encoded))
        val otherRaw=f.sign(f.descriptor,otherAnchor,other)
        val otherTicket=checkNotNull(BootstrapTrust.adminDiscovery(otherRaw,otherAnchor,f.floor,f.expected,f.now))
        assertNotEquals(replaced.binding,otherTicket.binding)
        assertEquals(deviceAuthority,Identity.bootstrapAuthority(f.expected))
    }
    @Test fun absentExpiredTamperedAndUncommittedDescriptorsCannotProduceDiscoveryTickets() {
        val f=AdminTicketFixture()
        assertNull(BootstrapTrust.adminDiscovery(f.raw,f.anchor,f.floor,f.expected,f.descriptor.expires))
        assertNull(BootstrapTrust.adminDiscovery(f.raw,f.anchor,f.floor,f.expected,0))
        assertNull(BootstrapTrust.adminDiscovery(f.raw+"x",f.anchor,f.floor,f.expected,f.now))
        f.advance(f.descriptor.copy(revision=2,adminBootstrap=null))
        assertNull(f.ticket())
        f.advance(f.descriptor.copy(revision=3,apiOrigin="https://127.0.0.1",adminBootstrap=f.oauth.metadata))
        f.expected=f.expected.copy(apiOrigin="https://127.0.0.1",tlsCaDer="synthetic-ca")
        assertNull(f.ticket()) // Caller TLS additions are not a signed ordinary projection.
    }
    @Test fun publicFactoryRequiresSuccessfulFreshDiscoveryBeforeBrowserAuthorization() {
        val f=AdminTicketFixture()
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.authorization(f.pending,7)}
        assertTrue(f.oauth.calls.isEmpty())
        val scope=IdentityScope()
        var certs=false;var reads=0
        f.oauth.handler={call->f.reply(call).also {if(call.url.endsWith("/certs"))certs=true}}
        f.onRead={if(certs && ++reads==2)scope.cancel()}
        AdminAuthFixture.failure(AdminFailure.CANCELLED){f.client.discover(scope)}
        f.onRead=null
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.authorization(f.pending,7)}
        f.discover()
        assertTrue(f.client.authorization(f.pending,7).startsWith(f.oauth.metadata.issuer))
    }
    @Test fun missingChangedOrThrowingDiscoverySourcesFailClosedButLogoutStaysLocal() {
        val f=AdminTicketFixture();val issuer=f.discover();val session=f.login(issuer)
        f.enabled=false;val count=f.oauth.calls.size
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.authorization(f.pending,7)}
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.refresh(session,issuer,IdentityScope())}
        val local=f.client.logout(session)
        assertEquals(session.authority,local.authority);assertFalse(session.available());assertEquals(count,f.oauth.calls.size)
        for(source in listOf<()->AdminDiscovery?>({null},{throw IllegalStateException("untrusted-source-text")})) {
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE) {
                AdminProtocol.fromDiscovery(source,f.oauth.key,f.oauth.exchange,{f.oauth.boot},{f.oauth.elapsed})
            }
        }
        val changed=AdminTicketFixture();changed.discover();changed.advance()
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){changed.client.newPending(8)}
    }
    @Test fun metadataChangeDuringActualDpopSigningCannotDispatchAuthorizationCode() {
        val f=AdminTicketFixture()
        val rotating=object:ProofKey {
            override val publicKey=f.oauth.key.publicKey
            override fun sign(input:ByteArray):ByteArray=f.oauth.key.sign(input).also {f.advance()}
        }
        val client=AdminProtocol.fromDiscovery(f.source,rotating,f.oauth.exchange,{f.oauth.boot},{f.oauth.elapsed})
        val issuer=client.discover(IdentityScope());val pending=client.newPending(7);val count=f.oauth.calls.size
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE) {
            client.exchangeCallback(f.callback(pending),pending,7,issuer,IdentityScope())
        }
        assertEquals(count,f.oauth.calls.size);assertTrue(pending.consumed.get())
    }
    @Test fun changedInflightHttpOrPostJwtTrustCannotPublishSessionOrReplayRefresh() {
        for(refresh in listOf(false,true))for(postJwt in listOf(false,true)) {
            val f=AdminTicketFixture();val issuer=f.discover();val previous=if(refresh)f.login(issuer) else null
            var produced=false;var reads=0
            f.oauth.handler={call->f.reply(call).also {if(call.url.endsWith("/token")) {
                produced=true;if(!postJwt)f.advance()
            }}}
            f.onRead={if(postJwt && produced && ++reads==2)f.advance()}
            val before=f.oauth.calls.size
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE) {
                if(previous==null)f.login(issuer) else f.client.refresh(previous,issuer,IdentityScope())
            }
            assertEquals(before+1,f.oauth.calls.size)
            if(previous!=null) {
                assertFalse(previous.available())
                AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){f.client.refresh(previous,issuer,IdentityScope())}
                assertEquals(before+1,f.oauth.calls.size)
            }
        }
    }
    @Test fun entireTrustedWindowRejectsExpiryEvenWhileStoreWallSecondsStillAcceptTheTicket() {
        for(refresh in listOf(false,true)) {
            val f=AdminTicketFixture(lifetime=2);val issuer=f.discover();val previous=if(refresh)f.login(issuer) else null
            f.oauth.handler={call->f.reply(call).also {if(call.url.endsWith("/token"))f.oauth.elapsed+=1001}}
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE) {
                if(previous==null)f.login(issuer) else f.client.refresh(previous,issuer,IdentityScope())
            }
            assertNotNull(f.ticket()) // Whole-second wall admission alone is insufficient.
            if(previous!=null)assertFalse(previous.available())
        }
    }
    @Test fun rediscoveryKeepsExplicitAndLastGoodSameBootFloorsAndNeverRevivesOldOwners() {
        val f=AdminTicketFixture();val initial=checkNotNull(f.ticket())
        val client=AdminProtocol.fromDiscovery({initial},f.oauth.key,f.oauth.exchange,{f.oauth.boot},{f.oauth.elapsed})
        val issuer=client.discover(IdentityScope());val pending=client.newPending(7)
        val future=TrustedTime(f.oauth.boot,f.oauth.elapsed,AdminAuthFixture.NOW+120_000,AdminAuthFixture.NOW+121_000)
        val count=f.oauth.calls.size
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){client.discover(IdentityScope(),future)}
        assertEquals(count,f.oauth.calls.size)
        f.oauth.elapsed+=60_000
        f.oauth.handler={call->f.reply(call).let {it.copy(headers=it.headers+mapOf("date" to listOf(AdminAuthFixture.date(AdminAuthFixture.NOW-60_000))))}}
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){client.discover(IdentityScope())}
        f.oauth.elapsed=999
        val before=f.oauth.calls.size
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){client.discover(IdentityScope())}
        assertEquals(before,f.oauth.calls.size)
        f.oauth.elapsed=1000;f.oauth.boot++
        f.oauth.handler=f::reply
        client.discover(IdentityScope())
        AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){client.authorization(pending,7)}
        // Old verified issuer cannot authorize old-BOOT credentials after new Date discovery.
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE) {
            client.exchangeCallback(f.callback(pending),pending,7,issuer,IdentityScope())
        }
    }
    @Test fun ownedTicketAndGuardDiagnosticsNeverRevealMetadataOrBinding() {
        val f=AdminTicketFixture();val ticket=checkNotNull(f.ticket())
        val guard=AdminDiscoveryGuard(ticket,f.source,{f.oauth.boot},{f.oauth.elapsed})
        assertEquals("AdminDiscovery([redacted])",ticket.toString())
        assertEquals("AdminDiscoveryGuard([redacted])",guard.toString())
        assertFalse(ticket.identity().toString().contains(ticket.binding))
    }
    @Test fun completedDiscoveryClockPublicationCannotOverwriteANewerSameBootFloor() {
        val f=AdminTicketFixture();val ticket=checkNotNull(f.ticket())
        val guard=AdminDiscoveryGuard(ticket,f.source,{f.oauth.boot},{f.oauth.elapsed})
        val later=TrustedTime(f.oauth.boot,f.oauth.elapsed,AdminAuthFixture.NOW+1000,AdminAuthFixture.NOW+2000)
        val earlier=TrustedTime(f.oauth.boot,f.oauth.elapsed,AdminAuthFixture.NOW,AdminAuthFixture.NOW+1000)
        guard.check(time=later,anonymous=true)
        guard.record(later)
        val accepted=guard.record(earlier)
        assertEquals(later.lowerMs,accepted.lowerMs);assertEquals(later.upperMs,accepted.upperMs)
        assertEquals(accepted,guard.priorTime())
        f.oauth.boot++
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){guard.record(earlier)}
    }
    @Test fun typedOperationCancellationPreservesClockButNeverGrantsOrSkipsFreshDiscoveryAdmission() {
        val f=AdminTicketFixture();val ticket=checkNotNull(f.ticket())
        val guard=AdminDiscoveryGuard(ticket,f.source,{f.oauth.boot},{f.oauth.elapsed})
        val accepted=TrustedTime(f.oauth.boot,f.oauth.elapsed,AdminAuthFixture.NOW,AdminAuthFixture.NOW+1000)
        guard.check(time=accepted,anonymous=true);guard.record(accepted)
        f.onRead={throw AdminException(AdminFailure.CANCELLED)}
        val cancelled=assertThrows(AdminException::class.java){guard.check(requireDiscovered=true)}
        assertEquals(AdminFailure.CANCELLED,cancelled.reason);assertEquals("CANCELLED",cancelled.message);assertNull(cancelled.cause)
        assertEquals(accepted,guard.priorTime())
        val fresh=AdminDiscoveryGuard(ticket,f.source,{f.oauth.boot},{f.oauth.elapsed})
        AdminAuthFixture.failure(AdminFailure.CANCELLED){fresh.check(requireDiscovered=true)}
        assertNull(fresh.priorTime())
        f.onRead=null
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){fresh.check(requireDiscovered=true)}
        guard.check(requireDiscovered=true)
        for(failure in listOf(AdminFailure.TRANSPORT,AdminFailure.INVALID_REPLY,AdminFailure.ACCESS_DENIED,AdminFailure.REAUTHENTICATE)) {
            f.onRead={throw AdminException(failure)}
            AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){guard.check(requireDiscovered=true)}
        }
        f.onRead={throw IllegalArgumentException("synthetic-invalid-source")}
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){guard.check(requireDiscovered=true)}
        f.onRead=null;f.enabled=false
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){guard.check(requireDiscovered=true)}
        f.enabled=true;f.advance()
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){guard.check(requireDiscovered=true)}
        assertEquals(accepted,guard.priorTime())
    }
}

/** Generated offline signatures over closed synthetic service descriptors, with an ordinary device projection. */
private class AdminTicketFixture(lifetime:Long=3600) {
    val oauth=AdminAuthFixture()
    private val offline=root()
    val anchor=TrustAnchor("synthetic-offline",Base64.getEncoder().encodeToString(offline.public.encoded),1)
    val online=Base64.getEncoder().encodeToString(root().public.encoded)
    val now:Long get()=oauth.wall/1000
    var descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"synthetic-service",
        "https://device-id.example.invalid/realms/device","syn443-android","https://device-api.example.invalid",
        mapOf("synthetic-online" to online),now,now,now+lifetime,
        controlPanelOrigin="https://console.example.invalid",adminBootstrap=oauth.metadata)
    var raw=sign(descriptor)
    var floor=BootstrapTrust.descriptor(raw,anchor,ServiceFloor(),now).second
    var expected=Bootstrap(descriptor.serviceId,descriptor.issuer,descriptor.clientId,descriptor.apiOrigin,
        descriptor.roots.toMap(),controlPanelOrigin=descriptor.controlPanelOrigin)
    var enabled=true
    var onRead:(()->Unit)?=null
    val source:()->AdminDiscovery?={onRead?.invoke();if(enabled)ticket() else null}
    val client=AdminProtocol.fromDiscovery(source,oauth.key,oauth.exchange,{oauth.boot},{oauth.elapsed})
    val pending=client.newPending(7)
    init {oauth.handler=::reply}
    fun ticket()=BootstrapTrust.adminDiscovery(raw,anchor,floor,expected,now)
    fun discover()=client.discover(IdentityScope())
    fun callback(attempt:AdminPending=pending)=AdminBootstrap.CALLBACK+"?"+Identity.form(linkedMapOf(
        "code" to "fixture-code","state" to attempt.state,"iss" to oauth.metadata.issuer))
    fun login(issuer:AdminIssuerState)=client.exchangeCallback(callback(),pending,7,issuer,IdentityScope())
    fun reply(call:AdminAuthFixture.Call)=if(call.url.endsWith("/token"))
        oauth.tokens(idChanges=mapOf("nonce" to JsonPrimitive(pending.nonce))) else oauth.normal(call)
    fun advance(next:ServiceDescriptor=descriptor.copy(revision=descriptor.revision+1)) {
        descriptor=next;raw=sign(next);floor=BootstrapTrust.descriptor(raw,anchor,ServiceFloor(),now).second
    }
    fun sign(value:ServiceDescriptor,root:TrustAnchor=anchor,key:KeyPair=offline):String {
        val header="""{"alg":"ES256","kid":"${root.id}","typ":"syn443-bootstrap+jws"}"""
        val payload=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(value)))
        val input=Identity.encode(header.toByteArray())+"."+Identity.encode(payload.toByteArray())
        val signature=Signature.getInstance("SHA256withECDSA").run {initSign(key.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
        return input+"."+Identity.encode(Identity.derToRaw(signature))
    }
    companion object {
        fun root():KeyPair=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
    }
}
