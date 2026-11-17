package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPair
import java.security.Signature
import java.util.Base64

/** Signed authority derivation and real OAuth owners, never a storage/HTTP grant. */
class AdminEditorAuthorityTest {
    private class Fixture {
        val oauth=AdminAuthFixture()
        val offline=AdminControlFixture.ec()
        val anchor=TrustAnchor("synthetic-editor-root",Base64.getEncoder().encodeToString(offline.public.encoded),1)
        val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"synthetic-service",
            "https://device-id.example.invalid/realms/device","syn443-android","https://device-api.example.invalid",
            mapOf("synthetic-online" to Base64.getEncoder().encodeToString(AdminControlFixture.ec().public.encoded)),
            oauth.wall/1000,oauth.wall/1000,oauth.wall/1000+3600,adminBootstrap=oauth.metadata)
        fun ordinary(value:ServiceDescriptor)=Bootstrap(value.serviceId,value.issuer,value.clientId,value.apiOrigin,value.roots.toMap(),controlPanelOrigin=value.controlPanelOrigin)
        fun raw(value:ServiceDescriptor,root:TrustAnchor=anchor,key:KeyPair=offline):String {
            val header="""{"alg":"ES256","kid":"${root.id}","typ":"syn443-bootstrap+jws"}"""
            val payload=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(value)))
            val input=Identity.encode(header.toByteArray())+"."+Identity.encode(payload.toByteArray())
            val signature=Signature.getInstance("SHA256withECDSA").run {initSign(key.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            return input+"."+Identity.encode(Identity.derToRaw(signature))
        }
        fun verified(value:ServiceDescriptor=descriptor,root:TrustAnchor=anchor,key:KeyPair=offline):AdminDiscovery {
            val manifest=raw(value,root,key)
            val floor=BootstrapTrust.descriptor(manifest,root,ServiceFloor(),oauth.wall/1000).second
            return checkNotNull(BootstrapTrust.adminDiscovery(manifest,root,floor,ordinary(value),oauth.wall/1000))
        }
        var current:AdminDiscovery?=verified()
        var controls=0
        private val exchange=IdentityExchange {method,url,headers,body,scope,max->
            if(url==oauth.metadata.apiOrigin+AdminControl.PATH) {controls++;throw DeliveryException(DeliveryFailure.TRANSPORT)}
            else oauth.exchange.request(method,url,headers,body,scope,max)
        }
        fun protocol()=AdminProtocol.fromDiscovery({current},oauth.key,exchange,{oauth.boot},{oauth.elapsed})
        fun login(client:AdminProtocol,subject:String="synthetic-user"):AdminSession {
            val pending=client.newPending(7)
            oauth.handler={call->if(call.url.endsWith("/token"))oauth.tokens(subject=subject,idChanges=mapOf("nonce" to JsonPrimitive(pending.nonce))) else oauth.normal(call)}
            val issuer=client.discover(IdentityScope())
            val callback=AdminBootstrap.CALLBACK+"?"+Identity.form(linkedMapOf("code" to "synthetic-code","state" to pending.state,"iss" to oauth.metadata.issuer))
            return client.exchangeCallback(callback,pending,7,issuer,IdentityScope())
        }
    }

    @Test fun signedLeaseAndFloorUpdatesKeepEditorOwnerWhileInvalidatingOldLiveSessions() {
        val f=Fixture();val oldTicket=checkNotNull(f.current);val before=f.protocol();val session=f.login(before)
        val old=before.layerOwnership(session);val ordinary=Identity.bootstrapAuthority(f.ordinary(f.descriptor))
        assertEquals(oldTicket.editorBinding,old.serviceHash);assertEquals(oldTicket.binding,old.legacyServiceHash)
        val nextDescriptor=f.descriptor.copy(revision=2,expires=f.descriptor.expires+60)
        f.current=f.verified(nextDescriptor)
        val next=checkNotNull(f.current)
        assertEquals(oldTicket.editorBinding,next.editorBinding);assertNotEquals(oldTicket.binding,next.binding)
        assertFalse(oldTicket.same(next));assertEquals(ordinary,Identity.bootstrapAuthority(f.ordinary(nextDescriptor)))
        val changedValidity=f.verified(nextDescriptor.copy(revision=3,issuedAt=f.descriptor.issuedAt-10,notBefore=f.descriptor.notBefore-5,expires=f.descriptor.expires+120))
        assertEquals(oldTicket.editorBinding,changedValidity.editorBinding);assertNotEquals(next.binding,changedValidity.binding)
        val calls=f.oauth.calls.size
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){before.layerOwnership(session)}
        assertEquals(calls,f.oauth.calls.size);assertTrue(session.available())
        val renewed=f.protocol();val fresh=f.login(renewed);val owned=renewed.layerOwnership(fresh)
        assertEquals(old.serviceHash,owned.serviceHash);assertEquals(old.actor,owned.actor)
        assertEquals(next.binding,owned.legacyServiceHash);assertNotEquals(old.legacyServiceHash,owned.legacyServiceHash)
        assertEquals(0,f.controls)
    }

    @Test fun stableEditorAuthorityBindsServiceAnchorOrdinaryProjectionAndCompleteAdminTuple() {
        val f=Fixture();val first=checkNotNull(f.current).editorBinding
        val d=f.descriptor
        val changed=listOf(d.copy(serviceId="other-service"),d.copy(issuer="https://other-device.example.invalid/realms/device"),
            d.copy(clientId="other-device-client"),d.copy(apiOrigin="https://other-device-api.example.invalid"),
            d.copy(roots=mapOf("other-online" to Base64.getEncoder().encodeToString(AdminControlFixture.ec().public.encoded))),
            d.copy(controlPanelOrigin="https://other-console.example.invalid"),
            d.copy(adminBootstrap=f.oauth.metadata.copy(issuer="https://other-admin.example.invalid/realms/admin")),
            d.copy(adminBootstrap=f.oauth.metadata.copy(apiOrigin="https://other-admin-api.example.invalid")))
        changed.forEach {assertNotEquals(first,f.verified(it).editorBinding)}
        assertNotEquals(first,f.verified(d,f.anchor.copy(id="other-root")).editorBinding)
        assertNotEquals(first,f.verified(d.copy(rootEpoch=2),f.anchor.copy(epoch=2)).editorBinding)
        assertNotEquals(first,f.verified(d,f.anchor.copy(lastTransition=Identity.random())).editorBinding)
        val key=AdminControlFixture.ec();val root=f.anchor.copy(spki=Base64.getEncoder().encodeToString(key.public.encoded))
        assertNotEquals(first,f.verified(d,root,key).editorBinding)
        for(metadata in listOf(f.oauth.metadata.copy(clientId="other-client"),f.oauth.metadata.copy(audience="other-api"),f.oauth.metadata.copy(assuranceAcr="urn:syn443:loa:1"))) {
            assertThrows(Exception::class.java){f.verified(d.copy(adminBootstrap=metadata))}
        }
        assertEquals(setOf("issuer","clientId","audience","apiOrigin","assuranceAcr"),Canonical.parse(Canonical.json.encodeToString(f.oauth.metadata)).jsonObject.keys)
    }

    @Test fun editorAuthorityDoesNotAlterTheExistingFullDiscoveryOrOauthAuthorityFormula() {
        val f=Fixture();val ticket=checkNotNull(f.current)
        val floor=BootstrapTrust.descriptor(f.raw(f.descriptor),f.anchor,ServiceFloor(),f.oauth.wall/1000).second
        val expected=Identity.hash(Canonical.encode(buildJsonObject {
            put("domain","syn443.admin-discovery.v1")
            put("anchor",buildJsonObject {put("id",f.anchor.id);put("spki",f.anchor.spki);put("epoch",f.anchor.epoch);put("lastTransition",f.anchor.lastTransition)})
            put("floor",buildJsonObject {put("serviceId",floor.serviceId);put("revision",floor.revision);put("hash",floor.hash)})
            put("deviceAuthority",Identity.bootstrapAuthority(f.ordinary(f.descriptor)))
        }).toByteArray())
        assertEquals(expected,ticket.binding)
        val identity=ticket.identity();val other=AdminIdentity(ticket.metadata,ticket.binding,Identity.random())
        assertEquals(identity.authority,other.authority);assertNotEquals(identity.editorServiceHash,other.editorServiceHash)
        assertEquals(ticket.binding,AdminIdentity(ticket.metadata,ticket.binding).editorServiceHash)
        val fake=AdminDiscovery(ticket.metadata,ticket.binding,1,1,2)
        assertEquals(ticket.binding,fake.editorBinding)
        assertEquals("AdminDiscovery([redacted])",ticket.toString());assertEquals("AdminIdentity([redacted])",identity.toString())
    }

    @Test fun editorDigestDefaultsAreCompatibleButMalformedStableOrLegacyValuesFailClosed() {
        val f=Fixture();val ticket=checkNotNull(f.current);val hash=Identity.random()
        val normal=AdminLayerOwnership(hash,hash,f.oauth.metadata.apiOrigin,TimeWindow(1,2),1,1,2)
        assertEquals("",normal.legacyServiceHash)
        for(bad in listOf("",hash+"=","bad",hash.dropLast(1)+"B")) {
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){AdminIdentity(ticket.metadata,ticket.binding,bad)}
            assertThrows(IllegalArgumentException::class.java){AdminDiscovery(ticket.metadata,ticket.binding,1,1,2,bad)}
            assertThrows(IllegalArgumentException::class.java){AdminLayerOwnership(bad,hash,f.oauth.metadata.apiOrigin,TimeWindow(1,2),1,1,2)}
            if(bad.isNotEmpty())assertThrows(IllegalArgumentException::class.java){AdminLayerOwnership(hash,hash,f.oauth.metadata.apiOrigin,TimeWindow(1,2),1,1,2,bad)}
        }
        assertThrows(IllegalArgumentException::class.java){AdminLayerOwnership(hash,"bad",f.oauth.metadata.apiOrigin,TimeWindow(1,2),1,1,2)}
        assertEquals("AdminLayerOwnership([redacted])",normal.toString())
    }

    @Test fun freshVerifiedAccountsRemainSeparateEvenWhenTheyShareStableServiceAuthority() {
        val f=Fixture();val one=f.protocol();val a=one.layerOwnership(f.login(one,"synthetic-one"))
        val two=f.protocol();val b=two.layerOwnership(f.login(two,"synthetic-two"))
        assertEquals(a.serviceHash,b.serviceHash);assertEquals(a.legacyServiceHash,b.legacyServiceHash)
        assertNotEquals(a.actor,b.actor)
        assertEquals(Identity.hash((f.oauth.metadata.issuer+"\u0000synthetic-one").toByteArray()),a.actor)
        assertEquals(Identity.hash((f.oauth.metadata.issuer+"\u0000synthetic-two").toByteArray()),b.actor)
        assertEquals(0,f.controls)
    }

    @Test fun stableEditorValuesCannotAuthorizeCancelledRemovedOrLoggedOutCredentials() {
        val f=Fixture();val client=f.protocol();val session=f.login(client);val owned=client.layerOwnership(session)
        val calls=f.oauth.calls.size;val cancelled=IdentityScope().also {it.cancel()}
        AdminAuthFixture.failure(AdminFailure.CANCELLED){client.configurationRequestVersion(session,cancelled)}
        assertEquals(0,f.controls);assertEquals(calls,f.oauth.calls.size)
        f.current=null
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){client.layerOwnership(session)}
        assertTrue(AdminIdentity.digest(owned.serviceHash));assertEquals(0,f.controls)
        f.current=f.verified();client.logout(session)
        AdminAuthFixture.failure(AdminFailure.REAUTHENTICATE){client.layerOwnership(session)}
        assertEquals(calls,f.oauth.calls.size);assertEquals(0,f.controls)
    }
}
