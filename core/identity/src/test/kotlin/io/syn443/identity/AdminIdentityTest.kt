package io.syn443.identity

import org.junit.Assert.*
import org.junit.Test
import java.net.URI

class AdminIdentityTest {
    @Test fun administrativeAuthorityBindsMetadataAndServiceWithoutConstructingDeviceBootstrap() {
        val f=AdminAuthFixture()
        assertEquals(f.identity.authority,AdminIdentity(f.metadata.copy(),f.binding).authority)
        for(changed in listOf(f.metadata.copy(issuer="https://other.example.invalid/realms/control"),
            f.metadata.copy(apiOrigin="https://other-api.example.invalid"))) {
            assertNotEquals(f.identity.authority,AdminIdentity(changed,f.binding).authority)
        }
        assertNotEquals(f.identity.authority,AdminIdentity(f.metadata,Identity.random()).authority)
        for(invalid in listOf("",f.binding+"=","foreign",f.binding.dropLast(1)+"!",f.binding.dropLast(1)+"B")) {
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){AdminIdentity(f.metadata,invalid)}
        }
        for(changed in listOf(f.metadata.copy(clientId="syn443-android"),f.metadata.copy(audience="syn443-api"),
            f.metadata.copy(issuer=f.metadata.issuer+"#"),f.metadata.copy(apiOrigin=f.metadata.apiOrigin+"/"),
            f.metadata.copy(assuranceAcr="urn:syn443:loa:1"))) {
            AdminAuthFixture.failure(AdminFailure.INVALID_REPLY){AdminIdentity(changed,f.binding)}
        }
    }
    @Test fun browserAuthorizationUsesFixedAdministrativeCallbackScopePkceAndDpopKey() {
        val f=AdminAuthFixture();val p=f.pending
        val url=URI(f.client.authorization(p,7))
        assertEquals(f.metadata.issuer+"/protocol/openid-connect/auth",url.toString().substringBefore('?'))
        val q=AdminAuthFixture.parameters(url.rawQuery)
        assertEquals(setOf("client_id","redirect_uri","response_type","scope","state","nonce",
            "code_challenge_method","code_challenge","dpop_jkt","acr_values"),q.keys)
        assertEquals(AdminBootstrap.CLIENT_ID,q["client_id"])
        assertEquals(AdminBootstrap.CALLBACK,q["redirect_uri"])
        assertEquals("openid syn443.control",q["scope"])
        assertEquals("S256",q["code_challenge_method"])
        assertEquals(Identity.hash(p.verifier.toByteArray(Charsets.US_ASCII)),q["code_challenge"])
        assertEquals(f.client.thumbprint,q["dpop_jkt"])
        assertEquals(AdminBootstrap.ASSURANCE_ACR,q["acr_values"])
        assertEquals(p.state,q["state"]);assertEquals(p.nonce,q["nonce"])
        assertTrue(f.calls.isEmpty())
    }
    @Test fun callbackShapeRejectsDeviceForeignDuplicateInjectedAndMalformedResponses() {
        val f=AdminAuthFixture()
        val good=f.callback()
        val invalid=listOf(good.replace("//admin/oauth/","//oauth/"),good.replace("//admin/","//foreign/"),
            good.replace("//admin/","//user@admin/"),good.replace("//admin/","//admin:443/"),good+"#",
            good.replace("/oauth/callback?","/oauth/%63allback?"),good+"&state="+f.pending.state,
            good+"&st%61te="+f.pending.state,good+"&unexpected=value",good+"&code=other",
            good.replace("code=fixture-code","code=%FF"),good.replace("code=fixture-code","code=%0A"),
            good.replace("code=fixture-code","code=%"),good.replace("code=fixture-code","error=access_denied&code=fixture-code"),
            good.replace(f.pending.state,Identity.random()),good.replace("iss=","iss=foreign"),
            good.replace("code=fixture-code","code="))
        for(raw in invalid) {
            assertThrows(Exception::class.java){f.identity.callback(raw,f.pending,7,f.client.thumbprint,f.boot,f.elapsed)}
            assertFalse(f.pending.consumed.get())
        }
        assertEquals("fixture-code",f.identity.callback(good,f.pending,7,f.client.thumbprint,f.boot,f.elapsed))
        assertTrue(f.pending.consumed.get())
        assertThrows(Exception::class.java){f.identity.callback(good,f.pending,7,f.client.thumbprint,f.boot,f.elapsed)}
    }
    @Test fun pendingAuthorityKeyGenerationBootClockAndFiveMinuteBoundaryAreIndependentFences() {
        val f=AdminAuthFixture();val p=f.pending
        for(action in listOf<()->Unit>(
            {f.identity.authorization(p,8,f.client.thumbprint,f.boot,f.elapsed)},
            {f.identity.authorization(p,7,Identity.random(),f.boot,f.elapsed)},
            {f.identity.authorization(p,7,f.client.thumbprint,f.boot+1,f.elapsed)},
            {f.identity.authorization(p,7,f.client.thumbprint,f.boot,f.elapsed-1)},
            {f.identity.authorization(p,7,f.client.thumbprint,f.boot,f.elapsed+300_000)},
            {AdminIdentity(f.metadata,Identity.random()).authorization(p,7,f.client.thumbprint,f.boot,f.elapsed)})) {
            assertThrows(Exception::class.java,action)
        }
        assertFalse(p.consumed.get())
        assertTrue(f.identity.authorization(p,7,f.client.thumbprint,f.boot,f.elapsed+299_999).startsWith(f.metadata.issuer))
    }
    @Test fun validatedOauthDenialIsConsumedRedactedAndNeverBecomesCredentials() {
        val f=AdminAuthFixture()
        val raw=f.callback().replace("code=fixture-code","error=access_denied&error_description=untrusted+message")
        AdminAuthFixture.failure(AdminFailure.ACCESS_DENIED) {
            f.identity.callback(raw,f.pending,7,f.client.thumbprint,f.boot,f.elapsed)
        }
        assertTrue(f.pending.consumed.get());assertTrue(f.calls.isEmpty())
        assertFalse(f.pending.toString().contains(f.pending.verifier))
        assertFalse(f.identity.toString().contains(f.metadata.issuer))
        assertEquals("ACCESS_DENIED",AdminException(AdminFailure.ACCESS_DENIED).message)
    }
}
