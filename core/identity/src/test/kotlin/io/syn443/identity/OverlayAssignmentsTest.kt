package io.syn443.identity

import io.syn443.policy.*
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class OverlayAssignmentsTest {
    private val key=Identity.hash("key".toByteArray());private val owner=Identity.hash("owner".toByteArray());private val reference=Identity.hash("reference".toByteArray())
    private val metadata=buildJsonObject {put("overlayId","home");put("resourceId","resource");put("networkId","tenant");put("identityEpoch",1);put("setupReference",reference);put("setupVersion",1)}
    private fun outbound()=buildJsonObject {put("type","netbird");put("tag","home");put("management_url","https://overlay.example.invalid");put("managed",metadata)}
    private fun policy(outbounds:List<JsonObject> = listOf(outbound())):Verified {
        val engine=Canonical.encode(buildJsonObject {put("outbounds",JsonArray(outbounds))})
        val p=Payload(2,1,0,0,"device-12345","syn443-device",1_800_000_000_000L,1_800_000_000_000L,1_800_000_030_000L,1_800_000_060_000L,listOf("engine-config.v1","tun.lease.v1","policy.keybound.v2","overlay.credentials.v1"),"m1-local-v1",Identity.encode(engine.toByteArray()),Policy.hash(engine),Gate(30,false,listOf(Check("internet","https_204","https://health.example.org/generate_204"))),keyThumbprint=key)
        return Verified("already-authorized-fixture",p,engine)
    }
    private fun resolve(v:Verified=policy())=OverlayAssignments.resolve(v,"fixture",owner,"device-12345",key)
    @Test fun assignedIdentityDerivesOnlyFromLocalScopeAndSignedMetadata() {
        val b=checkNotNull(resolve());assertEquals(reference,b.reference);assertEquals(1L,b.version);assertEquals(owner,b.address.ownerTag);assertEquals("device-12345",b.address.deviceId);assertEquals("fixture",b.address.serviceId)
        assertEquals(1_800_000_060_000L,b.offlineUntilMs)
        assertNull(resolve(policy(listOf(buildJsonObject {put("type","direct");put("tag","direct")}))))
        val alias=JsonObject(outbound()+("management_url" to JsonPrimitive("https://OVERLAY.EXAMPLE.INVALID:443/")))
        assertEquals(ManagedOverlay.namespace(b.address),ManagedOverlay.namespace(checkNotNull(resolve(policy(listOf(alias)))).address))
        val transport=JsonObject(outbound()+("connection_mode" to JsonPrimitive("vless"))+("detour" to JsonPrimitive("emergency")))
        assertEquals(b,resolve(policy(listOf(transport))))
    }
    @Test fun unmanagedInlineSecretPathUnknownFieldsAndDuplicateIdentityAreRejected() {
        val bad=listOf(
            JsonObject(outbound()-"managed"),
            JsonObject(outbound()+("managed" to JsonNull)),
            JsonObject(outbound()+("managed" to JsonObject(metadata+("unknown" to JsonPrimitive(true))))),
            JsonObject(outbound()+("setup_key" to JsonPrimitive("forbidden"))),
            JsonObject(outbound()+("state_directory" to JsonPrimitive("/forbidden"))),
            JsonObject(outbound()+("credential_pending" to JsonPrimitive(true))),
            JsonObject(outbound()+("managed_namespace" to JsonPrimitive("forbidden"))),
            JsonObject(outbound()+("managed" to JsonObject(metadata+("setupReference" to JsonPrimitive("bad"))))),
            JsonObject(outbound()+("managed" to JsonObject(metadata+("setupVersion" to JsonPrimitive(0))))),
            JsonObject(outbound()+("managed" to JsonObject(metadata+("identityEpoch" to JsonPrimitive("1"))))),
            JsonObject(outbound()+("management_url" to JsonPrimitive(1))),
            JsonObject(outbound()+("type" to JsonPrimitive("direct")))
        )
        for(out in bad)assertThrows(IllegalArgumentException::class.java){resolve(policy(listOf(out)))}
        assertThrows(IllegalArgumentException::class.java){resolve(policy(listOf(outbound(),outbound())))}
        assertThrows(IllegalArgumentException::class.java){resolve(policy(emptyList()))}
        assertThrows(IllegalArgumentException::class.java){resolve(policy(List(65){outbound()}))}
        val v=policy()
        for(p in listOf(v.payload.copy(operation="release"),v.payload.copy(schemaVersion=1),v.payload.copy(targetDevice="other-device"),v.payload.copy(keyThumbprint=Identity.random()),v.payload.copy(requiredCapabilities=IdentityOperation.requiredCapabilities))) {
            assertThrows(IllegalArgumentException::class.java){resolve(v.copy(payload=p))}
        }
    }
}
