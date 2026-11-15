package io.syn443.identity

import org.junit.Assert.*
import org.junit.Test
import io.syn443.policy.Canonical
import kotlinx.serialization.json.*

class ManagedOverlayTest {
    @Test fun sharedServerAndClientNamespaceVectorsAgree() {
        val raw=checkNotNull(javaClass.getResourceAsStream("/overlay-namespace-vectors.json")).bufferedReader().use {it.readText()}
        val cases=Canonical.parse(raw).jsonObject.getValue("cases").jsonArray
        assertEquals(7,cases.size)
        for(item in cases) {
            val row=item.jsonObject;val value=row.getValue("address").jsonObject
            fun text(key:String)=value.getValue(key).jsonPrimitive.content
            val address=OverlayAddress(text("serviceId"),text("ownerTag"),text("deviceId"),text("overlayId"),text("provider"),text("resourceId"),text("networkId"),value.getValue("identityEpoch").jsonPrimitive.long,text("managementURL"))
            assertEquals(row.getValue("expected").jsonPrimitive.content,ManagedOverlay.namespace(address))
        }
    }
    private fun address()=OverlayAddress("service-a",Identity.hash("owner-a".toByteArray()),"device-a",
        "personal-overlay","netbird","cloud-resource","provider-network",1,"https://api.example.invalid")
    private fun denied(block:()->Unit) {assertThrows(IllegalArgumentException::class.java,block)}
    @Test fun namespaceSeparatesEveryAuthorityAndNeverAliasesOperatorOrPhysicalNetworkState() {
        val a=address();val namespace=ManagedOverlay.namespace(a)
        assertTrue(namespace.matches(Regex("managed-netbird/[A-Za-z0-9_-]{43}")))
        assertFalse(namespace.startsWith("netbird/"));assertEquals(namespace,ManagedOverlay.namespace(a.copy()))
        val alternatives=listOf(a.copy(serviceId="service-b"),a.copy(ownerTag=Identity.hash("owner-b".toByteArray())),
            a.copy(deviceId="device-b"),a.copy(overlayId="other-overlay"),a.copy(resourceId="other-resource"),
            a.copy(networkId="other-provider-network"),a.copy(identityEpoch=2),a.copy(managementURL="https://other.example.invalid"))
        assertEquals(alternatives.size,alternatives.map {ManagedOverlay.namespace(it)}.toSet().size)
        alternatives.forEach {assertNotEquals(namespace,ManagedOverlay.namespace(it))}
        // A new signed configuration revision, renamed outbound, direct/VLESS
        // switch or Wi-Fi/LTE epoch has no field in the identity address.
        repeat(4) {assertEquals(namespace,ManagedOverlay.namespace(a))}
        assertEquals(namespace,ManagedOverlay.namespace(a.copy(managementURL="https://API.EXAMPLE.INVALID:443/")))
        assertFalse(a.toString().contains(a.ownerTag));assertFalse(a.toString().contains(a.managementURL))
        assertEquals("service-a",a.serviceId);assertEquals("personal-overlay",a.overlayId)
        assertEquals("cloud-resource",a.resourceId);assertEquals("provider-network",a.networkId)
        assertEquals("device-a",a.deviceId);assertEquals("netbird",a.provider);assertEquals(1L,a.identityEpoch)
        assertEquals(a,a.copy());assertEquals(a.hashCode(),a.copy().hashCode())
    }
    @Test fun malformedNamespacesFutureProvidersAndAmbiguousManagementOriginsFailClosed() {
        val a=address()
        for(bad in listOf(a.copy(serviceId="../outside"),a.copy(overlayId=""),a.copy(resourceId="r".repeat(65)),
            a.copy(networkId="provider/network"),a.copy(deviceId="short"),a.copy(ownerTag="x"),
            a.copy(ownerTag="_".repeat(43)),a.copy(provider="tailscale"),a.copy(provider="zerotier"),
            a.copy(identityEpoch=0),a.copy(identityEpoch=9_007_199_254_740_992L)))denied {ManagedOverlay.namespace(bad)}
        for(raw in listOf("http://api.example.invalid","https://api.example.invalid/path","https://api.example.invalid/?q=1",
            "https://api.example.invalid/#fragment","https://api.example.invalid:0","https://api.example.invalid:","https://[fe80::1%25wlan0]/","https://api.example.invalid//",
            "https://api.example.invalid/%2F","https://api.example.invalid/../","https://api.example.invalid\n"))denied {ManagedOverlay.managementOrigin(raw)}
        assertEquals("https://api.example.invalid:8443",ManagedOverlay.managementOrigin("https://api.example.invalid:8443/"))
        assertEquals("https://[::1]",ManagedOverlay.managementOrigin("https://[::1]:443/"))
        assertEquals("https://[::1]:8443",ManagedOverlay.managementOrigin("https://[::1]:8443"))
    }
}
