package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.util.Base64
import java.util.Locale

/** The first seven fields come from authenticated installation/account/device
 * state plus the signed overlay assignment. They are not import/ADB authority.
 * networkId names the provider tenant/network, never Wi-Fi/LTE or a peer group. */
data class OverlayAddress(val serviceId:String,val ownerTag:String,val deviceId:String,
    val overlayId:String,val provider:String,val resourceId:String,val networkId:String,
    val identityEpoch:Long,val managementURL:String) {
    override fun toString()="OverlayAddress([redacted])"
}

/** Pure namespacing only. It does not grant access, fetch a secret, create/delete
 * SDK files, confirm owner retirement or activate a managed overlay. */
object ManagedOverlay {
    private val identifier=Regex("[A-Za-z0-9_-]{1,64}")
    private fun digest(value:String) {
        require(value.matches(Regex("[A-Za-z0-9_-]{43}")))
        val bytes=Base64.getUrlDecoder().decode(value)
        require(bytes.size==32 && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)==value)
    }
    fun managementOrigin(raw:String):String {
        val uri=Identity.https(raw)
        require(uri.path.isEmpty() || uri.path=="/")
        require(!uri.rawAuthority.endsWith(":"))
        var host=uri.host.lowercase(Locale.ROOT)
        require(!host.contains('%'))
        if(host.contains(':') && !host.startsWith('['))host="[$host]"
        val port=if(uri.port==-1 || uri.port==443)"" else ":${uri.port}"
        return "https://$host$port"
    }
    fun namespace(address:OverlayAddress):String {
        require(listOf(address.serviceId,address.overlayId,address.resourceId,address.networkId).all {identifier.matches(it)})
        require(address.deviceId.matches(Regex("[A-Za-z0-9_-]{8,64}")))
        digest(address.ownerTag)
        require(address.provider=="netbird") // Future providers are contracts only.
        require(address.identityEpoch in 1..9_007_199_254_740_991L)
        val body=buildJsonObject {
            put("audience",JsonPrimitive("syn443-overlay-identity-v1"))
            put("serviceId",JsonPrimitive(address.serviceId));put("ownerTag",JsonPrimitive(address.ownerTag))
            put("deviceId",JsonPrimitive(address.deviceId));put("overlayId",JsonPrimitive(address.overlayId))
            put("provider",JsonPrimitive(address.provider));put("resourceId",JsonPrimitive(address.resourceId))
            put("networkId",JsonPrimitive(address.networkId));put("identityEpoch",JsonPrimitive(address.identityEpoch))
            put("managementOrigin",JsonPrimitive(managementOrigin(address.managementURL)))
        }
        // The separate top-level root can never alias legacy operator netbird/.
        return "managed-netbird/"+Identity.hash(Canonical.encode(body).toByteArray(Charsets.UTF_8))
    }
}
