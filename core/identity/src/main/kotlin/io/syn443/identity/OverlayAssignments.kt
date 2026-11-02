package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Verified
import io.syn443.policy.Policy
import kotlinx.serialization.json.*

/** This resolves metadata, never grants authority. The controller supplies its
 * freshly authorized signed policy and authenticated local owner/device state. */
object OverlayAssignments {
    private fun text(o:JsonObject,k:String)=o.getValue(k).jsonPrimitive.let {require(it.isString);it.content}
    private fun number(o:JsonObject,k:String)=o.getValue(k).jsonPrimitive.let {require(!it.isString);it.long}
    fun resolve(verified:Verified,serviceId:String,ownerTag:String,deviceId:String,keyThumbprint:String):OverlayCredentialBinding? = try {
        val p=verified.payload
        require(p.contentHash==Policy.hash(verified.engineConfig) && Policy.utf8(Policy.decode64(p.engineConfigB64))==verified.engineConfig)
        require(p.operation=="configure" && p.schemaVersion==2 && p.targetDevice==deviceId && p.keyThumbprint==keyThumbprint)
        val root=Canonical.parse(verified.engineConfig).jsonObject
        val outbounds=root.getValue("outbounds").jsonArray;require(outbounds.size in 1..64)
        var result:OverlayCredentialBinding?=null
        for(value in outbounds) {
            val outbound=value.jsonObject
            if(text(outbound,"type")!="netbird") {require("managed" !in outbound);continue}
            require(result==null && "overlay.credentials.v1" in p.requiredCapabilities)
            require("setup_key" !in outbound && "state_directory" !in outbound && "managed_namespace" !in outbound && "credential_pending" !in outbound)
            val metadata=outbound.getValue("managed").jsonObject
            require(metadata.keys==setOf("overlayId","resourceId","networkId","identityEpoch","setupReference","setupVersion"))
            val address=OverlayAddress(serviceId,ownerTag,deviceId,text(metadata,"overlayId"),"netbird",text(metadata,"resourceId"),text(metadata,"networkId"),number(metadata,"identityEpoch"),text(outbound,"management_url"))
            ManagedOverlay.namespace(address)
            val reference=text(metadata,"setupReference");val version=number(metadata,"setupVersion")
            require(overlayDigest(reference) && version in 1..9_007_199_254_740_991L && overlayDigest(keyThumbprint))
            result=OverlayCredentialBinding(address,keyThumbprint,reference,version,p.securityEpoch,p.offlineUntilMs)
        }
        result
    }catch(_:Exception){throw IllegalArgumentException("overlay_assignment_invalid")}
}
