package io.syn443.android.vpn

import io.syn443.identity.*
import io.syn443.policy.Policy
import java.io.File
import org.json.JSONObject

internal class OverlayLaunchPending:IllegalArgumentException("overlay_credentials_pending")

/** RAM-only launch material prepared by the identity worker. It never changes
 * the hash or disk copy of the signed configuration. The callbacks are bounded
 * volatile admission/clock reads, not network, Keystore or controller locks. */
internal class OverlayRuntimeMaterial(val binding:OverlayCredentialBinding,val configHash:String,
    val loginGeneration:Long,val identityEvidence:String,private val secret:OverlaySetupSecret?,
    private val admitted:()->Boolean,private val window:()->TimeWindow,val waiting:Boolean=false):AutoCloseable {
    val namespace=ManagedOverlay.namespace(binding.address)
    @Volatile private var closed=false
    init {
        require(configHash.matches(Regex("[0-9a-f]{64}")) && loginGeneration>=0)
        require(if(waiting)secret==null && identityEvidence.isEmpty()
            else if(secret==null)identityEvidence.length==43 && Policy.decode64(identityEvidence).size==32 else identityEvidence.isEmpty())
        secret?.let{require(it.namespace==namespace && it.reference==binding.reference && it.version==binding.version && it.securityEpoch==binding.securityEpoch)}
    }
    fun available():Boolean=runCatching{requireCurrent();true}.getOrDefault(false)
    val launchMode:String get()=if(waiting)"waiting" else if(secret!=null)"enrolling" else "keyless"
    fun authorized():Boolean=runCatching{requireAuthorized();true}.getOrDefault(false)
    private fun requireAuthorized() {
        check(!closed && admitted()){"overlay_material_unavailable"}
        val time=window();check(time.lowerMs>0 && time.upperMs>=time.lowerMs)
        val upper=time.upperMs
        check(upper<binding.offlineUntilMs){"overlay_material_unavailable"}
    }
    internal fun requireCurrent() {
        requireAuthorized()
        check(secret==null || window().upperMs<secret.expiresMs){"overlay_material_unavailable"}
    }
    internal fun validateOutbound(outbound:JSONObject) {
        requireAuthorized()
        require(outbound.getString("type")=="netbird" && !outbound.has("setup_key") &&
            !outbound.has("state_directory") && !outbound.has("managed_namespace") && !outbound.has("credential_pending"))
        require(ManagedOverlay.managementOrigin(outbound.getString("management_url"))==ManagedOverlay.managementOrigin(binding.address.managementURL))
        val metadata=outbound.getJSONObject("managed")
        require(metadata.keys().asSequence().toSet()==setOf("overlayId","resourceId","networkId","identityEpoch","setupReference","setupVersion"))
        require(listOf("overlayId","resourceId","networkId","setupReference").all{metadata.get(it) is String})
        require(listOf("identityEpoch","setupVersion").all{metadata.get(it) is Int || metadata.get(it) is Long})
        val address=binding.address
        require(metadata.getString("overlayId")==address.overlayId && metadata.getString("resourceId")==address.resourceId &&
            metadata.getString("networkId")==address.networkId && metadata.getLong("identityEpoch")==address.identityEpoch &&
            metadata.getString("setupReference")==binding.reference && metadata.getLong("setupVersion")==binding.version)
    }
    internal fun localize(outbound:JSONObject,stateRoot:File) {
        requireCurrent()
        validateOutbound(outbound)
        outbound.remove("managed")
        outbound.put("managed_namespace",namespace)
        // The authenticated namespace, never an imported path, selects storage.
        outbound.put("state_directory",File(stateRoot.canonicalFile,namespace).absolutePath)
        if(waiting)outbound.put("credential_pending",true)
        secret?.useValue {bytes->outbound.put("setup_key",bytes.toString(Charsets.US_ASCII))}
        requireCurrent()
    }
    override fun close(){closed=true;secret?.close()}
    override fun toString()="OverlayRuntimeMaterial([redacted])"
}
