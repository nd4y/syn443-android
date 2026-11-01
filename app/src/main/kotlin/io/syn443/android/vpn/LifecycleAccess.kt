package io.syn443.android.vpn

import android.content.Context
import android.os.UserManager
import org.json.JSONObject

/** No credential storage, Keystore or login recovery may run in Direct Boot. */
object LifecycleAccess {
    fun unlocked(context:Context)=checkNotNull(context.getSystemService(UserManager::class.java)).isUserUnlocked
    fun lockedStatus()=JSONObject().put("phase","NeedsUnlock").put("reason","credential_storage_locked")
        .put("desiredOn",JSONObject.NULL).put("desiredOnKnown",false).put("generation",JSONObject.NULL)
        .put("engineActive",false).put("osPolicy",JSONObject().put("unlocked",false).put("known",false))
    @Volatile private var service:java.lang.ref.WeakReference<TunnelService>?=null
    fun attach(value:TunnelService){service=java.lang.ref.WeakReference(value)}
    fun detach(value:TunnelService){if(service?.get()===value)service=null}
    fun policy(context:Context):JSONObject {
        val result=JSONObject().put("unlocked",unlocked(context)).put("known",false)
        service?.get()?.let {vpn->runCatching {result.put("alwaysOn",vpn.isAlwaysOn).put("lockdown",vpn.isLockdownEnabled).put("known",true)}}
        return result
    }
}
