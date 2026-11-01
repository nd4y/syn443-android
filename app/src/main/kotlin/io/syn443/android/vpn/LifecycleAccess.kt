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
    fun engineStatus(status:JSONObject,servicePresent:Boolean,processPresent:Boolean?):JSONObject {
        // The stored flag is a recovery checkpoint, not current process evidence.
        val active=if(servicePresent)status.optBoolean("engineActive") else if(processPresent==false)false else null
        return status.put("engineActive",active ?: JSONObject.NULL).put("engineStateKnown",active!=null)
    }
    fun engineStatus(context:Context,status:JSONObject):JSONObject {
        val attached=service?.get()!=null
        val present=if(attached)null else runCatching {
            context.getSystemService(android.app.ActivityManager::class.java)?.runningAppProcesses?.any {
                it.uid==android.os.Process.myUid() && it.processName==context.packageName+":engine"
            }
        }.getOrNull()
        return engineStatus(status,attached,present)
    }
    fun policy(context:Context):JSONObject {
        val result=JSONObject().put("unlocked",unlocked(context)).put("known",false)
        service?.get()?.let {vpn->runCatching {result.put("alwaysOn",vpn.isAlwaysOn).put("lockdown",vpn.isLockdownEnabled).put("known",true)}}
        return result
    }
}
