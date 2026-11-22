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
    @Synchronized fun attach(value:TunnelService){service=java.lang.ref.WeakReference(value)}
    @Synchronized fun detach(value:TunnelService){if(service?.get()===value)service=null}
    @Synchronized internal fun recordControllerStartup(store: StateStore) {
        val state = store.read()
        val intent = store.checkpoint(state)
        if (!intent.desiredOn) return
        val needsResume = state.optBoolean("resumeRequired")
        // BOOT_COMPLETED may have restored the service before the first UI or
        // shell request. That service owns its current phase, even during startup.
        if (!needsResume && service?.get() != null) return
        store.event(
            if (needsResume) "NeedsAction" else "Recovering",
            if (needsResume) "explicit_resume_required" else "controller_recreated",
            state.optLong("networkEpoch"), generation = intent.generation,
        )
    }
    internal fun ownsReadyEngine(generation: Long): Boolean = service?.get()?.ownsReadyEngine(generation) == true

    internal fun physicalLink(status: JSONObject): JSONObject? =
        if (status.optBoolean("desiredOn")) service?.get()?.physicalLinkReport(
            status.optLong("generation", -1), status.optLong("networkEpoch", -1)) else null

    internal fun requestNetworkMode(stamp:String,mode:String,minutes:Int) = service?.get()?.requestNetworkMode(stamp,mode,minutes)==true

    fun engineStatus(status:JSONObject,engineReady:Boolean,processPresent:Boolean?, serviceAttached:Boolean = true):JSONObject {
        // A newly attached controller can still be waiting for an old owner or
        // a restart budget. Only the current engine handshake is positive evidence.
        val awaitingResume = status.optBoolean("resumeRequired")
        // Process death can interrupt retirement after the durable Stop but before
        // engineActive is cleared. Both the service and native process must be absent.
        val detachedStop = !serviceAttached && status.opt("desiredOn") == false && status.optString("phase") == "Off"
        val active = when {
            engineReady -> true
            processPresent == false && (detachedStop || awaitingResume || !status.optBoolean("engineActive")) -> false
            else -> null
        }
        return status.put("engineActive",active ?: JSONObject.NULL).put("engineStateKnown",active!=null)
    }
    fun engineStatus(context:Context,status:JSONObject):JSONObject {
        val controller = service?.get()
        val ready = controller?.ownsReadyEngine(status.optLong("generation", -1)) == true
        val present=if(ready)null else runCatching {
            context.getSystemService(android.app.ActivityManager::class.java)?.runningAppProcesses?.any {
                it.uid==android.os.Process.myUid() && it.processName==context.packageName+":engine"
            }
        }.getOrNull()
        return engineStatus(status,ready,present,serviceAttached = controller != null || service?.get() != null)
    }
    fun policy(context:Context):JSONObject {
        val result=JSONObject().put("unlocked",unlocked(context)).put("known",false)
        service?.get()?.let {vpn->runCatching {result.put("alwaysOn",vpn.isAlwaysOn).put("lockdown",vpn.isLockdownEnabled).put("known",true)}}
        return result
    }
}
