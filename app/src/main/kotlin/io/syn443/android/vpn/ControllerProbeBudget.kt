package io.syn443.android.vpn

import android.content.Context
import android.os.Handler
import android.os.Looper

/** The controller process owns one lazy actor. Obtaining it performs no file or
 * settings I/O on Main/Binder. Other probe subsystems are outside this budget. */
internal object ControllerProbeBudget {
    @Volatile private var admission:AdaptiveStartAdmission?=null
    fun get(context:Context):AdaptiveStartAdmission=admission ?: synchronized(this) {
        admission ?: DurableAdaptiveProbeBudget(context,Handler(Looper.getMainLooper())).also {admission=it}
    }
}
