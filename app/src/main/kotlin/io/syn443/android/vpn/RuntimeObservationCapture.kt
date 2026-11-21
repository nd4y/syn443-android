package io.syn443.android.vpn

import io.syn443.identity.RuntimeObservation
import org.json.JSONObject

internal object RuntimeObservationCapture {
    fun sample(status:JSONObject,revision:Long,network:String,time:Long,build:Int):RuntimeObservation.Report {
        val known=status.optBoolean("engineStateKnown") && (!status.optBoolean("engineActive") || revision>0)
        val active=known && status.optBoolean("engineActive")
        val phase=when(status.optString("phase")) {
            "Online"->if(known && active && revision>0)"online" else "unknown"
            "Starting","Connecting"->"starting"
            "Recovering","Degraded"->"recovering"
            "NoNetwork"->"no_network"
            "Off"->if(known && !active)"off" else "unknown"
            "Blocked","BlockedByPolicy","NeedsUnlock"->"blocked"
            else->"unknown"
        }
        return RuntimeObservation.Report(1,1,build,phase,revision,known,active,network,time).also {it.validate()}
    }
}
