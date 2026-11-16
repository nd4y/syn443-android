package io.syn443.android.admin

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import java.net.URI

/** Callback codes live only in this short-lived RAM operation. No device login
 * callback, VPN command, logs, saved state or navigation extras are used. */
class AdminCallbackActivity:ComponentActivity() {
    private var handling=false
    override fun onCreate(savedInstanceState:Bundle?) {
        val raw=take(intent)
        super.onCreate(savedInstanceState)
        receive(raw)
    }
    override fun onNewIntent(intent:Intent) {
        val raw=take(intent)
        super.onNewIntent(intent)
        receive(raw)
    }
    private fun take(incoming:Intent):String? {
        val raw=incoming.dataString?.takeIf {it.length in 1..8192 && it.all {c->c.code in 33..126}}
        incoming.data=null
        intent.data=null
        return raw
    }
    private fun receive(raw:String?) {
        if(handling)return
        handling=true
        lifecycleScope.launch {
            try {
                if(raw!=null && raw.length in 1..8192 && raw.all {it.code in 33..126}) {
                    val route=runCatching {URI(raw)}.getOrNull()
                    if(route?.scheme=="syn443" && route.rawAuthority=="admin" && route.rawPath=="/oauth/callback" &&
                        route.rawUserInfo==null && route.port == -1 && route.rawFragment==null && route.rawQuery!=null)
                        runCatching {ResolverAdminUiBridge(applicationContext.contentResolver).callback(raw)}
                }
            } finally {
                startActivity(Intent(this@AdminCallbackActivity,AdminActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
                finish()
            }
        }
    }
}
