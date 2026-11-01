package io.syn443.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.core.net.toUri
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** No credential/code is logged, put in an Activity extra, or made a VPN Connect action. */
class LoginCallbackActivity:ComponentActivity() {
    override fun onCreate(savedInstanceState:Bundle?) {
        super.onCreate(savedInstanceState)
        val callback=intent.dataString
        intent.data=null
        lifecycleScope.launch {
            if(callback!=null && callback.length<=8192)withContext(Dispatchers.IO) {runCatching {
                contentResolver.call("content://io.syn443.control".toUri(),"auth-callback",callback,null)
            }}
            startActivity(Intent(this@LoginCallbackActivity,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
            finish()
        }
    }
}
