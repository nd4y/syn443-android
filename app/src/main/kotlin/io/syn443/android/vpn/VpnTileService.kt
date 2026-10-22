package io.syn443.android.vpn

import android.app.PendingIntent
import android.annotation.SuppressLint
import android.content.Intent
import androidx.core.net.toUri
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import io.syn443.android.MainActivity
import org.json.JSONObject

class VpnTileService : TileService() {
    private val uri = "content://io.syn443.control".toUri()
    private fun on() = runCatching {
        JSONObject(checkNotNull(contentResolver.call(uri, "status", null, null)?.getString("json"))).optBoolean("desiredOn")
    }.getOrDefault(false)
    override fun onStartListening() {
        qsTile?.apply { state = if (on()) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE; updateTile() }
    }
    @Suppress("DEPRECATION")
    @SuppressLint("StartActivityAndCollapseDeprecated") // PendingIntent overload exists only on API34+; guarded legacy branch is required on API29-33.
    override fun onClick() {
        if (on()) contentResolver.call(uri, "disconnect", null, null)
        else {
            val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("syn443.connect", true)
            if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(PendingIntent.getActivity(this, 443, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE))
            else startActivityAndCollapse(intent)
        }
        onStartListening()
    }
}
