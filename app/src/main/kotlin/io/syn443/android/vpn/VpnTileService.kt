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
    private fun status() = runCatching {
        JSONObject(checkNotNull(contentResolver.call(uri, "status", null, null)?.getString("json")))
    }.getOrNull()
    override fun onStartListening() {
        val current = status()
        val desiredOn = vpnTileIntent(current)
        qsTile?.apply {
            state = when (desiredOn) {
                true -> Tile.STATE_ACTIVE
                false -> Tile.STATE_INACTIVE
                null -> Tile.STATE_UNAVAILABLE
            }
            subtitle = vpnStatusLabel(current ?: JSONObject(), current != null, current?.hasBlockedAccountPolicy() == true)
            updateTile()
        }
    }
    private fun command(method: String) = runCatching {
        contentResolver.call(uri, method, null, null)
    }.getOrNull()

    @Suppress("DEPRECATION")
    @SuppressLint("StartActivityAndCollapseDeprecated") // PendingIntent overload exists only on API34+; guarded legacy branch is required on API29-33.
    override fun onClick() {
        val current = status() ?: return onStartListening()
        val desiredOn = vpnTileIntent(current) ?: return onStartListening()
        if (desiredOn && !current.optBoolean("resumeRequired")) {
            command("disconnect")
        } else {
            val result = command("connect")
            if (result?.getBoolean("ok") != true || android.net.VpnService.prepare(this) == null) { onStartListening(); return }
            val generation = runCatching { JSONObject(checkNotNull(result.getString("json"))).getLong("generation") }
                .getOrNull()?.takeIf { it >= 0 } ?: return onStartListening()
            val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("syn443.consentGeneration", generation)
            if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(PendingIntent.getActivity(this, 443, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE))
            else startActivityAndCollapse(intent)
        }
        onStartListening()
    }
}
