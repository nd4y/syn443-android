package io.syn443.android.vpn

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.SystemClock
import io.syn443.android.support.DiagnosticProjection
import org.json.JSONArray
import org.json.JSONObject

/** Owned by :controller. Process death, including reboot, revokes this local grant. */
internal object OperatorReadGrant {
    const val durationMs = 15 * 60_000L
    private var deadline = 0L

    @Synchronized fun applyOwnerAction(action: String): Long {
        val now = SystemClock.elapsedRealtime()
        when (action) {
            "grant" -> deadline = now + durationMs
            "revoke" -> deadline = 0
            "inspect" -> Unit
            else -> throw IllegalArgumentException()
        }
        return remaining(now, deadline)
    }

    internal fun remaining(now: Long, until: Long): Long =
        if (now >= 0 && until > now && until - now <= durationMs) until - now else 0

    @Synchronized fun read(block: () -> JSONObject): JSONObject? {
        if (remaining(SystemClock.elapsedRealtime(), deadline) == 0L) return null
        val result = block()
        return result.takeIf { remaining(SystemClock.elapsedRealtime(), deadline) > 0 }
    }
}

/** Separate from the private command writer. No URI conveys a grant or selects a file. */
class OperatorReadProvider : ContentProvider() {
    override fun onCreate() = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        fun rejected(code: String) = Bundle().apply { putBoolean("ok", false); putString("error", code) }
        if (Binder.getCallingUid() != 2000) return rejected("unauthorized")
        if (arg != null || (extras != null && !extras.isEmpty) || method !in setOf("capabilities", "status", "logs")) {
            return rejected("command_rejected")
        }
        val app = checkNotNull(context)
        if (!LifecycleAccess.unlocked(app)) return rejected("needs_unlock")
        return try {
            val data = OperatorReadGrant.read {
                when (method) {
                    "capabilities" -> JSONObject().put("schemaVersion", 1).put("operations",
                        JSONArray(listOf("capabilities", "status", "logs")))
                    "logs" -> DiagnosticProjection.logs(StateStore.get(app).read())
                    else -> DiagnosticProjection.operatorStatus(LifecycleAccess.engineStatus(app, StateStore.get(app).read()))
                }
            } ?: return rejected("local_consent_required")
            Bundle().apply { putBoolean("ok", true); putString("json", data.toString()) }
        } catch (_: Exception) { rejected("command_rejected") }
    }

    override fun getType(uri: Uri): String? = null
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = 0
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = 0
}
