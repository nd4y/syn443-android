package io.syn443.android.support

import android.content.Context
import android.net.Uri
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** UI calls stay off the main thread. Binary grants are never displayed or persisted. */
internal object SupportBundleClient {
    private val methods = setOf("bundle-collect", "bundle-status", "bundle-cancel", "bundle-open", "bundle-read")
    private val id = Regex("[a-f0-9]{32}")
    private val digest = Regex("[a-f0-9]{64}")
    suspend fun call(context: Context, method: String, argument: String? = null): JSONObject = withContext(Dispatchers.IO) {
        require(method in methods)
        val reply = checkNotNull(context.contentResolver.call(Uri.parse("content://io.syn443.control"), method, argument, null))
        check(reply.getBoolean("ok")) { "bundle_unavailable" }
        val raw = checkNotNull(reply.getString("json"))
        require(raw.toByteArray(Charsets.UTF_8).size <= 65_536) { "invalid_bundle_reply" }
        JSONObject(raw)
    }

    suspend fun export(context: Context, bundleId: String, target: Uri, reviewedHash: String, reviewedBytes: Int) = withContext(Dispatchers.IO) {
        require(id.matches(bundleId) && target.scheme == "content") { "invalid_bundle_export" }
        require(digest.matches(reviewedHash) && reviewedBytes in 1..524_288)
        val status = call(context, "bundle-status", bundleId)
        require(status.optString("state") == "ready" && status.optString("id") == bundleId)
        require(status.optString("sha256") == reviewedHash && number(status, "bytes") == reviewedBytes)
        val opened = call(context, "bundle-open", bundleId)
        require(opened.optString("state") == "open")
        val grant = opened.opt("grant") as? String ?: error("invalid_bundle_reply")
        require(id.matches(grant))
        val total = number(opened, "bytes").also { require(it in 1..524_288) }
        val sha = opened.opt("sha256") as? String ?: error("invalid_bundle_reply")
        require(digest.matches(sha) && sha == reviewedHash && total == reviewedBytes)
        require(number(opened, "expiresInMs") in 1..60_000)
        val output = ByteArrayOutputStream(total)
        var offset = 0
        while (offset < total) {
            val frame = call(context, "bundle-read", "$grant:$offset")
            require(frame.opt("grant") == grant && number(frame, "offset") == offset)
            val encoded = frame.opt("data") as? String ?: error("invalid_bundle_reply")
            require(encoded.length <= 43_692)
            val bytes = Base64.decode(encoded, Base64.NO_WRAP)
            require(bytes.size in 1..32_768 && Base64.encodeToString(bytes, Base64.NO_WRAP) == encoded)
            val next = offset + bytes.size
            require(next <= total && number(frame, "nextOffset") == next && frame.opt("done") == (next == total))
            output.write(bytes)
            offset = next
        }
        val bytes = output.toByteArray()
        try {
            require(MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) } == sha)
            // No document bytes are written until the complete authenticated
            // archive has been received and its advertised digest has matched.
            checkNotNull(context.contentResolver.openOutputStream(target, "w")).use { stream ->
                stream.write(bytes)
                stream.flush()
            }
        } finally { bytes.fill(0) }
    }

    private fun number(value: JSONObject, key: String): Int = when (val number = value.opt(key)) {
        is Int -> number
        is Long -> number.takeIf { it in 0..Int.MAX_VALUE }?.toInt() ?: error("invalid_bundle_reply")
        else -> error("invalid_bundle_reply")
    }
}
