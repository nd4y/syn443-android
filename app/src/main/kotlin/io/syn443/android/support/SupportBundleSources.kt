package io.syn443.android.support

import android.content.Context
import android.os.Build
import io.syn443.android.BuildConfig
import io.syn443.android.vpn.EngineExitDiagnostics
import io.syn443.android.vpn.LifecycleAccess
import io.syn443.android.vpn.OverlaySnapshot
import io.syn443.android.vpn.PolicyChecks
import java.io.File
import java.nio.file.Files
import org.json.JSONObject

/** Passive collection only. Never initializes login, decrypts config, or enters the engine. */
internal object SupportBundleSources {
    internal const val MAX_STATE_BYTES = 262_144

    fun capture(context: Context): List<DiagnosticArchive.Component> {
        check(LifecycleAccess.unlocked(context)) { "needs_unlock" }
        val file = File(context.noBackupFilesDir, "vpn-intent.json")
        return capture(
            state = { readState(file) },
            overlay = { OverlaySnapshot.read() },
            checks = { PolicyChecks.snapshotForDiagnostics() },
            exits = { EngineExitDiagnostics.snapshot(context) },
            versionName = BuildConfig.VERSION_NAME, versionCode = BuildConfig.VERSION_CODE, sdk = Build.VERSION.SDK_INT,
            journal = { io.syn443.android.observability.LocalDiagnosticJournal.passive(context) },
        )
    }

    internal fun capture(
        state: () -> JSONObject?, overlay: () -> JSONObject?, checks: (JSONObject) -> JSONObject?, exits: () -> JSONObject?,
        versionName: String, versionCode: Int, sdk: Int,
        journal: () -> DiagnosticArchive.Component? = { null },
    ): List<DiagnosticArchive.Component> {
        val before = runCatching { state() }.getOrNull()
        val source = before ?: JSONObject()
        val result = DiagnosticProjection.project(
            source, runCatching { overlay() }.getOrNull(), runCatching { checks(source) }.getOrNull(),
            runCatching { exits() }.getOrNull(), versionName, versionCode, sdk,
        )
        val suppliedHistory = try { journal() } catch (_: Exception) {
            DiagnosticArchive.Component(DiagnosticArchive.Name.EVENTS, null, DiagnosticArchive.State.ERROR, DiagnosticArchive.Reason.IO_ERROR)
        }
        val history = suppliedHistory?.let {
            if (it.name == DiagnosticArchive.Name.EVENTS) it else DiagnosticArchive.Component(
                DiagnosticArchive.Name.EVENTS, null, DiagnosticArchive.State.ERROR, DiagnosticArchive.Reason.INVALID_SOURCE)
        }
        val after = runCatching { state() }.getOrNull()
        val stable = before != null && after != null && sameContext(before, after)
        return result.map { part ->
            when {
                part.name == DiagnosticArchive.Name.EVENTS && history != null -> history
                before == null && part.name in setOf(DiagnosticArchive.Name.HEALTH, DiagnosticArchive.Name.EVENTS) ->
                    part.copy(bytes = null, state = DiagnosticArchive.State.MISSING, reason = DiagnosticArchive.Reason.UNAVAILABLE)
                !stable && part.name in setOf(DiagnosticArchive.Name.HEALTH, DiagnosticArchive.Name.CHECKS, DiagnosticArchive.Name.OVERLAY) ->
                    part.copy(bytes = null, state = DiagnosticArchive.State.ERROR, reason = DiagnosticArchive.Reason.INVALID_SOURCE)
                else -> part
            }
        }
    }

    private fun sameContext(before: JSONObject, after: JSONObject): Boolean =
        listOf("generation", "networkEpoch").all { before.opt(it) == after.opt(it) } &&
            listOf("configRevision", "desiredOn", "engineActive").all { before.opt(it) == after.opt(it) }

    internal fun readState(file: File): JSONObject? {
        if (!file.isFile || Files.isSymbolicLink(file.toPath())) return null
        val bytes = file.inputStream().use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= MAX_STATE_BYTES) { "state_over_limit" }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        val raw = decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        var depth = 0
        var quoted = false
        var escaped = false
        for (char in raw) {
            if (quoted) {
                if (escaped) escaped = false else if (char == '\\') escaped = true else if (char == '"') quoted = false
            } else when (char) {
                '"' -> quoted = true
                '{', '[' -> { depth++; require(depth <= 32) { "state_too_deep" } }
                '}', ']' -> { depth--; require(depth >= 0) { "invalid_state" } }
            }
        }
        require(depth == 0 && !quoted) { "invalid_state" }
        val token = org.json.JSONTokener(raw)
        val value = token.nextValue() as? JSONObject ?: error("invalid_state")
        require(token.nextClean() == '\u0000') { "invalid_state" }
        return value
    }
}
