package io.syn443.android.support

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.json.JSONArray
import org.json.JSONObject

/** In-memory packaging only. Components must already have passed their own
 * projection; this writer never treats arbitrary bytes as sanitized content. */
object DiagnosticArchive {
    const val MAX_COMPONENT = 65_536
    const val MAX_TOTAL = 262_144
    const val MAX_ARCHIVE = 524_288
    const val MAX_MANIFEST = 16_384
    const val MAX_COMPONENTS = 9
    private const val ZIP_TIME = 315_619_200_000L

    enum class Name(val path: String) {
        VERSIONS("versions.json"), CAPABILITIES("capabilities.json"),
        EFFECTIVE_CONFIG("effective-config.json"), HEALTH("health.json"),
        EVENTS("events.jsonl"), CHECKS("checks.json"), OVERLAY("overlay.json"),
        CRASHES("crashes.json"), NATIVE_STACKS("native-stacks.json"),
    }
    enum class State(val wire: String) {
        AVAILABLE("available"), MISSING("missing"), ERROR("error"), TRUNCATED("truncated"),
    }
    enum class Reason(val wire: String) {
        NONE("none"), UNAVAILABLE("unavailable"), UNSUPPORTED("unsupported"),
        OVER_LIMIT("over_limit"), INVALID_SOURCE("invalid_source"), IO_ERROR("io_error"),
        PROJECTION_ONLY("projection_only"),
    }
    data class Component(val name: Name, val bytes: ByteArray?, val state: State, val reason: Reason) {
        override fun toString() = "DiagnosticComponent([redacted])"
    }
    data class Result(val bytes: ByteArray, val manifest: JSONObject) {
        override fun toString() = "DiagnosticArchiveResult([redacted])"
    }

    fun create(inputs: List<Component>): Result {
        require(inputs.size <= MAX_COMPONENTS) { "invalid_components" }
        val supplied = mutableMapOf<Name, Component>()
        for (input in inputs) {
            require(supplied.size < MAX_COMPONENTS && !supplied.containsKey(input.name)) { "invalid_components" }
            supplied[input.name] = input
        }
        // Decide every bound and state before copying any payload or opening ZIP.
        var total = 0
        val plan = Name.entries.map { name ->
            val input = supplied[name] ?: Component(name, null, State.MISSING, Reason.UNAVAILABLE)
            when {
                input.state in setOf(State.MISSING, State.ERROR) ->
                    if (input.bytes != null || input.reason == Reason.NONE)
                        Component(name, null, State.ERROR, Reason.INVALID_SOURCE) else input
                input.bytes == null -> Component(name, null, State.ERROR, Reason.INVALID_SOURCE)
                input.bytes.size > MAX_COMPONENT || input.bytes.size > MAX_TOTAL - total ->
                    Component(name, null, State.ERROR, Reason.OVER_LIMIT)
                else -> input.also { total += input.bytes.size }
            }
        }
        require(total + MAX_MANIFEST + 2048 <= MAX_ARCHIVE) { "archive_unavailable" }
        val owned = plan.map { it.copy(bytes = it.bytes?.copyOf()) }
        val components = JSONArray()
        for (component in owned) components.put(JSONObject()
            .put("name", component.name.path).put("state", component.state.wire).put("reason", component.reason.wire)
            .put("bytes", component.bytes?.size ?: 0)
            .put("sha256", component.bytes?.let(::sha256) ?: JSONObject.NULL))
        val manifest = JSONObject().put("schemaVersion", 1).put("product", "SYN443")
            .put("complete", owned.all { it.state == State.AVAILABLE && it.reason == Reason.NONE && it.bytes != null })
            .put("components", components)
        val manifestBytes = manifest.toString().toByteArray(Charsets.UTF_8)
        require(manifestBytes.size <= MAX_MANIFEST) { "archive_unavailable" }
        val contents = owned.mapNotNull { item -> item.bytes?.let { item.name.path to it } } + ("manifest.json" to manifestBytes)
        // STORED entries, ASCII fixed names and a DOS-range timestamp require no
        // extra records, comments or data descriptors. Reserve the full bound.
        val expected = 22 + contents.sumOf { (name, bytes) -> 30 + 46 + name.length * 2 + bytes.size }
        require(expected <= MAX_ARCHIVE) { "archive_unavailable" }
        val output = ByteArrayOutputStream(expected)
        try {
            ZipOutputStream(output, Charsets.UTF_8).use { zip ->
                for ((name, bytes) in contents) {
                    val entry = ZipEntry(name).apply {
                        method = ZipEntry.STORED
                        size = bytes.size.toLong()
                        compressedSize = size
                        crc = CRC32().apply { update(bytes) }.value
                        time = ZIP_TIME
                        extra = null
                        comment = null
                    }
                    zip.putNextEntry(entry)
                    zip.write(bytes)
                    zip.closeEntry()
                }
            }
        } catch (_: Exception) { throw IllegalArgumentException("archive_unavailable") }
        require(output.size() <= MAX_ARCHIVE) { "archive_unavailable" }
        return Result(output.toByteArray(), manifest)
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
}
