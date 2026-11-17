package io.syn443.android

import io.syn443.android.support.DiagnosticArchive
import io.syn443.android.support.DiagnosticArchive.Component
import io.syn443.android.support.DiagnosticArchive.Name
import io.syn443.android.support.DiagnosticArchive.Reason
import io.syn443.android.support.DiagnosticArchive.State
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class DiagnosticArchiveTest {
    private fun component(name: Name, bytes: ByteArray = "{}".toByteArray(), state: State = State.AVAILABLE,
        reason: Reason = Reason.NONE) = Component(name, bytes, state, reason)
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun row(result: DiagnosticArchive.Result, name: Name): JSONObject = result.manifest.getJSONArray("components")
        .let { rows -> (0 until rows.length()).map(rows::getJSONObject).single { it.getString("name") == name.path } }
    private fun entries(result: DiagnosticArchive.Result): Map<String, ByteArray> {
        val output = linkedMapOf<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(result.bytes), Charsets.UTF_8).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                assertEquals(ZipEntry.STORED, entry.method)
                assertNull(entry.extra)
                assertNull(entry.comment)
                assertFalse(entry.isDirectory)
                assertFalse(output.containsKey(entry.name))
                val content = zip.readBytes()
                assertEquals(content.size.toLong(), entry.size)
                assertEquals(entry.size, entry.compressedSize)
                assertEquals(CRC32().apply { update(content) }.value, entry.crc)
                output[entry.name] = content
                zip.closeEntry()
            }
        }
        return output
    }

    @Test fun storedArchiveHasExactNamesCrcManifestHashesAndOwnedInputBytes() {
        val original = "{\"known\":true}".toByteArray()
        val result = DiagnosticArchive.create(listOf(component(Name.HEALTH, original), component(Name.EVENTS, byteArrayOf())))
        original.fill(0)
        val files = entries(result)
        assertEquals(setOf("health.json", "events.jsonl", "manifest.json"), files.keys)
        assertArrayEquals("{\"known\":true}".toByteArray(), files.getValue("health.json"))
        assertEquals(0, files.getValue("events.jsonl").size)
        assertEquals(9, result.manifest.getJSONArray("components").length())
        assertEquals(setOf("schemaVersion", "product", "complete", "components"), result.manifest.keys().asSequence().toSet())
        assertEquals(1, result.manifest.getInt("schemaVersion"))
        assertEquals("SYN443", result.manifest.getString("product"))
        val manifest = JSONObject(files.getValue("manifest.json").toString(Charsets.UTF_8))
        assertEquals(result.manifest.toString(), manifest.toString())
        for (name in Name.entries) {
            val item = row(result, name)
            assertEquals(setOf("name", "state", "reason", "bytes", "sha256"), item.keys().asSequence().toSet())
            if (files.containsKey(name.path)) {
                assertEquals(hash(files.getValue(name.path)), item.getString("sha256"))
                assertEquals(files.getValue(name.path).size, item.getInt("bytes"))
            } else {
                assertTrue(item.isNull("sha256")); assertEquals(0, item.getInt("bytes"))
            }
        }
        assertFalse(result.manifest.getBoolean("complete"))
        assertTrue(files.getValue("manifest.json").size <= DiagnosticArchive.MAX_MANIFEST)
        assertTrue(result.bytes.size <= DiagnosticArchive.MAX_ARCHIVE)
    }

    @Test fun missingAndErroredComponentsRemainExplicitAndIncomplete() {
        val result = DiagnosticArchive.create(listOf(
            Component(Name.CHECKS, null, State.MISSING, Reason.UNSUPPORTED),
            Component(Name.CRASHES, null, State.ERROR, Reason.IO_ERROR),
            Component(Name.HEALTH, null, State.AVAILABLE, Reason.NONE),
            Component(Name.EVENTS, byteArrayOf(1), State.MISSING, Reason.UNAVAILABLE)))
        assertEquals(setOf("manifest.json"), entries(result).keys)
        assertEquals("missing", row(result, Name.CHECKS).getString("state"))
        assertEquals("unsupported", row(result, Name.CHECKS).getString("reason"))
        assertEquals("io_error", row(result, Name.CRASHES).getString("reason"))
        for (name in listOf(Name.HEALTH, Name.EVENTS)) {
            assertEquals("error", row(result, name).getString("state"))
            assertEquals("invalid_source", row(result, name).getString("reason"))
        }
        assertEquals("unavailable", row(result, Name.OVERLAY).getString("reason"))
        for (name in Name.entries) {
            assertEquals(0, row(result, name).getInt("bytes"))
            assertTrue(row(result, name).isNull("sha256"))
        }
        assertFalse(result.manifest.getBoolean("complete"))
    }

    @Test fun duplicateAndTooManyComponentsFailBeforeArchiveCreation() {
        val huge = ByteArray(DiagnosticArchive.MAX_COMPONENT + 1)
        for (inputs in listOf(
            listOf(component(Name.HEALTH, huge), component(Name.HEALTH)),
            List(10) { component(Name.HEALTH, huge) })) {
            try { DiagnosticArchive.create(inputs); fail("invalid components accepted") }
            catch (error: IllegalArgumentException) {
                assertEquals("invalid_components", error.message)
                assertNull(error.cause)
            }
        }
        assertEquals(9, DiagnosticArchive.create(emptyList()).manifest.getJSONArray("components").length())
    }

    @Test fun componentByteLimitOmitsWholePayloadWithoutTruncatingJson() {
        val exact = ("{\"text\":\"" + "x".repeat(DiagnosticArchive.MAX_COMPONENT - 11) + "\"}").toByteArray()
        assertEquals(DiagnosticArchive.MAX_COMPONENT, exact.size)
        val kept = DiagnosticArchive.create(listOf(component(Name.HEALTH, exact)))
        assertArrayEquals(exact, entries(kept).getValue(Name.HEALTH.path))
        assertEquals(exact.size, row(kept, Name.HEALTH).getInt("bytes"))
        val oversized = exact + byteArrayOf(32)
        val omitted = DiagnosticArchive.create(listOf(component(Name.HEALTH, oversized), component(Name.VERSIONS)))
        val files = entries(omitted)
        assertFalse(files.containsKey(Name.HEALTH.path))
        assertTrue(files.containsKey(Name.VERSIONS.path))
        assertEquals("error", row(omitted, Name.HEALTH).getString("state"))
        assertEquals("over_limit", row(omitted, Name.HEALTH).getString("reason"))
        assertTrue(row(omitted, Name.HEALTH).isNull("sha256"))
        assertEquals(0, row(omitted, Name.HEALTH).getInt("bytes"))
        assertFalse(omitted.manifest.getBoolean("complete"))
        val utf8 = ("{\"x\":\"" + "ж".repeat((DiagnosticArchive.MAX_COMPONENT - 8) / 2) + "\"}").toByteArray(Charsets.UTF_8)
        assertEquals(DiagnosticArchive.MAX_COMPONENT, utf8.size)
        assertTrue(utf8.toString(Charsets.UTF_8).length < DiagnosticArchive.MAX_COMPONENT)
        assertArrayEquals(utf8, entries(DiagnosticArchive.create(listOf(component(Name.HEALTH, utf8)))).getValue(Name.HEALTH.path))
        val overUtf8 = utf8 + "ж".toByteArray(Charsets.UTF_8)
        val rejectedUtf8 = DiagnosticArchive.create(listOf(component(Name.HEALTH, overUtf8)))
        assertEquals("over_limit", row(rejectedUtf8, Name.HEALTH).getString("reason"))
        assertFalse(entries(rejectedUtf8).containsKey(Name.HEALTH.path))
    }

    @Test fun aggregateLimitIsDeterministicAndKeepsOtherComponents() {
        val inputs = Name.entries.map { component(it, ByteArray(DiagnosticArchive.MAX_COMPONENT) { 7 }) }
        val first = DiagnosticArchive.create(inputs.reversed())
        val second = DiagnosticArchive.create(inputs)
        assertArrayEquals(first.bytes, second.bytes)
        val files = entries(first)
        val expected = Name.entries.take(4).map { it.path }.toSet() + "manifest.json"
        assertEquals(expected, files.keys)
        assertEquals(DiagnosticArchive.MAX_TOTAL, Name.entries.sumOf { row(first, it).getInt("bytes") })
        for (name in Name.entries.drop(4)) {
            assertEquals("error", row(first, name).getString("state"))
            assertEquals("over_limit", row(first, name).getString("reason"))
            assertTrue(row(first, name).isNull("sha256"))
        }
        assertTrue(first.bytes.size <= DiagnosticArchive.MAX_ARCHIVE)
        assertFalse(first.manifest.getBoolean("complete"))
    }

    @Test fun allAvailableComponentsAreCompleteOnlyWithNoneReasons() {
        val all = Name.entries.map { component(it) }
        val complete = DiagnosticArchive.create(all)
        assertTrue(complete.manifest.getBoolean("complete"))
        assertEquals(Name.entries.map { it.path }.toSet() + "manifest.json", entries(complete).keys)
        for (index in all.indices) {
            val changed = all.toMutableList().also { it[index] = it[index].copy(reason = Reason.PROJECTION_ONLY) }
            assertFalse(DiagnosticArchive.create(changed).manifest.getBoolean("complete"))
        }
    }

    @Test fun truncatedAndProjectionOnlyComponentsNeverClaimComplete() {
        val raw = "{\"limited\":true}".toByteArray()
        val all = Name.entries.map { component(it) }.toMutableList()
        all[Name.HEALTH.ordinal] = component(Name.HEALTH, raw, State.TRUNCATED, Reason.OVER_LIMIT)
        val result = DiagnosticArchive.create(all)
        assertFalse(result.manifest.getBoolean("complete"))
        assertEquals("truncated", row(result, Name.HEALTH).getString("state"))
        assertEquals(hash(raw), row(result, Name.HEALTH).getString("sha256"))
        assertArrayEquals(raw, entries(result).getValue(Name.HEALTH.path))
        val absent = DiagnosticArchive.create(listOf(Component(Name.HEALTH, null, State.TRUNCATED, Reason.OVER_LIMIT)))
        assertEquals("invalid_source", row(absent, Name.HEALTH).getString("reason"))
        assertFalse(entries(absent).containsKey(Name.HEALTH.path))
    }

    @Test fun namesSizesAndDiagnosticsCannotEscapeOrEchoInputs() {
        val expected = setOf("versions.json", "capabilities.json", "effective-config.json", "health.json", "events.jsonl",
            "checks.json", "overlay.json", "crashes.json", "native-stacks.json")
        assertEquals(expected, Name.entries.map { it.path }.toSet())
        assertTrue(Name.entries.all { '/' !in it.path && '\\' !in it.path && ".." !in it.path && it.path.all { c -> c.code in 32..126 } })
        val value = component(Name.HEALTH, "synthetic-private-value".toByteArray())
        assertEquals("DiagnosticComponent([redacted])", value.toString())
        val result = DiagnosticArchive.create(listOf(value))
        assertEquals("DiagnosticArchiveResult([redacted])", result.toString())
        assertFalse(result.toString().contains("synthetic-private-value"))
        assertTrue(result.bytes.size <= DiagnosticArchive.MAX_ARCHIVE)
        assertEquals(0, result.bytes[result.bytes.size - 1].toInt())
        assertEquals(0, result.bytes[result.bytes.size - 2].toInt())
        assertTrue(entries(result).keys.all { it == "manifest.json" || it in expected })
        assertTrue(State.entries.all { it.wire.matches(Regex("[a-z_]+")) })
        assertTrue(Reason.entries.all { it.wire.matches(Regex("[a-z_]+")) })
    }
}
