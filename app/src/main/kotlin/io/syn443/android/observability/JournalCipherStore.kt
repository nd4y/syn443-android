package io.syn443.android.observability

import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import io.syn443.observability.EventClock
import io.syn443.observability.JournalClockState
import io.syn443.observability.JournalRetention
import io.syn443.observability.JournalSegment
import io.syn443.observability.StructuredEvent
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Shared by every store instance for the single production namespace. No IO
 * occurs under this lock. A blocked writer retains it until actual finally. */
internal class JournalPublicationFence {
    private val lock = Any()
    private var writing = false
    private var generation = 0L
    fun <T> write(block: () -> T): T {
        synchronized(lock) {
            check(!writing && generation < Long.MAX_VALUE) { "journal_busy" }
            writing = true; generation++
        }
        try { return block() } finally { synchronized(lock) { writing = false } }
    }
    fun <T> read(discard: (T) -> Unit, block: () -> T): T {
        val stamp = synchronized(lock) { check(!writing) { "journal_busy" }; generation }
        val value = block()
        return synchronized(lock) {
            if (writing || stamp != generation) { discard(value); error("journal_changed") }
            value
        }
    }
}

/** Storage-only owner. The controller's single journal worker calls append;
 * passive archive reads use a separate instance and never create storage/key.
 * These records grant no policy, network or health authority. */
internal class JournalCipherStore(
    private val directory: File,
    private val key: (Boolean) -> SecretKey,
    private val clock: () -> EventClock,
    private val publication: JournalPublicationFence,
    private val io: (Stage) -> Unit = {},
) {
    internal enum class Stage { BEFORE_WRITE, BEFORE_RENAME, BEFORE_READ }
    internal data class Snapshot(val bytes: ByteArray?, val partial: Boolean) {
        override fun toString() = "JournalSnapshot([redacted])"
    }
    private data class Identity(val device: Long, val inode: Long)
    private data class Entry(val file: File, val identity: Identity, val bytes: Long, val boot: Int, val elapsed: Long, val temporary: Boolean)
    private data class Loaded(val entry: Entry, val frame: JournalFrame, val id: Long)
    private val names = Regex("b([0-9]{1,10})-e([0-9]{16})-([a-f0-9]{32})\\.(enc|tmp)")

    fun append(events: List<StructuredEvent>) = publication.write {
        require(events.size in 1..64)
        val parent = prepare(true) ?: error("journal_unavailable")
        val all = inspect(parent).toMutableList()
        // A matching temporary is owned scratch in this fixed private namespace.
        // It was never a sealed record or a durable clock floor. Guard its inode
        // before removing it; unknown names/types/modes are always preserved.
        for (temp in all.filter { it.temporary }) {
            remove(temp, parent)
            all.remove(temp)
        }
        val secret = key(all.isEmpty())
        val ordered = all.sortedWith(compareBy<Entry> { it.boot }.thenBy { it.elapsed }.thenBy { it.file.name })
        val floorEntry = ordered.lastOrNull()
        val latest = floorEntry?.let { Loaded(it, read(it, parent, secret), ordered.size.toLong()) }
        val floor = latest?.frame?.committed
        val now = clock()
        val headPlan = checkNotNull(JournalRetention.plan(floor, now, listOfNotNull(latest?.let(::descriptor)), JournalRetention.MAX_FRAME_BYTES))
        check(headPlan.clockState != JournalClockState.CLOCK_UNCERTAIN && headPlan.appendAllowed) { "journal_clock_unavailable" }
        check(floor == null || floor.boot != now.boot || floor.elapsedMs != now.elapsedMs || floor.wallMs == now.wallMs) {
            "journal_clock_unavailable"
        }
        // A routine append authenticates only its floor. Consider more frames
        // for bounded expiry, reboot cleanup or slot eviction. A filename only
        // chooses a candidate; its authenticated frame authorizes removal.
        val full = ordered.size >= JournalRetention.MAX_SEALED_SEGMENTS
        val candidates = ordered.asSequence().withIndex()
            .filter { (_, entry) -> entry != floorEntry &&
                (full || entry.boot != now.boot || now.elapsedMs - entry.elapsed >= JournalRetention.MAX_AGE_MS) }
            .take(7)
            .map { (index, entry) -> Loaded(entry, read(entry, parent, secret), index.toLong() + 1) }
            .toList()
        val loaded = candidates + listOfNotNull(latest)
        val plan = checkNotNull(JournalRetention.plan(floor, now, loaded.map(::descriptor), JournalRetention.MAX_FRAME_BYTES))
        check(plan.clockState != JournalClockState.CLOCK_UNCERTAIN && plan.appendAllowed) { "journal_clock_unavailable" }
        // Validate and encode the entire new batch before retiring any durable
        // witness; malformed/future/oversized input must cause no pruning.
        val plain = StructuredJournalCodec.encode(JournalFrame(now, events))
        try {
            var removed = 0
            val victims = (plan.expired + plan.reset + plan.evicted).toSet()
            for (item in loaded) {
                if (item.id !in victims || item.entry == floorEntry && item.frame.committed.boot == now.boot) continue
                remove(item.entry, parent)
                all.remove(item.entry)
                removed++
            }
            // The planner receives the bounded authenticated sample. Enforce
            // the entire namespace quota before creating temporary ciphertext.
            if (all.size >= JournalRetention.MAX_SEALED_SEGMENTS) {
                check(removed < JournalRetention.MAX_PRUNE)
                val victim = checkNotNull(loaded.firstOrNull { it.entry in all && it.entry != floorEntry })
                remove(victim.entry, parent)
                all.remove(victim.entry)
                removed++
            }
            check(removed <= JournalRetention.MAX_PRUNE && all.size < JournalRetention.MAX_SEALED_SEGMENTS)
            check(all.sumOf { it.bytes } <= JournalRetention.MAX_BYTES - JournalRetention.MAX_FRAME_BYTES)
            write(parent, now, plain, secret)
        } finally { plain.fill(0) }
    }

    /** Missing directory is genuinely empty. All other errors are reported to
     * the caller, which emits one fixed unavailable/error component reason. */
    fun snapshot(): Snapshot = publication.read({ it.bytes?.fill(0) }) {
        val parent = prepare(false) ?: return@read Snapshot(null, false)
        val all = inspect(parent)
        val sealed = all.filterNot { it.temporary }.sortedWith(compareBy<Entry> { it.boot }.thenBy { it.elapsed }.thenBy { it.file.name })
        if (sealed.isEmpty()) return@read Snapshot(null, all.isNotEmpty())
        val secret = key(false)
        val selected = sealed.takeLast(8)
        val loaded = selected.mapIndexed { index, entry -> Loaded(entry, read(entry, parent, secret), index.toLong() + 1) }
        val now = clock()
        val plan = checkNotNull(JournalRetention.plan(loaded.last().frame.committed, now, loaded.map(::descriptor), 0))
        check(plan.clockState != JournalClockState.CLOCK_UNCERTAIN) { "journal_clock_unavailable" }
        val allowed = plan.exportable.toSet()
        val lines = ArrayList<ByteArray>()
        var size = 0
        var partial = all.any { it.temporary } || sealed.size > selected.size || plan.pruningIncomplete
        try {
            outer@ for (item in loaded.asReversed()) {
                if (item.id !in allowed) { partial = true; continue }
                for (event in item.frame.events.asReversed()) {
                    val line = StructuredJournalCodec.projectedLine(event)
                    if (line.size > 65_536 - size) { line.fill(0); partial = true; break@outer }
                    lines += line; size += line.size
                }
            }
            matches(parent)
            if (lines.isEmpty()) return@read Snapshot(null, partial || sealed.isNotEmpty())
            val result = ByteArray(size)
            var offset = 0
            for (line in lines.asReversed()) { line.copyInto(result, offset); offset += line.size }
            Snapshot(result, partial)
        } finally { lines.forEach { it.fill(0) } }
    }

    private fun descriptor(value: Loaded) = JournalSegment(value.id, value.entry.bytes, value.frame.first, value.frame.committed)
    private fun identity(stat: StructStat) = Identity(stat.st_dev, stat.st_ino)
    private fun prepare(create: Boolean): Identity? {
        if (create) {
            try { Os.mkdir(directory.absolutePath, 448) } catch (error: ErrnoException) {
                if (error.errno != OsConstants.EEXIST) throw error
            }
        } else if (!Files.exists(directory.toPath(), LinkOption.NOFOLLOW_LINKS)) return null
        val stat = Os.lstat(directory.absolutePath)
        require(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == Process.myUid() && (stat.st_mode and 511) == 448)
        return identity(stat)
    }
    private fun matches(expected: Identity) {
        val actual = checkNotNull(prepare(false))
        require(actual == expected)
    }
    private fun inspect(parent: Identity): List<Entry> {
        matches(parent)
        val result = ArrayList<Entry>()
        Files.newDirectoryStream(directory.toPath()).use { stream ->
            for (path in stream) {
                require(result.size < 1024)
                val file = path.toFile()
                val parsed = checkNotNull(names.matchEntire(file.name))
                val boot = parsed.groupValues[1].toLong().also { require(it <= Int.MAX_VALUE) }.toInt()
                val elapsed = parsed.groupValues[2].toLong().also { require(it <= StructuredEvent.MAX_SAFE) }
                val stat = regular(file)
                val temporary = parsed.groupValues[4] == "tmp"
                require(stat.st_size in (if (temporary) 0L else 30L)..JournalRetention.MAX_FRAME_BYTES)
                result += Entry(file, identity(stat), stat.st_size, boot, elapsed, temporary)
            }
        }
        require(result.count { it.temporary } <= 1 && result.count { !it.temporary } <= JournalRetention.MAX_SEALED_SEGMENTS)
        require(result.sumOf { it.bytes } <= JournalRetention.MAX_BYTES)
        matches(parent)
        return result
    }
    private fun regular(file: File): StructStat {
        require(file.parentFile == directory && names.matches(file.name))
        return Os.lstat(file.absolutePath).also {
            require(OsConstants.S_ISREG(it.st_mode) && it.st_uid == Process.myUid() && (it.st_mode and 511) == 384)
        }
    }
    private fun remove(entry: Entry, parent: Identity) {
        matches(parent)
        require(identity(regular(entry.file)) == entry.identity)
        Os.remove(entry.file.absolutePath)
    }
    private fun read(entry: Entry, parent: Identity, secret: SecretKey): JournalFrame {
        io(Stage.BEFORE_READ)
        matches(parent)
        require(!entry.temporary && entry.bytes in 30L..JournalRetention.MAX_FRAME_BYTES)
        val fd = Os.open(entry.file.absolutePath, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC, 0)
        var bytes: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            val input = try { FileInputStream(fd) } catch (error: Exception) { runCatching { Os.close(fd) }; throw error }
            input.use {
                val before = Os.fstat(fd)
                require(OsConstants.S_ISREG(before.st_mode) && before.st_uid == Process.myUid() &&
                    (before.st_mode and 511) == 384 && identity(before) == entry.identity && before.st_size == entry.bytes)
                val frame = ByteArray(entry.bytes.toInt()); bytes = frame
                var offset = 0
                while (offset < frame.size) { val n = input.read(frame, offset, frame.size - offset); require(n > 0); offset += n }
                val after = Os.fstat(fd)
                require(input.read() == -1 && identity(after) == entry.identity && after.st_size == entry.bytes)
            }
            val frame = checkNotNull(bytes)
            require(frame[0] == 1.toByte())
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, frame, 1, 12))
            cipher.updateAAD(aad(entry.file.name))
            val decoded = cipher.doFinal(frame, 13, frame.size - 13); plaintext = decoded
            val result = StructuredJournalCodec.decode(decoded)
            require(result.committed.boot == entry.boot && result.committed.elapsedMs == entry.elapsed)
            matches(parent)
            return result
        } finally { bytes?.fill(0); plaintext?.fill(0) }
    }

    private fun write(parent: Identity, now: EventClock, plaintext: ByteArray, secret: SecretKey) {
        val base = "b${now.boot}-e${now.elapsedMs.toString().padStart(16, '0')}-${UUID.randomUUID().toString().replace("-", "")}"
        val ready = File(directory, "$base.enc")
        val temporary = File(directory, "$base.tmp")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secret)
        require(cipher.iv.size == 12)
        cipher.updateAAD(aad(ready.name))
        val encrypted = cipher.doFinal(plaintext)
        val frame = try { byteArrayOf(1) + cipher.iv + encrypted } finally { encrypted.fill(0) }
        var created: Identity? = null
        var renamed = false
        try {
            require(frame.size.toLong() <= JournalRetention.MAX_FRAME_BYTES)
            io(Stage.BEFORE_WRITE)
            matches(parent)
            val fd = Os.open(temporary.absolutePath, OsConstants.O_WRONLY or OsConstants.O_CREAT or OsConstants.O_EXCL or
                OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 384)
            val output = try { FileOutputStream(fd) } catch (error: Exception) { runCatching { Os.close(fd) }; throw error }
            output.use {
                val opened = Os.fstat(fd)
                require(OsConstants.S_ISREG(opened.st_mode) && opened.st_uid == Process.myUid() && (opened.st_mode and 511) == 384)
                created = identity(opened)
                it.write(frame); it.fd.sync()
            }
            io(Stage.BEFORE_RENAME)
            matches(parent)
            require(!Files.exists(ready.toPath(), LinkOption.NOFOLLOW_LINKS))
            require(identity(regular(temporary)) == created)
            Os.rename(temporary.absolutePath, ready.absolutePath)
            renamed = true
            val stored = regular(ready)
            require(identity(stored) == created && stored.st_size == frame.size.toLong())
            val dirFd = Os.open(directory.absolutePath, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
            try { require(identity(Os.fstat(dirFd)) == parent); Os.fsync(dirFd) } finally { Os.close(dirFd) }
        } finally {
            frame.fill(0)
            if (created != null && !renamed) runCatching {
                matches(parent)
                if (identity(regular(temporary)) == created) Os.remove(temporary.absolutePath)
            }
        }
    }
    private fun aad(name: String) = "syn443/local-journal/v1/$name".toByteArray(Charsets.US_ASCII)
}
