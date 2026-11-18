package io.syn443.android.support

import android.content.Context
import android.os.Process
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import android.util.Base64
import io.syn443.android.BuildConfig
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** One passive collector and one admitted bounded read. No device identity keys,
 * network actions or source refreshes are performed by metadata operations. */
class SupportBundleController private constructor(
    private val directory: () -> File,
    private val executor: ExecutorService,
    private val clock: () -> Long,
    private val capture: () -> List<DiagnosticArchive.Component>,
    private val random: SecureRandom,
    private val io: (IoStage) -> Unit,
    private val test: Boolean,
) {
    internal enum class IoStage { BEFORE_CLEANUP, BEFORE_WRITE, BEFORE_RENAME, BEFORE_READ, AFTER_READ, AFTER_DECRYPT }
    private data class FileIdentity(val device: Long, val inode: Long, val bytes: Long)
    private data class Stored(val file: File, val directory: FileIdentity, val fileIdentity: FileIdentity)
    private class Ready(val stored: Stored, val bytes: Int, val sha256: String,
        val manifest: String, val key: ByteArray, val expires: Long)
    private class Job(val id: String, var state: String = "collecting", var ready: Ready? = null)
    private class Grant(val id: String, val job: Job, val ready: Ready, val expires: Long)
    private data class Read(val grant: Grant, val key: ByteArray, val offset: Int)

    private val lock = Any()
    private val readBusy = AtomicBoolean()
    private var running = false
    private var closed = false
    private var current: Job? = null
    private var grant: Grant? = null
    private var lastClock = -1L

    /** Collection is an explicit effect. A timeout/cancel never replaces its worker. */
    fun collect(): JSONObject {
        val job: Job
        synchronized(lock) {
            check(!closed)
            observeClock()
            if (running) return state("busy", checkNotNull(current).id)
            revokeCurrent("expired")
            job = Job(freshId(current?.id))
            current = job
            running = true
        }
        try {
            executor.execute { collect(job) }
        } catch (_: Exception) {
            synchronized(lock) {
                if (current === job) job.state = "failed"
                running = false // The executor never accepted an actual worker.
            }
            error("bundle_unavailable")
        }
        return synchronized(lock) {
            // This is the admission receipt; detailed terminal errors belong to
            // status(). A fast worker does not enlarge the collect envelope.
            state(if (current === job && job.state == "ready") "ready" else "collecting", job.id)
        }
    }

    fun status(id: String): JSONObject {
        identifier(id)
        return synchronized(lock) { observeClock(); statusLocked(id) }
    }

    fun cancel(id: String): JSONObject {
        identifier(id)
        return synchronized(lock) {
            observeClock()
            val job = current?.takeIf { it.id == id } ?: return@synchronized state("not_found", id)
            if (job.state in setOf("collecting", "ready")) revokeCurrent("cancelled")
            statusLocked(id)
        }
    }

    /** Pure RAM authorization. The encrypted file is authenticated by read(). */
    fun open(id: String): JSONObject {
        identifier(id)
        return synchronized(lock) {
            val now = observeClock()
            val job = current?.takeIf { it.id == id } ?: return@synchronized state("not_found", id)
            val ready = job.ready?.takeIf { job.state == "ready" }
                ?: return@synchronized statusLocked(id)
            val previous = grant?.id
            val opened = Grant(freshId(previous), job, ready, minOf(now + GRANT_MS, ready.expires))
            grant = opened
            JSONObject().put("state", "open").put("grant", opened.id).put("bytes", ready.bytes)
                .put("sha256", ready.sha256).put("expiresInMs", opened.expires - now)
                .put("manifest", JSONObject(ready.manifest))
        }
    }

    /** A regular-file read is byte-bounded, not a wall-clock I/O guarantee.
     * No state mutex is held during disk I/O or GCM. Only one actual read may
     * occupy this slot, including after its grant was cancelled or expired. */
    fun read(arg: String): JSONObject {
        require(arg.length <= 39)
        val match = READ.matchEntire(arg) ?: throw IllegalArgumentException()
        val offset = match.groupValues[2].toInt()
        require(offset <= MAX_ARCHIVE)
        check(android.os.Looper.myLooper() != android.os.Looper.getMainLooper())
        if (!readBusy.compareAndSet(false, true)) return JSONObject().put("state", "busy")
        var admitted: Read? = null
        var plain: ByteArray? = null
        try {
            val selected = synchronized(lock) {
                observeClock()
                val selected = grant?.takeIf { it.id == match.groupValues[1] }
                    ?: return JSONObject().put("state", "not_found")
                require(offset <= selected.ready.bytes)
                Read(selected, selected.ready.key.copyOf(), offset)
            }
            admitted = selected
            val verified = decrypt(selected.grant.ready.stored, selected.key)
            plain = verified
            require(verified.size == selected.grant.ready.bytes && hash(verified) == selected.grant.ready.sha256)
            io(IoStage.AFTER_DECRYPT)
            return synchronized(lock) {
                observeClock()
                if (!current(selected.grant)) return@synchronized unavailable(selected.grant)
                val size = minOf(CHUNK_BYTES, verified.size - selected.offset)
                val next = selected.offset + size
                // Create the plaintext-bearing string only after the final
                // current-job/current-grant/TTL fence, not before it.
                JSONObject().put("grant", selected.grant.id).put("offset", selected.offset)
                    .put("data", Base64.encodeToString(verified, selected.offset, size, Base64.NO_WRAP))
                    .put("nextOffset", next).put("done", next == verified.size)
            }
        } catch (_: Exception) {
            val selected = admitted
            return synchronized(lock) {
                if (selected != null) {
                    if (current === selected.grant.job && current?.ready === selected.grant.ready) revokeCurrent("failed")
                    unavailable(selected.grant)
                } else JSONObject().put("state", "not_found")
            }
        } finally {
            plain?.fill(0)
            admitted?.key?.fill(0)
            readBusy.set(false)
        }
    }

    private fun collect(job: Job) {
        var archive: ByteArray? = null
        var secret: ByteArray? = null
        var stored: Stored? = null
        var published = false
        try {
            val dir = directory()
            io(IoStage.BEFORE_CLEANUP)
            val identity = prepareDirectory(dir)
            cleanup(dir, identity)
            if (!admitted(job)) return
            // Only this worker invokes the compiled passive source provider.
            val result = DiagnosticArchive.create(capture())
            val bytes = result.bytes
            archive = bytes
            require(bytes.size in 1..MAX_ARCHIVE)
            val manifest = result.manifest.toString()
            require(manifest.toByteArray(Charsets.UTF_8).size <= MAX_MANIFEST)
            // Metadata, including its envelope, must fit the provider contract.
            require(manifest.toByteArray(Charsets.UTF_8).size <= MAX_MANIFEST - 512)
            if (!admitted(job)) return
            val key = ByteArray(32).also(random::nextBytes)
            secret = key
            val written = encrypt(dir, identity, job.id, bytes, key)
            stored = written
            val sha256 = hash(bytes)
            synchronized(lock) {
                val now = observeClock()
                if (current !== job || job.state != "collecting" || closed) return@synchronized
                job.ready = Ready(written, bytes.size, sha256, manifest, key.copyOf(), now + READY_MS)
                job.state = "ready"
                published = true
            }
        } catch (_: Exception) {
            synchronized(lock) { if (current === job && job.state == "collecting") job.state = "failed" }
        } finally {
            archive?.fill(0)
            secret?.fill(0)
            val abandoned = stored
            if (!published && abandoned != null) runCatching { remove(abandoned.file, abandoned.directory) }
            synchronized(lock) {
                if (current === job && job.state == "collecting") job.state = "failed"
                // Resource cleanup and all source work precede slot release.
                running = false
            }
        }
    }

    private fun admitted(job: Job) = synchronized(lock) {
        observeClock()
        current === job && job.state == "collecting" && !closed
    }

    private fun current(selected: Grant) = !closed && grant === selected && current === selected.job &&
        selected.job.state == "ready" && selected.job.ready === selected.ready

    private fun unavailable(selected: Grant): JSONObject {
        val value = if (current === selected.job && selected.job.state in TERMINAL) selected.job.state else "not_found"
        return JSONObject().put("state", value)
    }

    private fun observeClock(): Long {
        val now = try { clock() } catch (_: Exception) { -1L }
        if (now !in 0..MAX_CLOCK || (lastClock >= 0 && now < lastClock)) {
            revokeCurrent("expired")
            if (now in 0..MAX_CLOCK) lastClock = now
            return 0
        }
        lastClock = now
        val job = current
        if (job?.state == "ready" && now >= checkNotNull(job.ready).expires) revokeCurrent("expired")
        if (grant?.let { now >= it.expires } == true) grant = null
        return now
    }

    private fun revokeCurrent(state: String) {
        grant = null
        current?.let { job ->
            job.ready?.key?.fill(0)
            job.ready = null
            if (job.state == "collecting" || job.state == "ready") job.state = state
        }
    }

    private fun statusLocked(id: String): JSONObject {
        val job = current?.takeIf { it.id == id } ?: return state("not_found", id)
        val result = state(job.state, id)
        job.ready?.takeIf { job.state == "ready" }?.let {
            result.put("bytes", it.bytes).put("sha256", it.sha256).put("manifest", JSONObject(it.manifest))
        }
        return result
    }

    private fun freshId(previous: String?): String {
        repeat(8) {
            val bytes = ByteArray(16).also(random::nextBytes)
            val value = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
            bytes.fill(0)
            if (value != previous) return value
        }
        error("bundle_unavailable")
    }

    private fun prepareDirectory(dir: File): FileIdentity {
        try { Os.mkdir(dir.absolutePath, 448) } catch (error: ErrnoException) {
            if (error.errno != OsConstants.EEXIST) throw error
        }
        val stat = Os.lstat(dir.absolutePath)
        require(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == Process.myUid() && (stat.st_mode and 511) == 448)
        return identity(stat)
    }

    private fun directoryMatches(dir: File, expected: FileIdentity) {
        val stat = Os.lstat(dir.absolutePath)
        require(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == Process.myUid() && (stat.st_mode and 511) == 448)
        require(stat.st_dev == expected.device && stat.st_ino == expected.inode)
    }

    private fun regular(file: File): StructStat {
        require(OWNED.matches(file.name))
        return Os.lstat(file.absolutePath).also {
            require(OsConstants.S_ISREG(it.st_mode) && it.st_uid == Process.myUid() && (it.st_mode and 511) == 384)
        }
    }

    private fun cleanup(dir: File, expected: FileIdentity) {
        directoryMatches(dir, expected)
        val owned = mutableListOf<File>()
        Files.newDirectoryStream(dir.toPath()).use { entries ->
            for (path in entries) {
                require(owned.size < 2)
                val file = path.toFile()
                regular(file)
                owned += file
            }
        }
        require(owned.count { it.extension == "enc" } <= 1 && owned.count { it.extension == "tmp" } <= 1)
        directoryMatches(dir, expected)
        owned.forEach { remove(it, expected) }
    }

    private fun remove(file: File, expected: FileIdentity) {
        directoryMatches(checkNotNull(file.parentFile), expected)
        regular(file)
        Os.remove(file.absolutePath)
    }

    private fun encrypt(dir: File, directory: FileIdentity, id: String, bytes: ByteArray, key: ByteArray): Stored {
        val temp = File(dir, "$id.tmp")
        val ready = File(dir, "$id.enc")
        var created = false
        var renamed = false
        var frame: ByteArray? = null
        try {
            val nonce = ByteArray(12).also(random::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad(id))
            val encrypted = cipher.doFinal(bytes)
            val encoded = byteArrayOf(1) + nonce + encrypted
            frame = encoded
            encrypted.fill(0); nonce.fill(0)
            require(encoded.size <= MAX_CIPHER)
            io(IoStage.BEFORE_WRITE)
            directoryMatches(dir, directory)
            val fd = Os.open(temp.absolutePath, OsConstants.O_WRONLY or OsConstants.O_CREAT or
                OsConstants.O_EXCL or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC, 384)
            created = true
            val output = try { FileOutputStream(fd) } catch (error: Exception) {
                runCatching { Os.close(fd) }; throw error
            }
            output.use { it.write(encoded); it.fd.sync() }
            io(IoStage.BEFORE_RENAME)
            directoryMatches(dir, directory)
            require(!Files.exists(ready.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS))
            Os.rename(temp.absolutePath, ready.absolutePath)
            renamed = true
            val stat = regular(ready)
            require(stat.st_size == encoded.size.toLong())
            return Stored(ready, directory, identity(stat))
        } finally {
            frame?.fill(0)
            if (created && !renamed) runCatching { remove(temp, directory) }
        }
    }

    private fun decrypt(stored: Stored, key: ByteArray): ByteArray {
        io(IoStage.BEFORE_READ)
        directoryMatches(checkNotNull(stored.file.parentFile), stored.directory)
        val fd = Os.open(stored.file.absolutePath, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC, 0)
        var frame: ByteArray? = null
        try {
            val opened = try { FileInputStream(fd) } catch (error: Exception) {
                runCatching { Os.close(fd) }; throw error
            }
            opened.use { input ->
                val before = Os.fstat(fd)
                require(OsConstants.S_ISREG(before.st_mode) && before.st_uid == Process.myUid() && (before.st_mode and 511) == 384)
                require(identity(before) == stored.fileIdentity && before.st_size in 30L..MAX_CIPHER.toLong())
                frame = ByteArray(before.st_size.toInt())
                var size = 0
                while (size < frame!!.size) {
                    val n = input.read(frame!!, size, frame!!.size - size)
                    require(n > 0); size += n
                }
                require(input.read() == -1 && identity(Os.fstat(fd)) == stored.fileIdentity)
            }
            io(IoStage.AFTER_READ)
            val value = checkNotNull(frame)
            require(value[0] == 1.toByte())
            val nonce = value.copyOfRange(1, 13)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                cipher.updateAAD(aad(stored.file.nameWithoutExtension))
                val result = cipher.doFinal(value, 13, value.size - 13)
                if (result.size !in 1..MAX_ARCHIVE) {
                    result.fill(0)
                    throw IllegalArgumentException()
                }
                return result
            } finally { nonce.fill(0) }
        } finally { frame?.fill(0) }
    }

    internal fun busyForTest(): Boolean { check(test); return synchronized(lock) { running || readBusy.get() } }
    internal fun shutdownForTest() {
        check(test)
        synchronized(lock) { closed = true; revokeCurrent("cancelled") }
        executor.shutdownNow()
        check(executor.awaitTermination(15, TimeUnit.SECONDS))
        check(!readBusy.get())
    }

    companion object {
        private const val MAX_ARCHIVE = 524_288
        private const val MAX_CIPHER = 524_320
        private const val MAX_MANIFEST = 16_384
        private const val CHUNK_BYTES = 32_768
        private const val READY_MS = 900_000L
        private const val GRANT_MS = 60_000L
        private const val MAX_CLOCK = 9_007_199_254_740_991L - READY_MS
        private val ID = Regex("[a-f0-9]{32}")
        private val READ = Regex("([a-f0-9]{32}):(0|[1-9][0-9]{0,5})")
        private val OWNED = Regex("[a-f0-9]{32}\\.(enc|tmp)")
        @Volatile private var instance: SupportBundleController? = null

        @Synchronized fun get(context: Context): SupportBundleController = instance ?: run {
            val app = context.applicationContext
            check(android.app.Application.getProcessName() == app.packageName + ":controller")
            SupportBundleController({ File(app.noBackupFilesDir, "support-bundles") }, worker(),
                SystemClock::elapsedRealtime, { SupportBundleSources.capture(app) }, SecureRandom(), {}, false)
                .also { instance = it }
        }

        internal fun isolatedForTest(context: Context, namespace: String, clock: () -> Long,
            capture: () -> List<DiagnosticArchive.Component>, executor: ExecutorService = worker(),
            random: SecureRandom = SecureRandom(), io: (IoStage) -> Unit = {}): SupportBundleController {
            check(BuildConfig.DEBUG && namespace.matches(Regex("test-[a-f0-9]{32}")))
            return SupportBundleController({ File(context.noBackupFilesDir, "support-bundles-$namespace") },
                executor, clock, capture, random, io, true)
        }

        private fun worker(): ExecutorService = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(1), { task -> Thread(task, "syn443-support-bundle").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy())
        private fun identifier(value: String) { require(ID.matches(value)) }
        private fun state(value: String, id: String) = JSONObject().put("state", value).put("id", id)
        private fun hash(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        private fun identity(value: StructStat) = FileIdentity(value.st_dev, value.st_ino, value.st_size)
        private fun aad(id: String) = ("syn443/support-bundle/v1/" + id).toByteArray(Charsets.US_ASCII)
        private val TERMINAL = setOf("failed", "cancelled", "expired")
    }
}
