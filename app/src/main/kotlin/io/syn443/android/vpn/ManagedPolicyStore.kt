package io.syn443.android.vpn

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import io.syn443.policy.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.decodeFromJsonElement
import org.json.JSONObject
import java.net.URI

@Serializable data class PolicyBinding(val device: String, val keys: Map<String, String>, val url: String,
    val bearer: String, val serverTimeMs: Long)
@Serializable data class PolicyDisk(val binding: PolicyBinding? = null, val journal: Journal = Journal(),
    val anchorWall: Long = 0, val anchorElapsed: Long = 0, val anchorBoot: Int = -1,
    val applyDeadlineElapsed: Long = 0)

class ManagedPolicyStore private constructor(context: Context) {
    companion object {
        @Volatile private var instance: ManagedPolicyStore? = null
        @Synchronized fun get(context: Context): ManagedPolicyStore = instance ?: ManagedPolicyStore(context.applicationContext).also { instance = it }
    }
    private val file = SealedFile(context, "managed-policy.enc")
    private val resolver = context.contentResolver
    private var cached: PolicyDisk? = null
    private val verified = linkedMapOf<String, Verified>()
    private fun boot() = Settings.Global.getInt(resolver, Settings.Global.BOOT_COUNT, -1).also { require(it >= 0) }
    @Synchronized fun read(): PolicyDisk = cached ?: (file.read()?.let { Policy.json.decodeFromString<PolicyDisk>(it) } ?: PolicyDisk()).also { cached = it }
    @Synchronized private fun save(value: PolicyDisk) { file.write(Policy.json.encodeToString(value)); cached = value }
    fun managed() = read().binding != null
    @Synchronized fun resetEmulator() {
        require(io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        file.delete(); cached = null; verified.clear()
    }
    fun now(d: PolicyDisk = read()): Long {
        require(d.anchorBoot == boot() && d.anchorElapsed <= SystemClock.elapsedRealtime()) { "trusted_time_required" }
        return d.anchorWall + SystemClock.elapsedRealtime() - d.anchorElapsed
    }
    @Synchronized fun bind(raw: String) {
        require(io.syn443.android.BuildConfig.DEBUG && !managed())
        val b = Policy.json.decodeFromJsonElement<PolicyBinding>(Canonical.parse(raw))
        require(b.device.matches(Regex("[a-zA-Z0-9_-]{8,64}")) && b.keys.size in 1..4 && b.keys.keys.all { it.matches(Regex("[a-zA-Z0-9_-]{1,64}")) } && b.keys.values.all { it.length in 80..256 })
        require(b.bearer.length in 24..256 && b.bearer.all { it.code in 33..126 } && b.serverTimeMs > 0)
        val u = URI(b.url)
        require(u.userInfo == null && u.fragment == null && u.host != null &&
            (u.scheme == "https" || (io.syn443.android.BuildConfig.DEBUG && u.scheme == "http" && u.host == "127.0.0.1")))
        save(PolicyDisk(binding = b, anchorWall = b.serverTimeMs, anchorElapsed = SystemClock.elapsedRealtime(), anchorBoot = boot()))
    }
    @Synchronized fun verify(raw: String, d: PolicyDisk = read(), time: Long = now(d)): Verified {
        val v = verified[raw] ?: Policy.verify(raw, checkNotNull(d.binding).keys, d.binding.device, time).also {
            if (verified.size >= 4) verified.clear()
            verified[raw] = it
        }
        require(time >= v.payload.notBeforeMs && time < v.payload.offlineUntilMs)
        return v
    }
    fun allowed(raw: String?, d: PolicyDisk = read()): Verified? = raw?.let {
        verify(it, d).also { v -> require(v.payload.revision >= d.journal.floor && v.payload.securityEpoch >= d.journal.epoch) }
    }
    @Synchronized fun stage(raw: String, originalConfig: String?) {
        val d = read(); val v = verify(raw, d); EngineConfig.validate(v.engineConfig)
        if (raw == d.journal.active || raw == d.journal.candidate) return
        // Bootstrap first signs the current working configuration, never an unsigned fallback.
        if (d.journal.active == null) require(Policy.hash(checkNotNull(originalConfig)) == v.payload.contentHash)
        save(d.copy(journal = Policy.stage(d.journal, v)))
    }
    @Synchronized fun received(raw: String, serverTime: Long, originalConfig: String?) {
        require(serverTime > 0)
        val d = read(); require(serverTime + 999 >= d.anchorWall)
        val time = maxOf(serverTime, runCatching { now(d) }.getOrDefault(d.anchorWall))
        val v = verify(raw, d, time); EngineConfig.validate(v.engineConfig)
        // Only a response from the separately pinned HTTPS delivery channel may re-anchor after boot.
        val anchored = d.copy(anchorWall = time, anchorElapsed = SystemClock.elapsedRealtime(), anchorBoot = boot())
        if (raw == d.journal.active || raw == d.journal.candidate) { save(anchored); return }
        require(v.payload.revision > d.journal.maxRevision)
        if (d.journal.active == null) require(Policy.hash(checkNotNull(originalConfig)) == v.payload.contentHash)
        save(anchored.copy(journal = Policy.stage(d.journal, v)))
    }
    fun config(original: String?): String? {
        val d = read(); if (d.binding == null) return original
        val raw = when (d.journal.phase) {
            "applying" -> d.journal.candidate
            else -> d.journal.active ?: d.journal.candidate.takeIf { d.journal.phase == "prepared" }
        }
        return checkNotNull(allowed(raw, d)) { "no_authorized_policy" }.engineConfig
    }
    @Synchronized fun begin(baseline: List<Boolean>) {
        val d = read(); val v = checkNotNull(allowed(d.journal.candidate, d))
        save(d.copy(journal = Policy.begin(d.journal, baseline), applyDeadlineElapsed = SystemClock.elapsedRealtime() + v.payload.activation.timeoutSeconds * 1_000L))
    }
    @Synchronized fun finish(values: List<Boolean>, started: Boolean) {
        val d = read(); val v = checkNotNull(allowed(d.journal.candidate, d))
        save(d.copy(journal = Policy.finish(d.journal, v, values, started)))
    }
    @Synchronized fun rollback(reason: String) {
        val d = read(); if (d.journal.phase != "applying") return
        val revision = Policy.json.decodeFromString<Payload>(Policy.utf8(Policy.decode64(checkNotNull(d.journal.candidate).split('.')[1]))).revision
        save(d.copy(journal = Policy.rollback(d.journal, revision, reason)))
    }
    @Synchronized fun recover() {
        val d = read(); if (d.journal.phase == "applying") {
            // No need to trust the wall clock to poison an interrupted candidate.
            val revision = Policy.json.decodeFromString<Payload>(Policy.utf8(Policy.decode64(checkNotNull(d.journal.candidate).split('.')[1]))).revision
            save(d.copy(journal = Policy.rollback(d.journal, revision, "interrupted_activation")))
        }
    }
    fun status(): JSONObject = runCatching {
        val d = read(); val j = d.journal
        fun revision(raw: String?): Long? = raw?.let { Policy.json.decodeFromString<Payload>(Policy.utf8(Policy.decode64(it.split('.')[1]))).revision }
        JSONObject().put("managed", d.binding != null).put("phase", j.phase).put("reason", j.reason)
            .put("desiredRevision", revision(j.desired)).put("activeRevision", revision(j.active))
            .put("lastKnownGoodRevision", revision(j.lastGood)).put("candidateRevision", revision(j.candidate))
            .put("activationGeneration", j.activationGeneration).put("securityEpoch", j.epoch).put("revocationFloor", j.floor)
    }.getOrElse { JSONObject().put("managed", true).put("phase", "blocked").put("reason", "policy_store_unavailable") }
}
