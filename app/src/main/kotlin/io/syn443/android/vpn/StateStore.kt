package io.syn443.android.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.syn443.recovery.Checkpoint
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** All entry points execute in :controller. AtomicFile is never written by the UI/native host. */
class StateStore private constructor(context: Context) {
    companion object {
        @Volatile private var instance: StateStore? = null
        @Synchronized fun get(context: Context): StateStore = instance ?: StateStore(context.applicationContext).also { instance = it }
    }
    private val directory = context.noBackupFilesDir
    private val policyStore = RuntimePolicies(context)
    private val state = AtomicFile(File(directory, "vpn-intent.json"))
    private val config = AtomicFile(File(directory, "vpn-config.enc"))
    @Synchronized fun read(): JSONObject = if (!state.baseFile.exists()) JSONObject().put("desiredOn", false).put("generation", 0) else
        JSONObject(state.openRead().bufferedReader().use { it.readText() })
    @Synchronized fun update(block: (JSONObject) -> Unit): JSONObject {
        val value = read(); block(value)
        val output = state.startWrite()
        try { output.write(value.toString().toByteArray()); state.finishWrite(output) }
        catch (e: Exception) { state.failWrite(output); throw e }
        return value
    }
    @Synchronized fun adjustCheckpoint(block: (Checkpoint) -> Checkpoint): Checkpoint {
        val before = checkpoint()
        val after = block(before)
        if (after != before) update { put(it, after) }
        return after
    }
    @Synchronized fun updateCurrent(generation: Long, block: (JSONObject) -> Unit): Boolean {
        if (!io.syn443.recovery.Recovery.current(checkpoint(), generation)) return false
        update(block)
        return true
    }
    @Synchronized fun effectCurrent(generation: Long, block: () -> Unit): Boolean {
        if (!io.syn443.recovery.Recovery.current(checkpoint(), generation)) return false
        block()
        return true
    }
    @Synchronized fun <T> serialized(block: () -> T): T = block()
    fun checkpoint(value: JSONObject = read()) = Checkpoint(
        value.optBoolean("desiredOn"), value.optLong("generation"), value.optInt("attempt"),
        value.optLong("nextWallMs"), value.optLong("lastEarlyWallMs"),
        value.optJSONArray("heavyWallMs")?.let { a -> (0 until a.length()).map { a.getLong(it) } } ?: emptyList(),
    )
    fun put(value: JSONObject, cp: Checkpoint) {
        value.put("desiredOn", cp.desiredOn).put("generation", cp.generation).put("attempt", cp.attempt)
            .put("nextWallMs", cp.nextWallMs).put("lastEarlyWallMs", cp.lastEarlyWallMs).put("heavyWallMs", JSONArray(cp.heavyWallMs))
    }
    @Synchronized fun event(phase: String, code: String, epoch: Long, generation: Long? = null): Boolean {
        if (generation != null) {
            val cp = checkpoint()
            if (cp.generation != generation) return false
            if ((phase == "Off" && cp.desiredOn) || (phase != "Off" && !cp.desiredOn)) return false
        }
        update { value ->
            value.put("phase", phase).put("reason", code).put("networkEpoch", epoch)
            val events = value.optJSONArray("events") ?: JSONArray()
            events.put(JSONObject().put("at", System.currentTimeMillis()).put("phase", phase).put("code", code)
                .put("intentGeneration", value.optLong("generation")).put("networkEpoch", epoch))
            while (events.length() > 64) events.remove(0)
            value.put("events", events)
        }
        return true
    }
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey("syn443-config-v1", null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("syn443-config-v1", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    @Synchronized fun importConfig(raw: String) {
        require(!policyStore.managed()) { "managed_policy_locked" }
        require(!checkpoint().desiredOn) { "stop before importing" }
        require(raw.toByteArray().size <= 262_144) { "configuration too large" }
        EngineConfig.validate(raw)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val ciphertext = cipher.doFinal(raw.toByteArray())
        val output = config.startWrite()
        try { output.write(cipher.iv.size); output.write(cipher.iv); output.write(ciphertext); config.finishWrite(output) }
        catch (e: Exception) { config.failWrite(output); throw e }
        update { it.put("configRevision", revision(raw)) }
    }
    @Synchronized fun originalConfig(): String? {
        if (!config.baseFile.exists()) return null
        val bytes = config.openRead().use { it.readBytes() }
        require(bytes.size >= 30) { "stored configuration is truncated" }
        val size = bytes[0].toInt() and 255
        require(size == 12 && bytes.size > size + 17)
        val raw = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(1, size + 1)))
        }.doFinal(bytes.copyOfRange(size + 1, bytes.size)).toString(Charsets.UTF_8)
        val digest = revision(raw)
        if (!policyStore.managed() && read().optString("configRevision") != digest) update { it.put("configRevision", digest) }
        return raw
    }
    @Synchronized fun config(): String? = policyStore.config(::originalConfig).also { raw ->
        if (raw != null && read().optString("configRevision") != revision(raw)) update { it.put("configRevision", revision(raw)) }
    }
    private fun revision(raw: String) = java.security.MessageDigest.getInstance("SHA-256")
        .digest(raw.toByteArray()).joinToString("") { "%02x".format(it) }
}
