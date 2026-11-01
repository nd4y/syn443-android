package io.syn443.android.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Same Keystore protection as the existing engine config; no plaintext journal. */
class SealedFile(context: Context, name: String) {
    private val file = AtomicFile(File(context.noBackupFilesDir, name))
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey("syn443-policy-v1", null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("syn443-policy-v1", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    fun read(): String? {
        if (!file.baseFile.exists()) return null
        val data = file.openRead().use { require(it.available() <= 2_097_152); it.readBytes() }
        require(data.size in 29..2_097_152 && data[0].toInt() == 12)
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, data.copyOfRange(1, 13)))
            doFinal(data.copyOfRange(13, data.size)).toString(Charsets.UTF_8)
        }
    }
    fun write(text: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val data = byteArrayOf(12) + cipher.iv + cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        require(data.size <= 2_097_152)
        val output = file.startWrite()
        try { output.write(data); file.finishWrite(output) } catch (e: Exception) { file.failWrite(output); throw e }
    }
    fun delete() { file.delete() }
}
