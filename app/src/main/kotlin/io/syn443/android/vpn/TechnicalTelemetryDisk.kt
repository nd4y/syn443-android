package io.syn443.android.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.syn443.identity.TechnicalTelemetry
import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Accessed by the identity worker, never the VPN packet or controller loop. */
internal class TechnicalTelemetryDisk(context:Context,private val namespace:String="telemetry-queue-v1") {
    init {require(namespace.matches(Regex("[a-z0-9-]{8,64}")))}
    private val file=AtomicFile(File(context.noBackupFilesDir,"$namespace.bin"))
    private val alias="syn443-$namespace"
    private fun store()=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
    private fun key(create:Boolean):SecretKey {
        (store().getKey(alias,null) as? SecretKey)?.let {return it}
        require(create)
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build())
        }.generateKey()
    }
    private fun aad()="syn443/technical-telemetry/$namespace".toByteArray(Charsets.US_ASCII)
    private fun empty(scope:String)=TechnicalTelemetry.Snapshot(1,scope,emptyList()).also {it.validate()}
    private fun load():TechnicalTelemetry.Snapshot? {
        val raw=try {file.openRead().use {input->
            val bounded=ByteArray(65_537)
            try {
                var size=0
                while(size<bounded.size) {
                    val n=input.read(bounded,size,bounded.size-size)
                    if(n<0)break
                    require(n>0);size+=n
                }
                require(size<=65_536)
                bounded.copyOf(size)
            }finally {bounded.fill(0)}
        }}
            catch(_:FileNotFoundException){return null}
        require(raw.size in 30..65_536 && raw[0]==1.toByte())
        val plaintext=try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE,key(false),GCMParameterSpec(128,raw,1,12))
                updateAAD(aad());doFinal(raw,13,raw.size-13)
            }
        }finally {raw.fill(0)}
        return try {Canonical.json.decodeFromString<TechnicalTelemetry.Snapshot>(plaintext.decodeToString()).also {it.validate()}}
        finally {plaintext.fill(0)}
    }
    @Synchronized fun read(scope:String):TechnicalTelemetry.Snapshot =
        load()?.takeIf {it.scope==scope} ?: empty(scope)
    @Synchronized fun write(scope:String,snapshot:TechnicalTelemetry.Snapshot) {
        require(snapshot.scope==scope);snapshot.validate()
        val plain=Canonical.json.encodeToString(snapshot).toByteArray(Charsets.UTF_8)
        val frame=try {
            require(plain.size<=65_507)
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE,key(true));require(iv.size==12);updateAAD(aad())
                byteArrayOf(1)+iv+doFinal(plain)
            }
        }finally {plain.fill(0)}
        try {
            val output=file.startWrite()
            try {output.write(frame);file.finishWrite(output)}
            catch(error:Throwable){file.failWrite(output);throw error}
            require(load()==snapshot)
        }finally {frame.fill(0)}
    }
    @Synchronized fun erase() {
        file.delete()
        store().deleteEntry(alias)
    }
}
