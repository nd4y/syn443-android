package io.syn443.android.vpn

import android.content.Context
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.syn443.identity.RuntimeObservation
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Identity-worker-only, at most one small encrypted report. Never Android backup. */
internal class RuntimeObservationDisk(context:Context,private val namespace:String="runtime-observation-v1") {
    init {require(namespace.matches(Regex("[a-z0-9-]{8,64}")))}
    private val file=AtomicFile(File(context.noBackupFilesDir,"$namespace.bin"))
    private val alias="syn443-$namespace"
    private fun worker(){check(Looper.myLooper()!=Looper.getMainLooper())}
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
    private fun aad()="syn443/runtime-observation/$namespace".toByteArray(Charsets.US_ASCII)
    private fun load():RuntimeObservation.Snapshot? {
        val frame=try {file.openRead().use {input->
            val size=input.channel.size();require(size in 30..4096)
            ByteArray(size.toInt()).also {raw->
                try {var read=0;while(read<raw.size){val n=input.read(raw,read,raw.size-read);require(n>0);read+=n};require(input.read()==-1)}
                catch(e:Throwable){raw.fill(0);throw e}
            }
        }}catch(_:FileNotFoundException){return null}
        val plain=try {
            require(frame[0]==1.toByte())
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE,key(false),GCMParameterSpec(128,frame,1,12));updateAAD(aad())
                doFinal(frame,13,frame.size-13)
            }
        }finally {frame.fill(0)}
        return try {Canonical.json.decodeFromString<RuntimeObservation.Snapshot>(Policy.utf8(plain)).also {it.validate()}}
        finally {plain.fill(0)}
    }
    @Synchronized fun read(scope:String):RuntimeObservation.Snapshot {
        worker();return load()?.takeIf {it.scope==scope} ?: RuntimeObservation.empty(scope)
    }
    @Synchronized fun write(scope:String,snapshot:RuntimeObservation.Snapshot) {
        worker();require(snapshot.scope==scope);snapshot.validate()
        val plain=Canonical.json.encodeToString(snapshot).toByteArray(Charsets.UTF_8)
        val frame=try {
            require(plain.size<=4067)
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE,key(true));require(iv.size==12);updateAAD(aad());byteArrayOf(1)+iv+doFinal(plain)
            }
        }finally {plain.fill(0)}
        try {
            val output=file.startWrite()
            try {output.write(frame);file.finishWrite(output)}catch(e:Throwable){file.failWrite(output);throw e}
            require(load()==snapshot)
        }finally {frame.fill(0)}
    }
    @Synchronized fun erase(){worker();file.delete();store().deleteEntry(alias)}
    @Synchronized fun clearPending(){worker();load()?.let {write(it.scope,it.discard(it.scope))}}
}
