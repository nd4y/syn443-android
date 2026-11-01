package io.syn443.android.vpn

import android.content.Context
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.syn443.identity.*
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@Serializable private data class TrustRecord(val revision:Long=0,val anchor:TrustAnchor,
    val floors:Map<String,ServiceFloor> = emptyMap(),val timeFloor:Long=0)

/** Controller worker only. Corruption is a blocked state, never a fresh install.
 * The installation asset is public and cannot be replaced by an incoming URI.
 * Root/floor state survives logout and is excluded from Android backup. */
class BootstrapTrustStore(private val context:Context,private val namespace:String="installation-trust-v1",
    private val testAnchor:TrustAnchor?=null) {
    private val file:AtomicFile
    init {
        require(namespace.matches(Regex("[a-z0-9-]{1,48}")))
        if(testAnchor!=null)require(io.syn443.android.BuildConfig.DEBUG && namespace.startsWith("test-") && android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        file=AtomicFile(File(context.noBackupFilesDir,"$namespace.bin"))
    }
    companion object {private val lock=Any();private const val alias="syn443-bootstrap-trust-v1"}
    private fun worker(){check(Looper.myLooper()!=Looper.getMainLooper() && !Thread.currentThread().name.startsWith("Binder:"))}
    private fun aad()="SYN443-BOOTSTRAP-TRUST-1\n$namespace".toByteArray(Charsets.US_ASCII)
    private fun key(create:Boolean):SecretKey {
        val store=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        (store.getKey(alias,null) as? SecretKey)?.let {return it};check(create)
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false).build())
        }.generateKey()
    }
    private fun bounded(input:java.io.InputStream,limit:Int):ByteArray=input.use {
        val bytes=ByteArray(limit+1);var count=0
        while(count<bytes.size){val n=it.read(bytes,count,bytes.size-count);if(n<0)break;check(n>0);count+=n}
        require(count<=limit);bytes.copyOf(count).also {bytes.fill(0)}
    }
    private fun installed()=testAnchor?:Canonical.json.decodeFromString<TrustAnchor>(Policy.utf8(bounded(context.assets.open("installation-trust.json"),4096)))
    private fun validate(record:TrustRecord,installation:TrustAnchor) {
        BootstrapTrust.validateAnchor(installation);BootstrapTrust.validateAnchor(record.anchor)
        require(record.revision in 0..9_007_199_254_740_991L && record.anchor.epoch>=installation.epoch && record.timeFloor>=0 && record.floors.size<=32)
        if(record.anchor.epoch==installation.epoch)require(record.anchor==installation)
        record.floors.forEach {(id,floor)->require(id==floor.serviceId && id.matches(Regex("[A-Za-z0-9_-]{1,64}")) &&
            floor.revision in 1..9_007_199_254_740_991L && floor.hash.matches(Regex("[A-Za-z0-9_-]{43}")))}
    }
    private fun read():TrustRecord {
        val installation=installed().also(BootstrapTrust::validateAnchor)
        if(!file.baseFile.exists() && !File(file.baseFile.path+".bak").exists() && !File(file.baseFile.path+".new").exists())return TrustRecord(anchor=installation)
        val bytes=bounded(file.openRead(),65_536);require(bytes.size>=30 && bytes[0]==1.toByte())
        val plain=try {Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE,key(false),GCMParameterSpec(128,bytes.copyOfRange(1,13)));updateAAD(aad());doFinal(bytes.copyOfRange(13,bytes.size))
        }}finally {bytes.fill(0)}
        return try {Canonical.json.decodeFromString<TrustRecord>(Policy.utf8(plain)).also {validate(it,installation)}}finally{plain.fill(0)}
    }
    private fun write(record:TrustRecord) {
        validate(record,installed());val plain=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(record))).toByteArray(Charsets.UTF_8)
        require(plain.size<=65_000)
        val data=try {Cipher.getInstance("AES/GCM/NoPadding").run {init(Cipher.ENCRYPT_MODE,key(true));updateAAD(aad());byteArrayOf(1)+iv+doFinal(plain)}}finally{plain.fill(0)}
        val output=file.startWrite()
        try {output.write(data);file.finishWrite(output)}catch(e:Exception){file.failWrite(output);throw e}finally{data.fill(0)}
        require(read()==record)
    }
    fun preview(raw:String):AuthenticatedInvite {worker();return synchronized(lock){
        val state=read();val link=BootstrapTrust.parse(raw)
        BootstrapTrust.authenticate(raw,state.anchor,state.floors[link.serviceId]?:ServiceFloor(),maxOf(System.currentTimeMillis()/1000,state.timeFloor))
    }}
    fun accept(raw:String):AuthenticatedInvite {worker();return synchronized(lock){
        val state=read();val link=BootstrapTrust.parse(raw)
        val verified=BootstrapTrust.authenticate(raw,state.anchor,state.floors[link.serviceId]?:ServiceFloor(),maxOf(System.currentTimeMillis()/1000,state.timeFloor))
        require(verified.floor.serviceId in state.floors || state.floors.size<32)
        val next=state.copy(revision=Math.addExact(state.revision,1),floors=state.floors+(verified.floor.serviceId to verified.floor),timeFloor=maxOf(state.timeFloor,verified.descriptor.issuedAt))
        write(next);verified
    }}
    fun rotate(raw:String) {worker();require(raw.toByteArray(Charsets.UTF_8).size<=16_384);synchronized(lock){
        val state=read();val rotation=Canonical.json.decodeFromString<RootRotation>(Canonical.encode(Identity.objectJSON(raw)))
        val next=BootstrapTrust.advance(rotation,state.anchor,maxOf(System.currentTimeMillis()/1000,state.timeFloor))
        if(next!=state.anchor)write(state.copy(revision=Math.addExact(state.revision,1),anchor=next))
    }}
}
