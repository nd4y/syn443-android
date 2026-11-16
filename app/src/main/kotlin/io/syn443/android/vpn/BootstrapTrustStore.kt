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
    val floors:Map<String,ServiceFloor> = emptyMap(),val timeFloor:Long=0,val installationHash:String="")
@Serializable private data class RetainedAdminDescriptor(val floor:ServiceFloor,val manifest:String) {
    override fun toString()="RetainedAdminDescriptor([redacted])"
}

/** Controller worker only. Corruption is a blocked state, never a fresh install.
 * The installation asset is public and cannot be replaced by an incoming URI.
 * Root/floor state survives logout and is excluded from Android backup. */
class BootstrapTrustStore(private val context:Context,private val namespace:String="installation-trust-v1",
    private val testAnchor:TrustAnchor?=null,private val testProfile:InstallationProfile?=null,
    private val testAdminNow:(()->Long)?=null) {
    private val file:AtomicFile
    init {
        require(namespace.matches(Regex("[a-z0-9-]{1,48}")))
        if(testAnchor!=null || testProfile!=null)require((testAnchor==null || testProfile==null) &&
            io.syn443.android.BuildConfig.DEBUG && namespace.startsWith("test-") && android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        // Only the existing synthetic emulator trust fixture may override this
        // metadata lookup clock. Device admission and VPN lease clocks stay real.
        if(testAdminNow!=null)require(testAnchor!=null || testProfile!=null)
        file=AtomicFile(File(context.noBackupFilesDir,"$namespace.bin"))
    }
    companion object {
        private val lock=Any()
        private const val alias="syn443-bootstrap-trust-v1"
        private const val adminCacheLimit=8192
    }
    private val installationProfile by lazy {
        testProfile?:io.syn443.android.BuildConfig.INSTALLATION_PROFILE.takeIf {testAnchor==null && it.isNotEmpty()}
            ?.let(BootstrapTrust::installationProfile)
    }
    private fun worker(){check(Looper.myLooper()!=Looper.getMainLooper() && !Thread.currentThread().name.startsWith("Binder:"))}
    private fun aad()="SYN443-BOOTSTRAP-TRUST-1\n$namespace".toByteArray(Charsets.US_ASCII)
    private fun adminFile(service:String):AtomicFile {
        require(service.matches(Regex("[A-Za-z0-9_-]{1,64}")))
        val id=Identity.hash(service.toByteArray(Charsets.US_ASCII))
        return AtomicFile(File(context.noBackupFilesDir,"$namespace-admin-$id.bin"))
    }
    private fun adminAAD(service:String)="SYN443-ADMIN-DESCRIPTOR-1\n$namespace\n$service".toByteArray(Charsets.US_ASCII)
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
    private fun installed()=testAnchor?:installationProfile?.anchor?:
        Canonical.json.decodeFromString<TrustAnchor>(Policy.utf8(bounded(context.assets.open("installation-trust.json"),4096)))
    private fun installationHash(anchor:TrustAnchor)=Identity.hash(
        Canonical.encode(Canonical.parse(Canonical.json.encodeToString(anchor))).toByteArray(Charsets.UTF_8))
    private fun validate(record:TrustRecord,installation:TrustAnchor) {
        BootstrapTrust.validateAnchor(installation);BootstrapTrust.validateAnchor(record.anchor)
        require(record.revision in 0..9_007_199_254_740_991L && record.anchor.epoch>=installation.epoch && record.timeFloor>=0 && record.floors.size<=32)
        if(record.anchor.epoch==installation.epoch)require(record.anchor.copy(lastTransition="")==installation)
        if(record.installationHash.isNotEmpty())require(record.installationHash==installationHash(installation))
        else if(installationProfile!=null)require(record.anchor==installation)
        record.floors.forEach {(id,floor)->require(id==floor.serviceId && id.matches(Regex("[A-Za-z0-9_-]{1,64}")) &&
            floor.revision in 1..9_007_199_254_740_991L && floor.hash.matches(Regex("[A-Za-z0-9_-]{43}")))}
    }
    private fun read():TrustRecord {
        val installation=installed().also(BootstrapTrust::validateAnchor)
        val record=readRecord()?:return TrustRecord(anchor=installation)
        val profile=installationProfile
        val upgrade=profile?.upgrade
        if(upgrade==null || record.installationHash==installationHash(installation)) {
            validate(record,installation)
            return record
        }
        validate(record,upgrade.previousAnchor)
        val now=maxOf(System.currentTimeMillis()/1000,record.timeFloor)
        val next=BootstrapTrust.advance(upgrade.rotation,record.anchor,now)
        require(next.copy(lastTransition="")==installation)
        val (descriptor,floor)=defaultDescriptor(checkNotNull(profile).service,record.copy(anchor=next),now)
        val committed=write(record.copy(revision=Math.addExact(record.revision,1),anchor=next,
            floors=record.floors+(floor.serviceId to floor),timeFloor=maxOf(record.timeFloor,descriptor.issuedAt)))
        retainAdminDescriptor(profile.service,descriptor,floor)
        return committed
    }
    private fun readRecord():TrustRecord? {
        if(!file.baseFile.exists() && !File(file.baseFile.path+".bak").exists() && !File(file.baseFile.path+".new").exists())return null
        val bytes=bounded(file.openRead(),65_536);require(bytes.size>=30 && bytes[0]==1.toByte())
        val plain=try {Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE,key(false),GCMParameterSpec(128,bytes.copyOfRange(1,13)));updateAAD(aad());doFinal(bytes.copyOfRange(13,bytes.size))
        }}finally {bytes.fill(0)}
        return try {Canonical.json.decodeFromString<TrustRecord>(Policy.utf8(plain))}finally{plain.fill(0)}
    }
    private fun write(record:TrustRecord):TrustRecord {
        val installation=installed()
        val bound=record.copy(installationHash=installationHash(installation))
        validate(bound,installation)
        val plain=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(bound))).toByteArray(Charsets.UTF_8)
        require(plain.size<=65_000)
        val data=try {Cipher.getInstance("AES/GCM/NoPadding").run {init(Cipher.ENCRYPT_MODE,key(true));updateAAD(aad());byteArrayOf(1)+iv+doFinal(plain)}}finally{plain.fill(0)}
        val output=file.startWrite()
        try {output.write(data);file.finishWrite(output)}catch(e:Exception){file.failWrite(output);throw e}finally{data.fill(0)}
        require(readRecord()==bound)
        return bound
    }
    /** The committed floor is authoritative. This optional cache is written
     * afterwards, so an interrupted/missing write can only remove admin metadata
     * availability. It cannot change a valid device bootstrap or its journal. */
    private fun retainAdminDescriptor(raw:String,descriptor:ServiceDescriptor,floor:ServiceFloor) {
        try {
            require(floor.serviceId==descriptor.serviceId && raw.length in 1..BootstrapTrust.MAX_MANIFEST)
            val target=adminFile(descriptor.serviceId)
            if(descriptor.adminBootstrap==null) {target.delete();return}
            val plain=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(RetainedAdminDescriptor(floor,raw))))
                .toByteArray(Charsets.UTF_8)
            val data=try {
                require(plain.size<=adminCacheLimit-29)
                Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.ENCRYPT_MODE,key(false));updateAAD(adminAAD(descriptor.serviceId));byteArrayOf(1)+iv+doFinal(plain)
                }
            }finally {plain.fill(0)}
            try {
                val output=target.startWrite()
                try {output.write(data);target.finishWrite(output)}catch(e:Exception){target.failWrite(output);throw e}
            }finally {data.fill(0)}
        }catch(_:Exception) {
            // The next reader requires the exact current committed floor and
            // full signed projection. An old/partial cache is never a fallback.
        }
    }
    private fun readAdminDescriptor(service:String):RetainedAdminDescriptor? {
        val file=adminFile(service)
        if(!file.baseFile.exists() && !File(file.baseFile.path+".bak").exists() && !File(file.baseFile.path+".new").exists())return null
        val bytes=bounded(file.openRead(),adminCacheLimit)
        val plain=try {
            require(bytes.size>=30 && bytes[0]==1.toByte())
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE,key(false),GCMParameterSpec(128,bytes.copyOfRange(1,13)));updateAAD(adminAAD(service))
                doFinal(bytes.copyOfRange(13,bytes.size))
            }
        }finally {bytes.fill(0)}
        return try {Canonical.json.decodeFromString<RetainedAdminDescriptor>(Policy.utf8(plain))}finally {plain.fill(0)}
    }
    private fun deviceBootstrap(descriptor:ServiceDescriptor)=
        Bootstrap(descriptor.serviceId,descriptor.issuer,descriptor.clientId,descriptor.apiOrigin,
            descriptor.roots.toMap(),controlPanelOrigin=descriptor.controlPanelOrigin).also {it.validate()}

    /** Worker-only ticket from one locked root/floor/cache snapshot. This
     * authenticates discovery, not an administrative grant or session. */
    internal fun adminDiscovery(expected:Bootstrap):AdminDiscovery? {
        worker()
        return synchronized(lock) {try {
            expected.validate()
            val state=adminStateWithoutUpgrade()
            val current=state.floors[expected.serviceId] ?: return@synchronized null
            val retained=readAdminDescriptor(expected.serviceId) ?: return@synchronized null
            require(retained.floor==current && retained.manifest.length in 1..BootstrapTrust.MAX_MANIFEST)
            val now=maxOf(testAdminNow?.invoke() ?: (System.currentTimeMillis()/1000),state.timeFloor)
            BootstrapTrust.adminDiscovery(retained.manifest,state.anchor,current,expected,now)
        }catch(_:Exception){null}}
    }
    /** Compatibility projection only. Device Bootstrap and its authority are unchanged. */
    internal fun adminBootstrap(expected:Bootstrap):AdminBootstrap?=adminDiscovery(expected)?.metadata

    /** Administrative lookup and refresh cannot drive an installation upgrade.
     * A pending upgrade must first pass the existing ordinary trust flow. */
    private fun adminStateWithoutUpgrade():TrustRecord {
        val installation=installed().also(BootstrapTrust::validateAnchor)
        return (readRecord()?:TrustRecord(anchor=installation)).also {validate(it,installation)}
    }
    /** Signed metadata-only publication. Reject every ordinary projection
     * difference before committing a floor, advancing time or touching cache. */
    internal fun refreshAdminDescriptor(raw:String,expected:Bootstrap):Boolean {
        worker()
        val owned=expected.copy(roots=expected.roots.toMap()).also {it.validate()}
        return synchronized(lock) {
            val state=adminStateWithoutUpgrade()
            val now=maxOf(System.currentTimeMillis()/1000,state.timeFloor)
            val (descriptor,floor)=defaultDescriptor(raw,state,now)
            require(deviceBootstrap(descriptor)==owned)
            val timeFloor=maxOf(state.timeFloor,descriptor.issuedAt)
            if(floor!=state.floors[floor.serviceId] || timeFloor!=state.timeFloor)
                write(state.copy(revision=Math.addExact(state.revision,1),
                    floors=state.floors+(floor.serviceId to floor),timeFloor=timeFloor))
            retainAdminDescriptor(raw,descriptor,floor)
            true
        }
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
        write(next);retainAdminDescriptor(link.manifest,verified.descriptor,verified.floor);verified
    }}

    fun defaultBootstrap():Bootstrap = acceptDefaultDescriptor(checkNotNull(installationProfile).service)

    /** Worker-only semantic root identity. Store revision, descriptor floors
     * and trusted-time refreshes are deliberately not part of this stamp.
     * Missing persisted trust is not evidence of stable root continuity. */
    internal fun adaptiveAuthorityFingerprint():String? {
        worker()
        return synchronized(lock) {
            if(!file.baseFile.exists() && !File(file.baseFile.path+".bak").exists() && !File(file.baseFile.path+".new").exists())return@synchronized null
            val state=read()
            val anchor=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(state.anchor)))
            Policy.hash("syn443/adaptive-bootstrap-authority/v1\n"+anchor+"\n"+installationHash(installed()))
        }
    }

    private fun defaultDescriptor(raw:String,state:TrustRecord,now:Long):Pair<ServiceDescriptor,ServiceFloor> {
        val (descriptor,floor)=BootstrapTrust.descriptor(raw,state.anchor,ServiceFloor(),now)
        installationProfile?.upgrade?.previousAnchor?.let {require(it.spki !in descriptor.roots.values)}
        val previous=state.floors[floor.serviceId]
        require(if(previous==null) state.floors.size<32 else floor==previous || floor.revision>previous.revision)
        return descriptor to floor
    }

    internal fun acceptDefaultDescriptor(raw:String):Bootstrap {
        worker()
        return synchronized(lock) {
            val state=read()
            val now=maxOf(System.currentTimeMillis()/1000,state.timeFloor)
            val (descriptor,floor)=defaultDescriptor(raw,state,now)
            val bootstrap=deviceBootstrap(descriptor)
            if(floor!=state.floors[floor.serviceId])write(state.copy(revision=Math.addExact(state.revision,1),
                floors=state.floors+(floor.serviceId to floor),timeFloor=maxOf(state.timeFloor,descriptor.issuedAt)))
            retainAdminDescriptor(raw,descriptor,floor)
            bootstrap
        }
    }
    fun rotate(raw:String) {worker();require(raw.toByteArray(Charsets.UTF_8).size<=16_384);synchronized(lock){
        val state=read();val rotation=Canonical.json.decodeFromString<RootRotation>(Canonical.encode(Identity.objectJSON(raw)))
        val next=BootstrapTrust.advance(rotation,state.anchor,maxOf(System.currentTimeMillis()/1000,state.timeFloor))
        if(next!=state.anchor)write(state.copy(revision=Math.addExact(state.revision,1),anchor=next))
    }}
}
