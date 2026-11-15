package io.syn443.android.vpn

import android.content.Context
import android.os.Looper
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.BasicFileAttributes

/** SDK directories only; the setup-credential vault has a separate lifetime.
 * Neither imported paths nor directory contents can select a namespace. The
 * caller supplies its authenticated derivation and durable retirement fence. */
internal class ManagedOverlayStorage(private val context:Context,area:String="") {
    private val root:File
    init {
        require(area.isEmpty() || io.syn443.android.BuildConfig.DEBUG && area.matches(Regex("test-[a-z0-9-]{1,40}")))
        val base=if(area.isEmpty())context.noBackupFilesDir else File(context.noBackupFilesDir,area)
        root=File(base.canonicalFile,"managed-netbird")
    }
    fun directory(namespace:String):File {
        require(namespace.startsWith("managed-netbird/"))
        val digest=namespace.removePrefix("managed-netbird/")
        require(digest.length==43 && Policy.decode64(digest).size==32)
        return File(root,digest)
    }
    private fun worker() {
        if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
            throw LoginStorageException(LoginStorageFailure.WRONG_THREAD)
    }
    private fun attributes(file:File)=Files.readAttributes(file.toPath(),BasicFileAttributes::class.java,LinkOption.NOFOLLOW_LINKS)
    private fun exists(file:File)=Files.exists(file.toPath(),LinkOption.NOFOLLOW_LINKS)
    private fun ownedManifest(file:File,namespace:String,evidence:String?) {
        val bytes=file.inputStream().use{it.readBytesBounded(1024)}
        val o=Canonical.parse(Policy.utf8(bytes)).jsonObject
        require(o.keys==setOf("schemaVersion","namespace","initialized","identityEvidence"))
        fun text(k:String)=o.getValue(k).jsonPrimitive.let{require(it.isString);it.content}
        val version=o.getValue("schemaVersion").jsonPrimitive
        require(!version.isString && version.long==1L && text("namespace")==namespace)
        val initialized=o.getValue("initialized").jsonPrimitive.let{require(!it.isString);it.boolean}
        val actual=text("identityEvidence")
        require(initialized==(actual.isNotEmpty()))
        if(initialized)require(actual.length==43 && Policy.decode64(actual).size==32)
        if(evidence!=null)require(initialized && actual==evidence)
    }
    private fun java.io.InputStream.readBytesBounded(limit:Int):ByteArray {
        val bytes=ByteArray(limit+1);var count=0
        while(count<bytes.size) {val n=read(bytes,count,bytes.size-count);if(n<0)break;check(n>0);count+=n}
        require(count<=limit);return bytes.copyOf(count)
    }
    /** No root selection or recursive delete API is exposed. Preflight the
     * complete owned tree before the first deletion; never follow a link.
     * A partial I/O failure remains pending and can retry only this namespace. */
    fun retire(namespace:String,identityEvidence:String?,stillRetiring:()->Boolean):Boolean {
        worker()
        val selected=directory(namespace)
        identityEvidence?.let{require(it.length==43 && Policy.decode64(it).size==32)}
        return NativeRetirement.withReleased(context) {
            if(!stillRetiring())return@withReleased false
            if(!exists(root))return@withReleased true
            require(attributes(root).isDirectory && !attributes(root).isSymbolicLink)
            if(!exists(selected))return@withReleased true
            val entries=ArrayList<Pair<File,BasicFileAttributes>>()
            var total=0L
            fun visit(file:File,depth:Int) {
                require(depth<=8 && entries.size<512)
                val a=attributes(file)
                require(!a.isSymbolicLink && (a.isDirectory || a.isRegularFile))
                total=Math.addExact(total,a.size());require(total<=64L*1024*1024)
                entries.add(file to a)
                if(a.isDirectory)checkNotNull(file.listFiles()).sortedBy{it.name}.forEach{visit(it,depth+1)}
            }
            visit(selected,0)
            require(entries.first().second.isDirectory)
            val manifest=File(selected,"syn443-managed-identity.json")
            if(exists(manifest))ownedManifest(manifest,namespace,identityEvidence)
            else {
                // Native reserves the manifest before creating SDK keys. An
                // unclaimed config is never adopted, even during logout.
                require(identityEvidence==null && entries.drop(1).all{(file,a)->
                    file.parentFile==selected && a.isRegularFile && file.name in setOf("identity.lock","syn443-retry.json")})
            }
            // Retain the ownership manifest until all SDK files are gone. A
            // crash or I/O error must leave enough evidence for the same retry.
            val order=entries.asReversed().filter{it.first!=manifest && it.first!=selected}+
                entries.filter{it.first==manifest}+entries.take(1)
            for((file,before)in order) {
                if(!stillRetiring())return@withReleased false
                val now=attributes(file)
                require(!now.isSymbolicLink && now.isDirectory==before.isDirectory && now.fileKey()==before.fileKey())
                check(file.delete())
            }
            !exists(selected) && stillRetiring()
        }
    }
}
