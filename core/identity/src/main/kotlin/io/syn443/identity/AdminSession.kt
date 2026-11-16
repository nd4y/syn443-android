package io.syn443.identity

import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicBoolean

class AdminIssuerState internal constructor(keys:Map<String,RSAPublicKey>,val time:TrustedTime,
    internal val authority:String,internal val keyThumbprint:String) {
    internal val keys=keys.toMap()
    override fun toString()="AdminIssuerState([redacted])"
}

/** Separate administrative credentials. A refresh dispatch permanently consumes this process-owned pair. */
class AdminSession internal constructor(val accessToken:String,val refreshToken:String,val subject:String,
    val keyThumbprint:String,val authority:String,val bootCount:Int,val accessUntilElapsedMs:Long,
    val sessionUntilElapsedMs:Long,internal val time:TrustedTime,internal val originalNonce:String,
    internal val family:AdminSessionFamily=AdminSessionFamily()) {
    private val consumed=AtomicBoolean()
    internal fun available()=!consumed.get() && !family.isClosed()
    internal fun consume()=!family.isClosed() && consumed.compareAndSet(false,true) && !family.isClosed()
    internal fun retire() {family.close();consumed.set(true)}
    override fun toString()="AdminSession([redacted])"
}

/** Logout fences every rotation of one process-owned family, including an already dispatched refresh. */
internal class AdminSessionFamily {
    private val closed=AtomicBoolean()
    fun isClosed()=closed.get()
    fun close() {closed.set(true)}
    override fun toString()="AdminSessionFamily([redacted])"
}

/** Local retirement only: no server revocation, browser logout, or device-key operation. */
class AdminLogout internal constructor(val authority:String,val keyThumbprint:String) {
    override fun toString()="AdminLogout([redacted])"
}
