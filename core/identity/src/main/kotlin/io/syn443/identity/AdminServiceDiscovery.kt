package io.syn443.identity

import io.syn443.policy.Policy
import java.util.Collections

/** An untrusted signed-envelope value, not verified metadata, a role, a session or a committed floor. */
class AdminServiceManifest internal constructor(val raw:String) {
    override fun toString()="AdminServiceManifest([redacted])"
}

/** One anonymous fixed GET from an already owned ordinary bootstrap. Call only on the identity worker. */
class AdminServiceDiscovery(bootstrap:Bootstrap,private val exchange:IdentityExchange) {
    private val owned=checked {
        bootstrap.copy(roots=bootstrap.roots.toMap()).also {
            it.validate()
            Identity.controlOrigin(it.apiOrigin)
            // Operator loopback CA material has no representation in a signed service descriptor.
            // This transport cannot introduce a development TLS exception or downgrade.
            require(it.tlsCaDer.isEmpty())
        }
    }
    private val target=owned.apiOrigin+"/.well-known/syn443/bootstrap/"+owned.serviceId
    fun fetch(scope:IdentityScope):AdminServiceManifest=checked {
        scope.request {child->
            child.active()
            val headers=Collections.unmodifiableMap(linkedMapOf("Accept" to "application/jose","Cache-Control" to "no-store"))
            val reply=exchange.request("GET",target,headers,null,child,BootstrapTrust.MAX_MANIFEST)
            child.active()
            if(reply.status!=200)throw AdminException(AdminFailure.TRANSPORT)
            require(reply.single("content-type")?.trim()?.lowercase()=="application/jose")
            require(reply.body.size in 1..BootstrapTrust.MAX_MANIFEST)
            val bytes=reply.body.copyOf()
            try {
                val raw=Policy.utf8(bytes)
                require(raw.length in 1..BootstrapTrust.MAX_MANIFEST && raw.all {it.code in 33..126})
                val segments=raw.split('.')
                require(segments.size==3)
                for(segment in segments) {
                    require(segment.isNotEmpty() && segment.all {it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it=='_' || it=='-'})
                    Policy.decode64(segment).also {require(it.isNotEmpty());it.fill(0)}
                }
                child.active()
                AdminServiceManifest(raw)
            }finally {bytes.fill(0)}
        }
    }
    override fun toString()="AdminServiceDiscovery([redacted])"
    companion object {
        private fun <T> checked(action:()->T):T=try {action()}
            catch(error:AdminException) {throw error}
            catch(error:DeliveryException) {throw AdminException(when(error.reason) {
                DeliveryFailure.CANCELLED->AdminFailure.CANCELLED
                DeliveryFailure.PROTOCOL->AdminFailure.INVALID_REPLY
                else->AdminFailure.TRANSPORT
            })}
            catch(_:Exception) {throw AdminException(AdminFailure.INVALID_REPLY)}
    }
}
