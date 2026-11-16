package io.syn443.android.vpn

import io.syn443.identity.AdminDiscovery
import io.syn443.identity.Bootstrap

/** Owned ordinary bootstrap only. No administrative metadata, credentials or role. */
internal class AdminBootstrapContext(val binding:String,bootstrap:Bootstrap) {
    val bootstrap=bootstrap.copy(roots=bootstrap.roots.toMap())
    override fun toString()="AdminBootstrapContext([redacted])"
}

/** Worker-only owned-device fence and current signed administrative discovery.
 * It is neither a role grant nor an administrative credential. */
internal class AdminDeviceContext(val binding:String,val discovery:AdminDiscovery) {
    override fun toString()="AdminDeviceContext([redacted])"
}
