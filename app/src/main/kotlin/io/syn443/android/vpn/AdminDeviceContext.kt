package io.syn443.android.vpn

import io.syn443.identity.AdminDiscovery

/** Worker-only owned-device fence and current signed administrative discovery.
 * It is neither a role grant nor an administrative credential. */
internal class AdminDeviceContext(val binding:String,val discovery:AdminDiscovery) {
    override fun toString()="AdminDeviceContext([redacted])"
}
