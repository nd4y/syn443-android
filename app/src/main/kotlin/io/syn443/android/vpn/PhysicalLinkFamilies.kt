package io.syn443.android.vpn

import android.net.LinkProperties
import android.net.RouteInfo
import android.os.Build
import io.syn443.recovery.PhysicalTransport
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import org.json.JSONObject

/** Passive facts from the selected physical link. Never retain an address or a network name. */
internal data class PhysicalLinkFamilies(
    val ipv4Address: Boolean,
    val ipv4Default: Boolean,
    val ipv6Address: Boolean,
    val ipv6Default: Boolean,
) {
    companion object {
        fun observe(properties: LinkProperties): PhysicalLinkFamilies {
            val defaults = properties.routes.filter { route ->
                route.isDefaultRoute && (Build.VERSION.SDK_INT < 33 || route.type == RouteInfo.RTN_UNICAST)
            }
            return summarize(properties.linkAddresses.map { it.address }, defaults.map { it.destination.address })
        }

        internal fun summarize(addresses: List<InetAddress>, defaultDestinations: List<InetAddress>): PhysicalLinkFamilies {
            val unicast = addresses.filterNot {
                it.isLinkLocalAddress || it.isLoopbackAddress || it.isMulticastAddress || it.isAnyLocalAddress
            }
            return PhysicalLinkFamilies(unicast.any { it is Inet4Address }, defaultDestinations.any { it is Inet4Address },
                unicast.any { it is Inet6Address }, defaultDestinations.any { it is Inet6Address })
        }
    }
}

internal data class PhysicalLinkReport(val epoch: Long, val transport: PhysicalTransport, val families: PhysicalLinkFamilies) {
    fun forStatus(networkEpoch: Long): JSONObject? {
        if (epoch != networkEpoch) return null
        return JSONObject().put("transport", transport.name)
            .put("ipv4Address", families.ipv4Address).put("ipv4Default", families.ipv4Default)
            .put("ipv6Address", families.ipv6Address).put("ipv6Default", families.ipv6Default)
    }
}
