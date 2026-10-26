package io.syn443.android.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Looper
import io.syn443.identity.DeliveryException
import io.syn443.identity.DeliveryFailure
import io.syn443.identity.HttpRoute
import java.net.InetAddress
import java.net.Socket

internal data class PhysicalSnapshot(val handle:Long,val eligible:Boolean,val validated:Boolean,
    val wifi:Boolean,val signature:String) {
    override fun toString()="PhysicalSnapshot([redacted])"
}
internal interface PhysicalNetworks {
    fun snapshots():List<PhysicalSnapshot>
    fun resolve(handle:Long,host:String):List<InetAddress>
    fun bind(handle:Long,socket:Socket)
}
/** A request owns one physical route. It never falls back to process DNS or the active VPN. */
internal class PhysicalIdentityRoute private constructor(private val source:PhysicalNetworks,
    private val selected:PhysicalSnapshot):HttpRoute {
    companion object {
        private fun unavailable():Nothing=throw DeliveryException(DeliveryFailure.TRANSPORT)
        private fun inventory(source:PhysicalNetworks):List<PhysicalSnapshot> = source.snapshots().also {
            if(it.size>64 || it.any {s->s.handle<=0} || it.map {s->s.handle}.distinct().size!=it.size)unavailable()
        }
        internal fun capture(source:PhysicalNetworks):PhysicalIdentityRoute {
            val selected=inventory(source).filter {it.eligible}.sortedWith(
                compareByDescending<PhysicalSnapshot> {it.validated}.thenByDescending {it.wifi}.thenBy {it.handle})
                .firstOrNull()?:unavailable()
            return PhysicalIdentityRoute(source,selected).also {it.check()}
        }
        fun capture(context:Context):HttpRoute {
            check(Looper.myLooper()!=Looper.getMainLooper())
            val manager=checkNotNull(context.getSystemService(ConnectivityManager::class.java))
            return capture(object:PhysicalNetworks {
                override fun snapshots()=manager.allNetworks.map {network->
                    val caps=manager.getNetworkCapabilities(network)
                    val properties=manager.getLinkProperties(network)
                    val eligible=caps!=null && properties?.interfaceName!=null &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED) &&
                        !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                        !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
                    PhysicalSnapshot(network.networkHandle,eligible,
                        caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)==true,
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true,properties?.toString().orEmpty())
                }
                override fun resolve(handle:Long,host:String)=Network.fromNetworkHandle(handle).getAllByName(host).toList()
                override fun bind(handle:Long,socket:Socket)=Network.fromNetworkHandle(handle).bindSocket(socket)
            })
        }
    }
    override fun check() {if(inventory(source).singleOrNull {it.handle==selected.handle}!=selected)unavailable()}
    override fun resolve(host:String):List<InetAddress> {check();return source.resolve(selected.handle,host).also {check()}}
    override fun bind(socket:Socket) {check();source.bind(selected.handle,socket);check()}
    override fun toString()="PhysicalIdentityRoute([redacted])"
}
