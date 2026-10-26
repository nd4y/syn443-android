package io.syn443.android

import android.content.Context
import android.net.ConnectivityManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.syn443.android.vpn.PhysicalIdentityRoute
import io.syn443.android.vpn.PhysicalNetworks
import io.syn443.android.vpn.PhysicalSnapshot
import io.syn443.identity.DeliveryException
import io.syn443.identity.DeliveryFailure
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.Socket

@RunWith(AndroidJUnit4::class)
class PhysicalIdentityRouteTest {
    private class Networks:PhysicalNetworks {
        var values=listOf(PhysicalSnapshot(1,true,true,false,"mobile"),PhysicalSnapshot(2,true,true,true,"wifi"),
            PhysicalSnapshot(3,false,true,true,"vpn"))
        val actions=arrayListOf<Pair<String,Long>>()
        var changeOnResolve=false
        override fun snapshots()=values
        override fun resolve(handle:Long,host:String):List<InetAddress> {
            actions.add("dns" to handle)
            if(changeOnResolve)values=values.filter {it.handle!=handle}
            return listOf(InetAddress.getByAddress(byteArrayOf(127,0,0,1)))
        }
        override fun bind(handle:Long,socket:Socket) {actions.add("bind" to handle)}
    }
    private fun rejected(action:()->Unit) {
        assertEquals(DeliveryFailure.TRANSPORT,assertThrows(DeliveryException::class.java,action).reason)
    }
    @Test fun physicalIdentityUsesOneEligibleNetworkForDnsAndEverySocket() {
        val source=Networks();val route=PhysicalIdentityRoute.capture(source)
        route.resolve("synthetic.example.invalid");Socket().use {route.bind(it)};Socket().use {route.bind(it)}
        assertEquals(listOf("dns" to 2L,"bind" to 2L,"bind" to 2L),source.actions)
        assertEquals("PhysicalIdentityRoute([redacted])",route.toString())
        assertEquals("PhysicalSnapshot([redacted])",source.values.first().toString())
        source.values=source.values.map {if(it.handle==2L)it.copy(validated=false) else it}
        val validated=PhysicalIdentityRoute.capture(source);validated.resolve("synthetic.example.invalid")
        assertEquals("dns" to 1L,source.actions.last())
        source.values=source.values.map {it.copy(validated=false)}
        PhysicalIdentityRoute.capture(source).resolve("synthetic.example.invalid")
        assertEquals("dns" to 2L,source.actions.last()) // A restricted but non-captive link remains eligible.
    }
    @Test fun identityRouteLossOrChangedLinkRejectsWorkWithoutSwitchingNetworks() {
        for(change in listOf<(PhysicalSnapshot)->PhysicalSnapshot>({it.copy(signature="changed DNS")},{it.copy(eligible=false)},{it.copy(validated=false)})) {
            val source=Networks();val route=PhysicalIdentityRoute.capture(source)
            source.values=source.values.map {if(it.handle==2L)change(it) else it}
            rejected {route.check()};rejected {route.resolve("synthetic.example.invalid")}
            Socket().use {rejected {route.bind(it)}};assertTrue(source.actions.isEmpty())
        }
        val source=Networks();val route=PhysicalIdentityRoute.capture(source);source.changeOnResolve=true
        rejected {route.resolve("synthetic.example.invalid")};rejected {route.check()}
        assertEquals(listOf("dns" to 2L),source.actions)
    }
    @Test fun physicalIdentityRejectsMissingDuplicateAndOversizedInventory() {
        val source=Networks()
        for(values in listOf(emptyList(),source.values.map {it.copy(eligible=false)},
            source.values+source.values.first(),listOf(source.values.first().copy(handle=0)),
            (1L..65L).map {PhysicalSnapshot(it,true,true,true,"synthetic")})) {
            source.values=values;rejected {PhysicalIdentityRoute.capture(source)}
        }
        assertTrue(source.actions.isEmpty())
    }
    @Test fun androidPhysicalBindingDoesNotChangeProcessDefaultNetwork() {
        val context=ApplicationProvider.getApplicationContext<Context>()
        val manager=context.getSystemService(ConnectivityManager::class.java)
        val before=manager.boundNetworkForProcess
        val route=PhysicalIdentityRoute.capture(context)
        assertTrue(route.resolve("localhost").isNotEmpty())
        Socket().use {route.bind(it);assertFalse(it.isConnected)}
        route.check();assertEquals(before,manager.boundNetworkForProcess)
    }
}
