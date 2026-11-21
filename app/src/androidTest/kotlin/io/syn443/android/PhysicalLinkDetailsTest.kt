package io.syn443.android

import android.net.LinkProperties
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import io.syn443.android.vpn.PhysicalLinkDetails
import io.syn443.android.vpn.PhysicalLinkFamilies
import io.syn443.android.vpn.PhysicalLinkReport
import io.syn443.recovery.PhysicalTransport
import java.net.InetAddress
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class PhysicalLinkDetailsTest {
    @get:Rule val compose = createComposeRule()

    @Test fun familyFactsExcludeLinkLocalAndKeepAddressAndDefaultRouteSeparate() {
        fun ips(vararg values: String) = values.map(InetAddress::getByName)
        assertEquals(PhysicalLinkFamilies(false, false, false, false), PhysicalLinkFamilies.observe(LinkProperties()))
        val link = PhysicalLinkFamilies.summarize(
            ips("192.0.2.2", "fe80::1", "::1", "::", "ff02::1"), ips("::"))
        assertEquals(PhysicalLinkFamilies(true, false, false, true), link)
        val internalV6 = PhysicalLinkFamilies.summarize(ips("fd00::1"), ips("0.0.0.0"))
        assertEquals(PhysicalLinkFamilies(false, true, true, false), internalV6)
        val report = PhysicalLinkReport(9, PhysicalTransport.WIFI, link)
        assertNull(report.forStatus(8))
        assertNull(report.forStatus(10))
        val current = requireNotNull(report.forStatus(9))
        assertEquals(setOf("transport", "ipv4Address", "ipv4Default", "ipv6Address", "ipv6Default"), current.keys().asSequence().toSet())
        assertEquals("WIFI", current.getString("transport"))
        assertTrue(current.getBoolean("ipv4Address"))
        assertFalse(current.getBoolean("ipv6Address"))
    }

    @Test fun lostPhysicalLinkRemovesFamilyFactsFromVisibleDiagnostics() {
        val facts = PhysicalLinkFamilies(true, true, false, false)
        val current = mutableStateOf<JSONObject?>(PhysicalLinkReport(3, PhysicalTransport.WIFI, facts).forStatus(3))
        compose.setContent { Column { PhysicalLinkDetails(current.value) } }
        compose.onNodeWithTag("physical-link-transport").assertTextContains("Wi-Fi", substring = true)
        compose.onNodeWithTag("physical-link-ipv4").assertTextContains("есть адрес и маршрут", substring = true)
        compose.onNodeWithTag("physical-link-ipv6").assertTextContains("нет адреса и маршрута", substring = true)
        compose.runOnIdle { current.value = null }
        compose.onNodeWithTag("physical-link-ipv4").assertDoesNotExist()
        compose.onNodeWithTag("physical-link-ipv6").assertDoesNotExist()
        compose.onNodeWithTag("physical-link-pending").assertExists()
    }
}
