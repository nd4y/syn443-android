package io.syn443.recovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PhysicalNetworkSelectionTest {
    private val wifi = PhysicalCandidate(30, PhysicalTransport.WIFI, validated = false, captive = false, metered = false)
    private val cellular = PhysicalCandidate(40, PhysicalTransport.CELLULAR, validated = true, captive = false, metered = true)

    @Test fun validatedOrVerifiedPathSurvivesAnUnusableWifiAppearance() {
        for (newWifi in listOf(wifi, wifi.copy(captive = true))) {
            assertEquals(40L, PhysicalNetworkSelection.choose(listOf(newWifi, cellular), 40, false))
            assertEquals(40L, PhysicalNetworkSelection.choose(listOf(cellular.copy(validated = false), newWifi), 40, true))
        }
        assertEquals(30L, PhysicalNetworkSelection.choose(listOf(cellular, wifi.copy(validated = true)), 40, true))
    }

    @Test fun losingTheOwnerDropsItsProofAndEqualRanksDoNotFlap() {
        val a = wifi.copy(handle = 10, validated = true)
        val b = wifi.copy(handle = 20, validated = true)
        assertEquals(20L, PhysicalNetworkSelection.choose(listOf(a, b), 20, false))
        assertEquals(20L, PhysicalNetworkSelection.choose(listOf(b, a), 20, false))
        assertEquals(10L, PhysicalNetworkSelection.choose(listOf(a), 20, true))
        assertNull(PhysicalNetworkSelection.choose(emptyList(), 20, true))
    }

    @Test fun captiveCandidateCannotBeSelectedEvenWithPriorProof() {
        val portal=wifi.copy(captive=true)
        assertNull(PhysicalNetworkSelection.choose(listOf(portal), wifi.handle, true))
        assertNull(PhysicalNetworkSelection.choose(listOf(portal.copy(validated=true)), wifi.handle, true))
        // Unknown reachability alone is not evidence of a portal or allowlist.
        assertEquals(wifi.handle, PhysicalNetworkSelection.choose(listOf(wifi), null, false))
        assertEquals(cellular.handle, PhysicalNetworkSelection.choose(listOf(portal, cellular), wifi.handle, true))
        assertEquals(wifi.handle, PhysicalNetworkSelection.choose(listOf(wifi.copy(validated=true)), null, false))
    }
}
