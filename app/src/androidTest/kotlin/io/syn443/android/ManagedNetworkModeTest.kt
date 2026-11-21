package io.syn443.android

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import io.syn443.android.vpn.ManagedNetworkMode
import io.syn443.android.vpn.NetworkModeControls
import io.syn443.decision.NetworkMode
import io.syn443.policy.NetworkModePolicy
import io.syn443.policy.Policy
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class ManagedNetworkModeTest {
    @get:Rule val ui = createComposeRule()
    private val scope=ManagedNetworkMode.Scope(7,5,"native","config","authority",1)
    private val rule=NetworkModePolicy.parse(Policy.json.parseToJsonElement(
        """{"preferredMode":"HOME_WIFI","userModes":["WIFI","HOME_WIFI"],"maxOverrideMinutes":30}"""),true)

    @Test fun userChoicePrecedesAssignmentAndExpiresAtTheExactMonotonicBoundary() {
        val state=ManagedNetworkMode()
        fun read(now:Long,mode:NetworkMode=NetworkMode.HOME_WIFI)=checkNotNull(state.observe(scope,rule,mode,now,200_000))
        val assigned=read(1000)
        assertEquals("assigned",assigned.source)
        assertFalse(state.choose(assigned,assigned.stamp,"WIFI",31,1000))
        assertTrue(state.choose(assigned,assigned.stamp,"WIFI",1,1000))
        assertFalse(state.choose(assigned,assigned.stamp,"WIFI",1,1000))
        assertEquals(NetworkMode.WIFI,read(60_999).effective)
        assertEquals("manual",read(60_999).source)
        assertEquals(61_000L,read(60_999).until)
        assertEquals(NetworkMode.HOME_WIFI,read(61_000).effective)
        val guest=read(61_001,NetworkMode.WIFI)
        assertEquals("automatic",guest.source)
        assertEquals(listOf(NetworkMode.WIFI),guest.allowed)
        assertFalse(state.choose(guest,guest.stamp,"HOME_WIFI",1,61_001))
    }

    @Test fun changedPhysicalNetworkAuthorityOrExpiredLeaseRetireTheChoiceAndItsCommands() {
        for(replacement in listOf(scope.copy(epoch=6),scope.copy(authority="changed"),scope.copy(engine="replacement"),scope.copy(contentHash="new"))) {
            val state=ManagedNetworkMode()
            fun read(context:ManagedNetworkMode.Scope,now:Long)=state.observe(context,rule,NetworkMode.HOME_WIFI,now,120_000)
            val original=checkNotNull(read(scope,1))
            assertTrue(state.choose(original,original.stamp,"WIFI",20,1))
            val manual=checkNotNull(read(scope,2))
            assertEquals(120_000L,manual.until)
            val next=checkNotNull(read(replacement,3))
            assertEquals("assigned",next.source)
            assertFalse(state.choose(next,manual.stamp,"WIFI",20,4))
            assertNull(read(replacement,120_000))
        }
    }

    @Test fun screenShowsAssignedSourceAndAcceptsOnlyThePermittedDurationAndMode() {
        val state=ManagedNetworkMode()
        val view=checkNotNull(state.observe(scope,rule,NetworkMode.WIFI,1000,200_000))
        var request:Triple<String,String,Int>?=null
        ui.setContent {NetworkModeControls(view.json()){stamp,mode,minutes->request=Triple(stamp,mode,minutes)}}
        ui.onNodeWithTag("effective-network-mode").assertTextContains("Определено автоматически",substring=true)
        ui.onNodeWithTag("choose-network-mode").performClick()
        ui.onNodeWithTag("mode-choice-HOME_WIFI").assertDoesNotExist()
        ui.onNodeWithTag("mode-duration").performTextReplacement("31")
        ui.onNodeWithTag("mode-confirm").assertIsNotEnabled()
        ui.onNodeWithTag("mode-duration").performTextReplacement("1")
        ui.onNodeWithTag("mode-confirm").performClick()
        ui.runOnIdle {assertEquals(Triple(view.stamp,"WIFI",1),request)}
    }
}
