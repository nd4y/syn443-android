package io.syn443.android

import android.os.SystemClock
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import io.syn443.android.vpn.AdaptiveSearchState
import io.syn443.android.vpn.RouteControls
import io.syn443.android.vpn.RouteSnapshot
import io.syn443.policy.Policy
import io.syn443.recovery.RouteActivation
import io.syn443.recovery.RouteScope
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class RouteSearchStatusTest {
    @get:Rule val compose=createComposeRule()
    @After fun clearOwnedSnapshot() {RouteSnapshot.owner(null)}
    private fun configure(groups:Int=1):RouteScope {
        RouteSnapshot.owner(null)
        val raw=ManagedAdaptiveRoutesFairnessTest().config(choices=1,groupCount=groups)
        val scope=RouteScope(1,2,3,"synthetic-search-snapshot",Policy.hash(raw))
        RouteSnapshot.configure(raw,scope.config);RouteSnapshot.owner(scope)
        return scope
    }
    private fun row(scope:RouteScope,now:Long=SystemClock.elapsedRealtime(),ready:Boolean=true)=
        RouteSnapshot.readAt(true,ready,scope,now).getJSONArray("routes").getJSONObject(0)
    private fun search(value:JSONObject)=value.getJSONObject("search").getString("state")

    @Test fun verifiedProjectionJoinsExactExistingTtlScopeReadinessAndFutureSampleGuards() {
        val scope=configure()
        RouteSnapshot.adaptiveSearch(scope,mapOf("managed-00" to AdaptiveSearchState.VERIFIED))
        assertEquals("SEARCH_INCOMPLETE",search(row(scope)))
        RouteSnapshot.adaptive(scope,"managed-00",true,"ok",20,listOf("synthetic-hop"))
        val now=SystemClock.elapsedRealtime();val sampled=now-row(scope,now).getLong("ageMs")
        assertEquals("VERIFIED",search(row(scope,sampled+120_000)))
        assertEquals("SEARCH_INCOMPLETE",search(row(scope,sampled+120_001)))
        assertEquals("stale",row(scope,sampled+120_001).getString("state"))
        assertEquals("SEARCH_INCOMPLETE",search(row(scope,sampled-1)))
        assertEquals("WAITING_CONTEXT",search(row(scope,now,ready=false)))
        assertEquals("WAITING_CONTEXT",search(row(scope.copy(network=3),now)))
        assertEquals("WAITING_CONTEXT",search(RouteSnapshot.readAt(false,true,scope,now).getJSONArray("routes").getJSONObject(0)))
        assertThrows(IllegalArgumentException::class.java) {RouteSnapshot.readAt(true,true,scope,-1)}
    }

    @Test fun diagnosticProjectionCannotAuthorizeRequiredReadinessOrActivation() {
        val scope=configure()
        for(value in AdaptiveSearchState.entries) {
            RouteSnapshot.adaptiveSearch(scope,mapOf("managed-00" to value))
            assertFalse(RouteSnapshot.read(true,true,scope).getBoolean("requiredReady"))
            assertEquals(RouteActivation.WAIT,RouteSnapshot.activation(scope))
            assertEquals("unverified",row(scope).getString("state"))
        }
        RouteSnapshot.adaptive(scope,"managed-00",true,"ok",20,listOf("synthetic-hop"))
        RouteSnapshot.adaptiveSearch(scope,mapOf("managed-00" to AdaptiveSearchState.VERIFIED))
        assertTrue(RouteSnapshot.read(true,true,scope).getBoolean("requiredReady"))
        RouteSnapshot.adaptive(scope,"managed-00",false,"check_failed",null,emptyList())
        assertEquals("SEARCH_INCOMPLETE",search(row(scope)))
        assertEquals("failed",row(scope).getString("state"))
        assertFalse(RouteSnapshot.read(true,true,scope).getBoolean("requiredReady"))
    }

    @Test fun copiedSixteenGroupProjectionRejectsOverflowForeignScopeAndClearsOnInvalidate() {
        val scope=configure(16)
        val states=(0 until 16).associate {"managed-%02d".format(it) to AdaptiveSearchState.SEARCHING}.toMutableMap()
        RouteSnapshot.adaptiveSearch(scope,states);states["managed-00"]=AdaptiveSearchState.VERIFIED
        assertEquals("SEARCHING",search(row(scope)))
        states["foreign"]=AdaptiveSearchState.BUDGET_WAIT;RouteSnapshot.adaptiveSearch(scope,states)
        assertEquals("SEARCHING",search(row(scope)))
        RouteSnapshot.adaptiveSearch(scope.copy(intent=2),mapOf("managed-00" to AdaptiveSearchState.BUDGET_WAIT))
        val rows=RouteSnapshot.read(true,true,scope).getJSONArray("routes")
        assertEquals(16,rows.length())
        repeat(rows.length()) {assertEquals("SEARCHING",search(rows.getJSONObject(it)))}
        RouteSnapshot.invalidate();assertEquals("WAITING_CONTEXT",search(row(scope)))
        RouteSnapshot.owner(scope.copy(engine="synthetic-next-owner"))
        assertEquals("WAITING_CONTEXT",search(row(scope)))
    }

    @Test fun finiteSearchLabelsNeverClaimNoRoutesAndRecompositionDispatchesNothing() {
        val scope=configure()
        val view=mutableStateOf(JSONObject().put("routeHealth",RouteSnapshot.read(true,true,scope)))
        val commands=mutableListOf<String>()
        compose.setContent {MaterialTheme {RouteControls(view.value) {command,_->commands+=command}}}
        val labels=mapOf(
            "WAITING_CONTEXT" to "Поиск ожидает подключения к сети и VPN",
            "SEARCHING" to "Поиск маршрута продолжается",
            "BUDGET_WAIT" to "Поиск временно приостановлен и продолжится автоматически",
            "SEARCH_INCOMPLETE" to "Поиск ещё не завершён",
            "VERIFIED" to "Выбранный маршрут подтверждён свежей проверкой",
            "unknown-future-state" to "Поиск ещё не завершён")
        for((state,label) in labels) {
            compose.runOnIdle {
                val next=JSONObject(view.value.toString())
                next.getJSONObject("routeHealth").getJSONArray("routes").getJSONObject(0).put("search",JSONObject().put("state",state))
                view.value=next
            }
            compose.onNodeWithTag("route-1-search").assertTextEquals(label)
        }
        compose.runOnIdle {assertTrue(commands.isEmpty())}
    }
}
