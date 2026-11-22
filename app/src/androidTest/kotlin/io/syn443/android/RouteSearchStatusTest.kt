package io.syn443.android

import android.os.SystemClock
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
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

    @Test fun singleRouteControlKeepsItsRowAndRejectsAReplacedNetworkOrConfiguration() {
        val scope=configure(2)
        val report=RouteSnapshot.read(true,true,scope)
        val stamp=report.getString("checkContext")
        assertEquals(stamp,RouteSnapshot.captureManualCheck("route-2",scope.intent,null))
        assertEquals(stamp,RouteSnapshot.captureManualCheck("route-2",scope.intent,stamp))
        assertEquals("managed-01",RouteSnapshot.resolveManualCheck(scope,"route-2",stamp))
        assertNull(RouteSnapshot.captureManualCheck("route-8",scope.intent,stamp))
        assertNull(RouteSnapshot.captureManualCheck("route-2",scope.intent+1,stamp))
        assertNull(RouteSnapshot.resolveManualCheck(scope.copy(config="other"),"route-2",stamp))
        val status=JSONObject().put("desiredOn",true).put("engineActive",true).put("generation",scope.intent).put("networkEpoch",scope.network)
        assertFalse(RouteSnapshot.view(status.put("configRevision","old")).has("checkContext"))
        assertEquals(stamp,RouteSnapshot.view(status.put("configRevision",scope.config)).getString("checkContext"))
        val model=mutableStateOf(JSONObject().put("desiredOn",true).put("engineActive",true).put("routeHealth",report))
        val commands=mutableListOf<Pair<String,String?>>()
        compose.setContent {
            MaterialTheme {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    RouteControls(model.value) {action,arg->commands.add(action to arg)}
                }
            }
        }
        compose.onNodeWithTag("route-2-check").performScrollTo().performClick()
        compose.runOnIdle {
            assertEquals(listOf("routes-check" to "route-2"),commands)
            model.value=JSONObject(model.value.toString()).also {it.getJSONObject("routeHealth").put("running",true)}
        }
        compose.onNodeWithTag("route-2-check").assertIsNotEnabled()
        val next=scope.copy(network=scope.network+1)
        RouteSnapshot.owner(next)
        assertNull(RouteSnapshot.captureManualCheck("route-2",next.intent,stamp))
        assertNull(RouteSnapshot.resolveManualCheck(next,"route-2",stamp))
        assertNull(RouteSnapshot.resolveManualCheck(scope,"route-2",stamp))
        assertFalse(RouteSnapshot.read(false,true,next).has("checkContext"))
        assertFalse(RouteSnapshot.read(true,false,next).getJSONArray("routes").getJSONObject(1).getBoolean("individualCheck"))
        val nextStamp=checkNotNull(RouteSnapshot.captureManualCheck("route-2",next.intent,null))
        assertNotEquals(stamp,nextStamp)
        RouteSnapshot.invalidate()
        assertNull(RouteSnapshot.resolveManualCheck(next,"route-2",nextStamp))
    }

    @Test fun lifecycleRevisionMustMatchBeforeReportingVerifiedAdaptiveRoute() {
        val scope = configure()
        val status = JSONObject().put("desiredOn", true).put("engineActive", true)
            .put("generation", scope.intent).put("networkEpoch", scope.network)
        RouteSnapshot.adaptive(scope, "managed-00", true, "ok", 17, listOf("synthetic-hop"))
        RouteSnapshot.adaptiveSearch(scope, mapOf("managed-00" to AdaptiveSearchState.VERIFIED))
        for (revision in listOf(null, "replaced")) {
            if (revision == null) status.remove("configRevision") else status.put("configRevision", revision)
            val report = RouteSnapshot.view(status)
            val row = report.getJSONArray("routes").getJSONObject(0)
            assertEquals("unverified", row.getString("state"))
            assertEquals("WAITING_CONTEXT", search(row))
            assertFalse(report.getBoolean("requiredReady"))
            assertFalse(report.has("measurementRevision"))
            assertFalse(report.has("checkContext"))
            assertEquals(0, row.getJSONArray("measuredPath").length())
            assertTrue(row.isNull("ageMs"))
            assertTrue(row.isNull("latencyMs"))
            assertEquals("not_checked", row.getString("reason"))
        }
        val report = RouteSnapshot.view(status.put("configRevision", scope.config))
        assertEquals(scope.config, report.getString("measurementRevision"))
        assertTrue(report.getBoolean("requiredReady"))
        val row = report.getJSONArray("routes").getJSONObject(0)
        assertEquals("VERIFIED", search(row))
        assertEquals("synthetic-hop", row.getJSONArray("measuredPath").getString(0))
        assertEquals(17L, row.getLong("latencyMs"))
    }

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

    @Test fun activeAdaptiveRouteShowsOnlyComparableConfirmedApplicationTimings() {
        val raw = ManagedAdaptiveRoutesFairnessTest().config(choices = 1, publicExit = true)
        val owner = RouteScope(1, 2, 3, "owner", Policy.hash(raw))
        RouteSnapshot.configure(raw, owner.config)
        RouteSnapshot.owner(owner)
        fun display() = JSONObject().put("routeHealth", RouteSnapshot.read(true, true, owner))
        fun sample(ms: Long, receipt: String, vararg hops: String) {
            RouteSnapshot.adaptive(owner, "managed-00", true, "ok", ms, hops.toList(), receipt = receipt)
        }
        val state = mutableStateOf(display())
        compose.setContent { MaterialTheme { RouteControls(state.value) { _, _ -> } } }
        val summary = compose.onNodeWithTag("route-1-distribution")
        compose.runOnIdle {
            sample(30, "receipt-a", "first", "last")
            sample(30, "receipt-a", "first", "last")
            state.value = display()
        }
        summary.assertDoesNotExist()
        compose.runOnIdle {
            sample(70, "receipt-b", "first", "last")
            state.value = display()
        }
        summary.assertTextEquals("Длительность проверок · за 15 мин успешно 2 · p50 30 мс · p95 70 мс")
        compose.runOnIdle {
            sample(12, "receipt-c", "first", "different")
            state.value = display()
        }
        summary.assertDoesNotExist()
        compose.runOnIdle {
            sample(14, "receipt-d", "first", "different")
            RouteSnapshot.adaptiveOwnerChanged(owner, setOf("managed-00"))
            state.value = display()
        }
        summary.assertDoesNotExist()
    }

    @Test fun failedOrExpiredPathAndAbsentLatencyHaveDistinctLabels() {
        val scope = configure()
        RouteSnapshot.adaptive(scope, "managed-00", true, "ok", 0, listOf("synthetic-hop"))
        fun snapshot(at: Long) = JSONObject().put("routeHealth", RouteSnapshot.readAt(true, true, scope, at))
        val freshAt = SystemClock.elapsedRealtime()
        val display = mutableStateOf(snapshot(freshAt))
        compose.setContent { MaterialTheme { RouteControls(display.value) { _, _ -> error("read-only screen") } } }
        compose.onNodeWithTag("route-1-timing").assertTextEquals("Возраст проверки 0 с · длительность 0 мс")
        compose.onNodeWithTag("route-1-path").assertTextEquals("Проверенный путь · synthetic-hop")
        compose.runOnIdle { display.value = snapshot(freshAt + 125_000) }
        compose.onNodeWithTag("route-1-path").assertTextEquals("Путь предыдущей проверки · synthetic-hop")
        compose.runOnIdle {
            RouteSnapshot.adaptive(scope, "managed-00", false, "exit_mismatch", null, listOf("synthetic-next"))
            display.value = snapshot(SystemClock.elapsedRealtime())
        }
        compose.onNodeWithTag("route-1-timing").assertTextEquals("Возраст проверки 0 с · длительность неизвестна")
        compose.onNodeWithTag("route-1-path").assertTextEquals("Путь последней попытки · synthetic-next")
        compose.onNodeWithTag("route-1-reason").assertTextEquals("Выход не соответствует назначенной проверке")
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
