package io.syn443.android

import io.syn443.android.vpn.AdaptivePolicyBinding
import io.syn443.android.vpn.RouteSnapshot
import io.syn443.policy.Policy
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Coordinator simulations only. Reports are synthetic and authorize no real packets. */
class ManagedAdaptiveSearchStatusTest {
    private val fixture=ManagedAdaptiveRoutesFairnessTest()
    private fun state(h:ManagedAdaptiveRoutesFairnessTest.Harness,index:Int=0)=
        h.view().getJSONArray("routes").getJSONObject(index).getJSONObject("search").getString("state")

    @Test fun onlyFreshSelectedAcknowledgementChangesSearchingToVerified() {
        ManagedAdaptiveRoutesFairnessTest.Harness(fixture.config(choices=2)).use {h->
            assertEquals("WAITING_CONTEXT",state(h))
            h.ready(1000);assertEquals("SEARCH_INCOMPLETE",state(h))
            val probe=checkNotNull(h.tick(1000));assertEquals("SEARCHING",state(h))
            val commit=h.verified(probe,1000)
            assertEquals("SEARCHING",state(h));assertFalse(h.view().getBoolean("requiredReady"))
            val ack=h.status().put("request",probe.getString("request")).put("group",probe.getString("group"))
                .put("hops",JSONArray(probe.getJSONArray("hops").toString())).put("code","selected")
                .put("receipt",commit.getString("receipt"))
            h.acknowledge(ack.put("groupSelected",false),1000)
            assertEquals("SEARCHING",state(h));assertFalse(h.view().getBoolean("requiredReady"))
            h.acknowledge(ack.put("groupSelected",true).put("receipt",Policy.hash("wrong-receipt")),1000)
            assertEquals("SEARCHING",state(h))
            h.acknowledge(ack.put("receipt",commit.getString("receipt")),1000)
            assertEquals("VERIFIED",state(h));assertTrue(h.view().getBoolean("requiredReady"))
        }
    }

    @Test fun minuteBudgetWaitRetainsContinuationWithoutInventingNoCandidateVerdict() {
        ManagedAdaptiveRoutesFairnessTest.Harness(fixture.config(choices=10)).use {h->
            h.ready(1000)
            repeat(8) {index->val now=1000L+index*6000;h.failed(checkNotNull(h.tick(now)),now)}
            assertNull(h.tick(49000));assertEquals(8,h.starts.size)
            assertEquals("BUDGET_WAIT",state(h));assertFalse(h.view().getBoolean("requiredReady"))
            val resumed=checkNotNull(h.tick(62000))
            assertEquals("hop-008",resumed.getJSONArray("hops").getString(0))
            assertEquals("SEARCHING",state(h));assertEquals(9,h.starts.size)
        }
    }

    @Test fun cpuYieldAndExhaustedMetadataDoNotHideAnIndependentlyVerifiedGroup() {
        ManagedAdaptiveRoutesFairnessTest.Harness(fixture.config(choices=129,groupCount=2,blockedFirst=true)).use {h->
            h.ready(1000);assertNull(h.tick(1000))
            assertEquals("SEARCH_INCOMPLETE",state(h));assertTrue(h.starts.isEmpty())
            h.selected(checkNotNull(h.tick(2000)),2000)
            assertEquals("VERIFIED",state(h,1));assertFalse(h.view().getBoolean("requiredReady"))
            // The second64-slot quantum exhausts this group's static metadata,
            // not evidence that every possible usable route is unavailable.
            assertNull(h.tick(62000));assertEquals("SEARCH_INCOMPLETE",state(h))
            assertEquals("VERIFIED",state(h,1));assertEquals(1,h.starts.size)
            assertFalse(h.view().toString().contains("COMPLETE_NO_CANDIDATE"))
        }
    }

    @Test fun nativeEpochScopeAndPolicyRebindCannotBorrowAnOldVerifiedProjection() {
        ManagedAdaptiveRoutesFairnessTest.Harness(fixture.config(choices=2)).use {h->
            h.ready(1000);h.selected(checkNotNull(h.tick(1000)),1000)
            assertEquals("VERIFIED",state(h))
            h.acknowledge(h.status().put("ready",false),2000)
            assertEquals("WAITING_CONTEXT",state(h))
            h.ready(3000);assertEquals("SEARCH_INCOMPLETE",state(h))
            val old=h.status()
            h.epoch=2;h.nativeScope=Policy.hash("synthetic-status-next-native")
            h.ready(7000);assertEquals("SEARCH_INCOMPLETE",state(h))
            h.acknowledge(old,7000);assertEquals("SEARCH_INCOMPLETE",state(h))
            h.rebind(13000);assertEquals("SEARCH_INCOMPLETE",state(h))
            assertFalse(h.view().getBoolean("requiredReady"))
            assertEquals(1,h.starts.size)
        }
    }

    @Test fun expiredLeaseAndBackwardClockRetireStatusWithoutErasingAdmissions() {
        val raw=fixture.config(choices=2)
        val binding=AdaptivePolicyBinding(1,Policy.hash(raw),Policy.hash("synthetic-status-authority"),8000,1)
        ManagedAdaptiveRoutesFairnessTest.Harness(raw,binding).use {h->
            h.ready(1000);h.selected(checkNotNull(h.tick(1000)),1000)
            h.bind(AdaptivePolicyBinding(2,binding.contentHash,binding.semanticAuthority,8000,1),8000)
            assertTrue(h.controller.requiresRetirement());assertEquals("WAITING_CONTEXT",state(h))
            assertNull(h.tick(9000));assertEquals(1,h.starts.size)
        }
        ManagedAdaptiveRoutesFairnessTest.Harness(raw).use {h->
            h.ready(1000);h.selected(checkNotNull(h.tick(1000)),1000)
            assertNull(h.tick(999));assertTrue(h.controller.requiresRetirement())
            assertEquals("WAITING_CONTEXT",state(h));assertEquals(1,h.starts.size)
        }
    }

    @Test fun sixteenGroupProjectionIsClosedBoundedAndFailuresStayGroupLocal() {
        ManagedAdaptiveRoutesFairnessTest.Harness(fixture.config(choices=1,groupCount=16)).use {h->
            h.ready(1000);h.selected(checkNotNull(h.tick(1000)),1000)
            val failed=checkNotNull(h.tick(6000));h.failed(failed,6000)
            val rows=h.view().getJSONArray("routes");assertEquals(16,rows.length())
            repeat(rows.length()) {index->
                val search=rows.getJSONObject(index).getJSONObject("search")
                assertEquals(setOf("state"),search.keys().asSequence().toSet())
                assertEquals(if(index==0)"VERIFIED" else "SEARCH_INCOMPLETE",search.getString("state"))
                assertFalse(search.toString().contains("hop-"));assertFalse(search.toString().contains(h.nativeScope))
            }
            assertFalse(h.view().getBoolean("requiredReady"));assertEquals(2,h.starts.size)
        }
    }
}
