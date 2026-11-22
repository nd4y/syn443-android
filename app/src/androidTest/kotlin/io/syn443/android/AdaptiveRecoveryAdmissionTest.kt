package io.syn443.android

import io.syn443.policy.Policy
import io.syn443.android.vpn.RouteSnapshot
import java.io.Closeable
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Virtual-clock coordinator acceptance only. Reports below are synthetic;
 * these cases establish no native execution, packet, radio or physical proof. */
class AdaptiveRecoveryAdmissionTest {
    private class Sim(groupCount: Int=1, choices: Int=2) : Closeable {
        val h=ManagedAdaptiveRoutesFairnessTest.Harness(ManagedAdaptiveRoutesFairnessTest().config(choices, groupCount))
        val tokens=mutableMapOf<String, Long>()
        val selectedAt=mutableMapOf<String, MutableList<Long>>()
        val initialRequests=mutableSetOf<String>()
        val recoveryRequests=mutableSetOf<String>()
        var now=1000L
        init {h.ready(now)}
        fun tick(at: Long): JSONObject? {
            require(at>=now); now=at
            val before=h.commands.size
            h.controller.tick(at, false, false) { raw ->
                val envelope=JSONObject(raw)
                assertEquals(setOf("kind", "commandJson"), envelope.keys().asSequence().toSet())
                assertEquals("adaptive", envelope.getString("kind"))
                h.commands+=JSONObject(envelope.getString("commandJson"))
            }
            val starts=h.commands.drop(before).filter {it.getString("command")=="start"}
            assertTrue("one handler quantum created multiple starts", starts.size<=1)
            return starts.singleOrNull()?.also { start ->
                h.starts+=at to start
                assertTrue("global rolling minute budget exceeded", h.starts.count {at-it.first<60_000}<=8)
                assertTrue("global rolling hour budget exceeded", h.starts.count {at-it.first<3_600_000}<=128)
                if(h.starts.size>1) assertTrue("minimum I/O spacing bypassed", at-h.starts[h.starts.lastIndex-1].first>=5000)
            }
        }
        fun frame(probe: JSONObject, code: String)=h.status().put("request", probe.getString("request"))
            .put("group", probe.getString("group")).put("hops", JSONArray(probe.getJSONArray("hops").toString())).put("code", code)
        fun selectedAck(probe: JSONObject, commit: JSONObject, token: Long?=tokens.getOrDefault(probe.getString("group"), 0)+1): JSONObject {
            val ack=frame(probe, "selected").put("probeMs", 20).put("receipt", commit.getString("receipt")).put("groupSelected", true)
            if(token!=null) ack.put("selectionToken", token)
            return ack
        }
        fun select(probe: JSONObject, token: Long?=tokens.getOrDefault(probe.getString("group"), 0)+1) {
            val commit=h.verified(probe, now)
            assertEquals("commit", commit.getString("command"))
            h.acknowledge(selectedAck(probe, commit, token), now)
            tokens[probe.getString("group")]=token ?: 0
            selectedAt.getOrPut(probe.getString("group")) {mutableListOf()}.add(now)
        }
        fun initialize(count: Int) {
            var at=1000L
            while(tokens.size<count && at<300_000) {
                tick(at)?.let {probe ->
                    assertFalse("unselected group was starved by routine work", tokens.containsKey(probe.getString("group")))
                    initialRequests+=probe.getString("request"); select(probe)
                }
                at+=1000
            }
            assertEquals(count, tokens.size); assertTrue(h.view().getBoolean("requiredReady"))
        }
        fun hint(group: String="group-00", token: Long=tokens.getValue(group), sequence: Long=1, completed: Long=now)=
            JSONObject().put("group", group).put("selectionToken", token).put("sequence", sequence)
                .put("completedBootMs", completed).put("code", "traffic_network_failure")
        fun hints(values: Any, at: Long, change: (JSONObject)->Unit={}) {
            require(at>=now); now=at
            h.acknowledge(h.status().put("recheckHints", values).also(change), at)
        }
        fun checkedFailure(probe: JSONObject) {
            h.acknowledge(frame(probe, "check_failed").put("groupSelected", true).put("checkCode", "dial_failed")
                .put("checkCompletedBootMs", now), now)
        }
        fun awaitStart(until: Long): JSONObject {
            var at=now
            while(at<=until) {tick(at)?.let {return it}; at+=1000}
            throw AssertionError("critical route did not receive bounded recovery admission")
        }
        fun recover(group: String="group-00"): Pair<JSONObject, JSONObject> {
            val completed=now
            hints(JSONArray().put(hint(group=group)), completed)
            val current=awaitStart(completed+15_000)
            assertEquals(group, current.getString("group")); recoveryRequests+=current.getString("request")
            checkedFailure(current)
            assertFalse(h.view().getBoolean("requiredReady"))
            val replacement=awaitStart(completed+30_000)
            assertEquals(group, replacement.getString("group")); recoveryRequests+=replacement.getString("request")
            assertNotEquals(current.getJSONArray("hops").toString(), replacement.getJSONArray("hops").toString())
            select(replacement)
            assertMeasuredReadiness(group)
            assertTrue(now-completed<=30_000)
            return current to replacement
        }
        // Sixteen routes share a finite hourly budget. A successful replacement cannot
        // freshen observations on other routes while their individual measurements age.
        fun assertMeasuredReadiness(recoveredGroup: String? = null) {
            val snapshot = RouteSnapshot.readAt(true, true, h.scope, now)
            val rows = snapshot.getJSONArray("routes")
            assertEquals(selectedAt.size, rows.length())
            var allWorking = true
            for (i in 0 until rows.length()) {
                val row = rows.getJSONObject(i)
                val group = row.getString("label").replaceFirst("managed-", "group-")
                val age = now - selectedAt.getValue(group).last()
                val working = age in 0..120_000
                assertEquals("Measurement changed for $group", age, row.getLong("ageMs"))
                assertEquals(group, if (working) "working" else "stale", row.getString("state"))
                if (group == recoveredGroup) assertTrue("Replacement requires fresh payload evidence", working)
                allWorking = allWorking && working
            }
            assertEquals(allWorking, snapshot.getBoolean("requiredReady"))
        }

        fun observations(): Map<String, List<Any>> {
            val rows=RouteSnapshot.readAt(true, true, h.scope, now).getJSONArray("routes")
            return (0 until rows.length()).associate { i ->
                val row=rows.getJSONObject(i)
                row.getString("label") to listOf(now-row.getLong("ageMs"), row.getString("reason"),
                    row.getJSONArray("measuredPath").toString())
            }
        }
        fun signature(): Map<String, String> {
            val rows=h.view().getJSONArray("routes")
            return (0 until rows.length()).associate {i ->
                val row=rows.getJSONObject(i)
                row.getString("label") to listOf(row.getString("state"), row.getString("reason"), row.getJSONArray("measuredPath").toString()).joinToString("|")
            }
        }
        fun routineStarts()=h.starts.filter {it.second.getString("request") !in initialRequests && it.second.getString("request") !in recoveryRequests}
        override fun close()=h.close()
    }

    @Test fun sixteenHealthyGroupsReserveRecoveryAfterNinetySixForcedRoutineStarts() {
        Sim(groupCount=16).use {s ->
            s.initialize(16)
            var at=601_000L
            while(s.routineStarts().size<96 && at<3_000_000) {
                s.h.controller.force()
                s.tick(at)?.let {probe ->
                    assertEquals("hop-000", probe.getJSONArray("hops").getString(0))
                    s.select(probe)
                }
                at+=1000
            }
            assertEquals(96, s.routineStarts().size); assertEquals(112, s.h.starts.size)
            val last=s.h.starts.last().first
            // Let the minute cap expire too: the remaining block must be the
            // rolling96/hour routine ceiling, not an incidental short pause.
            for(now in last+1000..last+61_000 step 1000) {
                s.h.controller.force(); assertNull(s.tick(now))
            }
            assertEquals(112, s.h.starts.size)
            s.assertMeasuredReadiness()
            val before=s.observations()
            val completed=s.now
            val (a, b)=s.recover()
            assertEquals("hop-000", a.getJSONArray("hops").getString(0)); assertEquals("hop-001", b.getJSONArray("hops").getString(0))
            assertTrue(s.now-completed<=30_000); assertEquals(114, s.h.starts.size)
            val after=s.observations()
            for((tag, value) in before) if(tag!="managed-00") assertEquals("unrelated route changed during recovery", value, after[tag])
            assertEquals(96, s.routineStarts().size)
            assertFalse(s.h.controller.requiresRetirement())
        }
    }

    @Test fun malformedStaleForeignAndOldABASelectionHintsCannotChangeRoutesOrStartWork() {
        val variants=listOf<Pair<String, (Sim)->Any>>(
            "null array" to {JSONObject.NULL}, "object instead of array" to {JSONObject()},
            "nonobject member" to {JSONArray().put("foreign")}, "null member" to {JSONArray().put(JSONObject.NULL)},
            "extra field" to {s -> JSONArray().put(s.hint(completed=32_000).put("extra", "foreign"))},
            "missing field" to {s -> JSONArray().put(s.hint(completed=32_000).also {it.remove("code")})},
            "foreign code" to {s -> JSONArray().put(s.hint(completed=32_000).put("code", "confirmed_bad_proxy"))},
            "token string" to {s -> JSONArray().put(s.hint(completed=32_000).put("selectionToken", "1"))},
            "token float" to {s -> JSONArray().put(s.hint(completed=32_000).put("selectionToken", 1.0))},
            "token null" to {s -> JSONArray().put(s.hint(completed=32_000).put("selectionToken", JSONObject.NULL))},
            "token boolean" to {s -> JSONArray().put(s.hint(completed=32_000).put("selectionToken", true))},
            "token zero" to {s -> JSONArray().put(s.hint(token=0, completed=32_000))},
            "foreign token" to {s -> JSONArray().put(s.hint(token=2, completed=32_000))},
            "token overflow" to {s -> JSONArray().put(s.hint(token=9_007_199_254_740_992L, completed=32_000))},
            "sequence string" to {s -> JSONArray().put(s.hint(completed=32_000).put("sequence", "1"))},
            "sequence zero" to {s -> JSONArray().put(s.hint(sequence=0, completed=32_000))},
            "sequence overflow" to {s -> JSONArray().put(s.hint(sequence=9_007_199_254_740_992L, completed=32_000))},
            "timestamp string" to {s -> JSONArray().put(s.hint(completed=32_000).put("completedBootMs", "32000"))},
            "timestamp null" to {s -> JSONArray().put(s.hint(completed=32_000).put("completedBootMs", JSONObject.NULL))},
            "timestamp zero" to {s -> JSONArray().put(s.hint(completed=0))},
            "stale" to {s -> JSONArray().put(s.hint(completed=2000))},
            "future" to {s -> JSONArray().put(s.hint(completed=32_002))},
            "duplicate group" to {s -> JSONArray().put(s.hint(completed=32_000)).put(s.hint(sequence=2, completed=32_000))},
            "more than sixteen" to {s -> JSONArray().also {a -> repeat(17) {a.put(s.hint(sequence=it+1L, completed=32_000))}}},
            "atomic rejection" to {s -> JSONArray().put(s.hint(completed=32_000)).put(s.hint(completed=32_000).put("group", "unknown-group"))},
        )
        for((name, variant) in variants) Sim().use {s ->
            s.initialize(1); val before=s.signature()
            s.hints(variant(s), 32_001)
            assertNull(name, s.tick(37_001)); assertEquals(name, 1, s.h.starts.size)
            assertEquals(name, before, s.signature()); assertFalse(name, s.h.controller.requiresRetirement())
        }
        for(outer in listOf("policy", "scope", "old epoch", "new epoch")) Sim().use {s ->
            s.initialize(1); val before=s.signature()
            s.hints(JSONArray().put(s.hint(completed=2000)), 2000) {frame ->
                when(outer) {
                    "policy" -> frame.put("policyScope", Policy.hash("synthetic-foreign-policy"))
                    "scope" -> frame.put("scope", Policy.hash("synthetic-foreign-native"))
                    "old epoch" -> frame.put("nativeEpoch", 0L)
                    else -> frame.put("nativeEpoch", s.h.epoch+1)
                }
            }
            assertNull(outer, s.tick(6000)); assertEquals(outer, before, s.signature())
        }
        Sim().use {s ->
            s.initialize(1); s.now=2000; s.recover(); assertEquals(2L, s.tokens.getValue("group-00"))
            s.now+=1000; s.recover(); assertEquals(3L, s.tokens.getValue("group-00"))
            assertEquals("hop-000", s.h.view().getJSONArray("routes").getJSONObject(0).getJSONArray("measuredPath").getString(0))
            val before=s.signature()
            s.hints(JSONArray().put(s.hint(token=1, sequence=99)), s.now+1000)
            assertNull(s.tick(s.now+5000)); assertEquals(before, s.signature())
            s.hints(JSONArray().put(s.hint(token=2, sequence=100)), s.now+1000)
            assertNull(s.tick(s.now+5000)); assertEquals(before, s.signature())
            s.hints(JSONArray().put(s.hint(token=3)), s.now+1000)
            assertEquals("hop-000", s.awaitStart(s.now+10_000).getJSONArray("hops").getString(0))
        }
    }

    @Test fun duplicateHeartbeatsDoNotRequeueACompletedHintOrGrantMissingACKToken() {
        Sim().use {s ->
            s.initialize(1)
            val hint=s.hint(completed=2000)
            s.hints(JSONArray().put(hint), 2000)
            val probe=checkNotNull(s.tick(6000)); s.recoveryRequests+=probe.getString("request")
            s.h.acknowledge(s.frame(probe, "probe_unavailable").put("groupSelected", true), 6000)
            val after=s.signature()
            for(at in listOf(7000L, 11_000L, 20_000L, 32_001L)) {
                s.hints(JSONArray().put(JSONObject(hint.toString())), at)
                assertNull(s.tick(at)); assertEquals(after, s.signature())
            }
            assertEquals(2, s.h.starts.size)
            assertEquals(2000L, hint.getLong("completedBootMs"))
            // The one passive hint did not quarantine A; natural maintenance
            // can still verify the same path without a new hint or cold reset.
            val routine=checkNotNull(s.tick(61_000)); assertEquals("hop-000", routine.getJSONArray("hops").getString(0)); s.select(routine)
            assertTrue(s.h.view().getBoolean("requiredReady"))
        }
        Sim().use {s ->
            val first=checkNotNull(s.tick(1000)); s.select(first, token=null)
            assertTrue(s.h.view().getBoolean("requiredReady"))
            s.hints(JSONArray().put(s.hint(token=1, completed=2000)), 2000)
            assertNull(s.tick(6000)); assertEquals(1, s.h.starts.size)
            val routine=checkNotNull(s.tick(61_000)); s.select(routine, token=2)
            s.hints(JSONArray().put(s.hint(token=1, sequence=500, completed=62_000)), 62_000)
            assertNull(s.tick(66_000))
            s.hints(JSONArray().put(s.hint(token=2, completed=67_000)), 67_000)
            assertNotNull(s.tick(67_000))
        }
    }

    @Test fun busyAndPendingNativeOwnersKeepOneAdmissionAndHungOwnerRequiresRetirement() {
        Sim().use {s ->
            s.initialize(1); val before=s.signature()
            s.hints(JSONArray().put(s.hint(completed=2000)), 2000) {it.put("running", true).put("workAgeMs", 1000)}
            assertNull(s.tick(6000)); assertEquals(1, s.h.starts.size); assertEquals(before, s.signature())
            s.hints(JSONArray().put(s.hint(completed=2000)), 7000)
            val pending=checkNotNull(s.tick(7000))
            s.hints(JSONArray().put(s.hint(sequence=2, completed=8000)), 8000) {it.put("running", true).put("workAgeMs", 1000)}
            assertNull(s.tick(12_000)); assertEquals(2, s.h.starts.size); assertEquals(before, s.signature())
            s.hints(JSONArray().put(s.hint(sequence=3, completed=43_001)), 43_001) {it.put("running", true).put("workAgeMs", 36_001)}
            assertTrue(s.h.controller.requiresRetirement()); assertNull(s.tick(44_000)); assertEquals(2, s.h.starts.size)
            assertEquals(before, s.signature())
            assertEquals("group-00", pending.getString("group"))
        }
    }

    @Test fun wrongSelectedReceiptCannotMintTokenOrReadinessAndValidACKIsConsumedOnce() {
        Sim().use {s ->
            val probe=checkNotNull(s.tick(1000)); val commit=s.h.verified(probe, 1000)
            assertEquals("commit", commit.getString("command"))
            val valid=s.selectedAck(probe, commit, token=1)
            s.h.acknowledge(JSONObject(valid.toString()).put("receipt", Policy.hash("synthetic-other-receipt")), 1000)
            assertFalse(s.h.view().getBoolean("requiredReady"))
            s.hints(JSONArray().put(s.hint(token=1, completed=2000)), 2000)
            assertNull(s.tick(6000)); assertFalse(s.h.view().getBoolean("requiredReady")); assertEquals(1, s.h.starts.size)
            s.h.acknowledge(valid, 6000); s.tokens["group-00"]=1
            assertTrue(s.h.view().getBoolean("requiredReady"))
            val count=s.h.commands.size
            s.h.acknowledge(valid, 6000)
            assertEquals(count, s.h.commands.size)
            s.hints(JSONArray().put(s.hint(completed=7000)), 7000)
            val current=checkNotNull(s.tick(7000)); assertEquals("hop-000", current.getJSONArray("hops").getString(0))
            assertEquals(2, s.h.starts.size)
        }
    }

    @Test fun sixteenGroupsSustainTwoHoursOfPacedMaintenanceWithRecoveryCapacity() {
        Sim(groupCount=16).use {s ->
            s.initialize(16)
            var at=s.now+1000
            var recovered=false
            while(at<=7_200_000) {
                if(!recovered && at>=3_900_000) {
                    s.now=at; s.recover(); recovered=true; at=s.now+1000
                    continue
                }
                s.tick(at)?.let {s.select(it)}
                at+=1000
            }
            assertTrue(recovered); s.assertMeasuredReadiness()
            assertTrue("maintenance could not sustain16 groups", s.routineStarts().size>=144)
            for((group, times) in s.selectedAt) {
                assertTrue("group $group lost repeated maintenance", times.size>=9)
                for((previous, next) in times.zipWithNext()) assertTrue("group $group exceeded paced maintenance plus bounded admission delay", next-previous<=720_000)
            }
            val routine=s.routineStarts()
            for((time, _) in routine) {
                assertTrue("routine minute reserve was spent", routine.count {it.first<=time && time-it.first<60_000}<=6)
                assertTrue("routine hourly reserve was spent", routine.count {it.first<=time && time-it.first<3_600_000}<=96)
            }
            assertEquals(16, s.tokens.size); assertEquals(2, s.recoveryRequests.size)
            assertFalse(s.h.controller.requiresRetirement())
        }
    }

    @Test fun forceAndRealContextChangesPreserveMinuteAdmissionDebt() {
        Sim().use {s ->
            s.initialize(1)
            for(at in 61_000L..86_000L step 5000) {
                s.h.controller.force(); s.select(checkNotNull(s.tick(at)))
            }
            assertEquals(6, s.routineStarts().size)
            s.h.controller.force(); assertNull(s.tick(91_000))
            for(at in listOf(91_000L, 96_000L)) {
                s.h.rebind(at)
                val recovery=checkNotNull(s.tick(at)); s.recoveryRequests+=recovery.getString("request"); s.select(recovery)
            }
            s.h.rebind(101_000); s.h.controller.force()
            val before=s.h.starts.size
            assertNull(s.tick(101_000)); assertEquals(before, s.h.starts.size)
            assertEquals(8, s.h.starts.count {101_000-it.first<60_000})
            val recovered=checkNotNull(s.tick(121_000)); s.select(recovered)
            assertTrue(s.h.view().getBoolean("requiredReady")); assertFalse(s.h.controller.requiresRetirement())
        }
    }
}
