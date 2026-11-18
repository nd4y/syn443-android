package io.syn443.observability

import org.junit.Assert.*
import org.junit.Test

class StructuredEventTest {
    private fun event(detail: EventDetail = EventDetail.Lifecycle(EventPhase.ONLINE, EventCode.REQUIRED_HTTPS_OK)) = StructuredEvent(
        1, EventClock(2, 1_000, 50), EventCorrelation.fromBytes(ByteArray(16) { it.toByte() }),
        EventGenerations(3, 4, 5, 6), detail,
    )
    private fun rejected(block: () -> Unit) {
        try { block(); fail("Invalid structured metadata accepted") } catch (_: IllegalArgumentException) { }
    }

    @Test fun knownLifecycleInputsProduceClosedChannelsAndGenerationStamps() {
        val phases = setOf("Off", "NeedsLogin", "NeedsPermission", "NeedsUnlock", "NeedsAction", "NoNetwork", "Portal",
            "Detecting", "Connecting", "Online", "Degraded", "Recovering", "BlockedByPolicy")
        val codes = """
            awaiting_identity_release configuration_invalid configuration_or_capability_invalid controller_recreated
            dns_resolution_failed dns_timeout explicit_resume_required health_policy_not_authorized managed_route_recheck
            native_bind_failed native_binding_died native_binding_timeout native_died native_disconnected native_handshake_failed
            native_ipc_failed native_late_start native_lease_update_failed native_null_binding native_progress_timeout
            native_restart_budget native_start native_start_failed network_changed network_unavailable network_update_failed
            overlay_credentials_pending overlay_material_changed policy_baseline_degraded policy_checks_unavailable
            policy_gate_pending policy_lease_time_or_scope_invalid policy_rollback policy_store_unavailable policy_waiting_restart_budget
            required_https_ok required_route_unverified_or_failed retry_scheduled start_failed tcp_timeout tls_failed tls_timeout
            transport_eof user_stop vpn_permission_required vpn_permission_revoked redacted
        """.trimIndent().split(Regex("\\s+")).toSet()
        assertEquals(phases, EventPhase.entries.map { it.wire }.toSet())
        assertEquals(codes, EventCode.entries.map { it.wire }.toSet())
        EventPhase.entries.forEach { assertSame(it, EventPhase.fromWire(it.wire)) }
        EventCode.entries.forEach { code ->
            assertSame(code, EventCode.fromWire(code.wire))
            val item = event(EventDetail.Lifecycle(EventPhase.RECOVERING, code))
            assertEquals(Role.CONTROLLER, item.source)
            assertEquals(code.channel, item.channel)
            assertEquals(EventGenerations(3, 4, 5, 6), item.generations)
            assertEquals(EventLevel.INFO, item.level)
        }
        EventChannel.entries.forEach { assertSame(it, EventChannel.fromWire(it.wire)) }
        EventLevel.entries.forEach { level ->
            assertSame(level, EventLevel.fromWire(level.wire))
            assertEquals(level, event().copy(level = level).level)
        }
        assertEquals(EventChannel.DNS, EventCode.DNS_TIMEOUT.channel)
        assertEquals(EventChannel.SELECTOR, EventCode.MANAGED_ROUTE_RECHECK.channel)
        assertEquals(EventChannel.NETWORK, EventCode.NETWORK_CHANGED.channel)
        assertEquals(EventChannel.PROVISIONING, EventCode.CONFIGURATION_INVALID.channel)
        assertEquals(EventChannel.NETBIRD, EventCode.OVERLAY_MATERIAL_CHANGED.channel)
    }

    @Test fun unknownPhasesAndSecretBearingCodesCannotBeRetained() {
        for (raw in listOf(null, "online", "Online ", "synthetic-secret", "x".repeat(65_536))) {
            assertNull(EventPhase.fromWire(raw))
        }
        for (raw in listOf(null, "NATIVE_START", "native_start\nsynthetic-secret", "headers=synthetic-token",
            "serviceName=synthetic-secret", "path=synthetic-secret", "subscriptionUrl=synthetic-secret", "x".repeat(65_536))) {
            val code = EventCode.fromWire(raw)
            assertEquals(EventCode.REDACTED, code)
            val item = event(EventDetail.Lifecycle(EventPhase.RECOVERING, code))
            assertEquals("redacted", (item.detail as EventDetail.Lifecycle).code.wire)
            assertEquals("StructuredEvent([redacted])", item.toString())
        }
        for (raw in listOf(null, "debug", "trace", "INFO", "x".repeat(65_536))) assertNull(EventLevel.fromWire(raw))
        for (raw in listOf(null, "unknown", "DNS", "x".repeat(65_536))) assertNull(EventChannel.fromWire(raw))
    }

    @Test fun correlationStorageAndReturnedBytesHaveNoMutableAliases() {
        val input = ByteArray(16) { it.toByte() }
        val original = input.copyOf()
        val correlation = EventCorrelation.fromBytes(input)
        val equal = EventCorrelation.fromBytes(original)
        val beforeHash = correlation.hashCode()
        input.fill(99)
        correlation.bytes().fill(88)
        assertArrayEquals(original, correlation.bytes())
        assertEquals(equal, correlation)
        assertEquals(beforeHash, correlation.hashCode())
        assertEquals(beforeHash, equal.hashCode())
        assertFalse(correlation.equals(null))
        assertFalse(correlation.equals("synthetic-secret"))
        assertNotEquals(correlation, EventCorrelation.fromBytes(ByteArray(16) { 42 }))
        assertEquals("EventCorrelation([redacted])", correlation.toString())
        for (size in listOf(0, 15, 17, 32)) rejected { EventCorrelation.fromBytes(ByteArray(size)) }
        val item = event().copy(correlation = correlation)
        assertArrayEquals(original, item.correlation.bytes())
    }

    @Test fun eventClockSequenceAndGenerationBoundsAreChecked() {
        val maximum = StructuredEvent.MAX_SAFE
        assertEquals(EventClock(0, 0, 0), EventClock(0, 0, 0).copy())
        assertEquals(maximum, EventClock(Int.MAX_VALUE, maximum, maximum).elapsedMs)
        rejected { EventClock(-1, 0, 0) }
        rejected { EventClock(0, -1, 0) }
        rejected { EventClock(0, maximum + 1, 0) }
        rejected { EventClock(0, 0, -1) }
        rejected { EventClock(0, 0, maximum + 1) }
        assertEquals(maximum, event().copy(sequence = maximum).sequence)
        rejected { event().copy(sequence = 0) }
        rejected { event().copy(sequence = maximum + 1) }
        assertEquals(EventGenerations(0, 0), EventGenerations(0, 0, null, null))
        assertEquals(maximum, EventGenerations(maximum, maximum, maximum, maximum).engine)
        for (invalid in listOf(-1L, maximum + 1)) {
            rejected { EventGenerations(invalid, 0) }
            rejected { EventGenerations(0, invalid) }
            rejected { EventGenerations(0, 0, invalid) }
            rejected { EventGenerations(0, 0, engine = invalid) }
        }
        assertEquals("EventClock([redacted])", event().clock.toString())
        assertEquals("EventGenerations([redacted])", event().generations.toString())
    }

    @Test fun finiteEngineSignalsRemainDistinctAndPulseIsNotAnEvent() {
        assertEquals(setOf("ready", "failed", "invalid", "lease_restart"), EngineSignal.entries.map { it.wire }.toSet())
        EngineSignal.entries.forEach { signal ->
            assertSame(signal, EngineSignal.fromWire(signal.wire))
            val item = event(EventDetail.Engine(signal))
            assertEquals(Role.ENGINE, item.source)
            assertEquals(EventChannel.LIFECYCLE, item.channel)
            assertEquals(signal, (item.detail as EventDetail.Engine).signal)
            assertEquals("EngineEvent([redacted])", item.detail.toString())
            assertNotEquals(event(EventDetail.Lifecycle(EventPhase.CONNECTING, EventCode.NATIVE_START)), item)
        }
        for (raw in listOf(null, "pulse", "READY", "synthetic-secret", "x".repeat(65_536))) assertNull(EngineSignal.fromWire(raw))
    }

    @Test fun managedDecisionFieldsRequireExactCodeAndPairedKnownRevision() {
        for (algorithm in 1..2) {
            val stamp = DecisionStamp(StructuredEvent.MAX_SAFE, algorithm)
            val detail = EventDetail.Lifecycle(EventPhase.RECOVERING, EventCode.MANAGED_ROUTE_RECHECK, stamp)
            assertEquals(stamp, (event(detail).detail as EventDetail.Lifecycle).decision)
            assertEquals("DecisionStamp([redacted])", stamp.toString())
            assertEquals("LifecycleEvent([redacted])", detail.toString())
            rejected { EventDetail.Lifecycle(EventPhase.ONLINE, EventCode.REQUIRED_HTTPS_OK, stamp) }
            rejected { EventDetail.Lifecycle(EventPhase.RECOVERING, EventCode.REDACTED, stamp) }
        }
        assertNull(EventDetail.Lifecycle(EventPhase.RECOVERING, EventCode.MANAGED_ROUTE_RECHECK).decision)
        rejected { DecisionStamp(0, 1) }
        rejected { DecisionStamp(StructuredEvent.MAX_SAFE + 1, 1) }
        rejected { DecisionStamp(1, 0) }
        rejected { DecisionStamp(1, 3) }
    }
}
