package io.syn443.observability

/** Observed local clocks, never a trusted server clock or routing authority. */
data class EventClock(val boot: Int, val wallMs: Long, val elapsedMs: Long) {
    init {
        require(boot >= 0 && wallMs in 0..StructuredEvent.MAX_SAFE && elapsedMs in 0..StructuredEvent.MAX_SAFE) { "invalid_event_clock" }
    }
    override fun toString() = "EventClock([redacted])"
}

data class EventGenerations(val intent: Long, val network: Long, val activation: Long? = null, val engine: Long? = null) {
    init {
        require(intent in 0..StructuredEvent.MAX_SAFE && network in 0..StructuredEvent.MAX_SAFE &&
            (activation == null || activation in 0..StructuredEvent.MAX_SAFE) &&
            (engine == null || engine in 0..StructuredEvent.MAX_SAFE)) { "invalid_event_generations" }
    }
    override fun toString() = "EventGenerations([redacted])"
}

/** The Android producer supplies fresh local randomness, not an identity hash. */
class EventCorrelation private constructor(private val owned: ByteArray) {
    companion object {
        fun fromBytes(bytes: ByteArray): EventCorrelation {
            require(bytes.size == 16) { "invalid_event_correlation" }
            return EventCorrelation(bytes.copyOf())
        }
    }
    fun bytes(): ByteArray = owned.copyOf()
    override fun equals(other: Any?) = other is EventCorrelation && owned.contentEquals(other.owned)
    override fun hashCode() = owned.contentHashCode()
    override fun toString() = "EventCorrelation([redacted])"
}

enum class EventChannel(val wire: String) {
    LIFECYCLE("lifecycle"), NETWORK("network"), SELECTOR("selector"), DNS("dns"), ROUTING("routing"),
    PROTOCOL("protocol"), NETBIRD("netbird"), PROVISIONING("provisioning"), TELEMETRY("telemetry"), CRASH("crash");
    companion object {
        fun fromWire(raw: String?): EventChannel? = raw?.takeIf { it.length <= 16 }?.let { text -> entries.firstOrNull { it.wire == text } }
    }
}

enum class EventLevel(val wire: String) {
    ERROR("error"), WARN("warn"), INFO("info");
    companion object {
        fun fromWire(raw: String?): EventLevel? = raw?.takeIf { it.length <= 5 }?.let { text -> entries.firstOrNull { it.wire == text } }
    }
}

enum class EventPhase(val wire: String) {
    OFF("Off"), NEEDS_LOGIN("NeedsLogin"), NEEDS_PERMISSION("NeedsPermission"), NEEDS_UNLOCK("NeedsUnlock"),
    NEEDS_ACTION("NeedsAction"), NO_NETWORK("NoNetwork"), PORTAL("Portal"), DETECTING("Detecting"),
    CONNECTING("Connecting"), ONLINE("Online"), DEGRADED("Degraded"), RECOVERING("Recovering"), BLOCKED_BY_POLICY("BlockedByPolicy");
    companion object {
        fun fromWire(raw: String?): EventPhase? = raw?.takeIf { it.length <= 32 }?.let { text -> entries.firstOrNull { it.wire == text } }
    }
}

/** The existing DiagnosticProjection lifecycle catalog, plus one fixed fallback. */
enum class EventCode(val wire: String, val channel: EventChannel = EventChannel.LIFECYCLE) {
    AWAITING_IDENTITY_RELEASE("awaiting_identity_release"),
    CONFIGURATION_INVALID("configuration_invalid", EventChannel.PROVISIONING),
    CONFIGURATION_OR_CAPABILITY_INVALID("configuration_or_capability_invalid", EventChannel.PROVISIONING),
    CONTROLLER_RECREATED("controller_recreated"),
    DNS_RESOLUTION_FAILED("dns_resolution_failed", EventChannel.DNS), DNS_TIMEOUT("dns_timeout", EventChannel.DNS),
    EXPLICIT_RESUME_REQUIRED("explicit_resume_required"),
    HEALTH_POLICY_NOT_AUTHORIZED("health_policy_not_authorized", EventChannel.ROUTING),
    MANAGED_ROUTE_RECHECK("managed_route_recheck", EventChannel.SELECTOR),
    NATIVE_BIND_FAILED("native_bind_failed"), NATIVE_BINDING_DIED("native_binding_died"),
    NATIVE_BINDING_TIMEOUT("native_binding_timeout"), NATIVE_DIED("native_died"), NATIVE_DISCONNECTED("native_disconnected"),
    NATIVE_HANDSHAKE_FAILED("native_handshake_failed"), NATIVE_IPC_FAILED("native_ipc_failed"), NATIVE_LATE_START("native_late_start"),
    NATIVE_LEASE_UPDATE_FAILED("native_lease_update_failed"), NATIVE_NULL_BINDING("native_null_binding"),
    NATIVE_PROGRESS_TIMEOUT("native_progress_timeout"), NATIVE_RESTART_BUDGET("native_restart_budget"),
    NATIVE_START("native_start"), NATIVE_START_FAILED("native_start_failed"),
    NETWORK_CHANGED("network_changed", EventChannel.NETWORK), NETWORK_UNAVAILABLE("network_unavailable", EventChannel.NETWORK),
    NETWORK_UPDATE_FAILED("network_update_failed", EventChannel.NETWORK),
    OVERLAY_CREDENTIALS_PENDING("overlay_credentials_pending", EventChannel.NETBIRD),
    OVERLAY_MATERIAL_CHANGED("overlay_material_changed", EventChannel.NETBIRD),
    POLICY_BASELINE_DEGRADED("policy_baseline_degraded", EventChannel.ROUTING),
    POLICY_CHECKS_UNAVAILABLE("policy_checks_unavailable", EventChannel.ROUTING),
    POLICY_GATE_PENDING("policy_gate_pending", EventChannel.ROUTING),
    POLICY_LEASE_TIME_OR_SCOPE_INVALID("policy_lease_time_or_scope_invalid", EventChannel.ROUTING),
    POLICY_ROLLBACK("policy_rollback", EventChannel.PROVISIONING), POLICY_STORE_UNAVAILABLE("policy_store_unavailable", EventChannel.PROVISIONING),
    POLICY_WAITING_RESTART_BUDGET("policy_waiting_restart_budget", EventChannel.ROUTING),
    REQUIRED_HTTPS_OK("required_https_ok", EventChannel.PROTOCOL),
    REQUIRED_ROUTE_UNVERIFIED_OR_FAILED("required_route_unverified_or_failed", EventChannel.ROUTING),
    RETRY_SCHEDULED("retry_scheduled"), START_FAILED("start_failed"), TCP_TIMEOUT("tcp_timeout", EventChannel.PROTOCOL),
    TLS_FAILED("tls_failed", EventChannel.PROTOCOL), TLS_TIMEOUT("tls_timeout", EventChannel.PROTOCOL),
    TRANSPORT_EOF("transport_eof", EventChannel.PROTOCOL), USER_STOP("user_stop"),
    VPN_PERMISSION_REQUIRED("vpn_permission_required"), VPN_PERMISSION_REVOKED("vpn_permission_revoked"), REDACTED("redacted");
    companion object {
        fun fromWire(raw: String?): EventCode = raw?.takeIf { it.length <= 64 }?.let { text -> entries.firstOrNull { it.wire == text } } ?: REDACTED
    }
}

enum class EngineSignal(val wire: String) {
    READY("ready"), FAILED("failed"), INVALID("invalid"), LEASE_RESTART("lease_restart");
    companion object {
        fun fromWire(raw: String?): EngineSignal? = raw?.takeIf { it.length <= 16 }?.let { text -> entries.firstOrNull { it.wire == text } }
    }
}

data class DecisionStamp(val policyRevision: Long, val algorithmRevision: Int) {
    init { require(policyRevision in 1..StructuredEvent.MAX_SAFE && algorithmRevision in 1..2) { "invalid_event_decision" } }
    override fun toString() = "DecisionStamp([redacted])"
}

sealed interface EventDetail {
    data class Lifecycle(val phase: EventPhase, val code: EventCode, val decision: DecisionStamp? = null) : EventDetail {
        init { require(decision == null || code == EventCode.MANAGED_ROUTE_RECHECK) { "invalid_event_decision_context" } }
        override fun toString() = "LifecycleEvent([redacted])"
    }
    data class Engine(val signal: EngineSignal) : EventDetail {
        override fun toString() = "EngineEvent([redacted])"
    }
}

/** Immutable allowlist metadata only; no maps, arbitrary strings, targets or authority. */
data class StructuredEvent(
    val sequence: Long,
    val clock: EventClock,
    val correlation: EventCorrelation,
    val generations: EventGenerations,
    val detail: EventDetail,
    val level: EventLevel = EventLevel.INFO,
) {
    companion object { const val MAX_SAFE = 9_007_199_254_740_991L }
    init { require(sequence in 1..MAX_SAFE) { "invalid_event_sequence" } }
    val source: Role get() = if (detail is EventDetail.Engine) Role.ENGINE else Role.CONTROLLER
    val channel: EventChannel get() = when (val item = detail) {
        is EventDetail.Lifecycle -> item.code.channel
        is EventDetail.Engine -> EventChannel.LIFECYCLE
    }
    override fun toString() = "StructuredEvent([redacted])"
}
