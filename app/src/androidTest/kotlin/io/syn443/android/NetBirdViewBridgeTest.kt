package io.syn443.android

import android.os.ParcelFileDescriptor
import android.util.Log
import bridge.Bridge
import bridge.Protector
import io.syn443.android.vpn.OverlayViewRequest
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.Description
import org.junit.runner.notification.Failure
import org.junit.runner.notification.RunListener

class NetBirdViewBridgeTest {
    @Test fun nativeViewBridgeExistsAndInactiveQueryStartsNoEngineOrProbe() {
        val valid = """{"kind":"overlay-view","section":"peers","page":0,"request":"view-test"}"""
        assertEquals(OverlayViewRequest("peers", 0, "view-test"), OverlayViewRequest.parse(valid))
        assertEquals(63, OverlayViewRequest.parse(valid.replace("\"page\":0", "\"page\":63"))?.page)
        val invalid = listOf(valid + "{}", valid.replace("\"page\":0", "\"page\":64"),
            valid.replace("\"page\":0", "\"page\":\"0\""), valid.replace("\"page\":0", "\"page\":01"),
            valid.replace("\"page\":0", "\"page\":-1"), valid.replace("\"page\":0", "\"page\":0.0"),
            valid.replace("\"request\":\"view-test\"", "\"page\":0"), valid.replace("peers", "other"),
            valid.replace("view-test", "a".repeat(65)), valid.replace("view-test", "é"),
            valid.replace("\"kind\"", "kind"), valid.replace("\"request\"", "\"unknown\""),
            valid.replace("\"request\":\"view-test\"", "\"request\":true"), " ".repeat(1025), "{}")
        for (raw in invalid) assertNull("malformed local view accepted", OverlayViewRequest.parse(raw))
        assertNull(OverlayViewRequest.parse(null))
        // Construct through the packaged public API, without starting an engine,
        // opening a TUN, acquiring a managed owner or using a managed lease.
        val protects = AtomicInteger()
        val dns = AtomicInteger()
        val interfaces = AtomicInteger()
        val protector = object : Protector {
            override fun protect(socket: Int) {
                protects.incrementAndGet()
                error("unexpected synthetic protect call")
            }
            override fun exchangeDNS(query: ByteArray): ByteArray {
                dns.incrementAndGet()
                error("unexpected synthetic DNS call")
            }
            override fun physicalInterfaces(): String {
                interfaces.incrementAndGet()
                error("unexpected synthetic interface call")
            }
        }
        ParcelFileDescriptor.open(File("/dev/null"), ParcelFileDescriptor.MODE_READ_WRITE).use { fd ->
            NetBirdTestProgress.phase(NetBirdBridgePhase.CONSTRUCT)
            val runtime = Bridge.newRuntime(
                """{"log":{"disabled":true},"inbounds":[],"outbounds":[{"type":"direct","tag":"synthetic-direct"}],"route":{"final":"synthetic-direct"}}""",
                "", fd.fd, protector, "synthetic-inactive", 1, 0L,
            )
            try {
                NetBirdTestProgress.phase(NetBirdBridgePhase.LOOKUP)
                val method = runtime.javaClass.getMethod("netBirdView", String::class.java)
                assertEquals(Boolean::class.javaPrimitiveType, method.returnType)
                for ((phase, raw) in listOf(
                    NetBirdBridgePhase.VIEW_PEERS to valid,
                    NetBirdBridgePhase.DIAGNOSTICS to valid.replace("peers", "diagnostics"),
                    NetBirdBridgePhase.INVALID to "{}",
                )) {
                    NetBirdTestProgress.phase(phase)
                    assertEquals(false, method.invoke(runtime, raw))
                }
            } finally {
                NetBirdTestProgress.phase(NetBirdBridgePhase.CLOSE)
                runtime.close()
            }
        }
        assertEquals(0, protects.get())
        assertEquals(0, dns.get())
        assertEquals(0, interfaces.get())
    }
}

internal enum class NetBirdBridgePhase(val label: String) {
    CONSTRUCT("construct"), LOOKUP("lookup"), VIEW_PEERS("view_peers"),
    DIAGNOSTICS("diagnostics"), INVALID("invalid"), CLOSE("close"),
}

/** Test APK diagnostics only. FINISH is a lifecycle event, never PASS evidence. */
class NetBirdTestProgress : RunListener() {
    override fun testStarted(description: Description) = event("START", description)
    override fun testFinished(description: Description) = event("FINISH", description)
    override fun testFailure(failure: Failure) = event("FAIL", failure.description)
    override fun testAssumptionFailure(failure: Failure) = event("FAIL", failure.description)
    override fun testIgnored(description: Description) = event("FAIL", description)

    private fun event(event: String, description: Description) {
        val type = description.className ?: return
        val method = description.methodName ?: return
        if (method !in methods[type].orEmpty()) return
        Log.i(TAG, "SYN443_TEST_PROGRESS $event $type#$method")
    }

    companion object {
        private const val TAG = "Syn443TestProgress"
        private const val BRIDGE = "io.syn443.android.NetBirdViewBridgeTest#nativeViewBridgeExistsAndInactiveQueryStartsNoEngineOrProbe"
        private val methods = mapOf(
            "io.syn443.android.NetBirdReportTest" to setOf(
                "unknownConnectionFieldsNeverBecomeDisconnectedZeroPeersOrVless",
                "knownAndLegacySnapshotsRetainExplicitConnectionAndProxyLabels",
                "pagedPeerCountsDistinguishDisplayedRetainedAndOmittedRows",
                "completedPartialCancelledAndUnknownCoverageNeverClaimAllChecked",
                "malformedPagesFieldsUtf8AndOverLimitPayloadsFailBounded",
            ),
            "io.syn443.android.NetBirdPagingUiTest" to setOf(
                "onlyCurrentViewResponseCompletesPendingPageWithoutExtraCommands",
                "peerAndDiagnosticPagingControlsRespectBoundsAndOutstandingRequests",
            ),
            "io.syn443.android.NetBirdViewBridgeTest" to setOf(
                "nativeViewBridgeExistsAndInactiveQueryStartsNoEngineOrProbe",
            ),
        )

        internal fun phase(phase: NetBirdBridgePhase) {
            Log.i(TAG, "SYN443_TEST_PROGRESS PHASE $BRIDGE ${phase.label}")
        }
    }
}
