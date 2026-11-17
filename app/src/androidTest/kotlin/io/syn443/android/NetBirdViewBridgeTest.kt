package io.syn443.android

import io.syn443.android.vpn.OverlayViewRequest
import org.junit.Assert.*
import org.junit.Test

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
        // Exercise the packaged gomobile binding, not just a reflection name check.
        val type = Class.forName("bridge.Runtime")
        val method = type.getMethod("netBirdView", String::class.java)
        val runtime = type.getDeclaredConstructor().newInstance()
        for (raw in listOf(valid, valid.replace("peers", "diagnostics"), "{}"))
            assertEquals(false, method.invoke(runtime, raw))
    }
}
