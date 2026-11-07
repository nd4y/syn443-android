package io.syn443.host

import org.junit.Assert.assertEquals
import org.junit.Test

class RouteReportWindowTest {
    @Test fun onlyTheAdmittedBatchCanPublishAndItsTerminalReportEndsPolling() {
        val window = RouteReportWindow("admitted", 100)
        assertEquals(RouteReportWindow.Decision.PUBLISH_AND_POLL, window.accept("admitted", true, 101))
        assertEquals(RouteReportWindow.Decision.PUBLISH_FINAL, window.accept("admitted", false, 2_101))
        assertEquals(RouteReportWindow.Decision.DISCARD, window.accept("admitted", false, 2_102))

        val replaced = RouteReportWindow("admitted", 100)
        assertEquals(RouteReportWindow.Decision.DISCARD, replaced.accept("replacement", true, 102))
        assertEquals(RouteReportWindow.Decision.DISCARD, replaced.accept("admitted", false, 103))
    }

    @Test fun anExpiredOrRegressedClockCannotKeepPolling() {
        val deadline = 100 + RouteReportWindow.MAX_AGE_MS
        val window = RouteReportWindow("admitted", 100)
        assertEquals(RouteReportWindow.Decision.PUBLISH_AND_POLL, window.accept("admitted", true, deadline - 1))
        assertEquals(RouteReportWindow.Decision.DISCARD, window.accept("admitted", false, deadline))
        val regressed = RouteReportWindow("admitted", 100)
        assertEquals(RouteReportWindow.Decision.PUBLISH_AND_POLL, regressed.accept("admitted", true, 200))
        assertEquals(RouteReportWindow.Decision.DISCARD, regressed.accept("admitted", true, 199))
    }
}
