package io.syn443.android

import android.os.SystemClock
import io.syn443.android.support.BundleShellConnection
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Test

class BundleShellConnectionTest {
    @Test fun onlyOwnerCanReleaseTheSingleExternalCall() {
        val session = BundleShellConnection(10_000)
        val first = "a".repeat(32)
        val other = "b".repeat(32)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val hold = executor.submit<String> { session.command("bundle-shell-hold", first) }
            val until = SystemClock.elapsedRealtime() + 4_000
            while (session.command("bundle-shell-state", first) == "absent" && SystemClock.elapsedRealtime() < until) Thread.sleep(10)
            assertEquals("held", session.command("bundle-shell-state", first))
            assertEquals("busy", session.command("bundle-shell-hold", other))
            assertEquals("absent", session.command("bundle-shell-release", other))
            assertEquals("busy", session.command("bundle-shell-state", other))
            assertEquals("released", session.command("bundle-shell-release", first))
            assertEquals("released", hold.get(4, TimeUnit.SECONDS))
            assertEquals("absent", session.command("bundle-shell-state", first))
        } finally {
            session.command("bundle-shell-release", first)
            executor.shutdownNow()
        }
    }

    @Test fun abandonedConnectionExpiresAndReleasesItsSlot() {
        val session = BundleShellConnection(20)
        val first = "a".repeat(32)
        val second = "b".repeat(32)
        assertEquals("expired", session.command("bundle-shell-hold", first))
        assertEquals("absent", session.command("bundle-shell-state", first))
        assertEquals("expired", session.command("bundle-shell-hold", second))
        assertEquals("absent", session.command("bundle-shell-release", first))
    }
}
