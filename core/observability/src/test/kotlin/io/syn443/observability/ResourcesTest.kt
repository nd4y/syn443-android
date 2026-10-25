package io.syn443.observability

import org.junit.Assert.*
import org.junit.Test

class ResourcesTest {
    private fun reading(identity: String = "synthetic", cpu: Long = 10) =
        Reading(Availability.AVAILABLE, Counters(identity, cpu, 2048, 3, 7))
    private fun stat(pid: Int = 42, user: String = "123", system: String = "7", start: String = "900"): String {
        val fields = MutableList(22) { "0" }
        fields[0] = "S"; fields[11] = user; fields[12] = system; fields[19] = start
        return "$pid (synthetic ) process) " + fields.joinToString(" ")
    }
    private val status = "Uid:\t12345\t12345\t12345\t12345\nVmRSS:\t2048 kB\nThreads:\t7\n"
    private fun rejected(block: () -> Unit) {
        try { block(); fail("Malformed counters accepted") } catch (_: IllegalArgumentException) { }
    }

    @Test fun firstSampleIsNotZeroCpuAndCacheDoesNoWork() {
        var reads = 0
        val sampler = ResourceSampler { reads++; reading() }
        val first = sampler.sample(100, 90)
        assertEquals(2, reads)
        assertEquals("baseline", first.processes[0].window.state)
        assertNull(first.processes[0].window.cpuPermille)
        val cached = sampler.sample(30_099, 30_089)
        assertTrue(cached.cached); assertEquals(29_999, cached.ageMs)
        assertEquals(2, reads)
        assertEquals(first.elapsedMs, cached.elapsedMs)
    }

    @Test fun exactIntervalMeasuresCpuAndSuspendSeparately() {
        var cpu = 20L
        val sampler = ResourceSampler { reading(cpu = cpu) }
        sampler.sample(100, 90)
        cpu += 15_000
        val report = sampler.sample(30_100, 10_090)
        assertFalse(report.cached)
        val window = report.processes[1].window
        assertEquals("measured", window.state)
        assertEquals(30_000L, window.elapsedMs); assertEquals(10_000L, window.awakeMs)
        assertEquals(15_000L, window.cpuMs); assertEquals(500L, window.cpuPermille)
    }

    @Test fun multipleCoresAreNotClampedToOneHundredPercent() {
        var cpu = 0L
        val sampler = ResourceSampler { reading(cpu = cpu) }
        sampler.sample(0, 0); cpu = 90_000
        assertEquals(3000L, sampler.sample(30_000, 30_000).processes[0].window.cpuPermille)
    }

    @Test fun sequentialClockReadsAndMillisecondQuantizationDoNotResetWindow() {
        val sampler = ResourceSampler { reading() }
        sampler.sample(100, 99)
        val rounded = sampler.sample(30_100, 30_100)
        assertEquals("measured", rounded.processes[0].window.state)
        assertEquals(30_000L, rounded.processes[0].window.awakeMs)
        val bracketed = ResourceSampler { reading() }
        bracketed.sample(100, 80, 20)
        assertEquals("measured", bracketed.sample(30_100, 30_100).processes[0].window.state)
        val invalid = ResourceSampler { reading() }
        invalid.sample(100, 78, 20)
        assertEquals("clock_reset", invalid.sample(30_100, 30_100).processes[0].window.state)
        rejected { sampler.sample(60_100, 60_100, -1) }
        rejected { sampler.sample(60_100, 60_100, 1001) }
    }

    @Test fun processReplacementAndCounterResetCreateNewBaselines() {
        var id = "a"; var cpu = 40L
        val sampler = ResourceSampler { reading(id, cpu) }
        sampler.sample(0, 0); id = "b"
        assertEquals("process_changed", sampler.sample(30_000, 30_000).processes[0].window.state)
        cpu = 10
        assertEquals("counter_reset", sampler.sample(60_000, 60_000).processes[0].window.state)
        cpu = 20
        assertEquals("measured", sampler.sample(90_000, 90_000).processes[0].window.state)
    }

    @Test fun missingAndDeniedProcessesStayUnknownAndCannotReuseOldBaseline() {
        var available = false
        val sampler = ResourceSampler { role ->
            if (available) reading() else if (role == Role.ENGINE) Reading(Availability.NOT_RUNNING) else error("private error must not escape")
        }
        val missing = sampler.sample(0, 0)
        assertEquals(Availability.UNAVAILABLE, missing.processes[0].reading.state)
        assertEquals(Availability.NOT_RUNNING, missing.processes[1].reading.state)
        assertNull(missing.processes[0].reading.counters)
        assertNull(missing.processes[1].window.cpuPermille)
        available = true
        assertEquals("baseline", sampler.sample(30_000, 30_000).processes[1].window.state)
    }

    @Test fun clockResetNeverReusesCachedCpuWindow() {
        val sampler = ResourceSampler { reading() }
        sampler.sample(40_000, 30_000)
        assertEquals("clock_reset", sampler.sample(39_999, 29_999).processes[0].window.state)
        assertEquals("clock_reset", sampler.sample(80_000, 20_000).processes[0].window.state)
        assertEquals("clock_reset", sampler.sample(110_000, 90_000).processes[0].window.state)
        rejected { sampler.sample(-1, 0) }; rejected { sampler.sample(10, 11) }
    }

    @Test fun procParsingChecksOwnerIdentityUnitsAndUnusualCommandName() {
        val counters = ProcCounters.parse(stat(), status, 17, 42, 12345, 100)
        assertEquals("42:900", counters.identity); assertEquals(1300, counters.cpuMs)
        assertEquals(2_097_152L, counters.rssBytes); assertEquals(7, counters.threads); assertEquals(17, counters.fds)
        val unavailable = ProcCounters.parse(stat(), "Uid: 12345 12345 12345 12345", null, 42, 12345, 1024)
        assertNull(unavailable.rssBytes); assertNull(unavailable.threads); assertNull(unavailable.fds)
        assertEquals(126, unavailable.cpuMs)
    }

    @Test fun procRejectsForeignOwnersInvalidCountsAndTruncation() {
        rejected { ProcCounters.parse(stat(), status, null, 43, 12345, 100) }
        rejected { ProcCounters.parse(stat(), status, null, 42, 2000, 100) }
        rejected { ProcCounters.parse(stat(), status.replace("Uid:", "NoUid:"), null, 42, 12345, 100) }
        rejected { ProcCounters.parse("42 (short) S", status, null, 42, 12345, 100) }
        rejected { ProcCounters.parse(stat(), status, -1, 42, 12345, 100) }
        rejected { ProcCounters.parse(stat(), status, 4097, 42, 12345, 100) }
        rejected { ProcCounters.parse(stat(), status, null, 0, 12345, 100) }
        rejected { ProcCounters.parse(stat(), status, null, 42, 12345, 0) }
        rejected { ProcCounters.parse(stat(), status.repeat(1024), null, 42, 12345, 100) }
        rejected { ProcCounters.parse(stat(user = "-1"), status, null, 42, 12345, 100) }
        rejected { ProcCounters.parse(stat(), status.replace("kB", "MB"), null, 42, 12345, 100) }
        rejected { ProcCounters.parse(stat(), status.replace("Threads:\t7", "Threads:\t0"), null, 42, 12345, 100) }
    }

    @Test fun procArithmeticNeverWrapsLargeCounters() {
        for (input in listOf(stat(user = Long.MAX_VALUE.toString(), system = "1"), stat(user = Long.MAX_VALUE.toString(), system = "0"))) {
            try { ProcCounters.parse(input, status, null, 42, 12345, 1); fail("Overflow accepted") } catch (_: ArithmeticException) { }
        }
        try {
            ProcCounters.parse(stat(), status.replace("2048 kB", "${Long.MAX_VALUE} kB"), null, 42, 12345, 100)
            fail("RSS overflow accepted")
        } catch (_: ArithmeticException) { }
    }
}
