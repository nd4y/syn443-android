package io.syn443.emulatorheap;

import org.junit.Test;
import static org.junit.Assert.*;

public final class VmMemorySnapshotTest {
    @Test public void capturedTinyAndRepresentativeVmsRemainExactNumericEvidence() {
        assertEquals("{\"schemaVersion\":1,\"maxBytes\":16777216,\"totalBytes\":8388608,\"freeBytes\":1024,\"pid\":42,\"uptimeMs\":1000}",
                VmMemorySnapshot.encode(16L * 1024 * 1024, 8L * 1024 * 1024, 1024, 42, 1000));
        String maximum = VmMemorySnapshot.encode(VmMemorySnapshot.MAX_BYTES, VmMemorySnapshot.MAX_BYTES,
                VmMemorySnapshot.MAX_BYTES, Integer.MAX_VALUE, VmMemorySnapshot.MAX_TIME);
        assertTrue(maximum.length() <= VmMemorySnapshot.MAX_JSON);
        assertFalse(maximum.contains("error"));
    }

    @Test public void invalidCapacityAllocationProcessAndClockNeverBecomeSnapshots() {
        for (long[] values : new long[][] {
                {0, 0, 0, 1, 0}, {-1, 0, 0, 1, 0}, {VmMemorySnapshot.MAX_BYTES + 1, 0, 0, 1, 0},
                {64, -1, 0, 1, 0}, {64, 65, 0, 1, 0}, {64, 32, -1, 1, 0}, {64, 32, 33, 1, 0},
                {64, 32, 0, 0, 0}, {64, 32, 0, 1, -1}, {64, 32, 0, 1, VmMemorySnapshot.MAX_TIME + 1}
        }) {
            assertThrows(IllegalArgumentException.class,
                    () -> VmMemorySnapshot.encode(values[0], values[1], values[2], (int) values[3], values[4]));
        }
    }
}
