package io.syn443.android

import org.junit.Assert.assertTrue
import org.junit.Test

/** Check the actual running ART limit, independently of Android properties. */
class RuntimeHeapTest {
    @Test fun actualArtHeapSupportsTheMandatoryStorageAndUiSuite() {
        val limit = Runtime.getRuntime().maxMemory()
        assertTrue("Running ART heap is too small: $limit bytes", limit >= 64L * 1024 * 1024)
    }
}
