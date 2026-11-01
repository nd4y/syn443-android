package io.syn443.android

import androidx.core.net.toUri
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.EngineExitDiagnostics as D
import org.junit.Assert.*
import org.junit.Test
import org.json.JSONObject

class EngineExitDiagnosticsTest {
    private val process = "io.syn443.synthetic:engine"
    @Test fun exitSnapshotFiltersRolesBoundsAndSortsWithoutIdentifiers() {
        val observations = (1..31).map { D.Observation(it, process, 5, 6, it.toLong()) } +
            D.Observation(80, "foreign", 5, 6, 40)
        val result = D.render(process, 100) { observations }.getJSONArray("exits")
        assertEquals(4, result.length())
        assertEquals(31L, result.getJSONObject(0).getLong("at"))
        assertEquals("unavailable", D.render(process,100) { (observations + observations) }.getString("state"))
        for (i in 0 until result.length()) assertEquals(setOf("kind","at","status"), result.getJSONObject(i).keys().asSequence().toSet())
        assertFalse(result.toString().contains(process))
    }
    @Test fun exitCategoriesAreFixedAndUnknownReasonCannotBecomeCrash() {
        val kinds = mapOf(1 to "self_exit",2 to "signal",3 to "low_memory",4 to "java_crash",5 to "native_crash",6 to "anr",8 to "os_request",10 to "os_request",11 to "os_request",15 to "os_request",16 to "os_request",900 to "other")
        for ((code,kind) in kinds) {
            val result=D.render(process,100) {listOf(D.Observation(1,process,code,900,90))}.getJSONArray("exits").getJSONObject(0)
            assertEquals(kind,result.getString("kind"))
            assertFalse(result.has("status"))
            val valid=D.render(process,100) {listOf(D.Observation(1,process,code,6,90))}.getJSONArray("exits").getJSONObject(0)
            assertEquals(code in 1..2 || code==5,valid.has("status"))
            if(valid.has("status")) assertEquals(6,valid.getInt("status"))
        }
    }
    @Test fun exitReadFailureAndInvalidQueryReturnUnavailableWithoutText() {
        val error=D.render(process,100) {error("private exception value")}
        assertEquals("unavailable",error.getString("state"));assertEquals(0,error.getJSONArray("exits").length())
        assertFalse(error.toString().contains("private"))
        assertEquals("unavailable",D.render(process,100,0) {emptyList()}.getString("state"))
    }
    @Test fun exitPidFilterRejectsStaleFutureAndForeignRecords() {
        val entries=listOf(D.Observation(1,process,5,6,90),D.Observation(2,process,4,0,80),
            D.Observation(2,process,5,6,101),D.Observation(2,process,5,6,0),D.Observation(2,"foreign",5,6,95))
        val result=D.render(process,100,2) {entries}.getJSONArray("exits")
        assertEquals(1,result.length());assertEquals("java_crash",result.getJSONObject(0).getString("kind"))
    }
    @Test fun exitMetadataReadsRealPlatformWithoutChangingIntent() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        fun call(method:String):JSONObject {
            val result=checkNotNull(context.contentResolver.call("content://io.syn443.control".toUri(),method,null,null))
            assertTrue(result.getBoolean("ok"));return JSONObject(checkNotNull(result.getString("json")))
        }
        val before=call("status");val result=call("engine-exits");val after=call("status")
        assertEquals(1,result.getInt("schemaVersion"));assertTrue(result.getJSONArray("exits").length()<=4)
        assertEquals(if(android.os.Build.VERSION.SDK_INT<30) "unsupported" else "available",result.getString("state"))
        for(key in listOf("generation","desiredOn","configRevision")) assertEquals(before.opt(key),after.opt(key))
    }
    @Test fun emptyExitHistoryIsAvailableAndDoesNotInventSuccess() {
        val result=D.render(process,100) {emptyList()}
        assertEquals("available",result.getString("state"));assertEquals(0,result.getJSONArray("exits").length())
        assertEquals(0,D.render(process,0) {listOf(D.Observation(1,process,5,6,1))}.getJSONArray("exits").length())
        assertEquals(1,D.render(process,100) {listOf(D.Observation(1,process,5,6,100))}.getJSONArray("exits").length())
    }
}
