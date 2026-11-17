package io.syn443.android

import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.admin.*
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Pure same-UID presentation codec tests. No account, credential, storage, HTTP or VPN mutations. */
class AdminEditorWireTest {
    private fun <T> worker(action:()->T):T {
        val executor=Executors.newSingleThreadExecutor()
        try {return executor.submit<T> {action()}.get(30,TimeUnit.SECONDS)}
        finally {executor.shutdownNow();check(executor.awaitTermination(5,TimeUnit.SECONDS))}
    }
    private fun bytes(value:String)=value.toByteArray(Charsets.UTF_8)
    private fun model(pages:List<String> = emptyList(),parents:List<AdminEditorParent> = emptyList(),
        recipients:List<String> = emptyList(),differences:List<String> = emptyList(),error:String="",deadline:Long=0,
        localRevision:Long=0,comparisonBinding:String="")=AdminEditorModel(device="synthetic-device",privateDraftRevision=3,desiredHeadRevision=7,
        localRevision=localRevision,phase=AdminEditorPhase.REVIEW,busy=true,readOnly=true,unassigned=true,
        documentBinding="document-a",pages=pages,parents=parents,reviewBinding="review-a",reviewDeadlineElapsed=deadline,
        recipients=recipients,diffSummaries=differences,error=error,comparisonBinding=comparisonBinding)
    private fun failure(code:String="INVALID_REPLY",action:()->Unit) {
        val caught=assertThrows(AdminUiFailure::class.java,action)
        assertEquals(code,caught.code);assertEquals("administrative_operation_failed",caught.message);assertNull(caught.cause)
        assertFalse(caught.toString().contains("private-value"))
    }
    private fun raw()=AdminEditorWire.encode(AdminEditorModel()).toString(Charsets.UTF_8)
    private fun array(values:List<String>)=values.joinToString(",","[","]") {JsonPrimitive(it).toString()}
    private fun encoded(value:ByteArray)=Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun encodedArray(values:List<String>)=array(values.map {encoded(bytes(it))})

    @Test fun closedModelRoundTripRetainsEveryFieldLocalRevisionEscapesAndOwnedCollections()=worker {
        val pages=mutableListOf("{\"private-value\":true}","Русский текст \uD83D\uDE00 \" \\ /\n\t\u0000\u2028\u2029")
        val parents=mutableListOf(AdminEditorParent("template","template-a",2),AdminEditorParent("group","group-a",4))
        val recipients=mutableListOf("device-a","device-b");val differences=mutableListOf("/network: изменение \uD83D\uDE00")
        val original=model(pages,parents,recipients,differences,"REVIEW_EXPIRED",60_000,13,encoded(ByteArray(32) {3}))
        pages.clear();parents.clear();recipients.clear();differences.clear()
        val encoded=AdminEditorWire.encode(original);val preserved=encoded.copyOf()
        val decoded=AdminEditorWire.decode(encoded);encoded.fill(0)
        assertEquals(original.device,decoded.device);assertEquals(original.privateDraftRevision,decoded.privateDraftRevision)
        assertEquals(original.desiredHeadRevision,decoded.desiredHeadRevision);assertEquals(13L,decoded.localRevision)
        assertEquals(AdminEditorPhase.REVIEW,decoded.phase);assertTrue(decoded.busy);assertTrue(decoded.readOnly);assertTrue(decoded.unassigned)
        assertEquals(original.documentBinding,decoded.documentBinding);assertEquals(original.pages,decoded.pages)
        assertEquals(original.parents.map {Triple(it.kind,it.id,it.revision)},decoded.parents.map {Triple(it.kind,it.id,it.revision)})
        assertEquals(original.reviewBinding,decoded.reviewBinding);assertEquals(60_000L,decoded.reviewDeadlineElapsed)
        assertEquals(original.recipients,decoded.recipients);assertEquals(original.diffSummaries,decoded.diffSummaries)
        assertEquals("REVIEW_EXPIRED",decoded.error);assertArrayEquals(preserved,AdminEditorWire.encode(decoded))
        val document=Json.parseToJsonElement(preserved.toString(Charsets.UTF_8)).jsonObject
        assertEquals(21,document.size);assertEquals(1,document.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals(original.comparisonBinding,decoded.comparisonBinding)
        assertEquals(original.comparisonBinding,document.getValue("comparisonBinding").jsonPrimitive.content)
        assertFalse("pages" in document);assertFalse("diffSummaries" in document)
        assertEquals(original.pages.map {encoded(bytes(it))},document.getValue("pages64").jsonArray.map {it.jsonPrimitive.content})
        assertEquals(original.diffSummaries.map {encoded(bytes(it))},document.getValue("diffSummaries64").jsonArray.map {it.jsonPrimitive.content})
        for(list in listOf(decoded.pages,decoded.parents,decoded.recipients,decoded.diffSummaries)) {
            assertThrows(UnsupportedOperationException::class.java) {(list as MutableList<*>).clear()}
        }
        assertEquals("AdminEditorModel([redacted])",decoded.toString())
        val reordered=JsonObject(document.entries.reversed().associate {it.key to it.value}).toString()
        assertArrayEquals(preserved,AdminEditorWire.encode(AdminEditorWire.decode(bytes(" \n$reordered\t"))))
    }

    @Test fun exactUtf8TransportLimitAndAllCollectionBoundariesRoundTripWithoutTruncation()=worker {
        // The encrypted store accepts arbitrary/incomplete UTF8 text. JSON
        // escaping must never make its full 262144-byte proposal unreopenable.
        for(character in listOf('\u0000','\b','\u000c','\n','\r','\t','"','\\')) {
            val full=model(pages=List(64) {character.toString().repeat(4096)})
            assertEquals(262_144,full.pages.sumOf {bytes(it).size})
            val frame=AdminEditorWire.encode(full)
            assertTrue(frame.size<497_024);assertEquals(full.pages,AdminEditorWire.decode(frame).pages)
        }
        val exactText=model(pages=List(32) {"x".repeat(8192)})
        val frame=AdminEditorWire.encode(exactText)
        val padded=frame+ByteArray(AdminEditorWire.MAX_BODY-frame.size) {32}
        assertEquals(524_288,padded.size);assertEquals(exactText.pages,AdminEditorWire.decode(padded).pages)
        failure {AdminEditorWire.decode(padded+byteArrayOf(32))}
        failure {AdminEditorWire.encode(model(pages=List(32) {"x".repeat(8192)}+"x"))}
        failure {AdminEditorWire.encode(model(pages=List(64) {"x".repeat(8192)}))}
        val parents=listOf(AdminEditorParent("template","template",1))+List(16) {AdminEditorParent("group","g$it",1)}+
            listOf(AdminEditorParent("user","user",1),AdminEditorParent("device","device",1),AdminEditorParent("local","local",1))
        val wide=model(pages=List(64) {"x".repeat(30)+"\uD83D\uDE00"},parents=parents,
            recipients=List(64) {"device-$it"},differences=List(64) {"x".repeat(512)},deadline=9_007_199_254_740_991L,
            localRevision=9_007_199_254_740_991L)
        val restored=AdminEditorWire.decode(AdminEditorWire.encode(wide))
        assertEquals(64,restored.pages.size);assertEquals(20,restored.parents.size)
        assertEquals(64,restored.recipients.size);assertEquals(wide.diffSummaries,restored.diffSummaries)
        assertEquals(wide.localRevision,restored.localRevision);assertEquals(wide.reviewDeadlineElapsed,restored.reviewDeadlineElapsed)
        val paired=model(pages=listOf("x".repeat(8190)+"\uD83D\uDE00"))
        assertEquals(paired.pages,AdminEditorWire.decode(AdminEditorWire.encode(paired)).pages)
        val largest=AdminEditorModel(device="d".repeat(64),privateDraftRevision=9_007_199_254_740_991L,
            desiredHeadRevision=9_007_199_254_740_991L,localRevision=9_007_199_254_740_991L,phase=AdminEditorPhase.NEEDS_REAUTH,
            documentBinding="d".repeat(128),pages=List(64) {"\u0000".repeat(4096)},
            parents=List(20) {AdminEditorParent("template","p".repeat(62)+it.toString().padStart(2,'0'),9_007_199_254_740_991L)},
            reviewBinding="r".repeat(128),reviewDeadlineElapsed=9_007_199_254_740_991L,
            recipients=List(64) {"r".repeat(62)+it.toString().padStart(2,'0')},
            diffSummaries=List(64) {"\u0800".repeat(512)},error="E".repeat(64))
        val bounded=AdminEditorWire.encode(largest)
        assertTrue(bounded.size<=497_024);assertTrue(bounded.size<AdminEditorWire.MAX_BODY)
        val checked=AdminEditorWire.decode(bounded)
        assertEquals(largest.pages,checked.pages);assertEquals(largest.diffSummaries,checked.diffSummaries)
        assertEquals(20,checked.parents.size);assertEquals(largest.recipients,checked.recipients)
    }

    @Test fun duplicateUnknownNullCoercedAndNestedFieldsNeverProduceAStateSnapshot()=worker {
        val original=raw()
        val invalid=listOf(original.replace("\"schemaVersion\":1","\"schemaVersion\":2"),
            original.replace("\"schemaVersion\":1","\"schemaVersion\":1.0"),
            original.replace("\"schemaVersion\":1","\"schemaVersion\":1e0"),
            original.replace("\"device\":\"\"","\"device\":\"\",\"device\":\"other\""),
            original.replace("\"device\":\"\"","\"device\":\"\",\"de\\u0076ice\":\"other\""),
            original.replace("\"device\":\"\"","\"Device\":\"\""),
            original.replace(",\"comparisonBinding\":\"\"",""),
            original.replace("\"comparisonBinding\":\"\"","\"comparisonBinding\":null"),
            original.replace("\"comparisonBinding\":\"\"","\"comparisonBinding\":\"A\""),
            original.replace("\"comparisonBinding\":\"\"","\"comparisonBinding\":\""+"A".repeat(42)+"B\""),
            original.replace("\"comparisonBinding\":\"\"","\"comparisonBinding\":\"\",\"comparisonBinding\":\"\""),
            original.replace(",\"localRevision\":0",""),
            original.replace("\"localRevision\":0","\"localRevision\":null"),
            original.replace("\"localRevision\":0","\"localRevision\":\"0\""),
            original.replace("\"localRevision\":0","\"localRevision\":-1"),
            original.replace("\"localRevision\":0","\"localRevision\":00"),
            original.replace("\"localRevision\":0","\"localRevision\":9007199254740992"),
            original.replace("\"localRevision\":0","\"localRevision\":999999999999999999999999999999999"),
            original.replace("\"reviewDeadlineElapsed\":0","\"reviewDeadlineElapsed\":9007199254740992"),
            original.replace("\"busy\":false","\"busy\":\"false\""),
            original.replace("\"busy\":false","\"busy\":null"),
            original.replace("\"phase\":\"INVENTORY\"","\"phase\":\"FUTURE\""),
            original.replace("\"pages64\":[]","\"pages64\":[[]]"),
            original.replace("\"pages64\":[]","\"pages64\":{}"),
            original.replace("\"pages64\":[]","\"pages64\":null"),
            original.replace("\"pages64\":[]","\"pages\":[]"),
            original.replace("\"pages64\":[]","\"pages64\":[],\"pages64\":[]"),
            original.replace("\"pages64\":[]","\"pages64\":[],\"pa\\u0067es64\":[]"),
            original.replace("\"diffSummaries64\":[]","\"diffSummaries\":[]"),
            original.replace("\"diffSummaries64\":[]","\"diffSummaries64\":[{}]"),
            original.replace("\"parents\":[]","\"parents\":[null]"),
            original.replace("\"parents\":[]","\"parents\":[{\"kind\":\"group\",\"id\":\"g\",\"revision\":1,\"id\":\"other\"}]"),
            original.replace("\"parents\":[]","\"parents\":[{\"kind\":\"group\",\"id\":{},\"revision\":1}]"),
            original.replace("\"error\":\"\"","\"error\":\"private-value lower case\""),
            original.dropLast(1)+",\"unknown\":true}",original.dropLast(1)+",}",
            "[$original]",original+original,"\uFEFF"+original,original+" trailing")
        for(value in invalid)failure {AdminEditorWire.decode(bytes(value))}
        assertEquals(0L,AdminEditorWire.decode(bytes(original)).localRevision)
    }

    @Test fun malformedUtf8SurrogatesEscapesAndWideOrRepeatedCollectionsFailFinitely()=worker {
        val original=raw().replace("\"documentBinding\":\"\"","\"documentBinding\":\"document-a\"")
        for(value in listOf(ByteArray(0),ByteArray(AdminEditorWire.MAX_BODY+1),byteArrayOf(0xc3.toByte(),0x28),
            byteArrayOf(0xed.toByte(),0xa0.toByte(),0x80.toByte()),bytes(original)+byteArrayOf(0xff.toByte()))) {
            failure {AdminEditorWire.decode(value)}
        }
        val prefix=bytes(original.substringBefore("\"pages64\":[]")+"\"pages64\":[\"")
        val suffix=bytes("\"]"+original.substringAfter("\"pages64\":[]"))
        for(invalid in listOf(byteArrayOf(0xc3.toByte(),0x28),byteArrayOf(0xed.toByte(),0xa0.toByte(),0x80.toByte()))) {
            failure {AdminEditorWire.decode(prefix+invalid+suffix)}
            // Canonical base64 alphabet/pad bits are valid; the decoded UTF8
            // itself must be rejected, rather than replaced with U+FFFD.
            for(field in listOf("pages64","diffSummaries64")) {
                failure {AdminEditorWire.decode(bytes(original.replace("\"$field\":[]","\"$field\":"+array(listOf(encoded(invalid))))))}
            }
        }
        for(value in listOf("\\ud800","\\udc00","\\ud800x","\\ud800\\u0061","\\uＦＦＦＦ","\\uZZZZ","\\x00","\n")) {
            failure {AdminEditorWire.decode(bytes(original.replace("\"pages64\":[]","\"pages64\":[\"$value\"]")))}
        }
        for(value in listOf("A","AAAAA","AB","Zh","AA==","Zg=","AA+","AA/","AA ","\n")) {
            for(field in listOf("pages64","diffSummaries64")) {
                failure {AdminEditorWire.decode(bytes(original.replace("\"$field\":[]","\"$field\":"+array(listOf(value)))))}
            }
        }
        val parent="{\"kind\":\"group\",\"id\":\"g\",\"revision\":1}"
        val malformed=listOf(
            original.replace("\"pages64\":[]","\"pages64\":"+encodedArray(List(65) {"p"})),
            original.replace("\"pages64\":[]","\"pages64\":"+encodedArray(listOf("x".repeat(8193)))),
            original.replace("\"pages64\":[]","\"pages64\":"+encodedArray(listOf("\uD83D\uDE00".repeat(4097)))),
            original.replace("\"pages64\":[]","\"pages64\":"+array(listOf("A".repeat(32_769)))),
            original.replace("\"pages64\":[]","\"pages64\":"+encodedArray(List(32) {"x".repeat(8192)}+"x")),
            original.replace("\"parents\":[]","\"parents\":["+List(21) {parent.replace("\"g\"","\"g$it\"")}.joinToString(",")+"]"),
            original.replace("\"parents\":[]","\"parents\":[$parent,$parent]"),
            original.replace("\"recipients\":[]","\"recipients\":"+array(List(65) {"d$it"})),
            original.replace("\"recipients\":[]","\"recipients\":[\"same\",\"same\"]"),
            original.replace("\"recipients\":[]","\"recipients\":[\"bad/id\"]"),
            original.replace("\"diffSummaries64\":[]","\"diffSummaries64\":"+encodedArray(List(65) {"diff"})),
            original.replace("\"diffSummaries64\":[]","\"diffSummaries64\":"+encodedArray(listOf("x".repeat(513)))),
            original.replace("\"diffSummaries64\":[]","\"diffSummaries64\":"+array(listOf("A".repeat(2049)))),
            original.replace("\"device\":\"\"","\"device\":\"${"d".repeat(65)}\""),
            original.replace("\"documentBinding\":\"document-a\"","\"documentBinding\":\"${"b".repeat(129)}\""),
            original.replace("\"error\":\"\"","\"error\":\"${"E".repeat(65)}\""))
        for(value in malformed)failure {AdminEditorWire.decode(bytes(value))}
        assertEquals(listOf(""),AdminEditorWire.decode(bytes(original.replace("\"pages64\":[]","\"pages64\":[\"\"]"))).pages)
        failure {AdminEditorWire.encode(model(error="private-value"))}
        failure {AdminEditorWire.encode(model(deadline=9_007_199_254_740_992L))}
        failure {AdminEditorWire.encode(model(parents=listOf(AdminEditorParent("group","g",1),AdminEditorParent("group","g",1))))}
    }

    @Test fun mainAndBinderCannotSerializeOrParseEvenMalformedOrOversizedInput() {
        val prepared=worker {model(pages=listOf("private-value"),localRevision=4)}
        val encoded=worker {AdminEditorWire.encode(prepared)}
        val oversized=ByteArray(AdminEditorWire.MAX_BODY+1)
        fun guarded() {
            failure("WRONG_THREAD") {AdminEditorWire.encode(prepared)}
            failure("WRONG_THREAD") {AdminEditorWire.decode(encoded)}
            failure("WRONG_THREAD") {AdminEditorWire.decode(byteArrayOf(0xff.toByte()))}
            failure("WRONG_THREAD") {AdminEditorWire.decode(oversized)}
        }
        InstrumentationRegistry.getInstrumentation().runOnMainSync {guarded()}
        val binder=Executors.newSingleThreadExecutor {action->Thread(action,"Binder:admin-editor-wire-fixture")}
        try {binder.submit {guarded()}.get(10,TimeUnit.SECONDS)}
        finally {binder.shutdownNow();check(binder.awaitTermination(5,TimeUnit.SECONDS))}
        worker {assertEquals(prepared.pages,AdminEditorWire.decode(encoded).pages)}
    }
}
