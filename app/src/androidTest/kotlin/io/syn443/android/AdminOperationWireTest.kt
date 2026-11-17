package io.syn443.android

import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.admin.*
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Same-UID presentation codec only; parsed outcomes never authorize a mutation. */
class AdminOperationWireTest {
    private fun <T> worker(action:()->T):T {
        val executor=Executors.newSingleThreadExecutor()
        try {return executor.submit<T> {action()}.get(30,TimeUnit.SECONDS)}
        finally {executor.shutdownNow();check(executor.awaitTermination(5,TimeUnit.SECONDS))}
    }
    private fun digest()=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) {7})
    private fun model(outcome:String="UNKNOWN",seal:Boolean=false,pages:List<String> = listOf("{unfinished synthetic"))=
        AdminEditorModel(device="synthetic-device",privateDraftRevision=2,desiredHeadRevision=5,localRevision=9,
            phase=AdminEditorPhase.UNCERTAIN,documentBinding="document-a",pages=pages,operationBinding=digest(),
            operationOutcome=outcome,canSeal=seal,error="OUTCOME_UNKNOWN")
    private fun failure(code:String="INVALID_REPLY",block:()->Unit) {
        val error=assertThrows(AdminUiFailure::class.java,block)
        assertEquals(code,error.code);assertEquals("administrative_operation_failed",error.message);assertNull(error.cause)
    }
    private fun bytes(raw:String)=raw.toByteArray(Charsets.UTF_8)

    @Test fun closedOperationFrameRoundTripsAllOutcomesExactPendingBindingAndOwnedText()=worker {
        for(outcome in listOf("","UNKNOWN","NO_EFFECT","RECORDED","RECORDED_RESULT_UNAVAILABLE")) {
            val pages=mutableListOf("{unfinished synthetic","Русский текст \uD83D\uDE00\n\u0000")
            val original=model(outcome,outcome=="UNKNOWN",pages);pages.clear()
            val frame=AdminEditorWire.encode(original)
            val json=Json.parseToJsonElement(frame.toString(Charsets.UTF_8)).jsonObject
            assertEquals(21,json.size);assertEquals(digest(),json.getValue("operationBinding").jsonPrimitive.content)
            assertEquals(outcome,json.getValue("operationOutcome").jsonPrimitive.content)
            assertEquals(outcome=="UNKNOWN",json.getValue("canSeal").jsonPrimitive.boolean)
            val decoded=AdminEditorWire.decode(frame);frame.fill(0)
            assertEquals(original.operationBinding,decoded.operationBinding);assertEquals(outcome,decoded.operationOutcome)
            assertEquals(original.canSeal,decoded.canSeal);assertEquals(9L,decoded.localRevision)
            assertEquals(original.documentBinding,decoded.documentBinding);assertEquals(original.pages,decoded.pages)
            assertThrows(UnsupportedOperationException::class.java) {(decoded.pages as MutableList<String>).clear()}
            assertEquals("AdminEditorModel([redacted])",decoded.toString())
        }
    }

    @Test fun operationFieldsRejectMissingUnknownDuplicateNoncanonicalAndInvalidSealRelationships()=worker {
        val raw=AdminEditorWire.encode(model(seal=true)).toString(Charsets.UTF_8)
        val parsed=Json.parseToJsonElement(raw).jsonObject
        for(field in listOf("operationBinding","operationOutcome","canSeal")) {
            failure {AdminEditorWire.decode(bytes(JsonObject(parsed.filterKeys {it!=field}).toString()))}
            val token=JsonPrimitive(field).toString()+":"+parsed.getValue(field).toString()
            for(replacement in listOf(JsonPrimitive(field).toString()+":null",token+","+token,
                JsonPrimitive(field.replaceFirstChar {it.uppercaseChar()}).toString()+":"+parsed.getValue(field),
                token+",\"operation\\u0042inding\":\"${digest()}\"")) {
                val changed=raw.replace(token,replacement);assertNotEquals(raw,changed)
                failure {AdminEditorWire.decode(bytes(changed))}
            }
        }
        for(binding in listOf("",digest().dropLast(1),digest()+"A",digest()+"=",digest().dropLast(1)+"B","private/value")) {
            failure {AdminEditorWire.decode(bytes(raw.replace("\"operationBinding\":\"${digest()}\"","\"operationBinding\":\"$binding\"")))}
        }
        for(outcome in listOf("unknown","FUTURE_OUTCOME","NO_EFFECT","RECORDED","RECORDED_RESULT_UNAVAILABLE","")) {
            failure {AdminEditorWire.decode(bytes(raw.replace("\"operationOutcome\":\"UNKNOWN\"","\"operationOutcome\":\"$outcome\"")))}
        }
        for(value in listOf("null","1","\"true\"","[]","{}")) {
            failure {AdminEditorWire.decode(bytes(raw.replace("\"canSeal\":true","\"canSeal\":$value")))}
        }
        for(phase in listOf("EDITING","REVIEW","PUBLISHED","UNAVAILABLE")) {
            failure {AdminEditorWire.decode(bytes(raw.replace("\"phase\":\"UNCERTAIN\"","\"phase\":\"$phase\"")))}
        }
        failure {AdminEditorWire.decode(bytes(raw.dropLast(1)+",\"operationResult\":{}}"))}
    }

    @Test fun operationFrameKeepsHardUtf8LimitAndRejectsMainBinderBeforeParsing() {
        val prepared=worker {model(seal=true)}
        val frame=worker {AdminEditorWire.encode(prepared)}
        worker {
            val exact=frame+ByteArray(AdminEditorWire.MAX_BODY-frame.size) {32}
            assertEquals(524_288,exact.size)
            assertEquals(digest(),AdminEditorWire.decode(exact).operationBinding)
            failure {AdminEditorWire.decode(exact+byteArrayOf(32))}
            failure {AdminEditorWire.decode(frame+byteArrayOf(0xff.toByte()))}
            failure {AdminEditorWire.decode(byteArrayOf(0xc3.toByte(),0x28))}
        }
        fun guarded() {
            failure("WRONG_THREAD") {AdminEditorWire.encode(prepared)}
            failure("WRONG_THREAD") {AdminEditorWire.decode(frame)}
            failure("WRONG_THREAD") {AdminEditorWire.decode(ByteArray(AdminEditorWire.MAX_BODY+1))}
        }
        InstrumentationRegistry.getInstrumentation().runOnMainSync {guarded()}
        val binder=Executors.newSingleThreadExecutor {action->Thread(action,"Binder:operation-presentation-fixture")}
        try {binder.submit {guarded()}.get(10,TimeUnit.SECONDS)}
        finally {binder.shutdownNow();check(binder.awaitTermination(5,TimeUnit.SECONDS))}
        worker {assertEquals(prepared.pages,AdminEditorWire.decode(frame).pages)}
    }
}
