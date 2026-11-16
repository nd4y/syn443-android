package io.syn443.android

import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.admin.*
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Private presentation values only. No provider, account, storage, network or VPN calls. */
class AdminComparisonWireTest {
    private fun <T> worker(action:()->T):T {
        val executor=Executors.newSingleThreadExecutor()
        try {return executor.submit<T> {action()}.get(30,TimeUnit.SECONDS)}
        finally {executor.shutdownNow();check(executor.awaitTermination(5,TimeUnit.SECONDS))}
    }
    private fun bytes(value:String)=value.toByteArray(Charsets.UTF_8)
    private fun encoded(value:ByteArray)=Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun quote(value:String)=JsonPrimitive(value).toString()
    private fun id(value:Int):String=encoded(ByteArray(32).also {it[30]=(value ushr 8).toByte();it[31]=value.toByte()})
    private fun row(index:Int=1,sides:List<AdminComparisonSide> = listOf(AdminComparisonSide.BASE))=
        AdminComparisonRow(id(index),"setting","/network","VALUE_CHANGED",true,"CURRENT",sides)
    private fun model(detail:Boolean=false):AdminComparisonModel {
        val item=row()
        return AdminComparisonModel(device="synthetic-device",binding=id(90),localRevision=7,
            section=AdminComparisonSection.DIFF,total=1,rows=listOf(item),ready=true,
            detail=if(detail)AdminComparisonDetail(item.id,AdminComparisonSide.BASE,0,256,"f")else null,
            baseRevision=3,currentRevision=9)
    }
    private fun raw(value:AdminComparisonModel=AdminComparisonModel())=AdminComparisonWire.encode(value).toString(Charsets.UTF_8)
    private fun replace(raw:String,from:String,to:String):String {
        check(raw.contains(from));return raw.replace(from,to)
    }
    private fun failure(code:String="INVALID_REPLY",action:()->Unit) {
        val caught=assertThrows(AdminUiFailure::class.java,action)
        assertEquals(code,caught.code);assertEquals("administrative_operation_failed",caught.message);assertNull(caught.cause)
        assertFalse(caught.toString().contains("private-value"))
    }
    private fun assertModel(expected:AdminComparisonModel,actual:AdminComparisonModel) {
        assertEquals(expected.device,actual.device);assertEquals(expected.binding,actual.binding)
        assertEquals(expected.localRevision,actual.localRevision);assertEquals(expected.section,actual.section)
        assertEquals(expected.total,actual.total);assertEquals(expected.offset,actual.offset)
        assertEquals(expected.ready,actual.ready);assertEquals(expected.busy,actual.busy)
        assertEquals(expected.error,actual.error);assertEquals(expected.readOnly,actual.readOnly)
        assertEquals(expected.baseRevision,actual.baseRevision);assertEquals(expected.currentRevision,actual.currentRevision)
        assertEquals(expected.rows.size,actual.rows.size)
        for((left,right)in expected.rows.zip(actual.rows)) {
            assertEquals(left.id,right.id);assertEquals(left.kind,right.kind);assertEquals(left.path,right.path)
            assertEquals(left.code,right.code);assertEquals(left.resolvable,right.resolvable)
            assertEquals(left.choice,right.choice);assertEquals(left.availableSides,right.availableSides)
        }
        val expectedDetail=expected.detail
        if(expectedDetail==null)assertNull(actual.detail) else {
            val detail=actual.detail!!
            assertEquals(expectedDetail.rowId,detail.rowId);assertEquals(expectedDetail.side,detail.side)
            assertEquals(expectedDetail.page,detail.page);assertEquals(expectedDetail.totalPages,detail.totalPages)
            assertEquals(expectedDetail.text,detail.text)
        }
    }

    @Test fun closedComparisonFrameRoundTripsOwnedRowsHeadersAndOneDetail()=worker {
        val sides=AdminComparisonSide.entries.toMutableList()
        val rows=(0 until 20).map {index->
            val path=(List(15) {"k".repeat(64)}+("v".repeat(62)+index.toString().padStart(2,'0')))
                .joinToString("/",prefix="/")
            assertEquals(1040,path.length)
            AdminComparisonRow(id(index+1),"device->local",path,"APPROVAL_EXCEEDS_CURRENT",true,"CURRENT",sides)
        }.toMutableList()
        val detail=AdminComparisonDetail(rows.first().id,AdminComparisonSide.AFTER_ORIGIN,255,256,"\u0800".repeat(8192))
        val original=AdminComparisonModel(device="d".repeat(64),binding=id(80),localRevision=9_007_199_254_740_991L,
            section=AdminComparisonSection.DIFF,total=8194,offset=8174,rows=rows,ready=true,detail=detail,
            busy=true,error="E".repeat(64),readOnly=true,baseRevision=9_007_199_254_740_991L,currentRevision=9_007_199_254_740_991L)
        rows.clear();sides.clear()
        val frame=AdminComparisonWire.encode(original);val preserved=frame.copyOf()
        assertTrue(frame.size<AdminComparisonWire.MAX_BODY)
        val decoded=AdminComparisonWire.decode(frame);frame.fill(0)
        assertModel(original,decoded);assertArrayEquals(preserved,AdminComparisonWire.encode(decoded))
        val document=Json.parseToJsonElement(preserved.toString(Charsets.UTF_8)).jsonObject
        assertEquals(setOf("schemaVersion","device","binding","localRevision","section","total","offset","rows",
            "ready","detail","busy","error","readOnly","baseRevision","currentRevision"),document.keys)
        assertEquals(1,document.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals(20,document.getValue("rows").jsonArray.size)
        assertEquals(setOf("id","kind","path","code","resolvable","choice","availableSides"),
            document.getValue("rows").jsonArray.first().jsonObject.keys)
        assertEquals(setOf("rowId","side","page","totalPages","text64"),document.getValue("detail").jsonObject.keys)
        assertEquals(32768,document.getValue("detail").jsonObject.getValue("text64").jsonPrimitive.content.length)
        assertFalse("text" in document.getValue("detail").jsonObject)
        assertThrows(UnsupportedOperationException::class.java) {(decoded.rows as MutableList<*>).clear()}
        assertThrows(UnsupportedOperationException::class.java) {(decoded.rows.first().availableSides as MutableList<*>).clear()}
        for(value in listOf(decoded,decoded.rows.first(),decoded.detail!!)) {
            assertTrue(value.toString().contains("[redacted]"));assertFalse(value.toString().contains(id(1)))
        }
        val reordered=JsonObject(document.entries.reversed().associate {it.key to it.value}).toString()
        assertArrayEquals(preserved,AdminComparisonWire.encode(AdminComparisonWire.decode(bytes(" \n$reordered\t"))))
        val privateText="private-value \" \\ \u0000\n\t\uD83D\uDE00\u2028\u2029"
        val item=row()
        val controls=AdminComparisonModel(total=1,rows=listOf(item),detail=AdminComparisonDetail(item.id,AdminComparisonSide.BASE,0,1,privateText))
        assertEquals(privateText,AdminComparisonWire.decode(AdminComparisonWire.encode(controls)).detail!!.text)
    }

    @Test fun exact64KiBWhitespaceAndNullDetailKeepHardFrameBounds()=worker {
        val original=AdminComparisonModel()
        val frame=AdminComparisonWire.encode(original)
        val padded=frame+ByteArray(AdminComparisonWire.MAX_BODY-frame.size) {32}
        assertEquals(65_536,padded.size);assertModel(original,AdminComparisonWire.decode(padded))
        failure {AdminComparisonWire.decode(padded+byteArrayOf(32))}
        failure {AdminComparisonWire.decode(ByteArray(0))}
        failure {AdminComparisonWire.decode(ByteArray(AdminComparisonWire.MAX_BODY+1))}
        assertNull(Json.parseToJsonElement(frame.toString(Charsets.UTF_8)).jsonObject.getValue("detail").jsonPrimitive.contentOrNull)
        val withEmptyDetail=replace(raw(model(true)),"\"text64\":\"Zg\"","\"text64\":\"\"")
        assertEquals("",AdminComparisonWire.decode(bytes(withEmptyDetail)).detail!!.text)
        assertEquals(0L,AdminComparisonWire.decode(frame).localRevision)
    }

    @Test fun closedFrameRejectsDuplicateEscapedKeysTypesAndIntegersBeforeNarrowing()=worker {
        val original=raw();val populated=raw(model(true));val parsed=Json.parseToJsonElement(populated).jsonObject
        val item=parsed.getValue("rows").jsonArray.single().toString();val detail=parsed.getValue("detail").jsonObject
        val invalid=mutableListOf(
            replace(original,"\"schemaVersion\":1","\"schemaVersion\":0"),
            replace(original,"\"schemaVersion\":1","\"schemaVersion\":4294967297"),
            replace(original,"\"schemaVersion\":1","\"schemaVersion\":1.0"),
            replace(original,"\"schemaVersion\":1","\"schemaVersion\":1e0"),
            replace(original,"\"device\":\"\"","\"Device\":\"\""),
            replace(original,"\"device\":\"\"","\"device\":\"\",\"de\\u0076ice\":\"\""),
            replace(original,",\"baseRevision\":0",""),
            replace(original,"\"baseRevision\":0","\"baseRevision\":0,\"baseRevisi\\u006fn\":0"),
            replace(original,"\"total\":0","\"total\":4294967296"),
            replace(original,"\"offset\":0","\"offset\":4294967296"),
            replace(populated,"\"page\":0","\"page\":4294967296"),
            replace(populated,"\"totalPages\":256","\"totalPages\":4294967297"),
            replace(populated,"\"page\":0","\"page\":0,\"pa\\u0067e\":1"),
            replace(populated,"\"text64\":\"Zg\"","\"text64\":\"Zg\",\"text\\u003634\":\"Zg\""),
            replace(populated,"\"availableSides\":[\"BASE\"]","\"availableSides\":[\"BASE\",\"BASE\"]"),
            replace(populated,"\"path\":\"/network\"","\"path\":\"/network\",\"pa\\u0074h\":\"/other\""),
            replace(populated,"\"path\":\"/network\"","\"path\":\"/network\",\"extra\":true"),
            replace(populated,"\"rows\":[$item]","\"rows\":[$item,$item]"),
            replace(populated,"\"rows\":[$item]","\"rows\":[null]"),
            replace(populated,"\"rows\":[$item]","\"rows\":[]"),
            replace(populated,"\"detail\":$detail","\"detail\":false"),
            replace(populated,"\"detail\":$detail","\"detail\":[]"),
            replace(populated,"\"detail\":$detail","\"detail\":{}"),
            replace(populated,"\"detail\":{","\"detail\":[{"),
            replace(original,"\"rows\":[]","\"rows\":{}"),
            replace(original,"\"rows\":[]","\"rows\":["+"[".repeat(25)+"0"+"]".repeat(25)+"]"),
            replace(original,"\"error\":\"\"","\"error\":\"private-value\""),
            original.dropLast(1)+",\"rows\":[]}",original.dropLast(1)+",\"role\":\"admin\"}",
            original.dropLast(1)+",}","[$original]",original+original,"\uFEFF"+original,original+" trailing")
        for(field in listOf("schemaVersion","device","binding","localRevision","section","total","offset","rows",
            "ready","busy","error","readOnly","baseRevision","currentRevision")) {
            val token=Json.parseToJsonElement(original).jsonObject.getValue(field).toString()
            invalid+=replace(original,"\"$field\":$token","\"$field\":null")
        }
        for(field in listOf("localRevision","baseRevision","currentRevision")) {
            for(number in listOf("-1","00","1.0","1e0","\"0\"","9007199254740992","99999999999999999")) {
                invalid+=replace(original,"\"$field\":0","\"$field\":$number")
            }
        }
        for(field in listOf("ready","busy","readOnly")) {
            invalid+=replace(original,"\"$field\":false","\"$field\":\"false\"")
        }
        for(field in listOf("id","kind","path","code","resolvable","choice","availableSides")) {
            val token=Json.parseToJsonElement(item).jsonObject.getValue(field).toString()
            invalid+=replace(populated,"\"$field\":$token","\"$field\":null")
        }
        for(field in listOf("rowId","side","page","totalPages","text64")) {
            invalid+=replace(populated,"\"$field\":"+detail.getValue(field),"\"$field\":null")
        }
        for(value in invalid)failure {AdminComparisonWire.decode(bytes(value))}
        assertModel(model(true),AdminComparisonWire.decode(bytes(populated)))
    }

    @Test fun detailCanonicalEncodingUnicodeAndRowRelationsFailClosed()=worker {
        val original=raw(model(true))
        fun detail64(value:String)=replace(original,"\"text64\":\"Zg\"","\"text64\":"+quote(value))
        for(value in listOf("A","AAAAA","Zh","Zg=","Zg==","AA+","AA/","AA ","\n")) {
            failure {AdminComparisonWire.decode(bytes(detail64(value)))}
        }
        for(value in listOf(byteArrayOf(0xc3.toByte(),0x28),byteArrayOf(0xed.toByte(),0xa0.toByte(),0x80.toByte()),byteArrayOf(0xff.toByte()))) {
            failure {AdminComparisonWire.decode(bytes(detail64(encoded(value))))}
            val prefix=bytes(original.substringBefore("/network"));val suffix=bytes(original.substringAfter("/network"))
            failure {AdminComparisonWire.decode(prefix+value+suffix)}
        }
        for(value in listOf("\\ud800","\\udc00","\\ud800x","\\ud800\\u0061","\\uＦＦＦＦ","\\uZZZZ","\\x00","\n")) {
            failure {AdminComparisonWire.decode(bytes(replace(original,"\"path\":\"/network\"","\"path\":\"$value\"")))}
        }
        val invalid=listOf(
            detail64(encoded(bytes("x".repeat(8193)))),detail64(encoded(bytes("\uD83D\uDE00".repeat(4097)))),detail64("A".repeat(32769)),
            replace(original,"\"page\":0","\"page\":256"),replace(original,"\"totalPages\":256","\"totalPages\":257"),
            replace(original,"\"totalPages\":256","\"totalPages\":0"),
            replace(original,"\"rowId\":"+quote(id(1)),"\"rowId\":"+quote(id(2))),
            replace(original,"\"side\":\"BASE\"","\"side\":\"AFTER\""),
            replace(original,"\"side\":\"BASE\"","\"side\":\"FUTURE\""),
            replace(original,"\"side\":\"BASE\"","\"side\":null"),
            replace(original,"\"text64\":\"Zg\"","\"text64\":null"),
            replace(original,"\"text64\":\"Zg\"","\"text\":\"f\""),
            replace(original,"\"text64\":\"Zg\"","\"text64\":\"Zg\",\"unknown\":true"),
            replace(original,"\"device\":\"synthetic-device\"","\"device\":\"${"d".repeat(65)}\""),
            replace(original,"\"binding\":"+quote(id(90)),"\"binding\":\"${"A".repeat(42)}B\""),
            replace(original,"\"path\":\"/network\"","\"path\":\"/k\\u0000\""),
            replace(original,"\"path\":\"/network\"","\"path\":\"/${"k".repeat(65)}\""),
            replace(original,"\"path\":\"/network\"","\"path\":\"${List(17) {"k"}.joinToString("/",prefix="/")}\""),
            replace(original,"\"path\":\"/network\"","\"path\":\"${"/"+"k".repeat(1040)}\""),
            replace(raw(),"\"section\":\"CONFLICTS\"","\"section\":\"FUTURE\""),
            replace(raw(),"\"total\":0","\"total\":2051"),
            replace(raw(),"\"total\":0","\"total\":8195"),
            replace(original,"\"offset\":0","\"offset\":1"))
        for(value in invalid)failure {AdminComparisonWire.decode(bytes(value))}
        val repeated=List(21) {index->
            val item=row(index+1)
            Json.parseToJsonElement(raw(AdminComparisonModel(total=1,rows=listOf(item)))).jsonObject.getValue("rows").jsonArray.single().toString()
        }.joinToString(",","[","]")
        failure {AdminComparisonWire.decode(bytes(replace(replace(raw(),"\"rows\":[]","\"rows\":$repeated"),"\"total\":0","\"total\":21")))}
        assertEquals("f",AdminComparisonWire.decode(bytes(original)).detail!!.text)
        assertEquals("\uD83D\uDE00".repeat(4096),AdminComparisonWire.decode(bytes(detail64(encoded(bytes("\uD83D\uDE00".repeat(4096)))))).detail!!.text)
    }

    @Test fun mainAndBinderRejectBeforeAnyComparisonSerializationOrParsing() {
        val prepared=worker {model(true)};val frame=worker {AdminComparisonWire.encode(prepared)};val preserved=frame.copyOf()
        val oversized=ByteArray(AdminComparisonWire.MAX_BODY+1)
        fun guarded() {
            failure("WRONG_THREAD") {AdminComparisonWire.encode(prepared)}
            failure("WRONG_THREAD") {AdminComparisonWire.decode(frame)}
            failure("WRONG_THREAD") {AdminComparisonWire.decode(byteArrayOf(0xff.toByte()))}
            failure("WRONG_THREAD") {AdminComparisonWire.decode(oversized)}
        }
        InstrumentationRegistry.getInstrumentation().runOnMainSync {guarded()}
        val binder=Executors.newSingleThreadExecutor {action->Thread(action,"Binder:comparison-wire-fixture")}
        try {binder.submit {guarded()}.get(10,TimeUnit.SECONDS)}
        finally {binder.shutdownNow();check(binder.awaitTermination(5,TimeUnit.SECONDS))}
        assertArrayEquals(preserved,frame);worker {assertModel(prepared,AdminComparisonWire.decode(frame))}
    }
}
