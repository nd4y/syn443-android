package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class AdminLayerJsonTest {
    @Test fun rawSpansKeepWholeObjectsValuesChoiceEscapesAndNumericLexemesExactly() {
        val raw=""" {"z":{"second":"\u0061","first":1.00},"choices":["\u003c",1e0,2E+0],"nullable":null} """
        val doc=AdminLayerJson.document(raw);val root=doc.root.jsonObject
        assertEquals(raw.trim(),doc.raw(root))
        assertEquals("""{"second":"\u0061","first":1.00}""",doc.raw(root.getValue("z")))
        assertEquals("""["\u003c",1e0,2E+0]""",doc.raw(root.getValue("choices")))
        assertEquals("1.00",doc.raw(root.getValue("z").jsonObject.getValue("first")))
        assertEquals("null",doc.raw(root.getValue("nullable")))
        assertEquals("AdminLayerDocument([redacted])",doc.toString())
        assertThrows(Exception::class.java){doc.raw(JsonPrimitive("foreign-node"))}
        for(value in listOf("true","false","-0","\"quoted\\\"value\""))assertEquals(value,AdminLayerJson.document(value).let {it.raw(it.root)})
    }
    @Test fun recursiveBoundsDuplicatesUnicodeAndMalformedNumbersFailBeforeUnboundedTrees() {
        fun members(count:Int)=(0 until count).joinToString(",","{","}"){"\"k$it\":0"}
        fun items(count:Int)=(0 until count).joinToString(",","[","]"){"0"}
        assertEquals(512,AdminLayerJson.parse(members(512)).jsonObject.size)
        assertEquals(512,AdminLayerJson.parse(items(512)).jsonArray.size)
        assertThrows(Exception::class.java){Canonical.parse(members(65))}
        val depth24="[".repeat(24)+"0"+"]".repeat(24)
        assertNotNull(AdminLayerJson.parse(depth24))
        for(raw in listOf(members(513),items(513),"[$depth24]","", "{} {}","[1,]","{\"a\":1,}",
            "{\"a\":1,\"\\u0061\":2}","\"\\uD800\"","\"\\uDC00\"","\"\\x\"","\"\\u0\"","\"unterminated","\"\\",
            "{\"s\":\"\n\"}","\""+0xd800.toChar()+"\"","\""+0xdc00.toChar()+"\"","tru","fals","nul")) {
            assertThrows(Exception::class.java){AdminLayerJson.parse(raw)}
        }
        assertEquals("😀",AdminLayerJson.parse("\"\\uD83D\\uDE00\"").jsonPrimitive.content)
        assertEquals(0.toChar().toString(),AdminLayerJson.parse("\"\\u0000\"").jsonPrimitive.content)
    }
    @Test fun onlyExplicitInventoryRootOriginMapCanExceedGenericObjectLimits() {
        fun origins(count:Int)=(0 until count).joinToString(",","{","}"){"\"/x/k$it\":{\"layerId\":\"template\",\"kind\":\"template\",\"revision\":1}"}
        val fields=origins(4096);val exact="""{"effective":{"fields":$fields}}"""
        assertEquals(4096,AdminLayerJson.parse(exact,true).jsonObject.getValue("effective").jsonObject.getValue("fields").jsonObject.size)
        assertThrows(Exception::class.java){AdminLayerJson.parse(exact)}
        for(raw in listOf("""{"effective":{"fields":${origins(4097)}}}""","""{"x":$exact}""","[$exact]",
            """{"effective":[{"fields":$fields}]}""","""{"effective":{"fields":{"nested":$fields}}}""")) {
            assertThrows(Exception::class.java){AdminLayerJson.parse(raw,true)}
        }
    }
    @Test fun exactByteAndMathematicalNodeBoundsCoverTheWholeBoundedJsonTree() {
        val rows=(0 until 512).joinToString(",","[","]"){row->List(if(row==511)510 else 511){"0"}.joinToString(",","[","]")}
        assertEquals(524_287,rows.toByteArray().size)
        val tree=AdminLayerJson.parse(rows).jsonArray
        assertEquals(262_144,1+tree.size+tree.sumOf {it.jsonArray.size})
        assertThrows(Exception::class.java){AdminLayerJson.parse(rows+"  ")}
        val unicode="{\"s\":\""+"é".repeat((524_288-8)/2)+"\"}"
        assertEquals(524_288,unicode.toByteArray(Charsets.UTF_8).size)
        assertEquals(unicode,AdminLayerJson.document(unicode).let {it.raw(it.root)})
        assertThrows(Exception::class.java){AdminLayerJson.parse(unicode.dropLast(2)+"é\"}")}
    }
}
