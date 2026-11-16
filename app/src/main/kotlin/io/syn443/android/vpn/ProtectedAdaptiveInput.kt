package io.syn443.android.vpn

import io.syn443.decision.Decision
import kotlinx.serialization.json.jsonPrimitive

/** Extract original value bytes after the caller's strict JSON preflight.
 * Re-serializing a JsonObject would erase whitespace byte limits; JSONObject
 * would additionally coerce numeric lexemes such as schemaVersion1.0. */
internal fun protectedAdaptiveWire(raw:String):ByteArray? {
    require(raw.length<=524288)
    var i=0
    fun ws(){while(i<raw.length && raw[i] in " \r\n\t")i++}
    fun stringEnd():Int {
        require(i<raw.length && raw[i]=='"');i++
        while(i<raw.length) {
            when(raw[i++]) {
                '"'->return i
                '\\'->{require(i<raw.length);i++}
            }
        }
        error("invalid_adaptive_engine_config")
    }
    fun valueEnd():Int {
        ws();require(i<raw.length)
        if(raw[i]=='"')return stringEnd()
        if(raw[i]!='{' && raw[i]!='[') {
            while(i<raw.length && raw[i] !in ",} \r\n\t")i++
            return i
        }
        val stack=java.util.ArrayDeque<Char>()
        stack.addLast(raw[i++])
        while(i<raw.length && stack.isNotEmpty()) {
            when(val c=raw[i]) {
                '"'->stringEnd()
                '{','['->{require(stack.size<24);stack.addLast(c);i++}
                '}',']'->{require(stack.removeLast()==if(c=='}')'{' else '[');i++}
                else->i++
            }
        }
        require(stack.isEmpty());return i
    }
    ws();require(i<raw.length && raw[i++]=='{');ws()
    var found:String?=null
    while(i<raw.length && raw[i]!='}') {
        val keyStart=i;val keyEnd=stringEnd()
        val key=Decision.json.parseToJsonElement(raw.substring(keyStart,keyEnd)).jsonPrimitive.content
        ws();require(i<raw.length && raw[i++]==':');ws();val start=i;val end=valueEnd()
        if(key=="adaptive_routes") {require(found==null);found=raw.substring(start,end)}
        ws();require(i<raw.length)
        if(raw[i]=='}')break
        require(raw[i++]==',');ws()
    }
    require(i<raw.length && raw[i++]=='}');ws();require(i==raw.length)
    return found?.let {value->
        val bytes=Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(value))
        ByteArray(bytes.remaining()).also {bytes.get(it)}
    }
}
