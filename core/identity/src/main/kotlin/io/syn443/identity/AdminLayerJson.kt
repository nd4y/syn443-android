package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.*
import java.util.IdentityHashMap
import kotlin.math.abs

/** Layer-control documents only. Never changes OAuth, signed payload or device JSON admission. */
@OptIn(ExperimentalSerializationApi::class)
internal object AdminLayerJson {
    const val MAX_BYTES=524_288
    private const val MAX_NODES=262_144
    private const val MAX_DEPTH=24
    private const val MAX_INTEGER=9_007_199_254_740_991L
    private const val ROOT=0
    private const val EFFECTIVE=1
    private const val ORIGINS=2
    private const val OTHER=3
    class Document internal constructor(val root:JsonElement,private val source:String,
        private val spans:IdentityHashMap<JsonElement,IntArray>) {
        fun raw(value:JsonElement):String=checkNotNull(spans[value]).let {source.substring(it[0],it[1])}
        override fun toString()="AdminLayerDocument([redacted])"
    }
    fun parse(raw:String,inventory:Boolean=false):JsonElement=document(raw,inventory).root
    fun document(raw:String,inventory:Boolean=false):Document {
        require(raw.length in 1..MAX_BYTES && raw.toByteArray(Charsets.UTF_8).size<=MAX_BYTES)
        return Reader(raw,inventory).parse()
    }
    private class Reader(private val text:String,private val inventory:Boolean) {
        private var at=0
        private var nodes=0
        private val spans=IdentityHashMap<JsonElement,IntArray>()
        private fun whitespace() {while(at<text.length && text[at] in " \t\r\n")at++}
        private fun take(c:Char) {whitespace();require(at<text.length && text[at++]==c)}
        private fun peek():Char {whitespace();require(at<text.length);return text[at]}
        private fun string():String {
            whitespace();val start=at;take('"')
            while(at<text.length) {
                val c=text[at++];require(c>=' ')
                if(c=='"') {
                    val value=Canonical.json.decodeFromString<String>(text.substring(start,at))
                    var index=0
                    while(index<value.length) {
                        if(value[index].isHighSurrogate()) {require(index+1<value.length && value[index+1].isLowSurrogate());index++}
                        else require(!value[index].isLowSurrogate())
                        index++
                    }
                    return value
                }
                if(c=='\\') {require(at<text.length);at++}
            }
            error("admin_layer_json_string")
        }
        private fun value(depth:Int,path:Int):JsonElement {
            // Both bounds precede recursion/allocation. A JSON value tree with
            // N nodes needs at least2N-1 bytes, so this covers the whole byte cap.
            require(depth<=MAX_DEPTH && nodes<MAX_NODES);nodes++
            val first=peek();val start=at
            val result=when(first) {
                '{'->{
                    take('{');val fields=linkedMapOf<String,JsonElement>()
                    val limit=if(path==ORIGINS)4096 else 512
                    if(peek()!='}')while(true) {
                        require(fields.size<limit);val key=string();require(key !in fields);take(':')
                        val child=when {
                            inventory && path==ROOT && key=="effective"->EFFECTIVE
                            path==EFFECTIVE && key=="fields"->ORIGINS
                            else->OTHER
                        }
                        fields[key]=value(depth+1,child)
                        if(peek()=='}')break
                        take(',')
                    }
                    take('}');JsonObject(fields)
                }
                '['->{
                    take('[');val items=arrayListOf<JsonElement>()
                    if(peek()!=']')while(true) {
                        require(items.size<512);items.add(value(depth+1,OTHER))
                        if(peek()==']')break
                        take(',')
                    }
                    take(']');JsonArray(items)
                }
                '"'->JsonPrimitive(string())
                't','f','n'->{
                    val word=when(peek()) {'t'->"true";'f'->"false";else->"null"}
                    require(text.startsWith(word,at));at+=word.length
                    when(word) {"true"->JsonPrimitive(true);"false"->JsonPrimitive(false);else->JsonNull}
                }
                else->{
                    val start=at;if(text[at]=='-')at++
                    require(at<text.length && text[at] in '0'..'9')
                    if(text[at]=='0')at++ else while(at<text.length && text[at] in '0'..'9')at++
                    if(at<text.length && text[at]=='.') {
                        at++;val digits=at
                        while(at<text.length && text[at] in '0'..'9')at++
                        require(at>digits)
                    }
                    if(at<text.length && text[at] in "eE") {
                        at++;if(at<text.length && text[at] in "+-")at++
                        val digits=at;while(at<text.length && text[at] in '0'..'9')at++
                        require(at>digits)
                    }
                    val lexeme=text.substring(start,at)
                    require(lexeme.length<=64)
                    val exponent=lexeme.indexOfAny(charArrayOf('e','E'))
                    if(exponent>=0)require(lexeme.substring(exponent+1).toIntOrNull()?.let {it in -308..308}==true)
                    val number=lexeme.toDouble();require(number.isFinite() && abs(number)<=MAX_INTEGER.toDouble())
                    JsonUnquotedLiteral(lexeme)
                }
            }
            spans[result]=intArrayOf(start,at)
            return result
        }
        fun parse():Document {val result=value(0,ROOT);whitespace();require(at==text.length);return Document(result,text,spans)}
    }
}
