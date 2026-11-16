package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.json.*

/** Configuration-inventory replies only. OAuth, signatures and other control responses keep Canonical.parse. */
internal object AdminControlJson {
    private const val MAX_BYTES=524_288
    private const val MAX_MEMBERS=512
    private const val MAX_DEPTH=24
    private const val MAX_INTEGER=9_007_199_254_740_991L
    private const val ROOT=0
    private const val EFFECTIVE=1
    private const val EFFECTIVE_FIELDS=2
    private const val OTHER=3
    fun parse(raw:String):JsonElement {
        require(raw.length in 1..MAX_BYTES && raw.toByteArray(Charsets.UTF_8).size<=MAX_BYTES)
        return Reader(raw).parse()
    }
    private class Reader(private val text:String) {
        private var at=0
        private fun whitespace() {while(at<text.length && text[at] in " \t\r\n")at++}
        private fun take(c:Char) {whitespace();require(at<text.length && text[at++]==c)}
        private fun peek():Char {whitespace();require(at<text.length);return text[at]}
        private fun string():String {
            whitespace();val start=at;take('"')
            while(at<text.length) {
                val c=text[at++];require(c>=' ')
                if(c=='"') {
                    val value=Canonical.json.decodeFromString<String>(text.substring(start,at))
                    var i=0
                    while(i<value.length) {
                        if(value[i].isHighSurrogate()) {require(i+1<value.length && value[i+1].isLowSurrogate());i++}
                        else require(!value[i].isLowSurrogate())
                        i++
                    }
                    return value
                }
                if(c=='\\') {require(at<text.length);at++}
            }
            error("admin_configuration_json_string")
        }
        private fun value(depth:Int,path:Int):JsonElement {
            require(depth<=MAX_DEPTH)
            return when(peek()) {
                '{'->{
                    take('{');val fields=linkedMapOf<String,JsonElement>()
                    val limit=if(path==EFFECTIVE_FIELDS)4096 else MAX_MEMBERS
                    if(peek()!='}')while(true) {
                        require(fields.size<limit)
                        val key=string();require(key !in fields);take(':')
                        val child=when {
                            path==ROOT && key=="effective"->EFFECTIVE
                            path==EFFECTIVE && key=="fields"->EFFECTIVE_FIELDS
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
                        require(items.size<MAX_MEMBERS);items.add(value(depth+1,OTHER))
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
                    require(at-start<=17)
                    val number=text.substring(start,at).toLong();require(number in -MAX_INTEGER..MAX_INTEGER)
                    JsonPrimitive(number)
                }
            }
        }
        fun parse():JsonElement {
            val result=value(0,ROOT);whitespace();require(at==text.length);return result
        }
    }
}
