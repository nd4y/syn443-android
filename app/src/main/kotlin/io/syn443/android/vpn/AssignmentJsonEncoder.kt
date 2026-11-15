package io.syn443.android.vpn

import io.syn443.identity.AssignmentState
import io.syn443.policy.Policy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.CompositeEncoder
import java.io.OutputStream
import java.util.ArrayDeque

/** Canonical storage subset: typed objects, lists, null, booleans, integers and
 * UTF-8 strings. A quoted string never becomes a temporary escaped allocation.
 * Unsupported future field kinds fail closed until their encoding is reviewed. */
@OptIn(ExperimentalSerializationApi::class)
private class AssignmentStream(private val output:OutputStream):AbstractEncoder(),AutoCloseable {
    override val serializersModule=Policy.json.serializersModule
    private class Frame(val descriptor:SerialDescriptor,val array:Boolean,var first:Boolean=true)
    private val frames=ArrayDeque<Frame>()
    private val bytes=ByteArray(8192)
    private var used=0

    private fun flush() {if(used>0) {output.write(bytes,0,used);bytes.fill(0,0,used);used=0}}
    private fun byte(value:Int) {if(used==bytes.size)flush();bytes[used++]=value.toByte()}
    private fun ascii(value:String) {for(c in value) {require(c.code<128);byte(c.code)}}
    override fun beginStructure(descriptor:SerialDescriptor):CompositeEncoder {
        require(frames.size<16)
        val array=when(descriptor.kind) {
            StructureKind.CLASS,StructureKind.OBJECT->false
            StructureKind.LIST->true
            else->error("unsupported_assignment_structure")
        }
        byte(if(array)91 else 123);frames.addLast(Frame(descriptor,array));return this
    }
    override fun endStructure(descriptor:SerialDescriptor) {
        val frame=frames.removeLast();require(frame.descriptor==descriptor)
        byte(if(frame.array)93 else 125)
    }
    override fun encodeElement(descriptor:SerialDescriptor,index:Int):Boolean {
        val frame=checkNotNull(frames.peekLast());require(frame.descriptor==descriptor)
        if(!frame.first)byte(44)
        frame.first=false
        if(!frame.array) {encodeString(descriptor.getElementName(index));byte(58)}
        return true
    }
    override fun shouldEncodeElementDefault(descriptor:SerialDescriptor,index:Int)=true
    override fun encodeNull()=ascii("null")
    override fun encodeBoolean(value:Boolean)=ascii(if(value)"true" else "false")
    override fun encodeByte(value:Byte)=ascii(value.toString())
    override fun encodeShort(value:Short)=ascii(value.toString())
    override fun encodeInt(value:Int)=ascii(value.toString())
    override fun encodeLong(value:Long)=ascii(value.toString())
    override fun encodeChar(value:Char)=encodeString(value.toString())
    override fun encodeFloat(value:Float):Unit=error("unsupported_assignment_number")
    override fun encodeDouble(value:Double):Unit=error("unsupported_assignment_number")
    override fun encodeEnum(enumDescriptor:SerialDescriptor,index:Int)=encodeString(enumDescriptor.getElementName(index))
    override fun encodeString(value:String) {
        byte(34)
        var i=0
        while(i<value.length) {
            val c=value[i++].code
            when(c) {
                34->ascii("\\\"")
                92->ascii("\\\\")
                8->ascii("\\b")
                9->ascii("\\t")
                10->ascii("\\n")
                12->ascii("\\f")
                13->ascii("\\r")
                in 0..31->{ascii("\\u00");byte("0123456789abcdef"[c ushr 4].code);byte("0123456789abcdef"[c and 15].code)}
                in 32..127->byte(c)
                in 128..2047->{byte(0xc0 or (c ushr 6));byte(0x80 or (c and 63))}
                in 0xd800..0xdbff->{
                    require(i<value.length && value[i].isLowSurrogate())
                    val code=Character.toCodePoint(c.toChar(),value[i++])
                    byte(0xf0 or (code ushr 18));byte(0x80 or ((code ushr 12) and 63))
                    byte(0x80 or ((code ushr 6) and 63));byte(0x80 or (code and 63))
                }
                in 0xdc00..0xdfff->throw IllegalArgumentException("invalid_assignment_unicode")
                else->{byte(0xe0 or (c ushr 12));byte(0x80 or ((c ushr 6) and 63));byte(0x80 or (c and 63))}
            }
        }
        byte(34)
    }
    fun finish() {require(frames.isEmpty());flush()}
    override fun close() {bytes.fill(0);used=0;frames.clear()}
}

internal object AssignmentJsonEncoder {
    fun encode(value:AssignmentState,output:OutputStream) {
        AssignmentStream(output).use {writer->AssignmentState.serializer().serialize(writer,value);writer.finish()}
    }
}
