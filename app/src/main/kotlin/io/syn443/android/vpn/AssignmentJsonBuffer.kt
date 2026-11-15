package io.syn443.android.vpn

import io.syn443.identity.AssignmentState
import io.syn443.policy.Policy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.encodeToStream
import java.io.OutputStream
import javax.crypto.Cipher

/** Enforce the UTF-8 byte limit while encoding, before a full JSON allocation.
 * Plaintext chunks are private to one worker and wiped on every exit path. */
internal class AssignmentJsonBuffer(private val limit:Int):OutputStream() {
    private val chunks=ArrayList<ByteArray>()
    private var count=0
    private var closed=false
    init {require(limit in 1..2_097_152)}
    override fun write(value:Int) {
        require(!closed && count<limit)
        if(count%8192==0)chunks.add(ByteArray(minOf(8192,limit-count)))
        chunks.last()[count%8192]=value.toByte();count++
    }
    override fun write(bytes:ByteArray,offset:Int,length:Int) {
        require(!closed && offset>=0 && length>=0 && offset<=bytes.size && length<=bytes.size-offset && length<=limit-count)
        var from=offset;var remaining=length
        while(remaining>0) {
            if(count%8192==0)chunks.add(ByteArray(minOf(8192,limit-count)))
            val chunk=chunks.last();val position=count%8192
            val n=minOf(remaining,chunk.size-position)
            bytes.copyInto(chunk,position,from,from+n)
            from+=n;remaining-=n;count+=n
        }
    }
    /** Same v1 nonce/ciphertext/tag format, without concatenating large arrays. */
    fun encrypt(cipher:Cipher):ByteArray {
        require(!closed && count in 1..limit)
        val iv=cipher.iv;require(iv.size==12 && cipher.getOutputSize(count)==count+16)
        val result=ByteArray(count+29);result[0]=1;iv.copyInto(result,1)
        try {
            var offset=13;var remaining=count
            for(chunk in chunks) {
                val size=minOf(chunk.size,remaining)
                offset+=cipher.update(chunk,0,size,result,offset);remaining-=size
            }
            offset+=cipher.doFinal(result,offset)
            check(remaining==0 && offset==result.size)
            return result
        } catch(e:Exception) {result.fill(0);throw e}
    }
    override fun close() {chunks.forEach {it.fill(0)};chunks.clear();count=0;closed=true}

    companion object {
        /** A streaming comparison keeps strict canonical bytes, including UTF-8,
         * without allocating a second journal-sized String/character buffer. */
        @OptIn(ExperimentalSerializationApi::class)
        fun requireCanonical(value:AssignmentState,expected:ByteArray) {
            var at=0
            val output=object:OutputStream() {
                override fun write(value:Int) {
                    require(at<expected.size && (expected[at++].toInt() and 255)==(value and 255))
                }
                override fun write(bytes:ByteArray,offset:Int,length:Int) {
                    require(offset>=0 && length>=0 && offset<=bytes.size && length<=bytes.size-offset && length<=expected.size-at)
                    for(i in offset until offset+length)require(bytes[i]==expected[at++])
                }
            }
            Policy.json.encodeToStream(AssignmentState.serializer(),value,output)
            require(at==expected.size)
        }
    }
}
