package io.syn443.android.admin

import android.os.Looper
import io.syn443.policy.Policy
import kotlinx.serialization.json.JsonPrimitive
import java.io.ByteArrayOutputStream

/** Private same-UID presentation values only, never session, role or native credentials.
 * No remote JSON is spliced into this closed wire. Encoding and parsing require
 * a worker; the narrow reader accepts only this model's fixed-depth grammar. */
internal object AdminEditorWire {
    const val MAX_BODY=524_288
    private const val MAX_INTEGER=9_007_199_254_740_991L
    private val id=Regex("[A-Za-z0-9_-]{1,64}")
    private val binding=Regex("[A-Za-z0-9_-]{1,128}")
    private val code=Regex("[A-Z][A-Z0-9_]{0,63}")
    private val kinds=setOf("template","group","user","device","local")
    private val fields=setOf("schemaVersion","device","privateDraftRevision","desiredHeadRevision","localRevision",
        "phase","busy","readOnly","unassigned","documentBinding","pages","parents","reviewBinding",
        "reviewDeadlineElapsed","recipients","diffSummaries","error")

    private fun worker() {
        if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
            throw AdminUiFailure("WRONG_THREAD")
    }
    private inline fun <T> checked(action:()->T):T=try {action()}
        catch(error:AdminUiFailure) {throw error}
        catch(_:Exception) {throw AdminUiFailure("INVALID_REPLY")}
    private fun valid(value:AdminEditorModel) {
        require(value.device.isEmpty() || id.matches(value.device))
        require(listOf(value.privateDraftRevision,value.desiredHeadRevision,value.localRevision,value.reviewDeadlineElapsed)
            .all {it in 0..MAX_INTEGER})
        require(value.documentBinding.isEmpty() || binding.matches(value.documentBinding))
        require(value.reviewBinding.isEmpty() || binding.matches(value.reviewBinding))
        require(value.pages.size<=64 && value.pages.all {it.length<=8192 && editorUnicode(it)})
        require(value.pages.isEmpty() || value.documentBinding.isNotEmpty())
        require(value.parents.size<=20 && value.parents.all {it.kind in kinds && id.matches(it.id) && it.revision in 1..MAX_INTEGER})
        require(value.parents.map {it.kind to it.id}.toSet().size==value.parents.size)
        require(value.recipients.size<=64 && value.recipients.all {id.matches(it)} && value.recipients.toSet().size==value.recipients.size)
        require(value.diffSummaries.size<=64 && value.diffSummaries.all {it.length<=512 && editorUnicode(it)})
        require(value.error.isEmpty() || code.matches(value.error))
    }
    private class Output {
        private val bytes=ByteArrayOutputStream(4096)
        fun raw(value:String) {
            val part=value.toByteArray(Charsets.UTF_8)
            require(part.size<=MAX_BODY-bytes.size());bytes.write(part)
        }
        fun text(value:String)=raw(JsonPrimitive(value).toString())
        fun array(values:List<String>) {
            raw("[");values.forEachIndexed {index,value->if(index>0)raw(",");text(value)};raw("]")
        }
        fun body()=bytes.toByteArray()
    }
    fun encode(value:AdminEditorModel):ByteArray {
        worker()
        return checked {
            valid(value)
            val out=Output();out.raw("{\"schemaVersion\":1")
            fun field(name:String,body:()->Unit) {out.raw(",");out.text(name);out.raw(":");body()}
            field("device") {out.text(value.device)}
            field("privateDraftRevision") {out.raw(value.privateDraftRevision.toString())}
            field("desiredHeadRevision") {out.raw(value.desiredHeadRevision.toString())}
            field("localRevision") {out.raw(value.localRevision.toString())}
            field("phase") {out.text(value.phase.name)}
            field("busy") {out.raw(value.busy.toString())}
            field("readOnly") {out.raw(value.readOnly.toString())}
            field("unassigned") {out.raw(value.unassigned.toString())}
            field("documentBinding") {out.text(value.documentBinding)}
            field("pages") {out.array(value.pages)}
            field("parents") {
                out.raw("[")
                value.parents.forEachIndexed {index,parent->
                    if(index>0)out.raw(",")
                    out.raw("{\"kind\":");out.text(parent.kind);out.raw(",\"id\":");out.text(parent.id)
                    out.raw(",\"revision\":");out.raw(parent.revision.toString());out.raw("}")
                }
                out.raw("]")
            }
            field("reviewBinding") {out.text(value.reviewBinding)}
            field("reviewDeadlineElapsed") {out.raw(value.reviewDeadlineElapsed.toString())}
            field("recipients") {out.array(value.recipients)}
            field("diffSummaries") {out.array(value.diffSummaries)}
            field("error") {out.text(value.error)}
            out.raw("}");out.body()
        }
    }
    fun decode(raw:ByteArray):AdminEditorModel {
        worker()
        return checked {
            require(raw.size in 1..MAX_BODY)
            val owned=raw.copyOf()
            try {Reader(Policy.utf8(owned)).model().also(::valid)}finally {owned.fill(0)}
        }
    }

    /** No generic tree allocation or recursive/unbounded value skipper. Unknown
     * fields, duplicate decoded keys and nested strings/arrays fail immediately. */
    private class Reader(private val source:String) {
        private var at=0
        private fun space() {while(at<source.length && source[at] in " \t\r\n")at++}
        private fun take(value:Char):Boolean {space();return if(at<source.length && source[at]==value) {at++;true}else false}
        private fun expect(value:Char) {require(take(value))}
        private fun text(maximum:Int):String {
            expect('"');val out=StringBuilder()
            while(at<source.length) {
                val next=source[at++]
                if(next=='"')return out.toString().also {require(editorUnicode(it))}
                require(next.code>=32)
                val decoded=if(next!='\\')next else {
                    require(at<source.length)
                    when(val escaped=source[at++]) {
                        '"','\\','/'->escaped
                        'b'->'\b';'f'->'\u000c';'n'->'\n';'r'->'\r';'t'->'\t'
                        'u'->{
                            require(source.length-at>=4);var value=0
                            repeat(4) {
                                val digit=source[at++];require(digit in '0'..'9' || digit in 'a'..'f' || digit in 'A'..'F')
                                value=value*16+checkNotNull(digit.digitToIntOrNull(16))
                            }
                            value.toChar()
                        }
                        else->error("invalid_escape")
                    }
                }
                require(out.length<maximum);out.append(decoded)
            }
            error("incomplete_string")
        }
        private fun integer():Long {
            space();val start=at
            require(at<source.length && source[at] in '0'..'9')
            if(source[at]=='0')at++ else while(at<source.length && source[at] in '0'..'9') {
                require(at-start<16);at++
            }
            require(at==source.length || source[at] in " \t\r\n,}]")
            return source.substring(start,at).toLong().also {require(it in 0..MAX_INTEGER)}
        }
        private fun boolean():Boolean {
            space()
            return when {
                source.startsWith("true",at)->{at+=4;true}
                source.startsWith("false",at)->{at+=5;false}
                else->error("invalid_boolean")
            }
        }
        private fun strings(maximum:Int,length:Int):List<String> {
            expect('[');val result=ArrayList<String>()
            if(take(']'))return result
            do {require(result.size<maximum);result+=text(length)}while(take(','))
            expect(']');return result
        }
        private fun parentRows():List<AdminEditorParent> {
            expect('[');val result=ArrayList<AdminEditorParent>()
            if(take(']'))return result
            do {
                require(result.size<20);expect('{');val seen=HashSet<String>()
                var kind:String?=null;var id:String?=null;var revision:Long?=null
                do {
                    val name=text(16);require(seen.add(name));expect(':')
                    when(name) {"kind"->kind=text(16);"id"->id=text(64);"revision"->revision=integer();else->error("unknown_parent")}
                }while(take(','))
                expect('}');require(seen==setOf("kind","id","revision"))
                result+=AdminEditorParent(checkNotNull(kind),checkNotNull(id),checkNotNull(revision))
            }while(take(','))
            expect(']');return result
        }
        fun model():AdminEditorModel {
            expect('{');val seen=HashSet<String>()
            var device="";var privateRevision=0L;var desiredRevision=0L;var localRevision=0L
            var phase=AdminEditorPhase.INVENTORY;var busy=false;var readOnly=false;var unassigned=false
            var document="";var pages:List<String> = emptyList();var parents:List<AdminEditorParent> = emptyList()
            var review="";var deadline=0L;var recipients:List<String> = emptyList();var differences:List<String> = emptyList();var error=""
            do {
                val name=text(32);require(name in fields && seen.add(name));expect(':')
                when(name) {
                    "schemaVersion"->require(integer()==1L)
                    "device"->device=text(64)
                    "privateDraftRevision"->privateRevision=integer()
                    "desiredHeadRevision"->desiredRevision=integer()
                    "localRevision"->localRevision=integer()
                    "phase"->phase=AdminEditorPhase.valueOf(text(32))
                    "busy"->busy=boolean()
                    "readOnly"->readOnly=boolean()
                    "unassigned"->unassigned=boolean()
                    "documentBinding"->document=text(128)
                    "pages"->pages=strings(64,8192)
                    "parents"->parents=parentRows()
                    "reviewBinding"->review=text(128)
                    "reviewDeadlineElapsed"->deadline=integer()
                    "recipients"->recipients=strings(64,64)
                    "diffSummaries"->differences=strings(64,512)
                    "error"->error=text(64)
                }
            }while(take(','))
            expect('}');space();require(at==source.length && seen==fields)
            return AdminEditorModel(device=device,privateDraftRevision=privateRevision,desiredHeadRevision=desiredRevision,
                localRevision=localRevision,phase=phase,busy=busy,readOnly=readOnly,unassigned=unassigned,documentBinding=document,
                pages=pages,parents=parents,reviewBinding=review,reviewDeadlineElapsed=deadline,recipients=recipients,diffSummaries=differences,error=error)
        }
    }
}
