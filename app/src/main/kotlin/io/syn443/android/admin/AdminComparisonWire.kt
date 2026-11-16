package io.syn443.android.admin

import android.os.Looper
import io.syn443.policy.Policy
import kotlinx.serialization.json.JsonPrimitive
import java.util.Base64

/** Same-UID presentation only. No OAuth/native-identity fields or grants.
 * Explicitly requested configuration details can themselves be confidential.
 * All parsing/chunking belongs to an existing worker. */
internal object AdminComparisonWire {
    const val MAX_BODY=65_536
    private const val MAX_INTEGER=9_007_199_254_740_991L
    private val fields=setOf("schemaVersion","device","binding","localRevision","section","total","offset",
        "rows","ready","detail","busy","error","readOnly","baseRevision","currentRevision")
    private val rowFields=setOf("id","kind","path","code","resolvable","choice","availableSides")
    private val detailFields=setOf("rowId","side","page","totalPages","text64")
    private fun worker() {
        if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
            throw AdminUiFailure("WRONG_THREAD")
    }
    private inline fun <T> checked(block:()->T):T=try {block()}
        catch(error:AdminUiFailure){throw error}
        catch(_:Exception){throw AdminUiFailure("INVALID_REPLY")}
    private fun quote(value:String)=JsonPrimitive(value).toString()
    private fun encoded(value:String):String {
        val raw=value.toByteArray(Charsets.UTF_8)
        return try {Base64.getUrlEncoder().withoutPadding().encodeToString(raw)}finally {raw.fill(0)}
    }
    private fun decoded(value:String):String {
        require(value.length<=32768 && value.all {it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it=='_' || it=='-'})
        val raw=Base64.getUrlDecoder().decode(value)
        return try {
            require(raw.size<=24576 && Base64.getUrlEncoder().withoutPadding().encodeToString(raw)==value)
            Policy.utf8(raw).also {require(it.length<=8192 && editorUnicode(it))}
        }finally {raw.fill(0)}
    }
    fun encode(model:AdminComparisonModel):ByteArray {
        worker()
        return checked {
            val rows=model.rows.joinToString(",","[","]") {row->
                "{\"id\":"+quote(row.id)+",\"kind\":"+quote(row.kind)+",\"path\":"+quote(row.path)+
                    ",\"code\":"+quote(row.code)+",\"resolvable\":"+row.resolvable+
                    ",\"choice\":"+quote(row.choice)+",\"availableSides\":"+
                    row.availableSides.joinToString(",","[","]"){quote(it.name)}+"}"
            }
            val detail=model.detail?.let {value->
                "{\"rowId\":"+quote(value.rowId)+",\"side\":"+quote(value.side.name)+",\"page\":"+value.page+
                    ",\"totalPages\":"+value.totalPages+",\"text64\":"+quote(encoded(value.text))+"}"
            }?:"null"
            ("{\"schemaVersion\":1,\"device\":"+quote(model.device)+",\"binding\":"+quote(model.binding)+
                ",\"localRevision\":"+model.localRevision+",\"section\":"+quote(model.section.name)+
                ",\"total\":"+model.total+",\"offset\":"+model.offset+",\"rows\":"+rows+
                ",\"ready\":"+model.ready+",\"detail\":"+detail+",\"busy\":"+model.busy+
                ",\"error\":"+quote(model.error)+",\"readOnly\":"+model.readOnly+
                ",\"baseRevision\":"+model.baseRevision+",\"currentRevision\":"+model.currentRevision+"}").toByteArray(Charsets.UTF_8)
                .also {require(it.size in 1..MAX_BODY)}
        }
    }
    fun decode(raw:ByteArray):AdminComparisonModel {
        worker()
        return checked {require(raw.size in 1..MAX_BODY);Reader(Policy.utf8(raw)).model()}
    }
    private class Reader(private val source:String) {
        private var at=0
        private fun space(){while(at<source.length && source[at] in " \r\n\t")at++}
        private fun take(char:Char):Boolean {space();if(at<source.length && source[at]==char){at++;return true};return false}
        private fun expect(char:Char){require(take(char))}
        private fun text(limit:Int):String {
            expect('"');val out=StringBuilder()
            while(at<source.length) {
                val char=source[at++]
                if(char=='"')return out.toString().also {require(editorUnicode(it))}
                require(char>=' ')
                if(char=='\\') {
                    require(at<source.length)
                    out.append(when(val escaped=source[at++]) {
                        '"','\\','/'->escaped;'b'->'\b';'f'->'\u000C';'n'->'\n';'r'->'\r';'t'->'\t'
                        'u'->{
                            require(at+4<=source.length)
                            val digits=source.substring(at,at+4)
                            require(digits.all {it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F'})
                            at+=4;digits.toInt(16).toChar()
                        }
                        else->error("invalid_escape")
                    })
                } else out.append(char)
                require(out.length<=limit)
            }
            error("incomplete_string")
        }
        private fun number():Long {
            space();val start=at
            while(at<source.length && source[at] in '0'..'9'){at++;require(at-start<=16)}
            require(at>start)
            val raw=source.substring(start,at);require(raw=="0" || !raw.startsWith('0'))
            return raw.toLong().also {require(it in 0..MAX_INTEGER)}
        }
        private fun integer(maximum:Int):Int=number().also {require(it<=maximum)}.toInt()
        private fun boolean():Boolean {
            space()
            return when {source.startsWith("true",at)->{at+=4;true};source.startsWith("false",at)->{at+=5;false};else->error("invalid_boolean")}
        }
        private fun sides():List<AdminComparisonSide> {
            expect('[');val values=ArrayList<AdminComparisonSide>()
            if(take(']'))return values
            do {require(values.size<7);val side=AdminComparisonSide.valueOf(text(16));require(side !in values);values+=side}while(take(','))
            expect(']');return values
        }
        private fun row():AdminComparisonRow {
            expect('{');val seen=HashSet<String>()
            var id="";var kind="";var path="";var code="";var resolvable=false;var choice="";var sideValues:List<AdminComparisonSide> = emptyList()
            do {
                val name=text(32);require(name in rowFields && seen.add(name));expect(':')
                when(name) {
                    "id"->id=text(43);"kind"->kind=text(32);"path"->path=text(1040);"code"->code=text(64)
                    "resolvable"->resolvable=boolean();"choice"->choice=text(7);"availableSides"->sideValues=sides()
                }
            }while(take(','))
            expect('}');require(seen==rowFields)
            return AdminComparisonRow(id,kind,path,code,resolvable,choice,sideValues)
        }
        private fun rows():List<AdminComparisonRow> {
            expect('[');val rows=ArrayList<AdminComparisonRow>()
            if(take(']'))return rows
            do {require(rows.size<20);rows+=row()}while(take(','))
            expect(']');return rows
        }
        private fun detail():AdminComparisonDetail? {
            space();if(source.startsWith("null",at)){at+=4;return null}
            expect('{');val seen=HashSet<String>();var rowId="";var side=AdminComparisonSide.BASE;var page=0;var total=0;var bodyText=""
            do {
                val name=text(32);require(name in detailFields && seen.add(name));expect(':')
                when(name) {
                    "rowId"->rowId=text(43);"side"->side=AdminComparisonSide.valueOf(text(16))
                    "page"->page=integer(255);"totalPages"->total=integer(256);"text64"->bodyText=decoded(text(32768))
                }
            }while(take(','))
            expect('}');require(seen==detailFields)
            return AdminComparisonDetail(rowId,side,page,total,bodyText)
        }
        fun model():AdminComparisonModel {
            expect('{');val seen=HashSet<String>();var version=0;var device="";var binding="";var revision=0L
            var section=AdminComparisonSection.CONFLICTS;var total=0;var offset=0;var rowValues:List<AdminComparisonRow> = emptyList()
            var ready=false;var detailValue:AdminComparisonDetail?=null;var busy=false;var errorCode="";var readOnly=false;var baseRevision=0L;var currentRevision=0L
            do {
                val name=text(32);require(name in fields && seen.add(name));expect(':')
                when(name) {
                    "schemaVersion"->version=integer(1);"device"->device=text(64);"binding"->binding=text(43)
                    "localRevision"->revision=number();"section"->section=AdminComparisonSection.valueOf(text(16))
                    "total"->total=integer(8194);"offset"->offset=integer(8194);"rows"->rowValues=rows()
                    "ready"->ready=boolean();"detail"->detailValue=detail();"busy"->busy=boolean();"error"->errorCode=text(64);"readOnly"->readOnly=boolean()
                    "baseRevision"->baseRevision=number();"currentRevision"->currentRevision=number()
                }
            }while(take(','))
            expect('}');space();require(at==source.length && version==1 && seen==fields)
            return AdminComparisonModel(device=device,binding=binding,localRevision=revision,section=section,total=total,offset=offset,
                rows=rowValues,ready=ready,detail=detailValue,busy=busy,error=errorCode,readOnly=readOnly,baseRevision=baseRevision,currentRevision=currentRevision)
        }
    }
}
