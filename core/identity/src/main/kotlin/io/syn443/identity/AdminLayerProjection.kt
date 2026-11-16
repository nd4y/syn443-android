package io.syn443.identity

import kotlinx.serialization.json.*
import java.util.Collections

internal enum class AdminLayerProjectionCode { INVALID, LOCKED, CONFLICT }
internal class AdminLayerProjectionException(val code:AdminLayerProjectionCode):Exception(code.name)

/** Local declarative projection only; no supported-settings compiler, source
 * lookup, role, signature, current approval or publication authority. */
class AdminLayerProjection internal constructor(internal val document:JsonObject,internal val fields:Map<String,JsonObject>,
    internal val restrictions:List<JsonObject>) {
    fun documentJson():String=AdminLayerValues.go(document)
    fun wireJson():String=AdminLayerValues.go(JsonObject(mapOf("document" to document,"fields" to JsonObject(fields),"restrictions" to JsonArray(restrictions))))
    override fun toString()="AdminLayerProjection([redacted])"
}

internal object AdminLayerValues {
    const val MAX=9_007_199_254_740_991L
    fun same(a:JsonElement?,b:JsonElement?):Boolean=if(a==null || b==null)a==b else AdminLayerControl.sameLayerValue(a,b)
    fun contains(a:String,b:String)=a==b || b.startsWith(a+"/")
    fun overlaps(a:String,b:String)=contains(a,b) || contains(b,a)
    fun text(v:JsonElement)=v.jsonPrimitive.let {require(it.isString);it.content}
    fun n(v:JsonElement)=v.jsonPrimitive.let {require(!it.isString && Regex("-?(0|[1-9][0-9]*)").matches(it.content));it.long.also {n->require(n in -MAX..MAX)}}
    fun quote(s:String):String=buildString {
        append('"')
        for(c in s)when(c) {
            '"'->append("\\\"");'\\'->append("\\\\");'\b'->append("\\b");'\u000c'->append("\\f");'\n'->append("\\n");'\r'->append("\\r");'\t'->append("\\t")
            '<'->append("\\u003c");'>'->append("\\u003e");'&'->append("\\u0026");'\u2028'->append("\\u2028");'\u2029'->append("\\u2029")
            else->if(c.code<32)append("\\u"+c.code.toString(16).padStart(4,'0')) else append(c)
        }
        append('"')
    }
    private val utf8Order=Comparator<String> {a,b->
        val x=a.toByteArray(Charsets.UTF_8);val y=b.toByteArray(Charsets.UTF_8);var result=0;var i=0
        while(i<minOf(x.size,y.size) && result==0){result=(x[i].toInt() and 255)-(y[i].toInt() and 255);i++}
        if(result==0)x.size-y.size else result
    }
    // encoding/json with UseNumber: lexical numbers, HTML-safe strings, UTF-8
    // map-key ordering. This is deliberately not BigDecimal normalization.
    fun go(v:JsonElement):String=when(v) {
        is JsonObject->v.keys.sortedWith(utf8Order).joinToString(",","{","}"){quote(it)+":"+go(v.getValue(it))}
        is JsonArray->v.joinToString(",","[","]"){go(it)}
        is JsonPrimitive->if(v.isString)quote(v.content) else v.content
    }
    fun lexicalSame(a:JsonElement?,b:JsonElement?)=if(a==null || b==null)a==b else go(a)==go(b)
    fun rawObject(vararg fields:Pair<String,String>)=fields.joinToString(",","{","}"){quote(it.first)+":"+it.second}
    fun origin(layer:JsonObject)=JsonObject(mapOf("layerId" to layer.getValue("id"),"kind" to layer.getValue("kind"),"revision" to layer.getValue("revision")))
    fun rows(layer:JsonObject,key:String)=layer.getValue(key).takeIf {it!=JsonNull}?.jsonArray.orEmpty()
    fun identity(layer:JsonElement)=layer.jsonObject.let {text(it.getValue("kind"))+"/"+text(it.getValue("id"))}
    fun rawCompact(raw:String):String=buildString {
        var quoted=false;var escaped=false
        for(c in raw) {
            if(!quoted && c in " \t\r\n")continue
            if(quoted && !escaped)when(c){'<'->append("\\u003c");'>'->append("\\u003e");'&'->append("\\u0026");'\u2028'->append("\\u2028");'\u2029'->append("\\u2029");else->append(c)} else append(c)
            if(c=='"' && !escaped)quoted=!quoted
            if(quoted && c=='\\' && !escaped)escaped=true else escaped=false
        }
    }
    fun layerBytes(layer:JsonObject,doc:AdminLayerJson.Document):Int {
        fun changes()=if(layer["changes"]==JsonNull)"null" else rows(layer,"changes").joinToString(",","[","]") {row->
            val c=row.jsonObject
            rawObject(*listOfNotNull("path" to go(c.getValue("path")),"operation" to go(c.getValue("operation")),
                c["value"]?.let {"value" to rawCompact(doc.raw(it))}).toTypedArray())
        }
        fun permissions()=if(layer["permissions"]==JsonNull)"null" else rows(layer,"permissions").joinToString(",","[","]") {row->
            val p=row.jsonObject
            rawObject(*listOfNotNull("path" to go(p.getValue("path")),"mode" to go(p.getValue("mode")),
                p["choices"]?.jsonArray?.takeIf {it.isNotEmpty()}?.let {choices->"choices" to choices.joinToString(",","[","]"){rawCompact(doc.raw(it))}},
                p["minimum"]?.let {"minimum" to n(it).toString()},p["maximum"]?.let {"maximum" to n(it).toString()}).toTypedArray())
        }
        return rawObject("id" to go(layer.getValue("id")),"kind" to go(layer.getValue("kind")),"priority" to n(layer.getValue("priority")).toString(),
            "revision" to n(layer.getValue("revision")).toString(),"changes" to changes(),"permissions" to permissions()).toByteArray(Charsets.UTF_8).size
    }
}

internal object AdminLayerProjector {
    private val key=Regex("[A-Za-z][A-Za-z0-9_-]{0,63}")
    private fun bad(code:AdminLayerProjectionCode=AdminLayerProjectionCode.INVALID):Nothing=throw AdminLayerProjectionException(code)
    private fun lookup(root:JsonObject,path:String):JsonElement? {
        var value:JsonElement=root
        for(part in path.substring(1).split('/'))value=(value as? JsonObject)?.get(part) ?:return null
        return value
    }
    private fun apply(root:JsonObject,path:String,operation:String,value:JsonElement?):JsonObject {
        val parts=path.substring(1).split('/')
        fun at(node:JsonObject,index:Int):JsonObject {
            val values=node.toMutableMap();val name=parts[index]
            if(index==parts.lastIndex){if(operation=="delete")values.remove(name) else values[name]=checkNotNull(value)}
            else {
                val next=values[name]
                if(next==null && operation=="delete")return node
                val child=if(next==null)JsonObject(emptyMap()) else next as? JsonObject ?:bad()
                values[name]=at(child,index+1)
            }
            return JsonObject(values)
        }
        return at(root,0)
    }
    internal fun leaves(root:JsonObject):Map<String,JsonElement> {
        val result=linkedMapOf<String,JsonElement>()
        fun walk(value:JsonElement,path:String,depth:Int) {
            if(depth>16 || result.size>4096)bad()
            if(value is JsonObject && value.isNotEmpty())for((name,child) in value) {
                if(!key.matches(name))bad();walk(child,"$path/$name",depth+1)
            } else {
                if(path.isNotEmpty())AdminLayerControl.effectiveFieldPath(path)
                result[path]=value
            }
        }
        walk(root,"",0);result.remove("");if(result.size>4096)bad();return result
    }
    private fun allowed(permission:JsonObject,value:JsonElement?):Boolean=when(AdminLayerValues.text(permission.getValue("mode"))) {
        "locked"->false;"free"->true
        "choice"->value!=null && permission.getValue("choices").jsonArray.any {AdminLayerValues.lexicalSame(it,value)}
        "range"->if(value !is JsonPrimitive || value.isString || !Regex("-?(0|[1-9][0-9]*)").matches(value.content))false else {
            val n=value.content.toLongOrNull()
            n!=null && (permission["minimum"]?.let {n>=AdminLayerValues.n(it)}?:true) && (permission["maximum"]?.let {n<=AdminLayerValues.n(it)}?:true)
        }
        else->bad()
    }
    fun project(doc:AdminLayerJson.Document,layers:JsonArray,device:String):AdminLayerProjection {
        try {
            AdminLayerControl.layers(layers,device)
            if(layers.any {AdminLayerValues.layerBytes(it.jsonObject,doc)>262_144})bad()
            val order=mapOf("template" to 0,"group" to 1,"user" to 2,"device" to 3,"local" to 4)
            val sorted=layers.map {it.jsonObject}.sortedWith(compareBy<JsonObject> {order.getValue(AdminLayerValues.text(it.getValue("kind")))}
                .thenBy {AdminLayerValues.n(it.getValue("priority"))}.thenBy {AdminLayerValues.text(it.getValue("id"))})
            var root=JsonObject(emptyMap());val fields=linkedMapOf<String,JsonObject>();val restrictions=ArrayList<JsonObject>()
            data class Claim(val signature:String,val layerId:String)
            val groups=mutableMapOf<Long,MutableMap<String,Claim>>()
            fun claim(priority:Long,path:String,signature:String,layerId:String) {
                val writes=groups.getOrPut(priority){linkedMapOf()}
                for((prior,old) in writes)if(old.layerId!=layerId) {
                    if(prior==path && old.signature!=signature)bad(AdminLayerProjectionCode.CONFLICT)
                    if(prior!=path && AdminLayerValues.overlaps(prior,path) && (old.signature!="deleted" || signature!="deleted"))bad(AdminLayerProjectionCode.CONFLICT)
                }
                writes[path]=Claim(signature,layerId)
            }
            for(layer in sorted) {
                val origin=AdminLayerValues.origin(layer);val kind=AdminLayerValues.text(layer.getValue("kind"));val id=AdminLayerValues.text(layer.getValue("id"));val priority=AdminLayerValues.n(layer.getValue("priority"))
                for(row in AdminLayerValues.rows(layer,"changes")) {
                    val change=row.jsonObject;val path=AdminLayerValues.text(change.getValue("path"));val operation=AdminLayerValues.text(change.getValue("operation"))
                    val previous=root;root=apply(root,path,operation,change["value"])
                    if(AdminLayerValues.go(root).toByteArray(Charsets.UTF_8).size>262_144)bad()
                    val old=leaves(previous);val next=leaves(root)
                    for(r in restrictions) {
                        val p=r.getValue("permission").jsonObject;val restricted=AdminLayerValues.text(p.getValue("path"))
                        if(!AdminLayerValues.overlaps(path,restricted) || AdminLayerValues.lexicalSame(lookup(previous,restricted),lookup(root,restricted)))continue
                        if(!allowed(p,lookup(root,restricted)))bad(AdminLayerProjectionCode.LOCKED)
                    }
                    if(kind=="local" && restrictions.none {r->val p=r.getValue("permission").jsonObject
                        AdminLayerValues.contains(AdminLayerValues.text(p.getValue("path")),path) && AdminLayerValues.text(p.getValue("mode"))!="locked"})bad(AdminLayerProjectionCode.LOCKED)
                    var touched=false
                    for(p in old.keys+next.keys) {
                        val changed=!AdminLayerValues.lexicalSame(old[p],next[p])
                        if(!AdminLayerValues.contains(path,p) && !(changed && AdminLayerValues.contains(p,path)))continue
                        touched=true
                        if(kind=="group") {
                            if(p !in next && lookup(root,p)!=null){fields.remove(p);continue}
                            claim(priority,p,next[p]?.let {"set/"+AdminLayerValues.go(it)}?:"deleted",id)
                        }
                        if(p in next)fields[p]=origin else fields.remove(p)
                    }
                    if(kind=="group" && !touched && operation=="delete")claim(priority,path,"deleted",id)
                }
                for(row in AdminLayerValues.rows(layer,"permissions")) {
                    val p=row.jsonObject;val path=AdminLayerValues.text(p.getValue("path"));val mode=AdminLayerValues.text(p.getValue("mode"))
                    if(kind!="template" && mode!="locked") {
                        var inherited=false
                        for(r in restrictions) {
                            val existing=r.getValue("permission").jsonObject;val parent=AdminLayerValues.text(existing.getValue("path"));val parentMode=AdminLayerValues.text(existing.getValue("mode"))
                            if(AdminLayerValues.contains(parent,path) && parentMode!="locked")inherited=true
                            if(parentMode=="locked" && AdminLayerValues.overlaps(parent,path))bad(AdminLayerProjectionCode.LOCKED)
                        }
                        if(!inherited)bad(AdminLayerProjectionCode.LOCKED)
                    }
                    val value=lookup(root,path)
                    if(value==null || mode!="locked" && !allowed(p,value))bad()
                    restrictions+=JsonObject(mapOf("permission" to p,"origin" to origin))
                }
            }
            return AdminLayerProjection(root,Collections.unmodifiableMap(fields),Collections.unmodifiableList(restrictions))
        }catch(e:AdminLayerProjectionException){throw e}catch(_:Exception){bad()}
    }
}
