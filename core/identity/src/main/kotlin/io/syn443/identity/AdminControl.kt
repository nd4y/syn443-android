package io.syn443.identity

import io.syn443.identity.AdminIdentity.Companion.integer
import io.syn443.identity.AdminIdentity.Companion.text
import io.syn443.policy.Canonical
import kotlinx.serialization.json.*
import java.util.Collections

class AdminActivation internal constructor(val state:String,val policyRevision:Long,val outcome:String,
    val activePolicyRevision:Long,val receivedAtMs:Long) {
    override fun toString()="AdminActivation([redacted])"
}
class AdminDeviceSummary internal constructor(val device:String,val policyRevision:Long,val desiredRevision:Long,
    val report:AdminActivation) {
    override fun toString()="AdminDeviceSummary([redacted])"
}
class AdminDevicePage internal constructor(devices:List<AdminDeviceSummary>,val next:String,val observedAtMs:Long,private val wire:String) {
    val devices:List<AdminDeviceSummary> = Collections.unmodifiableList(ArrayList(devices))
    fun wireJson()=wire
    override fun toString()="AdminDevicePage([redacted])"
}
/** Read-only metadata projection. Explicit wire handoff is for the authorized private UI, never global status/logging. */
class AdminDeviceConfiguration internal constructor(val device:String,val state:String,val revision:Long,
    val policyRevision:Long,val mode:String,val publicationSource:String?,val activation:AdminActivation?,
    private val completeDocument:String) {
    fun wireJson()=completeDocument
    override fun toString()="AdminDeviceConfiguration([redacted])"
}
class AdminRuntimeReport internal constructor(val sample:RuntimeObservation.Report,val receivedAtMs:Long) {
    override fun toString()="AdminRuntimeReport([redacted])"
}
/** A historical client observation, not proof that a VPN is currently connected. */
class AdminDeviceRuntime internal constructor(val device:String,val observedAtMs:Long,val state:String,val report:AdminRuntimeReport?,private val wire:String) {
    fun wireJson()=wire
    override fun toString()="AdminDeviceRuntime([redacted])"
}

internal object AdminControl {
    const val PATH="/v1/control/action"
    const val MAX_INTEGER=9_007_199_254_740_991L
    enum class Read(val action:String,val maxReply:Int) {
        DEVICES("configuration.devices.list",32_768),
        CONFIGURATION("configuration.inventory.get",524_288),
        RUNTIME("configuration.runtime.get",4096)
    }
    fun id(raw:String)=raw.matches(Regex("[A-Za-z0-9_-]{1,64}"))
    fun request(read:Read,target:String,prefix:String=""):ByteArray {
        require(id(target) || read==Read.DEVICES && target.isEmpty())
        require(prefix.isEmpty() || read==Read.DEVICES && id(prefix))
        return Canonical.encode(buildJsonObject {
            put("version",1);put("requestId",Identity.random());put("action",read.action)
            put("payload",buildJsonObject {
                put(if(read==Read.DEVICES)"after" else "id",target)
                if(prefix.isNotEmpty())put("prefix",prefix)
            })
        }).toByteArray(Charsets.UTF_8).also {require(it.size<=8192)}
    }
    fun objectReply(raw:String,read:Read):JsonObject {
        require(raw.toByteArray(Charsets.UTF_8).size in 1..read.maxReply)
        return (if(read==Read.CONFIGURATION)AdminControlJson.parse(raw) else Canonical.parse(raw)).jsonObject
    }
    private fun shape(value:JsonObject,required:Set<String>,optional:Set<String> = emptySet()) {
        require(value.keys.containsAll(required) && value.keys.all {it in required || it in optional} && value.values.none {it==JsonNull})
    }
    private fun JsonObject.number(key:String,minimum:Long=0):Long=getValue(key).integer().also {require(it in minimum..MAX_INTEGER)}
    private fun JsonObject.optionalNumber(key:String)=get(key)?.integer()?.also {require(it in 0..MAX_INTEGER)}?:0
    private fun JsonElement.boolean():Boolean=jsonPrimitive.let {require(!it.isString);it.boolean}
    private fun observation(value:Long,time:TimeWindow) {
        require(value in 1..MAX_INTEGER && value>=time.lowerMs-30_000 && value<=Math.addExact(time.upperMs,30_000))
    }
    private fun activation(value:JsonObject,issued:Long,time:TimeWindow):AdminActivation {
        shape(value,setOf("state","activePolicyRevision"),setOf("policyRevision","outcome","receivedAtMs"))
        val state=value.getValue("state").text();val policy=value.optionalNumber("policyRevision")
        val active=value.number("activePolicyRevision");val received=value.optionalNumber("receivedAtMs")
        val outcome=value["outcome"]?.text()?:""
        require(state in setOf("not_issued","awaiting_report","historical","reported") &&
            received<=Math.addExact(time.upperMs,30_000) && outcome in setOf("","committed","degraded","rolled_back"))
        when(state) {
            "not_issued"->require(issued==0L && policy==0L && active==0L && received==0L && outcome.isEmpty())
            "awaiting_report"->require(issued>0 && policy==0L && active==0L && received==0L && outcome.isEmpty())
            else->{
                require(policy>0 && received>0 && outcome.isNotEmpty())
                if(state=="reported")require(policy==issued)
                if(outcome=="rolled_back")require(active<policy) else require(active==policy)
            }
        }
        return AdminActivation(state,policy,outcome,active,received)
    }
    fun devices(value:JsonObject,after:String,time:TimeWindow,wire:String,prefix:String=""):AdminDevicePage {
        shape(value,setOf("devices","next","observedAtMs"))
        val observed=value.number("observedAtMs",1);observation(observed,time)
        val entries=value.getValue("devices").jsonArray;require(entries.size<=32)
        var previous=after
        val devices=entries.map {
            val row=it.jsonObject;shape(row,setOf("device","policyRevision","desiredRevision","report"))
            val device=row.getValue("device").text()
            require(id(device) && device>previous && device.startsWith(prefix,ignoreCase=true))
            previous=device
            val policy=row.number("policyRevision");val desired=row.number("desiredRevision")
            AdminDeviceSummary(device,policy,desired,activation(row.getValue("report").jsonObject,policy,time))
        }
        val next=value.getValue("next").text()
        require(next.isEmpty() || devices.size==32 && next==devices.last().device)
        return AdminDevicePage(devices,next,observed,wire)
    }
    fun configuration(value:JsonObject,target:String,time:TimeWindow,wire:String):AdminDeviceConfiguration {
        shape(value,setOf("device","owner","state","revision","hash","policyRevision","mode","approvalUntilMs","layers","currentRevision"),
            setOf("issuedSettings","publicationSource","effective","historical","activation"))
        val device=value.getValue("device").text();require(device==target && id(value.getValue("owner").text()))
        val revision=value.number("revision");require(value.number("currentRevision")==revision)
        val policy=value.number("policyRevision");val approval=value.number("approvalUntilMs")
        val state=value.getValue("state").text();val hash=value.getValue("hash").text();val mode=value.getValue("mode").text()
        val layers=value.getValue("layers").jsonArray;require(layers.size<=20 && layers.all {it is JsonObject})
        require(value["historical"]?.boolean()!=true)
        if(revision==0L)require(state=="unassigned" && hash.isEmpty() && mode.isEmpty() && approval==0L && layers.isEmpty() && "effective" !in value)
        else require(state in setOf("assigned","expired") && hash.matches(Regex("[0-9a-f]{64}")) && approval>0 &&
            mode in setOf("home_wifi","wifi","cellular_restricted","cellular") && layers.isNotEmpty() && value["effective"] is JsonObject)
        value["issuedSettings"]?.let {require(it is JsonObject && policy>0 && it.number("revision",1)==policy)}
        val publication=value["publicationSource"]?.text()
        require(publication==null || publication in setOf("not_issued","unlinked","different_revision","matches_desired"))
        require(publication!="not_issued" || policy==0L)
        val activation=value["activation"]?.let {activation(it.jsonObject,policy,time)}
        // All nested layer/effective/issued fields survive privately; this is not their compiler/schema validator.
        return AdminDeviceConfiguration(device,state,revision,policy,mode,publication,activation,wire)
    }
    fun runtime(value:JsonObject,target:String,time:TimeWindow,wire:String):AdminDeviceRuntime {
        shape(value,setOf("device","observedAtMs","state"),setOf("report"))
        val device=value.getValue("device").text();require(device==target)
        val observed=value.number("observedAtMs",1);observation(observed,time)
        val state=value.getValue("state").text();require(state in setOf("none","recent","stale"))
        val report=value["report"]?.let {
            val row=it.jsonObject
            shape(row,setOf("version","sequence","build","phase","policyRevision","engineKnown","engineActive","network","sampledAtMs","receivedAtMs"))
            val version=row.number("version",1);val build=row.number("build",1)
            require(version==1L && build<=2_100_000_000)
            val sample=RuntimeObservation.Report(1,row.number("sequence",1),build.toInt(),row.getValue("phase").text(),
                row.number("policyRevision"),row.getValue("engineKnown").boolean(),row.getValue("engineActive").boolean(),
                row.getValue("network").text(),row.number("sampledAtMs",1)).also {it.validate()}
            val received=row.number("receivedAtMs",1)
            require(received<=observed && sample.sampledAtMs>=received-120_000 && sample.sampledAtMs<=Math.addExact(received,30_000))
            require((state=="recent")== (observed<Math.addExact(minOf(received,sample.sampledAtMs),180_000)))
            AdminRuntimeReport(sample,received)
        }
        require((state=="none")== (report==null))
        return AdminDeviceRuntime(device,observed,state,report,wire)
    }
}
