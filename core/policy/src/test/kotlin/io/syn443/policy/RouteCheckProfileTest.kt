package io.syn443.policy

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class RouteCheckProfileTest {
    private fun leaf(id:String,method:String="tcp",target:String="$id.example.invalid:443",extra:String="") =
        """{"id":"$id","check":{"method":"$method","target":"$target"$extra}}"""
    private fun profile(leaves:String=leaf("a")+","+leaf("b"),gates:String="[]",stages:String="""[{"any":[{"leaf":"a"},{"leaf":"b"}]}]""") =
        """{"schemaVersion":2,"id":"connectivity","revision":1,"deadlineMs":12000,"leaves":[$leaves],"gates":$gates,"stages":$stages}"""
    private fun rejected(block:()->Unit) {
        try {block();fail("invalid check composition admitted")}
        catch(_:IllegalArgumentException){} catch(_:IllegalStateException){}
    }
    @Test fun sharedClosedProfilesAcceptNineValidAndRejectAllFortyThreeInvalidVectors() {
        val raw=checkNotNull(javaClass.getResourceAsStream("/route-check-profile-v2-vectors.json")).use {it.readBytes().toString(Charsets.UTF_8)}
        val vectors=Canonical.parse(raw).jsonObject
        assertEquals(9,vectors.getValue("validCases").jsonArray.size)
        assertEquals(37,vectors.getValue("invalidCases").jsonArray.size)
        assertEquals(6,vectors.getValue("invalidRawCases").jsonArray.size)
        for(value in vectors.getValue("validCases").jsonArray) {
            val item=RouteCheckProfile.decode(value.jsonObject.getValue("profile").toString())
            assertEquals(item.wireJson(),RouteCheckProfile.decode(item.wireJson()).wireJson())
        }
        for(value in vectors.getValue("invalidCases").jsonArray) rejected {
            RouteCheckProfile.decode(value.jsonObject.getValue("profile").toString())
        }
        for(value in vectors.getValue("invalidRawCases").jsonArray) rejected {
            RouteCheckProfile.decode(value.jsonObject.getValue("raw").jsonPrimitive.content)
        }
    }
    @Test fun ownedSortedLeavesAndCompleteWirePreserveOrderedExpressionsWithoutLeakingTargets() {
        val raw=profile(leaf("b")+","+leaf("a"))
        val value=RouteCheckProfile.decode(raw)
        assertEquals(listOf("a","b"),value.leafIDs())
        assertEquals("connectivity",value.id);assertEquals(1L,value.revision);assertEquals(12000L,value.deadlineMs)
        (value.leafIDs() as MutableList<String>).clear()
        try {(value.methods() as MutableSet<String>).clear()}catch(_:UnsupportedOperationException){}
        assertEquals(listOf("a","b"),value.leafIDs())
        assertEquals(setOf("tcp"),value.methods())
        val wire=Canonical.parse(value.wireJson()).jsonObject
        assertEquals("a",wire.getValue("leaves").jsonArray[0].jsonObject.getValue("id").jsonPrimitive.content)
        assertEquals(Canonical.parse(raw).jsonObject.getValue("stages"),wire.getValue("stages"))
        assertEquals("RouteCheckProfile([redacted])",value.toString())
        assertFalse(value.toString().contains("example.invalid"))
    }
    @Test fun securityLeavesAreUnconditionalAndPublicIntentRequiresMatchingCountryGate() {
        val country=leaf("country","https_exit_country","https://country.example.invalid/",",\"expected_exit_class\":\"RU\"")
        val value=RouteCheckProfile.decode(profile(country+","+leaf("a"),"[\"country\"]","[{\"leaf\":\"a\"}]"))
        value.requireIntent("RU")
        rejected {value.requireIntent("NON_RU")}; rejected {value.requireIntent("INTERNAL")}
        rejected {RouteCheckProfile.decode(profile()).requireIntent("RU")}
        for(security in listOf(leaf("a","tls","https://tls.example.invalid/"),country.replace("\"id\":\"country\"","\"id\":\"a\""),
            leaf("a","https_exit_ip","https://address.example.invalid/ip",",\"expected_ip\":\"192.0.2.9\""))) {
            rejected {RouteCheckProfile.decode(profile(security+","+leaf("b")))}
        }
        val ipv6=leaf("a","https_exit_ip","https://[2001:db8::1]:443/address",",\"expected_ip\":\"2001:db8::2\"")
        RouteCheckProfile.decode(profile(ipv6,"[\"a\"]","[]")).requireIntent("INTERNAL")
        RouteCheckProfile.decode(profile(ipv6.replace("[2001:db8::1]","[::ffff:192.0.2.1]"),"[\"a\"]","[]"))
        for(ip in listOf("::ffff:192.0.2.1","fe80::1%eth0","999.1.1.1","192.0.2.01")) rejected {
            RouteCheckProfile.decode(profile(ipv6.replace("2001:db8::2",ip),"[\"a\"]","[]"))
        }
    }
    @Test fun sevenNodeDepthFourProgramAndExactIntegerEndpointsStayBounded() {
        val nested="""[{"all":[{"leaf":"a"},{"all":[{"leaf":"b"},{"all":[{"leaf":"c"},{"leaf":"d"}]}]}]}]"""
        val base=profile(listOf("a","b","c","d").joinToString(","){leaf(it)},stages=nested)
        assertEquals(4,RouteCheckProfile.decode(base).leafIDs().size)
        assertEquals(1L,RouteCheckProfile.decode(base.replace("12000","1")).deadlineMs)
        assertEquals(9_007_199_254_740_991L,RouteCheckProfile.decode(base.replace("\"revision\":1","\"revision\":9007199254740991")).revision)
        for(number in listOf("0","12001","12000.0","12e3","\"12000\"","true","null")) rejected {
            RouteCheckProfile.decode(base.replace("\"deadlineMs\":12000","\"deadlineMs\":$number"))
        }
    }
    @Test fun duplicateDefinitionsReferencesAndUnknownOrUnusedLeavesCannotInflateQuorum() {
        rejected {RouteCheckProfile.decode(profile(leaf("a")+","+leaf("b",target="a.example.invalid:443")))}
        rejected {RouteCheckProfile.decode(profile(stages="""[{"quorum":{"k":2,"of":[{"leaf":"a"},{"leaf":"a"}]}}]"""))}
        rejected {RouteCheckProfile.decode(profile(stages="[{\"leaf\":\"a\"}]"))}
        rejected {RouteCheckProfile.decode(profile(stages="[{\"leaf\":\"missing\"}]"))}
    }
    @Test fun originalEngineFieldRetainsDuplicateEscapedAndNumericLexemeGuards() {
        val row="""{"outbound":"entry","required":true,"profile":${profile()}}"""
        val engine="""{"outbounds":[],"route_checks":[$row]}"""
        assertEquals(1,RouteCheckProfiles.inspectEngine("""{"label":"synthetic","revision":1,"enabled":true,"route_checks":[$row]}""").profileCount)
        assertEquals(1,RouteCheckProfiles.inspectEngine(engine.replace("route_checks","route_\\u0063hecks")).profileCount)
        rejected {RouteCheckProfiles.inspectEngine(engine.replace("\"revision\":1","\"revision\":1.0"))}
        rejected {RouteCheckProfiles.inspectEngine(engine.replace("\"revision\":1","\"revision\":1,\"\\u0072evision\":1"))}
        rejected {RouteCheckProfiles.inspectEngine(engine.replace("\"profile\":","\"checks\":[],\"profile\":"))}
        rejected {RouteCheckProfiles.inspectEngine(engine.replace("\"profile\":","\"Profile\":"))}
        rejected {RouteCheckProfiles.inspectEngine(engine.replace("\"route_checks\":", "\"route_checks\":[],\"route_\\u0063hecks\":"))}
        rejected {RouteCheckProfiles.inspectEngine(engine.replace("\"required\":true,",""))}
        for(value in listOf("null","1","\"true\"")) rejected {RouteCheckProfiles.inspectEngine(engine.replace("\"required\":true","\"required\":$value"))}
        for(value in listOf("null","1","\"\"")) rejected {RouteCheckProfiles.inspectEngine(engine.replace("\"outbound\":\"entry\"","\"outbound\":$value"))}
        for(raw in listOf("{", """{"route_checks":[$row""", """{"route_checks":[$row]}trailing""")) rejected {RouteCheckProfiles.inspectEngine(raw)}
    }
    @Test fun profileByteCostAndUnsafePrimitiveTargetsFailBeforeRuntimeConstruction() {
        rejected {RouteCheckProfile.decode(" ".repeat(24001)+profile())}
        rejected {RouteCheckProfile.decode(profile().replace("a.example","a\uD800.example"))}
        rejected {RouteCheckProfiles.inspectEngine("""{"route_checks":[${" ".repeat(24001)}{"outbound":"entry","required":true,"profile":${profile()}}]}""")}
        for(target in listOf("http://a.example.invalid/","https://synthetic@a.example.invalid/","https://a.example.invalid/#","https://a.example.invalid/ bad")) {
            rejected {RouteCheckProfile.decode(profile(leaf("a","tls",target),"[\"a\"]","[]"))}
        }
    }
    @Test fun legacyOrderedArrayHashAndOpaqueMetadataAreNotConvertedIntoVersionTwo() {
        val checks="""[{"method":"tcp","target":"a.example.invalid:443"},{"method":"https_204","target":"https://a.example.invalid/"}]"""
        assertEquals("13e996e1be0a00462e788708fbf2ec92bc5e580c8d66a6980613f8c00bbd7d4e",Policy.hash(checks))
        val old="""{"route_checks":[{"outbound":"entry","checks":$checks}]}"""
        val inspected=RouteCheckProfiles.inspectEngine(old)
        assertEquals(0,inspected.profileCount)
        assertEquals(0,RouteCheckProfiles.inspectEngine(old.replace("\"route_checks\":[","\"route_checks\":["+" ".repeat(24001))).profileCount)
        assertTrue(inspected.hasMethod("tcp"));assertTrue(inspected.hasMethod("https_204"))
        assertFalse(inspected.hasMethod("https_exit_country"))
        assertEquals("RouteCheckInspection([redacted])",inspected.toString())
        assertEquals(checks,Canonical.parse(old).jsonObject.getValue("route_checks").jsonArray[0].jsonObject.getValue("checks").toString())
    }
}
