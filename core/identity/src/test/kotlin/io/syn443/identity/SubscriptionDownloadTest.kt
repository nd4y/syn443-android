package io.syn443.identity

import java.net.InetAddress
import java.net.Socket
import org.junit.Assert.*
import org.junit.Test

class SubscriptionDownloadTest {
    private fun address(vararg parts:Int)=InetAddress.getByAddress(parts.map(Int::toByte).toByteArray())
    private fun prefix(vararg parts:Int)=parts.joinToString(".")+"/24"

    @Test fun validatorsAreScopedToTheOriginalRepresentationEvenOnSameOriginRedirect() {
        val route=object:HttpRoute {
            override fun resolve(host:String)=listOf(address(8,8,8,8))
            override fun bind(socket:Socket)=Unit
            override fun check()=Unit
        }
        val credential=SubscriptionCredential("https://source.example.invalid/initial")
        val seen=mutableListOf<String>()
        var redirect=false
        var finish=304
        val download=SubscriptionDownload {uri,headers,_,_,_,_->
            seen.add(uri.rawPath)
            if(uri.rawPath=="/initial") {
                assertEquals("\"cached\"",headers["If-None-Match"])
                if(redirect)Reply(307,mapOf("location" to listOf("/other")),byteArrayOf())
                else Reply(304,emptyMap(),byteArrayOf())
            } else {
                assertFalse(headers.containsKey("If-None-Match"))
                Reply(finish,mapOf("etag" to listOf("\"different\"")),if(finish==200)"content".toByteArray() else byteArrayOf())
            }
        }
        assertEquals(304,download.fetch(credential,route,IdentityScope(),emptySet(),"\"cached\"").status)
        redirect=true;finish=200
        val redirected=download.fetch(credential,route,IdentityScope(),emptySet(),"\"cached\"")
        assertEquals(200,redirected.status);assertNull(redirected.single("etag"))
        finish=304
        assertThrows(IllegalArgumentException::class.java) {
            download.fetch(credential,route,IdentityScope(),emptySet(),"\"cached\"")
        }
        assertEquals(listOf("/initial","/initial","/other","/initial","/other"),seen)
    }

    @Test fun privateAddressesRequireExplicitScopeAndNeverAllowMetadataOrLoopback() {
        val local=address(10,12,34,56)
        val metadata=address(100,100,100,200)
        val default=SubscriptionEgress(emptyList())
        assertTrue(default.allows(address(8,8,8,8)))
        assertFalse(default.allows(local))
        val scoped=SubscriptionEgress(listOf(prefix(10,12,34,0),prefix(100,100,100,0),prefix(127,0,0,0),"fd00::/32"))
        assertTrue(scoped.allows(local))
        assertFalse(scoped.allows(address(10,12,35,1)))
        assertFalse(scoped.allows(metadata))
        assertFalse(scoped.allows(address(127,0,0,1)))
        assertFalse(scoped.allows(address(169,254,169,254)))
        assertTrue(scoped.allows(InetAddress.getByName("fd00::1")))
        assertFalse(scoped.allows(InetAddress.getByName("fd00:ec2::254")))
        assertFalse(default.allows(InetAddress.getByName("2001:db8::1")))
        assertTrue(default.allows(InetAddress.getByName("2606:4700::1111")))
        assertThrows(IllegalArgumentException::class.java) {SubscriptionEgress(listOf(prefix(10,12,34,1)))}
    }

    @Test fun redirectRechecksResolvedAddressesAndNeverRestoresRemovedCredentials() {
        val initial="https://source.example.invalid/list?key=synthetic"
        val alternate="https://mirror.example.invalid"
        val visited=mutableListOf<String>()
        val authorized=mapOf("Authorization" to "Bearer synthetic","X-Api-Key" to "synthetic","User-Agent" to "syn443-test")
        val route=object:HttpRoute {
            override fun resolve(host:String)=listOf(address(8,8,8,8),address(127,0,0,1))
            override fun bind(socket:Socket)=Unit
            override fun check()=Unit
        }
        val download=SubscriptionDownload {uri,headers,_,remaining,bound,_ ->
            assertTrue(remaining in 1L..30_000L)
            assertEquals(listOf(address(8,8,8,8)),bound.resolve(uri.host))
            visited.add(uri.toString())
            when(visited.size) {
                1 -> {
                    assertEquals(authorized+mapOf("If-None-Match" to "synthetic-etag"),headers)
                    Reply(302,mapOf("location" to listOf("$alternate/redirected")),byteArrayOf())
                }
                2 -> {
                    assertEquals(mapOf("User-Agent" to "syn443-test"),headers)
                    Reply(307,mapOf("location" to listOf(initial)),byteArrayOf())
                }
                else -> {
                    assertEquals(mapOf("User-Agent" to "syn443-test"),headers)
                    Reply(200,emptyMap(),"provider data".toByteArray())
                }
            }
        }
        val credential=SubscriptionCredential(initial,authorized,listOf(alternate))
        assertEquals("provider data",download.fetch(credential,route,IdentityScope(),emptySet(),"synthetic-etag").body.decodeToString())
        assertEquals(listOf(initial,"$alternate/redirected",initial),visited)
        visited.clear()
        assertThrows(IllegalArgumentException::class.java) {
            download.fetch(credential,route,IdentityScope(),setOf(alternate),"synthetic-etag")
        }
        assertEquals(listOf(initial),visited)
    }
}
