package io.syn443.identity

import java.net.InetAddress
import java.net.Socket
import java.net.URI
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory

@Serializable data class SubscriptionCredential(val url:String,val headers:Map<String,String> = emptyMap(),
    val redirectOrigins:List<String> = emptyList(),val allowedNetworks:List<String> = emptyList(),val rootCa:String="") {
    override fun toString()="SubscriptionCredential([redacted])"
}

/** Captures one route for the whole transfer. Redirects never reuse its prior
 * DNS result, and credentials are never forwarded to a different origin. */
class SubscriptionDownload internal constructor(private val request:(URI,Map<String,String>,BoundedHttp.Scope,Long,HttpRoute,SSLSocketFactory)->Reply) {
    constructor(http:BoundedHttp):this(http::subscription)

    fun fetch(credential:SubscriptionCredential,route:HttpRoute,scope:IdentityScope,blockedOrigins:Set<String>,
        etag:String="",lastModified:String=""):Reply {
        val initial=sourceUrl(credential.url)
        require(credential.redirectOrigins.size<=3 && credential.headers.size<=4 && blockedOrigins.size<=8)
        val redirects=credential.redirectOrigins.map {
            val uri=sourceUrl(it);require(uri.rawPath.isEmpty() && uri.rawQuery==null);origin(uri)
        }.toSet()
        val blocked=blockedOrigins.map {origin(sourceUrl(it))}.toSet()
        val egress=SubscriptionEgress(credential.allowedNetworks)
        val bound=object:HttpRoute {
            override fun resolve(host:String):List<InetAddress> = route.resolve(host).also {require(it.size<=32)}.filter(egress::allows)
            override fun bind(socket:Socket)=route.bind(socket)
            override fun check()=route.check()
        }
        val originalHeaders=credential.headers.toMap()
        require(originalHeaders.keys.map {it.lowercase(Locale.ROOT)}.distinct().size==originalHeaders.size)
        require(originalHeaders.all {(name,value)->name.lowercase(Locale.ROOT) in setOf("authorization","x-api-key","user-agent","accept") && validHeader(value,4096)})
        require(etag.isEmpty() || validHeader(etag,512))
        require(lastModified.isEmpty() || validHeader(lastModified,128))
        val tls=subscriptionTrust(credential.rootCa)
        val started=System.nanoTime();val first=origin(initial)
        var current=initial
        var credentialsAllowed=true
        repeat(4) {hop->
            val target=origin(current)
            require(target !in blocked && (target==first || target in redirects))
            val headers=originalHeaders.filterKeys {credentialsAllowed || it.lowercase(Locale.ROOT) in setOf("accept","user-agent")}.toMutableMap()
            if(hop==0 && etag.isNotEmpty())headers["If-None-Match"]=etag
            if(hop==0 && lastModified.isNotEmpty())headers["If-Modified-Since"]=lastModified
            val remaining=30_000-TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started)
            if(remaining<=0)throw DeliveryException(DeliveryFailure.DEADLINE)
            val reply=scope.request {request(current,headers,it,remaining,bound,tls)}
            if(reply.status !in setOf(301,302,303,307,308)) {
                if(reply.status==304)require(hop==0 && (etag.isNotEmpty() || lastModified.isNotEmpty()) && reply.body.isEmpty())
                return if(hop==0)reply else reply.copy(headers=reply.headers.filterKeys {
                    it.lowercase(Locale.ROOT) !in setOf("etag","last-modified")
                })
            }
            reply.body.fill(0)
            require(hop<3)
            val location=sourceUrl(current.resolve(relativeLocation(requireNotNull(reply.single("location")))).toASCIIString())
            credentialsAllowed=credentialsAllowed && origin(location)==target
            current=location
        }
        throw DeliveryException(DeliveryFailure.PROTOCOL)
    }

    private fun validHeader(value:String,maximum:Int)=value.length in 1..maximum && value.all {it.code in 32..126}
    private fun origin(uri:URI)=uri.host.lowercase(Locale.ROOT) to (if(uri.port==-1)443 else uri.port)
    private fun relativeLocation(raw:String):URI {
        require(raw.length in 1..8192 && raw.all {it.code in 33..126})
        return try {URI(raw)}catch(_:Exception){throw DeliveryException(DeliveryFailure.PROTOCOL)}
    }
    private fun sourceUrl(raw:String):URI=relativeLocation(raw).also {
        require(it.scheme=="https" && !it.host.isNullOrEmpty() && it.rawUserInfo==null && it.rawFragment==null &&
            (it.port==-1 || it.port in 1..65535) && !it.rawAuthority.endsWith(':') && !it.host.endsWith('.'))
    }
    private fun subscriptionTrust(pem:String):SSLSocketFactory {
        if(pem.isEmpty())return SSLSocketFactory.getDefault() as SSLSocketFactory
        require(pem.length<=32_768 && pem.all {it.code in 32..126 || it in "\r\n\t"})
        val certs=try {CertificateFactory.getInstance("X.509").generateCertificates(pem.byteInputStream(Charsets.US_ASCII))}
            catch(_:Exception){throw DeliveryException(DeliveryFailure.TLS)}
        require(certs.size in 1..16 && certs.all {it is X509Certificate})
        val store=KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null);certs.forEachIndexed {i,cert->setCertificateEntry("source-$i",cert)}
        }
        val trust=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {init(store)}
        return SSLContext.getInstance("TLS").apply {init(null,trust.trustManagers,null)}.socketFactory
    }
}

/** Public addresses plus an explicitly bounded private network for this source.
 * Metadata, loopback, multicast and link-local addresses are always denied. */
internal class SubscriptionEgress(networks:List<String>) {
    private data class Prefix(val bytes:ByteArray,val bits:Int) {
        fun matches(address:ByteArray):Boolean = address.size==bytes.size && bytes.indices.all {i->
            val mask=(0xff shl (8-(bits-8*i).coerceIn(0,8))) and 0xff
            ((address[i].toInt() xor bytes[i].toInt()) and mask)==0
        }
    }
    private val allowed=networks.also {require(it.size<=8)}.map {raw->
        val parts=raw.split('/');require(parts.size==2 && parts[1].matches(Regex("[0-9]{1,3}")))
        val literal=parts[0]
        val address=if(':' in literal) {
            require(literal.matches(Regex("[0-9A-Fa-f:]{2,39}")))
            (try {InetAddress.getByName(literal)}catch(_:Exception){throw DeliveryException(DeliveryFailure.PROTOCOL)})
                .address.also {require(it.size==16)}
        } else {
            val fields=literal.split('.');require(fields.size==4)
            fields.map {require(it.matches(Regex("0|[1-9][0-9]{0,2}")));it.toInt().also {n->require(n<=255)}.toByte()}.toByteArray()
        }
        val bits=parts[1].toInt();require(bits in (if(address.size==4)8 else 32)..(address.size*8))
        val masked=address.mapIndexed {i,n->(n.toInt() and ((0xff shl (8-(bits-8*i).coerceIn(0,8))) and 0xff)).toByte()}.toByteArray()
        require(address.contentEquals(masked))
        Prefix(address,bits)
    }
    fun allows(ip:InetAddress):Boolean {
        if(ip.isAnyLocalAddress || ip.isLoopbackAddress || ip.isLinkLocalAddress || ip.isMulticastAddress)return false
        val bytes=ip.address;val n=bytes.map {it.toInt() and 0xff}
        if(bytes.size==4) {
            val (a,b,c,d)=n
            if(a==100 && b==100 && c==100 && d==200)return false
            val private=a==10 || a==172 && b in 16..31 || a==192 && b==168 || a==100 && b in 64..127
            if(private)return allowed.any {it.matches(bytes)}
            return a in 1..223 && !(a==192 && b==0 && c in setOf(0,2) || a==198 && (b in 18..19 || b==51 && c==100) || a==203 && b==0 && c==113)
        }
        if(bytes.size!=16)return false
        if(n[0]==0xfd && n[1]==0 && n[2]==0x0e && n[3]==0xc2 && n.drop(4).take(10).all {it==0} && n[14]==2 && n[15]==0x54)return false
        if(n[0] in 0xfc..0xfd)return allowed.any {it.matches(bytes)}
        return n[0] in 0x20..0x3f && !(n[0]==0x20 && (n[1]==2 || n[1]==1 && (n[2]==0 && n[3]==0 || n[2]==0x0d && n[3]==0xb8)))
    }
}
