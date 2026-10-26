package io.syn443.identity

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

enum class DeliveryFailure { CAPACITY, CANCELLED, DEADLINE, DNS, TLS, EOF, TRANSPORT, PROTOCOL }
class DeliveryException(val reason: DeliveryFailure):Exception(reason.name)
data class Reply(val status: Int, val headers: Map<String,List<String>>, val body: ByteArray) {
    fun single(name:String):String? {
        val values=headers[name.lowercase()]?:return null
        if(values.size!=1)throw DeliveryException(DeliveryFailure.PROTOCOL)
        return values.single()
    }
}

/** One controller-owned instance survives logout/retry; blocked platform DNS cannot grow the pool. */
class BoundedHttp:AutoCloseable {
    private val workers=ThreadPoolExecutor(2,2,30,TimeUnit.SECONDS,ArrayBlockingQueue(1),
        ThreadFactory {r->Thread(r,"syn443-identity-http").apply {isDaemon=true}},ThreadPoolExecutor.AbortPolicy())
        .apply {allowCoreThreadTimeOut(true)}
    internal val waitingRequests:Int get()=workers.queue.size
    class Scope {
        private val socket=AtomicReference<Socket?>()
        private val stopped=AtomicBoolean()
        private val future=AtomicReference<Future<*>?>()
        internal fun attach(raw:Socket) {check(socket.compareAndSet(null,raw));if(stopped.get())socket.getAndSet(null)?.let {runCatching {it.close()}}}
        internal fun bind(value:Future<*>) {check(future.compareAndSet(null,value));if(stopped.get())value.cancel(true)}
        internal fun active() {if(stopped.get())throw DeliveryException(DeliveryFailure.CANCELLED)}
        internal fun finish() {socket.getAndSet(null)?.let {runCatching {it.close()}}}
        fun cancel() {stopped.set(true);finish();future.get()?.cancel(true)}
    }
    /** Blocking only on the dedicated identity coordinator; never call from Binder or the UI. */
    fun exchange(method:String,url:String,headers:Map<String,String> = emptyMap(),body:ByteArray? = null,
        scope:Scope=Scope(),timeoutMs:Long=20_000,maxBody:Int=65_536,
        factory:SSLSocketFactory=SSLSocketFactory.getDefault() as SSLSocketFactory,
        connect:(Socket,URI,Int)->Unit={socket,uri,remaining->socket.connect(InetSocketAddress(uri.host,if(uri.port>0)uri.port else 443),remaining)}):Reply {
        require(timeoutMs in 1..20_000 && maxBody in 1..524_288 && method in setOf("GET","POST"))
        val uri=Identity.https(url);require((method=="GET" && body==null) || (method=="POST" && body!=null && body.size<=8192))
        val reserved=setOf("host","content-length","connection","transfer-encoding","accept-encoding")
        require(headers.size<=16 && headers.keys.map {it.lowercase()}.distinct().size==headers.size)
        require(headers.all {(k,v)->k.matches(Regex("[A-Za-z0-9-]{1,64}")) && k.lowercase() !in reserved && v.length<=16_384 && v.all {it.code in 32..126}})
        require(headers.entries.sumOf {it.key.length+it.value.length}<=24_576)
        val safeHeaders=headers.toMap();val safeBody=body?.copyOf();val deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        var future:Future<Reply>?=null
        try {
            if(Thread.currentThread().isInterrupted)throw DeliveryException(DeliveryFailure.CANCELLED)
            scope.active()
            future=workers.submit<Reply> {
                scope.active();val raw=Socket();scope.attach(raw)
                fun remaining():Int {scope.active();val ms=TimeUnit.NANOSECONDS.toMillis(deadline-System.nanoTime());if(ms<=0)throw DeliveryException(DeliveryFailure.DEADLINE);return ms.coerceAtMost(20_000).toInt()}
                try {
                    connect(raw,uri,remaining());scope.active()
                    val tls=factory.createSocket(raw,uri.host,if(uri.port>0)uri.port else 443,true) as SSLSocket
                    tls.soTimeout=remaining();tls.sslParameters=tls.sslParameters.apply {endpointIdentificationAlgorithm="HTTPS";applicationProtocols=arrayOf("http/1.1")}
                    tls.startHandshake();scope.active()
                    val path=uri.rawPath.ifEmpty {"/"};val host=uri.rawAuthority
                    val request=buildString {
                        append("$method $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\nAccept-Encoding: identity\r\n")
                        safeHeaders.forEach {(name,value)->append("$name: $value\r\n")}
                        if(safeBody!=null)append("Content-Length: ${safeBody.size}\r\n")
                        append("\r\n")
                    }
                    tls.soTimeout=remaining();tls.outputStream.write(request.toByteArray(Charsets.US_ASCII));safeBody?.let {tls.outputStream.write(it)};tls.outputStream.flush()
                    response(tls.inputStream.buffered(),maxBody) {tls.soTimeout=remaining()}
                } finally {scope.finish()} // Close the raw FD, without waiting for TLS close-notify.
            }
            scope.bind(future)
            val left=deadline-System.nanoTime();if(left<=0)throw DeliveryException(DeliveryFailure.DEADLINE)
            return future.get(left,TimeUnit.NANOSECONDS).also {if(System.nanoTime()>=deadline)throw DeliveryException(DeliveryFailure.DEADLINE)}
        } catch(e:RejectedExecutionException) {throw DeliveryException(DeliveryFailure.CAPACITY)
        } catch(e:TimeoutException) {throw DeliveryException(DeliveryFailure.DEADLINE)
        } catch(e:CancellationException) {throw DeliveryException(DeliveryFailure.CANCELLED)
        } catch(e:InterruptedException) {Thread.currentThread().interrupt();throw DeliveryException(DeliveryFailure.CANCELLED)
        } catch(e:ExecutionException) {
            throw when(val cause=e.cause) {
                is DeliveryException->cause
                is java.net.UnknownHostException->DeliveryException(DeliveryFailure.DNS)
                is javax.net.ssl.SSLException->DeliveryException(DeliveryFailure.TLS)
                is EOFException->DeliveryException(DeliveryFailure.EOF)
                is java.net.SocketTimeoutException->DeliveryException(DeliveryFailure.DEADLINE)
                else->DeliveryException(DeliveryFailure.TRANSPORT)
            }
        } finally {scope.cancel();future?.cancel(true);(future as? Runnable)?.let {workers.remove(it)}}
    }
    override fun close() {workers.shutdownNow()}
}

internal fun response(input:InputStream,maxBody:Int,beforeRead:()->Unit={}):Reply {
    var headerBudget=16_384
    fun line(max:Int=16_384):String {
        val out=StringBuilder()
        while(true) {
            beforeRead();if(--headerBudget<0 || out.length>=max)throw DeliveryException(DeliveryFailure.PROTOCOL)
            val c=input.read();if(c<0)throw EOFException()
            if(out.endsWith("\r") && c!=10)throw DeliveryException(DeliveryFailure.PROTOCOL)
            if(c==10) {if(!out.endsWith("\r"))throw DeliveryException(DeliveryFailure.PROTOCOL);return out.dropLast(1).toString()}
            if(c!=13 && c!=9 && c !in 32..126)throw DeliveryException(DeliveryFailure.PROTOCOL)
            out.append(c.toChar())
        }
    }
    val match=Regex("HTTP/1\\.[01] ([2-5][0-9]{2})(?: [ -~]*)?").matchEntire(line())?:throw DeliveryException(DeliveryFailure.PROTOCOL)
    val status=match.groupValues[1].toInt();val headers=linkedMapOf<String,MutableList<String>>()
    while(true) {
        val text=line();if(text.isEmpty())break
        val split=text.indexOf(':');if(split<1 || !text.substring(0,split).matches(Regex("[A-Za-z0-9-]{1,64}")))throw DeliveryException(DeliveryFailure.PROTOCOL)
        val name=text.substring(0,split).lowercase();if(headers.size>=128 && name !in headers)throw DeliveryException(DeliveryFailure.PROTOCOL)
        headers.getOrPut(name){arrayListOf()}.add(text.substring(split+1).trim())
    }
    val result=Reply(status,headers,byteArrayOf())
    val length=result.single("content-length");val encoding=result.single("transfer-encoding")
    if(length!=null && encoding!=null || encoding!=null && encoding.lowercase()!="chunked" || result.single("content-encoding")?.lowercase() !in setOf(null,"identity"))throw DeliveryException(DeliveryFailure.PROTOCOL)
    val count=length?.let {if(!it.matches(Regex("0|[1-9][0-9]{0,6}")))throw DeliveryException(DeliveryFailure.PROTOCOL);it.toInt().also {n->if(n>maxBody)throw DeliveryException(DeliveryFailure.PROTOCOL)}}
    val out=ByteArrayOutputStream()
    fun readCount(size:Int) {
        if(size<0 || size>maxBody-out.size())throw DeliveryException(DeliveryFailure.PROTOCOL)
        val buffer=ByteArray(minOf(8192,maxOf(size,1)));var left=size
        while(left>0) {beforeRead();val n=input.read(buffer,0,minOf(left,buffer.size));if(n<0)throw EOFException();if(n==0)throw DeliveryException(DeliveryFailure.PROTOCOL);out.write(buffer,0,n);left-=n}
    }
    if(status==204 || status==304) {if(encoding!=null || count!=null && count!=0)throw DeliveryException(DeliveryFailure.PROTOCOL);return result}
    if(encoding!=null) {
        var chunks=0
        while(true) {
            if(++chunks>1024)throw DeliveryException(DeliveryFailure.PROTOCOL)
            val chunk=line(16);if(!chunk.matches(Regex("[A-Fa-f0-9]{1,6}")))throw DeliveryException(DeliveryFailure.PROTOCOL)
            val size=chunk.toInt(16)
            if(size==0) {while(line().isNotEmpty()) { /* bounded trailers are ignored, never authority headers */ };break}
            readCount(size);if(line(2).isNotEmpty())throw DeliveryException(DeliveryFailure.PROTOCOL)
        }
    } else if(count!=null)readCount(count) else {
        val buffer=ByteArray(8192)
        while(true) {beforeRead();val n=input.read(buffer);if(n<0)break;if(n==0 || out.size()+n>maxBody)throw DeliveryException(DeliveryFailure.PROTOCOL);out.write(buffer,0,n)}
    }
    return result.copy(body=out.toByteArray())
}
