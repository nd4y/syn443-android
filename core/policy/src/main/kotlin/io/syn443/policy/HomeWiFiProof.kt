package io.syn443.policy

import java.net.InetAddress
import java.util.Base64
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

/** Address is a numeric private destination. Hostname is exclusively the TLS peer name. */
class HomeWiFiProof private constructor(val hostname:String,val address:String,val port:Int,val spkiSha256:String) {
    override fun toString()="HomeWiFiProof([redacted])"

    fun socketAddress(): InetAddress = privateAddress(address)

    companion object {
        private val label=Regex("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
        private val ipv4Part=Regex("0|[1-9][0-9]{0,2}")
        private val ipv6=Regex("[0-9a-fA-F:]{2,39}")

        private fun privateAddress(text:String): InetAddress {
            // No DNS resolver input is accepted. Dotted quads are decoded locally;
            // IPv6 literals have a colon and an exclusively numeric alphabet.
            val value=if (':' in text) {
                require(ipv6.matches(text))
                InetAddress.getByName(text).also {
                    val bytes=it.address
                    require(bytes.size==16 && (bytes[0].toInt() and 0xfe)==0xfc)
                }
            } else {
                val parts=text.split('.')
                require(parts.size==4 && parts.all {ipv4Part.matches(it) && it.toInt()<=255})
                val octets=parts.map(String::toInt)
                require(octets[0]==10 || octets[0]==172 && octets[1] in 16..31 || octets[0]==192 && octets[1]==168)
                InetAddress.getByAddress(ByteArray(4){octets[it].toByte()})
            }
            return value
        }

        fun parse(input:JsonElement):HomeWiFiProof {
            val fields=input as? JsonObject ?: throw IllegalArgumentException("invalid_home_proof")
            require(fields.keys==setOf("hostname","address","port","spkiSha256"))
            fun text(name:String)=(fields[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: throw IllegalArgumentException("invalid_home_proof")
            val host=text("hostname");val labels=host.split('.')
            require(host.length<=253 && labels.size>=2 && labels.all(label::matches) &&
                !host.endsWith(".localhost") && labels.last().any {it !in '0'..'9'})
            val address=text("address");privateAddress(address)
            val port=(fields["port"] as? JsonPrimitive)?.takeUnless { it.isString }?.intOrNull
            require(port!=null && port in 1..65535)
            val pin=text("spkiSha256");require(pin.length==43)
            val bytes=Base64.getUrlDecoder().decode(pin)
            require(bytes.size==32 && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)==pin)
            return HomeWiFiProof(host,address,port,pin)
        }
    }
}
