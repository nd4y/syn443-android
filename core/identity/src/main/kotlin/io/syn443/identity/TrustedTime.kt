package io.syn443.identity

import kotlinx.serialization.Serializable
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

data class TimeWindow(val lowerMs:Long,val upperMs:Long)

/** Trusted HTTPS Date plus measured RTT/second precision; wall-clock changes grant no time. */
@Serializable data class TrustedTime(val boot:Int,val elapsedMs:Long,val lowerMs:Long,val upperMs:Long) {
    init {require(boot>=0 && elapsedMs>=0 && lowerMs>0 && upperMs>=lowerMs && upperMs-lowerMs<=51_000)}
    fun window(currentBoot:Int,elapsed:Long):TimeWindow {
        require(currentBoot==boot && elapsed>=elapsedMs && elapsed-elapsedMs<=86_400_000)
        val delta=elapsed-elapsedMs
        // Bound oscillator drift by 200ppm in either direction, rounded conservatively.
        val drift=(delta+4999)/5000
        return TimeWindow(Math.addExact(lowerMs,delta-drift),Math.addExact(upperMs,delta+drift))
    }
    fun proofSecond(currentBoot:Int,elapsed:Long):Long {
        val w=window(currentBoot,elapsed);require(w.upperMs-w.lowerMs<=50_000)
        return (w.lowerMs+(w.upperMs-w.lowerMs)/2)/1000
    }
    companion object {
        fun observe(date:String,boot:Int,started:Long,ended:Long,floor:TrustedTime?=null):TrustedTime {
            require(started>=0 && ended>=started && ended-started<=20_000)
            require(date.matches(Regex("[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT")))
            val lower=ZonedDateTime.parse(date,DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli()
            val upper=Math.addExact(lower,1000+ended-started)
            val prior=floor?.window(boot,ended)
            // Date may be rounded to a second, but it cannot roll back a preceding issuer anchor.
            require(prior==null || upper>=prior.lowerMs && lower<=Math.addExact(prior.upperMs,30_000))
            return TrustedTime(boot,ended,maxOf(lower,prior?.lowerMs?:lower),maxOf(upper,prior?.upperMs?:upper))
        }
    }
}
