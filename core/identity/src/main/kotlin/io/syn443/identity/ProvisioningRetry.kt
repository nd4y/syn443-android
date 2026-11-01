package io.syn443.identity

/** Foreground admission only. No timer, network operation or VPN side effect. */
class ProvisioningRetry private constructor(private val generation:Long,private val admissions:List<Long>) {
    constructor():this(-1,emptyList())

    fun admit(expectedGeneration:Long,now:Long,lastFetch:Long,throttled:Boolean=false):ProvisioningRetry? {
        require(expectedGeneration>=0 && now>=0 && lastFetch>=0)
        val history=if(generation==expectedGeneration)admissions else emptyList()
        if(now<lastFetch || history.any {it>now})return null
        val recent=history.filter {now-it<300_000}
        if(recent.size>=6)return null
        val delay=if(throttled)60_000L else (5_000L shl recent.size).coerceAtMost(60_000L)
        val anchor=maxOf(lastFetch,history.lastOrNull()?:lastFetch)
        if(now-anchor<delay)return null
        return ProvisioningRetry(expectedGeneration,recent+now)
    }
}
