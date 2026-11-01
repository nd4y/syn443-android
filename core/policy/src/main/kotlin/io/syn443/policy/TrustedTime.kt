package io.syn443.policy

data class TimeAnchor(val wall: Long, val elapsed: Long, val boot: Int)

/** Wall-clock changes never extend a lease. A reboot requires fresh authenticated time. */
object TrustedTime {
    const val MAX = 9_007_199_254_740_991L
    fun estimate(anchor: TimeAnchor, elapsed: Long, boot: Int): Long {
        require(anchor.wall in 1..MAX && anchor.elapsed in 0..MAX && anchor.boot >= 0)
        require(boot == anchor.boot && elapsed in anchor.elapsed..MAX)
        val delta = elapsed - anchor.elapsed
        require(delta <= MAX - anchor.wall)
        return anchor.wall + delta
    }
    fun accept(anchor: TimeAnchor, server: Long, elapsed: Long, boot: Int): TimeAnchor {
        require(server in 1..MAX && anchor.wall in 1..MAX && server + 999 >= anchor.wall && boot >= 0 && elapsed in 0..MAX)
        val effective = maxOf(server, runCatching { estimate(anchor, elapsed, boot) }.getOrDefault(anchor.wall))
        return TimeAnchor(effective, elapsed, boot)
    }
}
