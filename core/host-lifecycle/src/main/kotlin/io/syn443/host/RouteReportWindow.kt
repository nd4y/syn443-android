package io.syn443.host

/** One admitted native route batch. Times use Android elapsed realtime. */
class RouteReportWindow(private val request: String, private val started: Long) {
    enum class Decision { PUBLISH_AND_POLL, PUBLISH_FINAL, DISCARD }

    companion object {
        const val INTERVAL_MS = 2_000L
        const val MAX_AGE_MS = 35_000L
    }

    private var finished = false
    private var lastObserved = started

    init {
        require(request.length in 1..80 && started in 0L..(Long.MAX_VALUE - MAX_AGE_MS))
    }

    fun accept(observed: String, running: Boolean, now: Long): Decision {
        if (finished || observed != request || now !in lastObserved until (started + MAX_AGE_MS)) {
            finished = true
            return Decision.DISCARD
        }
        lastObserved = now
        if (running) return Decision.PUBLISH_AND_POLL
        finished = true
        return Decision.PUBLISH_FINAL
    }
}
