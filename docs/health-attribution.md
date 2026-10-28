# Bounded health failure attribution

Health probes record only a fixed stage: queued, resolve, connect, TLS, request or response. The first HTTPS timeout can now be distinguished as `dns_timeout`, `tcp_timeout`, `tls_timeout`, `request_timeout` or `response_timeout` without recording a hostname, address, exception text or response content.

The existing three-second total check deadline, two-worker pool, one waiting slot, TLS trust and native recovery budgets remain unchanged. Cancellation freezes the stage before closing the raw socket. A resolver that ignores interruption cannot overwrite the terminal attribution when it eventually returns. A queued check that never began is unavailable capacity, not a network timeout. A completed result after its deadline is still a timeout.

Three additional JVM methods exercise every stalled stage with late completion, a queued timeout and queued cancellation. The health evidence minimum is 21 methods with the existing 90% line coverage gate. This instrumentation identifies the stage of a future physical failure; it does not by itself establish or fix the cause of a cold-start failure.

Android v23 also cancels the underlying platform DNS query on interruption/deadline and bypasses DNS for numeric addresses. Four Android regressions include three cancelled queries followed by successful work in the same bounded pool. Incomplete observations distinguish cancelled, unavailable and deadline outcomes; they never prove connectivity or become a false baseline. Generic injected noninterruptible resolvers remain covered by the existing pool-cap tests.
