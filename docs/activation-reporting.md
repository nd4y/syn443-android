# Report the outcome of managed activation

The encrypted assignment journal records the final commit, degraded commit or
rollback for the exact signed envelope. The existing supervisor tick can send
this observation through the device's authenticated physical transport while VPN
intent is On. Reports contain policy revision, envelope hash, activation
generation, result and selected journal revision. They carry no probe targets,
logs or traffic.

The worker rechecks the current login, signature, time window and durable journal
receipt before dispatch. This reporting path adds no timer, session refresh,
restart or enrollment. Delivery failures do not change the login or VPN state.
An unacknowledged observation has a bounded retry interval. An older server
without the endpoint and a server rejecting a superseded publication end
delivery for that exact envelope. Server retries use a fresh DPoP proof.

Preparing a candidate and renewing the lease for an unchanged execution produce
no new activation report. The stored report is optional in the journal encoding
so an older journal remains readable. Report construction cannot prevent the
actual commit or safety rollback.

Two required JVM cases and one required controller case per emulator API cover
the journal boundary, stale or renewed envelopes, bound request body, older
servers, Off, failure isolation and a subsequent rollback report. All builds
and tests run in GitHub Actions. The complete Android-to-panel path still needs
physical acceptance.

The existing enrolled native TUN and rollback scenarios also wait for the exact
signed decision over the emulator's loopback TLS transport. The fixture checks
the current envelope hash, session, nonce, ES256 proof and request-body digest.
