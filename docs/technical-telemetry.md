# Technical telemetry pilot

After an enrolled user receives a verified policy from a telemetry-enabled
server, the account screen can offer a local opt-in. The consent starts at
the current event sequence. It does not transmit earlier events. Account
logout and opt-out cancel delivery and erase the local queue.

The pilot maps VPN states and selected failure codes to a fixed technical
schema. It does not transmit raw logs, hostnames, addresses, profile names
or credentials. On the identity worker it copies eligible events into an
encrypted, scoped queue of at most 128 entries. Event IDs survive retries.
Only a committed acknowledgement with the exact submitted IDs in order
removes the prefix. An empty success or mismatching acknowledgement leaves
the queue intact.

While the VPN is active, uploads are attempted at least five minutes apart
on validated unmetered Wi-Fi. The DPoP proof covers the exact bounded batch
and the current device session. Stop or a change of physical route cancels
in-flight work. Delivery failure does not affect route health or VPN intent.

This pilot does not provide full probe metrics, compressed delivery, the
shared traffic budget, background uploads while Off, analysis or operator
dashboards. Device/server end-to-end acceptance remains separate.
