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

While the VPN is active, ordinary batches use a five-minute interval on
validated unmetered Wi-Fi. A full queue batch (32 events), an unexpected
native service disconnect, a policy rollback or a recorded loss of VPN
consent can request earlier delivery during the existing supervisor tick.
Attempts stay at least one minute apart. An unacknowledged batch with the
same first event retains its five-minute retry interval across process restarts.
The controller records a lost service connection without guessing whether
the process suffered a Java or native crash. The DPoP proof covers the exact bounded batch
and the current device session. Stop or a change of physical route cancels
in-flight work. Delivery failure does not affect route health or VPN intent.

This pilot does not provide full probe metrics, compressed delivery, the
shared traffic budget, background uploads while Off, analysis or operator
dashboards. Device/server end-to-end acceptance remains separate.

The hosted enrolled rollback scenario enables telemetry for its disposable
test identity. The fixture verifies the actual authenticated request body,
acknowledges its event IDs in order and measures the interval until it sees
the rollback. The emulator must retain its enrollment and return online
through the previous managed route.

## Managed adaptive reselection

Build 128 records a managed adaptive route change after the native engine
acknowledges replacing its existing selection. Initial selection, the reserve
probe and its commit request produce no reselection event. A duplicate
acknowledgement cannot create another event. The local event retains the
current VPN phase and reason. With telemetry enabled, the encrypted queue
carries the policy revision, numeric algorithm ID 3 and the observed network
mode. The event carries no route, address, group or peer identifier.
