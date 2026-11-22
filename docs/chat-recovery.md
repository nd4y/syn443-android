# Support chat availability and bounded recovery

Chat can be disabled independently of enrolled-device policy and VPN operation.
A404 from the exact device `self` endpoint means chat is unavailable; a missing
attachment or an unrelated API404 does not acquire that meaning. The session,
device key, route policy and TLS requirements remain unchanged.

The Android screen keeps its encrypted generation-bound outbox visible when the
server is unavailable. It mentions a saved message only when the actual pending
queue is nonempty. A failed initial connection shows a connection error and a
retry control instead of implying that a nonexistent message was queued.

Visible polling uses one owned attempt,10-second healthy intervals and bounded
60/120/240/300-second failure backoff. Optional manual retry is limited to once
per30seconds; server throttling holds it for at least60seconds. Authentication
and permission failures require explicit action or a new account generation.
Cancellation is not a failed route and cannot replace a newer attempt. Leaving
the screen cancels its operation; no screen scheduling hint grants API or VPN
authority. The controller rechecks actual session/DPoP/account on every request.
A changed login generation starts a fresh advisory schedule and clears old UI.

Seven scheduling boundary/concurrency cases and one real protocol404/recovery
case are mandatory actual JVM outcomes. The scheduler has an independently
checked90-percent line-coverage gate. Existing chat/storage/media/controller
checks and all238Android outcomes perAPI29/35/37 remain mandatory. Debug logging
uses a closed error code, without response text, message contents or credentials.

Exact-head Actions and physical unavailable-to-available recovery on Xperia are
pending. This change does not grant an administrator role, enable a deployment,
complete support-retention controls or close M4/M5. No LTE or battery claim.

## Temporary attachments during screen recreation

Preparation and export use private cache files tagged with the current chat process. Opening or rotating a chat screen can remove up to 256 abandoned files from previous processes, including the legacy filename format. The current owner closes its temporary files after normal completion or cancellation. Draft attachments stay in the encrypted outbox.
