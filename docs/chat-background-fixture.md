# Real chat background transitions

API35 job132927100492 in run43751059629 failed when ActivityScenario requested
CREATED but the target remained RESUMED. No application crash or permanent
upstream root cause was established. The failure remains recorded.

The background test now opens an owned opaque MainActivity from the visible
SupportActivity in the same task, then finishes only that nonce-marked cover.
It observes five actual ON_STOP/ON_RESUME pairs on the same SupportActivity
instance, retaining the original CREATED/RESUMED and visible root/title/status
assertions. A separate test still performs five actual recreations. VPN intent,
generation and configuration must remain unchanged after every return. Cleanup
finishes only the owned cover and removes its lifecycle observer.

The initial strengthened fixture incorrectly required a configuration revision
on a fresh installation. Run43753828711 failed that assertion on all three APIs
before the background loop. StateStore's initial state contains generation and
desired intent; configuration absence is valid. The snapshot now requires those
two typed fields and preserves both the presence and value of the optional
revision, so navigation cannot silently create or change a configuration.

This tests ordinary foreground navigation without relying on an auxiliary
library activity's NEW_TASK launch/broadcast lifecycle transition. It does not
relax production lifecycle behavior, permissions, test counts or ownership gates.
All earlier242 actual outcomes plus the negative readiness case remain mandatory
on API29/35/37, raising the minimum to243. Exact-source Actions and the four safe
UI methods on Xperia remain separate acceptance gates; no LTE or real message is
involved.

## Bounded root readiness

A later physical cold-start observation failed inside the semantics fetch before
the five-second wait could poll: the default fetch required an existing Compose
root and threw immediately when no hierarchy had registered yet. Manual chat
navigation still showed its title and connection status. This observation does
not establish an application crash or replace the pending exact-source checks.

Only the semantics fetch inside the existing bounded wait now passes
`atLeastOneRootRequired=false`. The five-second limit, native content-child
assertion and final displayed title/status assertions are unchanged. The three
original tests still require five recreations and five actual stop/resume cycles,
with the same instance and unchanged VPN intent.

The fourth test replaces only its owned SupportActivity content with a native
TextView and requires the precise ComposeTimeoutException from the bounded wait.
It recreates the real screen, then installs a synthetic Compose title without a
status and requires an assertion failure. A final recreation must restore the
real title and status. Native idle synchronization avoids a separate operation
that itself requires a Compose root. The fixture never sends a message, modifies
VPN intent or changes production UI. Source, Actions and physical acceptance for
this change are pending until independently recorded.
