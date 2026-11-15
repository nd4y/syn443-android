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
All241 actual outcomes remain mandatory on API29/35/37. Exact-source Actions and
the three safe UI methods on Xperia remain separate acceptance gates; no LTE or
real message is involved.
