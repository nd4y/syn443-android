# Identity transport on a physical network

OIDC and device API requests capture one eligible non-VPN Android Network. DNS resolution and every TCP socket use that same Network. Validated links are preferred, then Wi-Fi, then a stable handle ordering. An unvalidated restricted link is still eligible; a captive, suspended, missing or VPN link is not. No process-wide network binding is changed.

The route snapshot includes capabilities relevant to selection and link properties. It is checked around DNS, binding, TLS and response consumption. A lost or changed captured route invalidates the result, without silently moving the request to a different network. A later bounded controller retry captures a new route. Platform DNS can still ignore interruption, so the existing two-worker pool, one waiting slot and absolute request deadline remain in force.

A request tries at most four distinct DNS addresses in resolver order. Each failed TCP attempt gets a fresh socket bound to the captured network, a maximum 2500ms connect timeout and the remaining shared request budget. Previous sockets are closed before the next one is attached to cancellation. TLS validation failures are terminal; fallback is limited to TCP setup, never a reason to relax trust or hostname verification. There is no default-network DNS/socket fallback.

Tests cover actual TLS with address fallback, socket closure, cancellation and stale-route reply rejection; Android tests cover route eligibility, bounded inventory, DNS/bind identity and loss, platform binding without process changes, and a running real TUN whose synthetic proxy sees the ordinary socket but not the physically bound control socket. These are controlled network tests, not physical cellular or battery acceptance.

Initial browser login requires VPN Off. The [enrolled native lifecycle](enrolled-vpn.md) now uses this transport for bounded session/policy refresh during an established account VPN. Transport tests alone do not establish that full lifecycle or physical enrollment acceptance.
