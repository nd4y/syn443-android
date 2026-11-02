# Embedded protocol wire acceptance

Parser/registry acceptance does not prove a working tunnel. The loopback wire
fixtures run the actual registered embedded outbound clients against real socket
servers, send a payload and count the target/hop sockets or datagrams. They use
only per-test generated credentials/certificates and synthetic loopback targets.
No production provider, DNS resolver, host key or account is contacted.

Accepted baseline atfb18f759fd0aa5df937a213a05aa2af76b96b829,
[Actions41372861986](https://github.com/nd4y/syn443-android/actions/runs/41372861986):
HTTP CONNECT authentication, SOCKS5 TCP, HTTP over SOCKS, wrong HTTP authentication
and refused HTTP/SOCKS, with no target connection on failure.

Additional wire fixtures passed the native job at430283e34f5d3582acea52c8ca2ae1599f7a112a,
[Actions41389169139](https://github.com/nd4y/syn443-android/actions/runs/41389169139).
The complete run remained red because an external API37 Settings-navigation case
failed; that failure is distinct from the native protocol result.

| Path | Actual traffic and boundary |
| --- | --- |
| VLESS/TLS | Generated trusted certificate/UUID, TCP payload; wrong UUID, trust root, name and refused server cannot reach target |
| VLESS/WS | Real embedded VLESS server/client with WebSocket transport and TLS |
| VLESS/gRPC | Real embedded VLESS server/client with gRPC transport and TLS |
| VLESS/XHTTP/h2 | `stream-one` with h2-only ALPN and actual SOCKS entry counter |
| VLESS/XHTTP/h3 | `stream-one` with h3-only ALPN/QUIC and actual target payload |
| VLESS/XHTTP packet-up | h2 and packet-up transport, actual payload |
| SOCKS5 UDP | Actual UDP ASSOCIATE control channel, datagram envelope, UDP relay and independent echo target counter |
| SOCKS5 UDP over HTTP entry | Unsupported packet path must fail without physical UDP escape |
| SSH | Actual SSH password/key handshake, pinned generated host key, direct-tcpip channel and target payload; wrong key/password/refused endpoint cannot reach target |

Listeners, accepted connections, packet sockets and goroutines have bounded
retirement/deadlines. No retry, skipped negative assertion or permissive TLS/SSH
verification substitutes for a passed fixture. These are loopback protocol tests,
not actual-provider or physical Wi-Fi/LTE acceptance. Reality, broader XHTTP mode
combinations, full meaningful chain/selector matrix and affected exact APK checks
remain separate open M3 gates until their own evidence is recorded.

## Transport concurrency defects found by the new wire tests

At e0cbccb3ef6176698b74d8be6d8495d99c9b42c8,
[Actions41387421463](https://github.com/nd4y/syn443-android/actions/runs/41387421463),
ordinary wire traffic passed, including real SOCKS UDP and rejection of its
unsupported HTTP entry. The mandatory race run exposed three library races:
late gRPC setup versus first Read, duplicated/concurrent XHTTP request-body buffer
release, and XHTTP upload-queue Close versus Read/heap state.

The pinned source patch now publishes gRPC setup through immutable channels,
serializes stream read/write framing, lets Close wake a pending reader and cancels
its own HTTP request. A late response is closed once; write buffers are released.
MultiBufferContainer uses a per-container lock for its nonblocking memory methods.
The upload queue serializes state/heap access and reader consumers, but never holds
its state lock during blocking receives or body Read/Close. Closing a sequence gap
wakes readers and retires the accepted body once.

Additional bounded regression files cover setup/read/close races, frame integrity,
request-body duplicate release, queue reorder/gap behavior and a blocking body.
Actions now run the complete three affected upstream packages under race detector
in addition to the actual outbound wire checks. The source patch hash remains
pinned. These native race checks passed at430283e; this is not proof about the
cause of a historical phone hang. Version30/0.9.2-transport-lifecycle has not been
physically accepted while the mandatory full-run gate remains red.

## Additional protocol/chain cases awaiting Actions

New actual-wire cases cover VLESS Reality with generated X25519/short-ID/UUID,
a local TLS1.3 camouflage origin and no public network dependency. A wrong public
key, short ID or UUID must never reach the payload target. A four-hop path uses
HTTP, SOCKS, SSH and VLESS in order, with independent counters for every hop.
An actual selector used as a VLESS entry must switch the complete chain, reject
unknown members and never implicitly escape a failed selected member. VLESS UDP
inside a TLS/TCP stream through HTTP CONNECT must deliver an actual echoed datagram;
wrong VLESS authentication must not send a physical UDP packet to the target.
These additions remain unaccepted until their exact native Actions results exist.
