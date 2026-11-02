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

New fixtures awaiting exact Actions acceptance:

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
