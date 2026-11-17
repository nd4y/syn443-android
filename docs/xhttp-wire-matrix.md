# Source-bound VLESS/XHTTP wire evidence

The existing native ordinary and race Go JSON streams must each contain two
registered wire roots and28 leaf outcomes, plus one independent fixture deadline
case:31 outcomes in total (30 protocol +1 fixture). The positive root covers TLS, WS,
gRPC and five XHTTP variants: h2, h3, packet-up, auto and stream-up. The negative
root crosses each XHTTP variant with wrong UUID, certificate, server-name and
refused-server failures. Its single composite subtest name is
`transport/failure`; it has no intermediate transport test groups.

`tools/check_native_protocol_evidence.py` reads the actual repository Go source
and checks the closed literal tables, root signatures, nesting and `t.Run`
name binding. Comments and fixture strings cannot substitute for source
bindings. It also reads the fixed `proxy_wire_test.go` source and binds the exact
`TestPayloadWireClosesDeadlineIgnoringConnOnContextExpiry` signature. Each of
the31 identities must have exactly one ordered run/pass
pair, every leaf must complete before its parent and one bridge package pass
must follow all tests. Any bridge fail, skip, error or build-fail rejects the
stream, including unrelated tests and build failures identified by `ImportPath`.
Testless `build-output` before package/test start is harmless compile metadata;
it adds no outcome and is rejected after start/completion or when test-bound.
Wrong packages, unknown intermediate groups, missing/duplicate/late outcomes,
invalid JSON and source drift fail closed.

The gate uses the same JSON files immediately after the existing53-path-root
gate. It adds no build/test command, job, timeout, tag, dependency or pin. The
documents job's existing `test_*.py` discovery includes eight validator cases;
there is no duplicate focused unit invocation. Existing native diagnostics,
coverage, secret/privacy scanning and artifact guards remain unchanged.

The wire fixtures use owned loopback endpoints and synthetic test identities.
Positive cases require actual payload delivery; the h2 case also uses the
owned SOCKS entry. Negative cases require failed authority and zero target
accepts, rather than a successful direct fallback. This is source-stage
enforcement of the declared pinned-engine matrix. It is not a claim of all
protocol/version combinations, production providers, complete four-hop routing,
physical Wi-Fi/LTE/handover, performance, battery or final M3 acceptance.
Execution remains pending exact-head GitHub Actions. No local build or test
result is asserted here.

The additional real `net.Pipe` fixture case wraps a connection whose deadline
methods do nothing. It requires the two-second operation context to close and
retire the blocked operation, with watchdog and cleanup join. It guards the
test helper's hard bound independently of XHTTP's no-op connection deadlines.
Its signature alone proves no behavior: the actual Go case must pass in both
existing streams. This fixture-only correction does not change the production
route probe implementation or its existing close-on-cancellation behavior.
