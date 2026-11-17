# Negative history on an observed stable path

Validation and metered capability changes revoke route evidence and advance the
Java network epoch. They can occur without a new network handle or link
signature. Previously, the corresponding coordinator reset also discarded its
bad-path cooldown and half-open debt. Repeated metadata changes could therefore
retry an already cooling path earlier than its original deadline.

## Narrow compatibility proof

One live TunnelService owns an opaque identity token. Ordered physical-network
observations retain it only when handle, complete link signature and transport
remain equal. Null, captive or invalid observations, loss of the selected handle,
a different path/transport and a newly created service clear or rotate it.
Losing an unrelated candidate does not rotate the selected token. Tokens carry
no path data, equality override, serialization, network or route authority.

All four production adaptive bind sites use this service-owned token. A bounded
negative-only fork is eligible only with the same non-null token identity, an
increasing Java network epoch, and unchanged intent, activation, engine, config,
mode, content and semantic authority. Boot must match, revision must not
decrease, and both old and current leases must still be valid. Ordinary callers
without a token retain their existing complete-reset behavior.
An otherwise compatible delayed bind with a lower Java epoch is ignored; it
cannot replace the current context with older or empty history.

The proof recognizes only the same observed OS path inside a live service. It
does not identify a Wi-Fi access point, prove physical network identity or allow
continuity through a missing observation, service/process restart or reboot.

## What survives

The synchronized core fork owns a new bounded map of at most64 negative or
configuration entries. It retains failure ordinals, original observation time,
absolute cooldown/half-open deadlines and insertion order. Old attempt numbers
become an internal zero sentinel; old-context results cannot settle the copy.
There is no shared mutable map, renewed deadline, admission refund or positive
evidence import. The caller, not the core map, proves path/policy compatibility.

Every full rebind still retracts positive selected paths, measurements and
diagnostics. Native configuration/epoch acknowledgements and fresh one-use
selection proofs remain necessary. The shared durable start budget is unchanged.
If an otherwise eligible fork rejects its context or clock, the coordinator
retires instead of silently substituting a fresh empty history. A genuine path,
mode, policy, credential-content or owner change uses its normal reset boundary.

This implements one part of BAD-01/04 and AUTO-02. Full profile/edge/chain keys,
selective credential-version invalidation, persistent5000-entry/seven-day BAD-08
history, global resource scheduling and all four-mode acceptance remain open.

## Required evidence

Three JVM roots exercise owned negative copies, original cooldown and15-second
half-open boundaries, old-context rejection, clock bounds, permanent
configuration fences and64-entry capacity. Six Android roots exercise actual
coordinator rebinds and route projection using synthetic physical observations
and native reports. They cover token rotation, compatible repeated flips,
incompatible owner/mode/policy/token changes, lease/boot/clock denial, fresh ACK
and retained admission debt. Earlier tests remain byte-identical.

Expected source counts are522 JVM and476 unique outcomes on each API29/35/37,
including218 affected Android outcomes. The existing90% RouteHealthMemory and
all previous coverage/native/lifecycle gates remain mandatory. Source, Actions,
protected main and real Xperia USB/Wi-Fi preservation are separate stages.
Synthetic metadata flips do not prove real managed-route cooldown behavior,
cellular, battery, natural Doze or endurance acceptance.
