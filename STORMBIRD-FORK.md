# Stormbird dependency compatibility fork

This branch starts at SagerNet Tailscale
`v1.102.1-sing-box-1.14-mod.5` (`68e5133990b266b90c856200178ba91c11ece2b8`).
It retains the upstream module path and license. Stormbird pins the immutable
fork commit through a Go module replacement; it must not consume a moving branch.

The local patch makes HTTPS netcheck honor the existing proxy-resolution hook,
including a fail-closed resolution error. Without it, the SagerNet TLS racing
implementation calls `NewDialerAlwaysDirect` before consulting that hook.
It also bounds the TLS handshake by the caller context and closes failed or
losing race connections instead of closing the unrelated DERP client.

The magicsock patch retains loopback-backed DERP connections for the existing
bounded health ping during UDP rebinding. Comparing a local CONNECT hop with
physical-interface addresses previously closed a healthy relay as a supposed
default-route change. This matters when approved LAN prefixes keep native UDP
discovery enabled. Non-loopback addresses still follow interface-change
reconnection; unhealthy loopback-backed relays still reconnect after ping
failure. Native discovery, transport authorization and fail-closed policy are
unchanged. Remove this patch when equivalent upstream behavior passes both
the address-class regression and Stormbird's explicit-rebind transport gate.

A failed `Rebind` is retried with exponential backoff (1 s to 30 s) until
the IPv4 socket binds or the connection closes. Upstream leaves a
`blockForeverConn` and waits for a later link change. On macOS, sing-box binds
magicsock sockets to the current default interface, and a brief Wi-Fi
`link_off` makes that bind fail with no route. The recovery then produced no
change that called `Rebind` again, so native UDP stayed down and every peer,
including LAN peers, used DERP until an unrelated network event (observed
2026-10-12 on the MacBook Air for more than ten minutes). Remove this patch
when upstream retries a failed rebind and passes the consumer's flapping-link
regression.

There are no fleet identities, relay lists, proxy credentials, or routing
policies here. Those remain Stormbird-owned runtime configuration. Remove the
replacement when an upstream release includes equivalent behavior and passes
the consumer's negative socket and approved-proxy regressions.

The optional per-peer `UnderlayAddressFamily` restricts authenticated outer
UDP candidates before discovery timers, native or proxy socket writes, path
promotion, and receive authorization. Its zero value preserves dual stack.
It does not constrain inner WireGuard address families, shared DERP sockets,
or public application traffic. Stormbird owns all policy values. Remove this
boundary when equivalent upstream per-peer enforcement passes the consumer's
family, domestic IPv6, proxy authorization and fail-closed regressions.

The optional per-peer `HedgeCopies` and `HedgeBudgetBytesPerSecond` copy native
WireGuard data to up to `HedgeCopies-1` alternate direct endpoints of the same
peer. An alternate must satisfy the peer's transport policy and have answered
discovery within the trusted-path window; hedging never discovers or authorizes
a path. A per-endpoint token bucket bounds duplicate bytes and copies are best
effort. The zero value preserves single-path sends. Stormbird owns all values.
Remove this when upstream offers equivalent policy-bounded multipath sends.

Validation from the pinned Stormbird development shell:

The optional `derphttp.HookDialPolicy` authorizes DERP independently of control
HTTPS before region data dials, netcheck, explicit URLs, and native WebSocket
requests or redirects. The consumer supplies all authorities. Native WebSockets
also retain the managed proxy boundary. Browsers cannot enforce redirected
socket policy and fail closed when this optional hook is installed; ordinary
clients without a hook retain upstream behavior and default HTTP client settings.

The optional `derphttp.HookMapPolicy` filters a data relay map before magicsock
netcheck and home selection, without mutating the control client's cached map.
Cached and reported homes absent from the active map cannot become fallback
homes. This closes the authority-only gap where a denied control-only DERP
could still be advertised as the client's home. The consumer owns node/port
approval, including mixed regions; this fork contains no fleet topology.

```sh
go test -race ./derp/derphttp ./net/netcheck ./wgengine/magicsock
go vet ./derp/derphttp
```

The focused tests cover proxy denial, proxy-resolution failure, a successful
CONNECT path to an otherwise unreachable target, and cancellation of a silent
native TLS peer. Stormbird additionally exercises its actual managed proxy
hook and production build tags. Full consumer and isolated transport gates
remain necessary before a daemon deployment.
