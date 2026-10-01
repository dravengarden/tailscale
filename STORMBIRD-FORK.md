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

There are no fleet identities, relay lists, proxy credentials, or routing
policies here. Those remain Stormbird-owned runtime configuration. Remove the
replacement when an upstream release includes equivalent behavior and passes
the consumer's negative socket and approved-proxy regressions.

Validation from the pinned Stormbird development shell:

```sh
go test -race ./derp/derphttp ./net/netcheck ./wgengine/magicsock
go vet ./derp/derphttp
```

The focused tests cover proxy denial, proxy-resolution failure, a successful
CONNECT path to an otherwise unreachable target, and cancellation of a silent
native TLS peer. Stormbird additionally exercises its actual managed proxy
hook and production build tags. Full consumer and isolated transport gates
remain necessary before a daemon deployment.
