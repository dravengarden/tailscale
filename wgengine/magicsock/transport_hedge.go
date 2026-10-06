package magicsock

import (
	"net/netip"
	"slices"
	"time"

	"github.com/sagernet/tailscale/tstime/mono"
)

// Hedging copies native WireGuard ciphertext to additional recently
// pong-confirmed direct endpoints of the same peer. It never discovers or
// authorizes a path: every copy targets an endpoint that already answered
// discovery and still satisfies the peer's transport policy. WireGuard replay
// protection discards copies at the receiver.
const (
	maxHedgeCopies       = 4
	hedgeEndpointFresh   = trustUDPAddrDuration
	hedgeBudgetBurstSpan = time.Second
)

type hedgeBudget struct {
	tokens   float64
	refilled mono.Time
}

// hedgeAddrsLocked returns at most copies-1 alternate direct endpoints,
// lowest recent latency first, charging bytes extra bytes per copy against
// the policy budget. endpoint.mu must be held.
func (de *endpoint) hedgeAddrsLocked(now mono.Time, primary epAddr, policy PeerTransportPolicy, bytes int) []epAddr {
	copies := min(int(policy.HedgeCopies), maxHedgeCopies)
	if copies < 2 || policy.HedgeBudgetBytesPerSecond == 0 || !primary.isDirect() || policy.ProxyUDP || !policy.NativeUDP {
		return nil
	}
	type candidate struct {
		addr    netip.AddrPort
		latency time.Duration
	}
	var candidates []candidate
	for addr, state := range de.endpointState {
		if addr == primary.ap || !de.c.permitsPeerAddress(de.publicKey, addr) || len(state.recentPongs) == 0 {
			continue
		}
		latest := state.recentPongs[state.recentPong]
		if now.Sub(latest.pongAt) > hedgeEndpointFresh {
			continue
		}
		candidates = append(candidates, candidate{addr, latest.latency})
	}
	slices.SortFunc(candidates, func(a, b candidate) int {
		if a.latency != b.latency {
			return int(a.latency - b.latency)
		}
		return a.addr.Compare(b.addr)
	})
	budget := float64(policy.HedgeBudgetBytesPerSecond)
	if de.hedge.refilled == 0 {
		de.hedge.tokens = budget
	} else {
		de.hedge.tokens = min(budget*hedgeBudgetBurstSpan.Seconds(), de.hedge.tokens+now.Sub(de.hedge.refilled).Seconds()*budget)
	}
	de.hedge.refilled = now
	var result []epAddr
	for _, c := range candidates {
		if len(result) == copies-1 || de.hedge.tokens < float64(bytes) {
			break
		}
		de.hedge.tokens -= float64(bytes)
		result = append(result, epAddr{ap: c.addr})
	}
	return result
}
