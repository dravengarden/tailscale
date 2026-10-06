package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/tstime/mono"
	"github.com/sagernet/tailscale/types/key"
)

func TestHedgeUsesOnlyFreshPolicyApprovedEndpointsWithinBudget(t *testing.T) {
	old := HookPeerTransportPolicy.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(old) })
	policy := PeerTransportPolicy{NativeUDP: true, UnderlayAddressFamily: PeerUnderlayIPv4Only, HedgeCopies: 3, HedgeBudgetBytesPerSecond: 3000}
	HookPeerTransportPolicy.Store(func(tailcfg.StableNodeID) PeerTransportPolicy { return policy })
	c := &Conn{}
	peer := key.NewNode().Public()
	c.transportPeers.Store(peer, (&tailcfg.Node{Key: peer, StableID: "domestic"}).View())
	now := mono.Now()
	primary := netip.MustParseAddrPort("203.0.113.1:41641")
	fast := netip.MustParseAddrPort("203.0.113.2:41641")
	slow := netip.MustParseAddrPort("203.0.113.3:41641")
	stale := netip.MustParseAddrPort("203.0.113.4:41641")
	v6 := netip.MustParseAddrPort("[2001:db8::5]:41641")
	unconfirmed := netip.MustParseAddrPort("203.0.113.6:41641")
	pong := func(latency time.Duration, at mono.Time) *endpointState {
		state := &endpointState{}
		state.addPongReplyLocked(pongReply{latency: latency, pongAt: at})
		return state
	}
	ep := &endpoint{c: c, publicKey: peer, endpointState: map[netip.AddrPort]*endpointState{
		primary:     pong(time.Millisecond, now),
		fast:        pong(10*time.Millisecond, now),
		slow:        pong(90*time.Millisecond, now),
		stale:       pong(time.Millisecond, now.Add(-time.Minute)),
		v6:          pong(time.Millisecond, now),
		unconfirmed: {},
	}}
	got := ep.hedgeAddrsLocked(now, epAddr{ap: primary}, policy, 1000)
	if len(got) != 2 || got[0].ap != fast || got[1].ap != slow {
		t.Fatalf("hedge must use fresh approved endpoints by latency: %v", got)
	}
	if got := ep.hedgeAddrsLocked(now, epAddr{ap: primary}, policy, 1000); len(got) != 1 {
		t.Fatalf("hedge exceeded its duplicate-byte budget: %v", got)
	}
	if got := ep.hedgeAddrsLocked(now.Add(time.Second), epAddr{ap: primary}, policy, 1000); len(got) != 2 {
		t.Fatalf("budget did not refill: %v", got)
	}
	for _, disabled := range []PeerTransportPolicy{
		{NativeUDP: true, HedgeCopies: 1, HedgeBudgetBytesPerSecond: 3000},
		{NativeUDP: true, HedgeCopies: 3},
		{ProxyUDP: true, HedgeCopies: 3, HedgeBudgetBytesPerSecond: 3000},
	} {
		if got := ep.hedgeAddrsLocked(now.Add(2*time.Second), epAddr{ap: primary}, disabled, 10); got != nil {
			t.Fatalf("disabled policy hedged: %+v %v", disabled, got)
		}
	}
	if got := ep.hedgeAddrsLocked(now, epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 17)}, policy, 10); got != nil {
		t.Fatal("a DERP primary must not hedge", got)
	}
}
