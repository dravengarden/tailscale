package magicsock

import (
	"net/netip"
	"testing"

	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/tstime/mono"
	"github.com/sagernet/tailscale/types/key"
)

func TestPeerFamilySkipsDiscoveryBeforeTimersAndProxySockets(t *testing.T) {
	oldPolicy, oldTransport := HookPeerTransportPolicy.Load(), HookPeerDatagramTransport.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(oldPolicy); HookPeerDatagramTransport.Store(oldTransport) })
	HookPeerTransportPolicy.Store(func(id tailcfg.StableNodeID) PeerTransportPolicy {
		if id == "foreign" {
			return PeerTransportPolicy{ProxyUDP: true, UnderlayAddressFamily: PeerUnderlayIPv4Only}
		}
		return PeerTransportPolicy{NativeUDP: true}
	})
	transport := &testPeerDatagrams{}
	HookPeerDatagramTransport.Store(transport)
	c := &Conn{}
	peer := key.NewNode().Public()
	c.transportPeers.Store(peer, (&tailcfg.Node{Key: peer, StableID: "foreign"}).View())
	v4, v6 := netip.MustParseAddrPort("203.0.113.8:41641"), netip.MustParseAddrPort("[2001:db8::8]:41641")
	c.transportEndpoints.Store(peer, []netip.AddrPort{v4, v6})
	ep := &endpoint{c: c, publicKey: peer}
	// This must return before requiring discovery state or allocating a timer.
	ep.startDiscoPingLocked(epAddr{ap: v6}, mono.Now(), pingDiscovery, 0, nil)
	if len(ep.sentPing) != 0 {
		t.Fatal("disabled family created a pending discovery probe")
	}
	if sent, err := c.sendProxyDatagram(peer, v6, []byte{4, 0, 0, 0}); sent || err == nil || transport.sends != 0 {
		t.Fatal("disabled family reached proxy transport")
	}
	if sent, err := c.sendProxyDatagram(peer, v4, []byte{4, 0, 0, 0}); !sent || err != nil || transport.sends != 1 {
		t.Fatal("approved IPv4 proxy path was blocked", err)
	}
	c.transportPeers.Store(peer, (&tailcfg.Node{Key: peer, StableID: "domestic"}).View())
	if !c.permitsPeerAddress(peer, v6) || !c.permitsNativePeer(peer, false) {
		t.Fatal("foreign policy disabled domestic native IPv6")
	}
}

func TestPeerFamilyMappedAddressesAndFailClosedUnknownValue(t *testing.T) {
	old := HookPeerTransportPolicy.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(old) })
	c := &Conn{}
	peer := key.NewNode().Public()
	c.transportPeers.Store(peer, (&tailcfg.Node{Key: peer, StableID: "peer"}).View())
	for _, tc := range []struct {
		family  PeerUnderlayAddressFamily
		address string
		allowed bool
	}{
		{PeerUnderlayIPv4Only, "[::ffff:203.0.113.8]:41641", true},
		{PeerUnderlayIPv6Only, "[::ffff:203.0.113.8]:41641", false},
		{PeerUnderlayIPv6Only, "[2001:db8::8]:41641", true},
		{PeerUnderlayAddressFamily(99), "203.0.113.8:41641", false},
	} {
		HookPeerTransportPolicy.Store(func(tailcfg.StableNodeID) PeerTransportPolicy {
			return PeerTransportPolicy{UnderlayAddressFamily: tc.family}
		})
		if got := c.permitsPeerAddress(peer, netip.MustParseAddrPort(tc.address)); got != tc.allowed {
			t.Fatalf("family %d: got %v, want %v", tc.family, got, tc.allowed)
		}
	}
}
