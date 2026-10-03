package magicsock

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/tailscale/disco"
	"github.com/sagernet/tailscale/net/stun"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/tstime/mono"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/tailscale/types/netmap"
	"github.com/sagernet/tailscale/util/set"
)

type testPeerDatagrams struct{ sends int }

type recordingPeerDatagrams struct {
	packets  chan PeerDatagramPacket
	failures chan PeerDatagramPacket
}

func (p *recordingPeerDatagrams) ProbeFailed(peer tailcfg.StableNodeID, destination netip.AddrPort, _ mono.Time) {
	if p.failures != nil {
		p.failures <- PeerDatagramPacket{Peer: peer, Source: destination}
	}
}
func (*testPeerDatagrams) ProbeFailed(tailcfg.StableNodeID, netip.AddrPort, mono.Time) {}

func (p *recordingPeerDatagrams) Send(peer tailcfg.StableNodeID, destination netip.AddrPort, data []byte) error {
	p.packets <- PeerDatagramPacket{Peer: peer, Source: destination, Data: append([]byte(nil), data...)}
	return nil
}
func (*recordingPeerDatagrams) Receive(<-chan struct{}) (PeerDatagramPacket, error) {
	return PeerDatagramPacket{}, net.ErrClosed
}

func TestProxyAuthenticatedSharedDiscoPingRepliesToBoundPeer(t *testing.T) {
	oldPolicy, oldTransport := HookPeerTransportPolicy.Load(), HookPeerDatagramTransport.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(oldPolicy); HookPeerDatagramTransport.Store(oldTransport) })
	HookPeerTransportPolicy.Store(func(tailcfg.StableNodeID) PeerTransportPolicy { return PeerTransportPolicy{ProxyUDP: true} })
	transport := &recordingPeerDatagrams{packets: make(chan PeerDatagramPacket, 1)}
	HookPeerDatagramTransport.Store(transport)
	c := &Conn{peerMap: newPeerMap(), privateKey: key.NewNode(), discoInfo: make(map[key.DiscoPublic]*discoInfo), logf: t.Logf}
	localDisco, remoteDisco := key.NewDisco(), key.NewDisco()
	c.discoAtomic.Set(localDisco)
	first, second := key.NewNode().Public(), key.NewNode().Public()
	addr := netip.MustParseAddrPort("203.0.113.8:41641")
	for index, peer := range []key.NodePublic{first, second} {
		ep := &endpoint{c: c, publicKey: peer, nodeID: tailcfg.NodeID(index + 1), endpointState: make(map[netip.AddrPort]*endpointState)}
		ep.updateDiscoKey(remoteDisco.Public())
		c.peerMap.upsertEndpoint(ep, key.DiscoPublic{})
		id := tailcfg.StableNodeID("first")
		if peer == second {
			id = "second"
		}
		c.transportPeers.Store(peer, (&tailcfg.Node{StableID: id, Key: peer}).View())
		c.transportDiscoKeys.Store(peer, remoteDisco.Public())
		c.transportEndpoints.Store(peer, []netip.AddrPort{addr})
	}
	message := append([]byte(disco.Magic), remoteDisco.Public().AppendTo(nil)...)
	message = append(message, remoteDisco.Shared(localDisco.Public()).Seal((&disco.Ping{NodeKey: second}).AppendMarshal(nil))...)
	c.handleDiscoMessage(message, epAddr{ap: addr}, false, second, discoRXPathProxy)
	select {
	case reply := <-transport.packets:
		if reply.Peer != "second" {
			t.Fatal("proxy discovery reply lost authenticated node binding", reply.Peer)
		}
		plaintext, ok := remoteDisco.Shared(localDisco.Public()).Open(reply.Data[discoHeaderLen:])
		if !ok {
			t.Fatal("reply was not encrypted for expected discovery peer")
		}
		parsed, err := disco.Parse(plaintext)
		if _, ok := parsed.(*disco.Pong); err != nil || !ok {
			t.Fatal("missing authenticated discovery pong", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shared discovery identity prevented proxy pong")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ep, _ := c.peerMap.endpointForNodeKey(first)
	if len(ep.endpointState) != 0 {
		t.Fatal("proxy ping widened another shared node's endpoint authority")
	}
}

func TestProxyDiscoveryTimeoutReportsWithoutSelectedPath(t *testing.T) {
	oldPolicy, oldTransport := HookPeerTransportPolicy.Load(), HookPeerDatagramTransport.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(oldPolicy); HookPeerDatagramTransport.Store(oldTransport) })
	HookPeerTransportPolicy.Store(func(tailcfg.StableNodeID) PeerTransportPolicy { return PeerTransportPolicy{ProxyUDP: true} })
	transport := &recordingPeerDatagrams{failures: make(chan PeerDatagramPacket, 1)}
	HookPeerDatagramTransport.Store(transport)
	c := &Conn{logf: t.Logf}
	peer := key.NewNode().Public()
	c.transportPeers.Store(peer, (&tailcfg.Node{StableID: "cloud", Key: peer}).View())
	ep := &endpoint{c: c, publicKey: peer, sentPing: make(map[stun.TxID]sentPing)}
	addr := netip.MustParseAddrPort("203.0.113.8:41641")
	for attempt, size := range []int{0, 0, slices.Min(mtuProbePingSizesV4)} {
		txid := stun.TxID{byte(attempt + 1)}
		ep.sentPing[txid] = sentPing{to: epAddr{ap: addr}, at: mono.Now(), size: size, purpose: pingDiscovery, timer: time.NewTimer(time.Hour)}
		ep.discoPingTimeout(txid)
		select {
		case failed := <-transport.failures:
			if failed.Peer != "cloud" || failed.Source != addr {
				t.Fatal("probe failure lost authenticated destination")
			}
		case <-time.After(time.Second):
			t.Fatal("unselected/recovery discovery failure never reached proxy manager")
		}
	}
	addr = netip.MustParseAddrPort("[2001:db8::8]:41641")
	txid := stun.TxID{4}
	ep.sentPing[txid] = sentPing{to: epAddr{ap: addr}, at: mono.Now(), size: slices.Min(mtuProbePingSizesV6), purpose: pingDiscovery, timer: time.NewTimer(time.Hour)}
	ep.discoPingTimeout(txid)
	select {
	case <-transport.failures:
	case <-time.After(time.Second):
		t.Fatal("IPv6 baseline MTU discovery failure never reached proxy manager")
	}
	txid = stun.TxID{5}
	ep.sentPing[txid] = sentPing{to: epAddr{ap: addr}, at: mono.Now(), size: slices.Max(mtuProbePingSizesV6), purpose: pingDiscovery, timer: time.NewTimer(time.Hour)}
	ep.discoPingTimeout(txid)
	select {
	case <-transport.failures:
		t.Fatal("larger MTU probe incorrectly retired baseline reachability")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestProxyDiscoveryResolvesExplicitPeerWithSharedDiscoKey(t *testing.T) {
	c := &Conn{peerMap: newPeerMap()}
	disco := key.NewDisco().Public()
	first, second := key.NewNode().Public(), key.NewNode().Public()
	c.peerMap.nodesOfDisco[disco] = set.Set[key.NodePublic]{first: {}, second: {}}
	c.transportDiscoKeys.Store(first, disco)
	c.transportDiscoKeys.Store(second, disco)
	if got, ok := c.proxyDiscoPeer(disco, second); !ok || got != second {
		t.Fatal("explicit authenticated node rejected with shared disco key")
	}
	if _, ok := c.proxyDiscoPeer(disco, key.NodePublic{}); ok {
		t.Fatal("ambiguous discovery created peer authority")
	}
	if _, ok := c.proxyDiscoPeer(key.NewDisco().Public(), second); ok {
		t.Fatal("explicit node accepted another discovery identity")
	}
}

func TestAuthenticatedPeerTrafficRenewsOnlySelectedPath(t *testing.T) {
	old := HookPeerTransportPolicy.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(old) })
	HookPeerTransportPolicy.Store(func(tailcfg.StableNodeID) PeerTransportPolicy { return PeerTransportPolicy{ProxyUDP: true} })
	c := new(Conn)
	peer, other := key.NewNode().Public(), key.NewNode().Public()
	c.transportPeers.Store(peer, (&tailcfg.Node{StableID: "cloud", Key: peer}).View())
	addr := netip.MustParseAddrPort("203.0.113.8:41641")
	ep := &endpoint{c: c, publicKey: peer, bestAddr: addrQuality{epAddr: epAddr{ap: addr}}, bestAddrAt: mono.Now()}
	wrapped := &transportAuthorizedEndpoint{endpoint: ep, proxy: true, source: addr}
	if wrapped.AuthorizePeer(other.Raw32()) || !ep.trustBestAddrUntil.IsZero() {
		t.Fatal("unrelated WireGuard identity renewed path trust")
	}
	wrapped.FromPeer(other.Raw32())
	if !ep.trustBestAddrUntil.IsZero() {
		t.Fatal("unrelated accepted peer renewed path trust")
	}
	if !wrapped.AuthorizePeer(peer.Raw32()) || !ep.trustBestAddrUntil.IsZero() {
		t.Fatal("pre-replay authorization renewed path liveness")
	}
	wrapped.source = netip.MustParseAddrPort("203.0.113.9:41641")
	wrapped.FromPeer(peer.Raw32())
	if !ep.trustBestAddrUntil.IsZero() {
		t.Fatal("another source renewed selected path trust")
	}
	wrapped.source = addr
	wrapped.FromPeer(peer.Raw32())
	if !ep.trustBestAddrUntil.After(mono.Now()) {
		t.Fatal("authenticated selected path liveness was discarded")
	}
	ep.bestAddrAt = mono.Now().Add(-2 * trustUDPAddrDuration)
	wrapped.FromPeer(peer.Raw32())
	if ep.trustBestAddrUntil.After(mono.Now()) {
		t.Fatal("receive-only traffic masked expired bidirectional reachability")
	}
}

func (p *testPeerDatagrams) Send(tailcfg.StableNodeID, netip.AddrPort, []byte) error {
	p.sends++
	return nil
}
func (*testPeerDatagrams) Receive(<-chan struct{}) (PeerDatagramPacket, error) {
	return PeerDatagramPacket{}, net.ErrClosed
}

func TestProxyDatagramsRequireAuthenticatedPeerAndEndpoint(t *testing.T) {
	HookPeerTransportPolicy.Store(func(id tailcfg.StableNodeID) PeerTransportPolicy {
		if id == "cloud" {
			return PeerTransportPolicy{ProxyUDP: true, DERPRegions: []int{17}}
		}
		return PeerTransportPolicy{}
	})
	transport := new(testPeerDatagrams)
	HookPeerDatagramTransport.Store(transport)
	t.Cleanup(func() { HookPeerTransportPolicy.Store(nil); HookPeerDatagramTransport.Store(nil) })
	c := new(Conn)
	peer := key.NewNode().Public()
	other := key.NewNode().Public()
	addr := netip.MustParseAddrPort("203.0.113.7:41641")
	c.transportPeers.Store(peer, (&tailcfg.Node{StableID: "cloud", Key: peer, Endpoints: []netip.AddrPort{addr}}).View())
	c.transportEndpoints.Store(peer, []netip.AddrPort{addr})
	if c.permitsNativePeer(peer, false) || c.permitsPeerUDP(peer, true) {
		t.Fatal("proxy path authorized native UDP or peer relay")
	}
	if !c.permitsPeerUDP(peer, false) {
		t.Fatal("proxy peer cannot discover endpoints")
	}
	if sent, err := c.sendProxyDatagram(peer, addr, []byte{4, 0, 0, 0}); !sent || err != nil {
		t.Fatal("approved endpoint rejected", err)
	}
	if sent, _ := c.sendProxyDatagram(other, addr, []byte{4, 0, 0, 0}); sent {
		t.Fatal("unknown peer reached proxy")
	}
	if sent, _ := c.sendProxyDatagram(peer, netip.MustParseAddrPort("203.0.113.8:41641"), []byte{4, 0, 0, 0}); sent {
		t.Fatal("arbitrary endpoint reached proxy")
	}
	if transport.sends != 1 {
		t.Fatal("denied packets escaped", transport.sends)
	}
	// Endpoint authority follows authenticated control-plane deltas, rather
	// than the older immutable NodeView used to bind the peer identity.
	updated := netip.MustParseAddrPort("203.0.113.9:41641")
	c.peerMap = newPeerMap()
	peerEndpoint := &endpoint{c: c, publicKey: peer, nodeID: 2, endpointState: make(map[netip.AddrPort]*endpointState)}
	c.peerMap.byNodeID[2] = newPeerInfo(peerEndpoint)
	mutations, ok := netmap.NodeMutationsFromPatch(&tailcfg.PeerChange{NodeID: 2, Endpoints: []netip.AddrPort{updated}})
	if !ok {
		t.Fatal("could not construct endpoint delta")
	}
	c.UpdateNetmapDelta(mutations)
	if sent, _ := c.sendProxyDatagram(peer, addr, []byte{4, 0, 0, 0}); sent {
		t.Fatal("revoked control endpoint remained authorized")
	}
	if sent, err := c.sendProxyDatagram(peer, updated, []byte{4, 0, 0, 0}); !sent || err != nil {
		t.Fatal("new control endpoint rejected", err)
	}
	mutations[0].(netmap.NodeMutationEndpoints).Endpoints[0] = addr
	if sent, _ := c.sendProxyDatagram(peer, addr, []byte{4, 0, 0, 0}); sent {
		t.Fatal("caller mutation changed endpoint authority")
	}
	ep := &transportAuthorizedEndpoint{endpoint: &endpoint{c: c, publicKey: peer}, proxy: true}
	if !ep.AuthorizePeer(peer.Raw32()) || ep.AuthorizePeer(other.Raw32()) {
		t.Fatal("proxy return bypassed WireGuard peer authentication")
	}
}
