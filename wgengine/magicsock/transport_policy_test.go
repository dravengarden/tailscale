package magicsock

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/tailscale/derp/derphttp"
	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/net/packet"
	"github.com/sagernet/tailscale/net/stun"
	"github.com/sagernet/tailscale/syncs"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/tstime/mono"
	"github.com/sagernet/tailscale/types/key"
)

func TestScopedDERPWriterRechecksQueuedAuthorization(t *testing.T) {
	oldPolicy, oldObservation := HookPeerTransportPolicy.Load(), HookPeerTransportObservation.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(oldPolicy); HookPeerTransportObservation.Store(oldObservation) })
	HookPeerTransportPolicy.Store(func(tailcfg.StableNodeID) PeerTransportPolicy { return PeerTransportPolicy{} })
	blocked := make(chan struct{}, 1)
	HookPeerTransportObservation.Store(func(_ tailcfg.StableNodeID, path string, region int, action string, _ int) {
		if path == "derp" && region == 17 && action == "blocked_send" {
			blocked <- struct{}{}
		}
	})
	peer := key.NewNode().Public()
	c := &Conn{}
	c.transportPeers.Store(peer, (&tailcfg.Node{StableID: "revoked", Key: peer}).View())
	queue := make(chan derpWriteRequest, 1)
	queue <- derpWriteRequest{pubKey: peer, b: []byte("queued-before-revocation")}
	gate := make(chan struct{})
	close(gate)
	ctx, cancel := context.WithCancel(context.Background())
	wg := syncs.NewWaitGroupChan()
	wg.Add(1)
	// A revoked queued packet must never reach the nil DERP client.
	go c.runDerpWriter(ctx, nil, 17, queue, wg, gate)
	select {
	case <-blocked:
	case <-time.After(time.Second):
		cancel()
		wg.Wait()
		t.Fatal("revoked queued packet was not rejected")
	}
	cancel()
	wg.Wait()
}

func TestScopedDiscoveryTracksActualRendezvous(t *testing.T) {
	old := HookPeerTransportPolicy.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(old) })
	HookPeerTransportPolicy.Store(func(tailcfg.StableNodeID) PeerTransportPolicy {
		return PeerTransportPolicy{DERPRegions: []int{17}}
	})
	peer := key.NewNode().Public()
	c := &Conn{closed: true, logf: t.Logf}
	c.transportPeers.Store(peer, (&tailcfg.Node{StableID: "cloud", Key: peer}).View())
	ep := &endpoint{c: c, publicKey: peer, sentPing: make(map[stun.TxID]sentPing)}
	ep.updateDiscoKey(key.NewDisco().Public())
	ep.mu.Lock()
	ep.startDiscoPingLocked(epAddr{ap: peerDERPAddress(999)}, mono.Now(), pingCLI, 0, nil)
	if len(ep.sentPing) != 1 {
		t.Fatal("discovery ping was not recorded")
	}
	for _, ping := range ep.sentPing {
		ping.timer.Stop()
		if ping.to.ap != peerDERPAddress(17) {
			t.Errorf("diagnostic retained the forbidden advertised region: %v", ping.to)
		}
	}
	ep.mu.Unlock()
	// Let the asynchronous failed send revoke the tracked ping before the
	// process-global embedding hook is restored by cleanup.
	deadline := time.Now().Add(time.Second)
	for {
		ep.mu.Lock()
		done := len(ep.sentPing) == 0
		ep.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("discovery send did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestScopedPeerTransport(t *testing.T) {
	old := HookPeerTransportPolicy.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(old) })
	HookPeerTransportPolicy.Store(func(id tailcfg.StableNodeID) PeerTransportPolicy {
		switch id {
		case "domestic":
			return PeerTransportPolicy{NativeUDP: true, DERPRegions: []int{999}}
		case "foreign":
			return PeerTransportPolicy{DERPRegions: []int{17}}
		default:
			return PeerTransportPolicy{}
		}
	})
	c := new(Conn)
	domestic, foreign, unknown := key.NewNode().Public(), key.NewNode().Public(), key.NewNode().Public()
	disco := key.NewDisco().Public()
	c.transportPeers.Store(domestic, (&tailcfg.Node{StableID: "domestic", Key: domestic, DiscoKey: disco}).View())
	c.transportDiscoKeys.Store(domestic, disco)
	c.transportPeers.Store(foreign, (&tailcfg.Node{StableID: "foreign", Key: foreign}).View())
	if !c.permitsNativePeer(domestic, false) || c.permitsNativePeer(foreign, false) || c.permitsNativePeer(unknown, false) {
		t.Fatal("native UDP must be scoped to authenticated domestic peers")
	}
	nativeEndpoint := &transportAuthorizedEndpoint{endpoint: &endpoint{c: c, publicKey: domestic}}
	if !nativeEndpoint.AuthorizePeer(domestic.Raw32()) || nativeEndpoint.AuthorizePeer(foreign.Raw32()) {
		t.Fatal("source-address association authorized a different WireGuard identity")
	}
	foreignEndpoint := &transportAuthorizedEndpoint{endpoint: &endpoint{c: c, publicKey: foreign}, region: 17}
	if !foreignEndpoint.AuthorizePeer(foreign.Raw32()) || foreignEndpoint.AuthorizePeer(domestic.Raw32()) {
		t.Fatal("shared DERP socket authorized the wrong cryptographic identity")
	}
	if c.permitsNativePeer(domestic, true) || !c.permitsNativeDisco(disco, false) || c.permitsNativeDisco(disco, true) {
		t.Fatal("discovery must preserve the native/peer-relay boundary")
	}
	for _, test := range []struct {
		peer            key.NodePublic
		requested, want int
	}{
		{domestic, 17, 999}, {domestic, 999, 999}, {foreign, 999, 17}, {foreign, 17, 17},
	} {
		region, ok := c.selectPeerDERP(test.peer, test.requested)
		if !ok || region != test.want {
			t.Fatalf("DERP region: got %d, want %d", region, test.want)
		}
	}
	if c.permitsPeerDERP(domestic, 17) || c.permitsPeerDERP(foreign, 999) || c.permitsPeerDERP(unknown, 999) {
		t.Fatal("shared DERP connections must not authorize the wrong peer")
	}
	wgOnly := key.NewNode().Public()
	c.transportPeers.Store(wgOnly, (&tailcfg.Node{StableID: "domestic", Key: wgOnly, IsWireGuardOnly: true}).View())
	if c.permitsNativePeer(wgOnly, false) || c.permitsPeerDERP(wgOnly, 999) {
		t.Fatal("scoped mode silently admitted an unsupported WireGuard-only peer")
	}
	// Key rotation/removal must immediately revoke the old identity.
	ep := &endpoint{c: c, nodeID: 1, publicKey: domestic}
	ep.updateDiscoKey(disco)
	c.peerMap = newPeerMap()
	c.peerMap.upsertEndpoint(ep, key.DiscoPublic{})
	c.discoInfo = make(map[key.DiscoPublic]*discoInfo)
	c.discoAtomic.Set(key.NewDisco())
	c.logf = t.Logf
	rotated := key.NewDisco().Public()
	c.HandleDiscoKeyAdvertisement((&tailcfg.Node{ID: 1, StableID: "domestic", Key: domestic, DiscoKey: disco}).View(), packet.TSMPDiscoKeyAdvertisement{Key: rotated})
	if c.permitsNativeDisco(disco, false) || !c.permitsNativeDisco(rotated, false) {
		t.Fatal("authenticated discovery-key rotation not applied")
	}
	c.transportPeers.Delete(domestic)
	if c.permitsNativeDisco(disco, false) || c.permitsNativePeer(domestic, false) {
		t.Fatal("stale identity admitted")
	}
	HookPeerTransportPolicy.Store(nil)
	if !c.permitsNativePeer(unknown, true) || !c.permitsPeerDERP(unknown, 999) {
		t.Fatal("an embedding without the hook must retain upstream behavior")
	}
}

func TestScopedRequiredDERPsReconnectAndReleaseAfterPeerRemoval(t *testing.T) {
	old := HookPeerTransportPolicy.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(old) })
	HookPeerTransportPolicy.Store(func(tailcfg.StableNodeID) PeerTransportPolicy { return PeerTransportPolicy{DERPRegions: []int{17}} })
	peer := key.NewNode().Public()
	monitor := netmon.NewStatic()
	dc, err := derphttp.NewClient(key.NewNode(), "https://relay.example/derp", t.Logf, monitor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dc.Close(); monitor.Close() })
	staleHome, stalePeer := time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)
	c := &Conn{privateKey: key.NewNode(), myDerp: 999, logf: t.Logf,
		derpMap:      &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{999: {RegionID: 999}, 17: {RegionID: 17}}},
		activeDerp:   map[int]activeDerp{999: {lastWrite: &staleHome}, 17: {lastWrite: &stalePeer, c: dc, cancel: func() {}}},
		peerLastDerp: make(map[key.NodePublic]int),
	}
	c.transportPeers.Store(peer, (&tailcfg.Node{StableID: "cloud", Key: peer}).View())
	c.SetNetworkUp(true)
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		reconnected := time.Since(stalePeer) < time.Minute
		c.mu.Unlock()
		if reconnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("network-up did not reconnect the required non-home region")
		}
		time.Sleep(time.Millisecond)
	}
	// A pinned connection must keep the cleanup timer alive even when it is
	// the only non-home region. Removal then allows the usual idle cleanup.
	c.mu.Lock()
	stalePeer = time.Now().Add(-time.Hour)
	c.mu.Unlock()
	c.cleanStaleDerp()
	c.mu.Lock()
	armed := c.derpCleanupTimerArmed
	c.mu.Unlock()
	if !armed {
		t.Fatal("pinned non-home connection stopped cleanup scheduling")
	}
	c.transportPeers.Delete(peer)
	c.cleanStaleDerp()
	c.mu.Lock()
	_, retained := c.activeDerp[17]
	if c.derpCleanupTimer != nil {
		c.derpCleanupTimer.Stop()
	}
	c.mu.Unlock()
	if retained {
		t.Fatal("obsolete rendezvous retained after peer removal")
	}
}

func TestScopedSendUsesPeerRendezvousNotSharedHome(t *testing.T) {
	old := HookPeerTransportPolicy.Load()
	t.Cleanup(func() { HookPeerTransportPolicy.Store(old) })
	HookPeerTransportPolicy.Store(func(id tailcfg.StableNodeID) PeerTransportPolicy {
		if id == "phone" {
			return PeerTransportPolicy{NativeUDP: true, DERPRegions: []int{999}}
		}
		return PeerTransportPolicy{DERPRegions: []int{17}}
	})
	phone, cloud := key.NewNode().Public(), key.NewNode().Public()
	local, foreign := make(chan derpWriteRequest, 1), make(chan derpWriteRequest, 1)
	now := time.Now()
	c := &Conn{
		privateKey:   key.NewNode(),
		derpMap:      &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{999: {RegionID: 999}, 17: {RegionID: 17}}},
		activeDerp:   map[int]activeDerp{999: {writeCh: local, lastWrite: &now}, 17: {writeCh: foreign, lastWrite: &now}},
		peerLastDerp: make(map[key.NodePublic]int),
		logf:         t.Logf,
	}
	c.transportPeers.Store(phone, (&tailcfg.Node{StableID: "phone", Key: phone}).View())
	c.transportPeers.Store(cloud, (&tailcfg.Node{StableID: "cloud", Key: cloud}).View())
	if sent, err := c.sendAddr(peerDERPAddress(17), phone, []byte("domestic"), false, false); !sent || err != nil {
		t.Fatalf("phone send: %v %v", sent, err)
	}
	select {
	case packet := <-local:
		if string(packet.b) != "domestic" {
			t.Fatal("wrong payload")
		}
	default:
		t.Fatal("domestic packet did not use native rendezvous")
	}
	if len(foreign) != 0 {
		t.Fatal("domestic packet escaped to overseas DERP")
	}
	if sent, err := c.sendAddr(peerDERPAddress(999), cloud, []byte("cross-border"), false, false); !sent || err != nil {
		t.Fatalf("cloud send: %v %v", sent, err)
	}
	if len(foreign) != 1 || len(local) != 0 {
		t.Fatal("cloud packet borrowed domestic DERP")
	}
	// No UDP socket exists: any unintended dial would fail/panic this test.
	if sent, err := c.sendAddr(netip.MustParseAddrPort("203.0.113.7:41641"), cloud, []byte("probe"), true, false); sent || err != nil {
		t.Fatal("cross-border native discovery sent")
	}
}
