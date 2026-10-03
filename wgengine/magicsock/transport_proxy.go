package magicsock

import (
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/tailscale/syncs"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/tstime/mono"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/wireguard-go/conn"
)

// PeerDatagramPacket is ciphertext received on an embedding-owned proxy
// session bound to a control-authenticated peer. It is not authentication:
// WireGuard/disco must still authenticate the payload before accepting it.
type PeerDatagramPacket struct {
	Peer   tailcfg.StableNodeID
	Source netip.AddrPort
	Data   []byte
}

// PeerDatagramTransport must have bounded sessions and buffers, an explicit
// approved proxy set, and no native fallback. Receive must honor done even
// while idle. The embedding owns its lifetime, independently of socket rebind.
type PeerDatagramTransport interface {
	Send(tailcfg.StableNodeID, netip.AddrPort, []byte) error
	Receive(done <-chan struct{}) (PeerDatagramPacket, error)
	ProbeFailed(tailcfg.StableNodeID, netip.AddrPort, mono.Time)
}

var HookPeerDatagramTransport syncs.AtomicValue[PeerDatagramTransport]

var errProxyDatagramUnavailable = errors.New("approved peer datagram transport unavailable")

func (c *Conn) permitsPeerUDP(peer key.NodePublic, relay bool) bool {
	p, scoped := c.transportPolicy(peer)
	return !scoped || (!relay && (p.NativeUDP || p.ProxyUDP))
}

func (c *Conn) proxyPeerKey(id tailcfg.StableNodeID) (peer key.NodePublic, ok bool) {
	value, exists := c.transportPeerKeys.Load(id)
	if !exists {
		return peer, false
	}
	peer = value.(key.NodePublic)
	current, exists := c.transportPeers.Load(peer)
	if !exists {
		return peer, false
	}
	view := current.(tailcfg.NodeView)
	return peer, view.StableID() == id && !view.IsWireGuardOnly()
}

func (c *Conn) proxyDiscoPeer(disco key.DiscoPublic, hint key.NodePublic) (peer key.NodePublic, ok bool) {
	if !hint.IsZero() {
		current, known := c.transportDiscoKeys.Load(hint)
		return hint, known && current.(key.DiscoPublic) == disco
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	peers := c.peerMap.nodesOfDisco[disco]
	if len(peers) != 1 {
		return peer, false
	}
	for candidate := range peers {
		return candidate, true
	}
	return peer, false
}

func (c *Conn) sendProxyDatagram(peer key.NodePublic, destination netip.AddrPort, packet []byte) (bool, error) {
	path := "proxy_udp"
	if kind, _ := packetLooksLike(packet); kind == packetLooksLikeDisco {
		path = "proxy_discovery"
	}
	p, scoped := c.transportPolicy(peer)
	transport := HookPeerDatagramTransport.Load()
	if !scoped || !p.ProxyUDP || transport == nil {
		return false, errProxyDatagramUnavailable
	}
	if !c.permitsPeerAddress(peer, destination) {
		c.observePeerTransport(peer, path, 0, "skipped_address_family", 0)
		return false, errProxyDatagramUnavailable
	}
	node, ok := c.transportPeers.Load(peer)
	if !ok {
		return false, errProxyDatagramUnavailable
	}
	view := node.(tailcfg.NodeView)
	// Only the authenticated control map can authorize a remote destination.
	// A discovered address or a caller-supplied public IP cannot create a proxy.
	found := false
	approved, exists := c.transportEndpoints.Load(peer)
	if !exists {
		return false, errProxyDatagramUnavailable
	}
	for _, endpoint := range approved.([]netip.AddrPort) {
		if endpoint == destination {
			found = true
			break
		}
	}
	if !found {
		c.observePeerTransport(peer, path, 0, "blocked_send", len(packet))
		return false, errProxyDatagramUnavailable
	}
	if err := transport.Send(view.StableID(), destination, packet); err != nil {
		return false, err
	}
	c.observePeerTransport(peer, path, 0, "sent", len(packet))
	return true, nil
}

func (c *Conn) receiveProxyDatagram(done <-chan struct{}) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		for {
			transport := HookPeerDatagramTransport.Load()
			if transport == nil {
				return 0, net.ErrClosed
			}
			packet, err := transport.Receive(done)
			if err != nil {
				return 0, err
			}
			peer, ok := c.proxyPeerKey(packet.Peer)
			policy, scoped := c.transportPolicy(peer)
			if !ok || !scoped || !policy.ProxyUDP {
				continue
			}
			if !c.permitsPeerAddress(peer, packet.Source) {
				c.observePeerTransport(peer, "proxy_udp", 0, "blocked_receive", len(packet.Data))
				continue
			}
			if len(packet.Data) < 4 || len(packet.Data) > len(packets[0]) {
				continue
			}
			kind, encap := packetLooksLike(packet.Data)
			if encap {
				continue
			}
			if kind == packetLooksLikeDisco {
				if len(packet.Data) < discoHeaderLen {
					continue
				}
				c.handleDiscoMessage(packet.Data, epAddr{ap: packet.Source}, false, peer, discoRXPathProxy)
				continue
			}
			if kind == packetLooksLikeSTUNBinding || !c.havePrivateKey.Load() {
				continue
			}
			c.mu.Lock()
			ep, known := c.peerMap.endpointForNodeKey(peer)
			c.mu.Unlock()
			if !known {
				continue
			}
			sizes[0] = copy(packets[0], packet.Data)
			endpoints[0] = &transportAuthorizedEndpoint{endpoint: ep, proxy: true, source: packet.Source, packetBytes: sizes[0]}
			return 1, nil
		}
	}
}
