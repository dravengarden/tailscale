package magicsock

import (
	"github.com/sagernet/tailscale/tstime/mono"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/wireguard-go/conn"
	"go4.org/mem"
	"net/netip"
)

// transportAuthorizedEndpoint binds the outer transport to the identity
// WireGuard authenticates. Address-to-peer cache entries are not proof that a
// packet belongs to that peer. WireGuard checks this before accepting it.
type transportAuthorizedEndpoint struct {
	*endpoint
	region      int // zero is native UDP; otherwise the actual receive DERP region
	packetBytes int
	proxy       bool
	source      netip.AddrPort
}

var _ conn.PeerAuthorizingEndpoint = (*transportAuthorizedEndpoint)(nil)

func (ep *transportAuthorizedEndpoint) AuthorizePeer(raw [32]byte) bool {
	peer := key.NodePublicFromRaw32(mem.B(raw[:]))
	path := "derp"
	if ep.region == 0 {
		path = "native_udp"
	}
	if ep.proxy {
		path = "proxy_udp"
	}
	if peer != ep.publicKey {
		ep.c.observePeerTransport(peer, path, ep.region, "blocked_receive", ep.packetBytes)
		return false
	}
	allowed := ep.c.permitsPeerDERP(peer, ep.region)
	if ep.region == 0 {
		allowed = ep.c.permitsNativePeer(peer, false)
	}
	if ep.proxy {
		policy, scoped := ep.c.transportPolicy(peer)
		allowed = scoped && policy.ProxyUDP
	}
	action := "blocked_receive"
	if allowed {
		action = "received"
	}
	if ep.packetBytes > 0 {
		ep.c.observePeerTransport(peer, path, ep.region, action, ep.packetBytes)
	}
	return allowed
}

var _ conn.PeerAwareEndpoint = (*transportAuthorizedEndpoint)(nil)

// WireGuard invokes FromPeer only after decryption AND replay validation.
// Authorization alone must not let replayed ciphertext renew path liveness.
func (ep *transportAuthorizedEndpoint) FromPeer(raw [32]byte) {
	peer := key.NodePublicFromRaw32(mem.B(raw[:]))
	if peer != ep.publicKey || ep.region != 0 || !ep.source.IsValid() {
		return
	}
	if ep.proxy {
		policy, scoped := ep.c.transportPolicy(peer)
		if !scoped || !policy.ProxyUDP {
			return
		}
	} else if !ep.c.permitsNativePeer(peer, false) {
		return
	}
	now := mono.Now()
	ep.lastRecvUDPAny.StoreAtomic(now)
	ep.noteRecvActivity(epAddr{ap: ep.source}, now)
	// Fresh authenticated data on the already-probed best path is liveness
	// evidence. Do not promote another source or extend an unselected path.
	ep.mu.Lock()
	if ep.bestAddr.isDirect() && ep.bestAddr.ap == ep.source {
		until := now.Add(trustUDPAddrDuration)
		// Receive-only traffic is not proof of bidirectional reachability.
		// Allow at most one heartbeat interval beyond the last actual Pong.
		limit := ep.bestAddrAt.Add(trustUDPAddrDuration + heartbeatInterval)
		if until.After(limit) {
			until = limit
		}
		ep.trustBestAddrUntil = until
	}
	ep.mu.Unlock()
}
