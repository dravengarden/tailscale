package magicsock

import (
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/tailscale/types/key"
	"go4.org/mem"
)

// transportAuthorizedEndpoint binds the outer transport to the identity
// WireGuard authenticates. Address-to-peer cache entries are not proof that a
// packet belongs to that peer. WireGuard checks this before accepting it.
type transportAuthorizedEndpoint struct {
	*endpoint
	region      int // zero is native UDP; otherwise the actual receive DERP region
	packetBytes int
}

var _ conn.PeerAuthorizingEndpoint = (*transportAuthorizedEndpoint)(nil)

func (ep *transportAuthorizedEndpoint) AuthorizePeer(raw [32]byte) bool {
	peer := key.NodePublicFromRaw32(mem.B(raw[:]))
	path := "derp"
	if ep.region == 0 {
		path = "native_udp"
	}
	if peer != ep.publicKey {
		ep.c.observePeerTransport(peer, path, ep.region, "blocked_receive", ep.packetBytes)
		return false
	}
	allowed := ep.c.permitsPeerDERP(peer, ep.region)
	if ep.region == 0 {
		allowed = ep.c.permitsNativePeer(peer, false)
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
