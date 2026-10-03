package magicsock

import (
	"net/netip"
	"slices"

	"github.com/sagernet/tailscale/syncs"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/types/key"
)

// PeerTransportPolicy is an optional embedding boundary. NativeUDP includes
// discovery, not just WireGuard data. DERPRegions confines both discovery and
// data to the same region set; it also constrains reverse-route reuse.
type PeerTransportPolicy struct {
	NativeUDP             bool
	ProxyUDP              bool
	DERPRegions           []int
	UnderlayAddressFamily PeerUnderlayAddressFamily
}

// PeerUnderlayAddressFamily restricts only a peer's outer UDP endpoints.
// It does not restrict WireGuard's inner addresses or shared DERP sockets.
// The zero value preserves the legacy dual-stack behavior.
type PeerUnderlayAddressFamily uint8

const (
	PeerUnderlayDualStack PeerUnderlayAddressFamily = iota
	PeerUnderlayIPv4Only
	PeerUnderlayIPv6Only
)

func (c *Conn) permitsPeerAddress(peer key.NodePublic, address netip.AddrPort) bool {
	p, scoped := c.transportPolicy(peer)
	if !scoped || p.UnderlayAddressFamily == PeerUnderlayDualStack {
		return true
	}
	if !address.IsValid() {
		return false
	}
	switch p.UnderlayAddressFamily {
	case PeerUnderlayDualStack:
		return true
	case PeerUnderlayIPv4Only:
		return address.Addr().Unmap().Is4()
	case PeerUnderlayIPv6Only:
		return address.Addr().Unmap().Is6()
	default:
		return false
	}
}

func (c *Conn) permitsDiscoAddress(disco key.DiscoPublic, address netip.AddrPort) bool {
	if HookPeerTransportPolicy.Load() == nil {
		return true
	}
	found, allowed := false, true
	c.transportDiscoKeys.Range(func(k, value any) bool {
		if value.(key.DiscoPublic) == disco {
			found = true
			allowed = allowed && c.permitsPeerAddress(k.(key.NodePublic), address)
		}
		return allowed
	})
	return found && allowed
}

// HookPeerTransportPolicy returns the embedding application's explicit policy
// for a control-authenticated stable node identity. An empty policy denies all
// paths. With no hook installed, upstream behavior is unchanged.
// Scoped mode supports Tailscale discovery peers only. WireGuard-only peers
// cannot establish a control-authenticated discovery identity after roaming
// and are denied rather than admitting unknown UDP or emitting cookie replies.
// The callback must be bounded and must not call back into Conn.
var HookPeerTransportPolicy syncs.AtomicValue[func(tailcfg.StableNodeID) PeerTransportPolicy]

// HookHomeDERPRegion confines the advertised receive rendezvous without
// removing regions needed by other scoped peers from the shared DERP map.
var HookHomeDERPRegion syncs.AtomicValue[func() int]

// HookFallbackDERPRegions is an optional legacy embedding boundary for a
// deliberately filtered DERP map. A peer may advertise a home outside that
// map. Retain the approved rendezvous connections and use the first approved
// region in that case; never reopen the filtered authority. Both endpoints
// must share a rendezvous. Explicit per-peer policy takes precedence.
// This hook does not change native UDP or WireGuard peer authorization.
var HookFallbackDERPRegions syncs.AtomicValue[func() []int]

// HookPeerTransportObservation is local, bounded telemetry. It never carries
// packet contents, keys, destinations, or credentials. "sent" means a socket
// write succeeded, not that the remote application acknowledged the packet.
var HookPeerTransportObservation syncs.AtomicValue[func(tailcfg.StableNodeID, string, int, string, int)]

func (c *Conn) observePeerTransport(peer key.NodePublic, path string, region int, action string, bytes int) {
	if hook := HookPeerTransportObservation.Load(); hook != nil {
		if node, ok := c.transportPeers.Load(peer); ok {
			hook(node.(tailcfg.NodeView).StableID(), path, region, action, bytes)
		}
	}
}

func (c *Conn) transportPolicy(peer key.NodePublic) (PeerTransportPolicy, bool) {
	hook := HookPeerTransportPolicy.Load()
	if hook == nil {
		return PeerTransportPolicy{}, false
	}
	node, ok := c.transportPeers.Load(peer)
	if !ok {
		return PeerTransportPolicy{}, true
	}
	view := node.(tailcfg.NodeView)
	if view.IsWireGuardOnly() {
		return PeerTransportPolicy{}, true
	}
	return hook(view.StableID()), true
}

func (c *Conn) permitsNativePeer(peer key.NodePublic, peerRelay bool) bool {
	p, scoped := c.transportPolicy(peer)
	return !scoped || (!peerRelay && p.NativeUDP)
}

// selectPeerDERP never substitutes an unauthorized reverse route or region.
// The first region is the deterministic rendezvous when the peer advertises
// a home outside its approved set. Both scoped peers must share that region.
func (c *Conn) selectPeerDERP(peer key.NodePublic, region int) (int, bool) {
	p, scoped := c.transportPolicy(peer)
	if !scoped {
		if hook := HookFallbackDERPRegions.Load(); hook != nil {
			p.DERPRegions = hook()
		} else {
			return region, true
		}
	}
	if slices.Contains(p.DERPRegions, region) {
		return region, true
	}
	if len(p.DERPRegions) == 0 {
		return 0, false
	}
	return p.DERPRegions[0], true
}

func (c *Conn) permitsPeerDERP(peer key.NodePublic, region int) bool {
	p, scoped := c.transportPolicy(peer)
	if !scoped {
		if hook := HookFallbackDERPRegions.Load(); hook != nil {
			return slices.Contains(hook(), region)
		}
	}
	return !scoped || slices.Contains(p.DERPRegions, region)
}

// Discovery can identify peers by a disco key before their UDP endpoint is
// known. Ambiguous disco keys are admitted only if every matching peer agrees.
func (c *Conn) permitsNativeDisco(disco key.DiscoPublic, peerRelay bool) bool {
	if HookPeerTransportPolicy.Load() == nil {
		return true
	}
	found, allowed := false, true
	c.transportPeers.Range(func(k, _ any) bool {
		current, exists := c.transportDiscoKeys.Load(k)
		if exists && current.(key.DiscoPublic) == disco {
			found = true
			allowed = allowed && c.permitsNativePeer(k.(key.NodePublic), peerRelay)
		}
		return allowed
	})
	return found && allowed
}

func peerDERPAddress(region int) netip.AddrPort {
	return netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, uint16(region))
}

func (c *Conn) requiredPeerDERPs() map[int]bool {
	regions := make(map[int]bool)
	if HookPeerTransportPolicy.Load() == nil {
		if hook := HookFallbackDERPRegions.Load(); hook != nil {
			for _, region := range hook() {
				regions[region] = true
			}
		}
		return regions
	}
	c.transportPeers.Range(func(k, _ any) bool {
		p, _ := c.transportPolicy(k.(key.NodePublic))
		for _, region := range p.DERPRegions {
			regions[region] = true
		}
		return true
	})
	return regions
}

func (c *Conn) ensurePeerPolicyDERPs() {
	for region := range c.requiredPeerDERPs() {
		c.goDerpConnect(region)
	}
}
