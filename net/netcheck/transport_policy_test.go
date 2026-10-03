package netcheck

import (
	"context"
	"fmt"
	"net/netip"
	"syscall"
	"testing"

	"github.com/sagernet/tailscale/net/stun"
	"github.com/sagernet/tailscale/tailcfg"
)

func TestSTUNPolicyDenialIsNotSocketFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		port        int
		err         error
		short       bool
		wantSend    bool
		wantFailure bool
	}{
		{name: "no approved STUN authority", port: -1},
		{name: "policy denied", port: 3478, err: fmt.Errorf("bounded embedding: %w", ErrPacketPolicyDenied)},
		{name: "physical socket failed", port: 3478, err: syscall.EBADF, wantFailure: true},
		{name: "short write", port: 3478, short: true, wantFailure: true},
		{name: "successful send", port: 3478, wantSend: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{Logf: t.Logf, SendPacket: func(packet []byte, _ netip.AddrPort) (int, error) {
				if tc.err != nil || tc.short {
					return 0, tc.err
				}
				return len(packet), nil
			}}
			report := &Report{}
			state := &reportState{c: client, report: report, inFlight: make(map[stun.TxID]func(netip.AddrPort))}
			region := &tailcfg.DERPRegion{RegionID: 17, Nodes: []*tailcfg.DERPNode{{Name: "approved", RegionID: 17, IPv4: "203.0.113.8", STUNPort: tc.port}}}
			state.runProbe(context.Background(), &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{17: region}}, probe{node: "approved", proto: probeIPv4}, func() {})
			if report.IPv4CanSend != tc.wantSend || report.IPv4SendError != tc.wantFailure {
				t.Fatalf("policy/no-probe and actual socket failure conflated: send=%v error=%v", report.IPv4CanSend, report.IPv4SendError)
			}
		})
	}
}
