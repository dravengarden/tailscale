package magicsock

import (
	"net/netip"
	"testing"
)

func TestDERPRebindLocalProxyAndPhysicalAddresses(t *testing.T) {
	interfaces := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32"), netip.MustParsePrefix("2001:db8::10/128")}
	for _, tc := range []struct {
		address       string
		retainForPing bool
	}{
		{"127.0.0.1", true}, {"::1", true}, {"::ffff:127.0.0.1", true},
		{"192.0.2.10", true}, {"2001:db8::10", true},
		{"192.0.2.11", false}, {"2001:db8::11", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			if got := derpLocalAddrOnCurrentNetwork(netip.MustParseAddr(tc.address), interfaces); got != tc.retainForPing {
				t.Fatalf("retain for DERP health ping = %v, want %v", got, tc.retainForPing)
			}
		})
	}
}
