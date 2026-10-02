package magicsock

import (
	"testing"

	"github.com/sagernet/tailscale/derp/derphttp"
	"github.com/sagernet/tailscale/health"
	"github.com/sagernet/tailscale/net/netcheck"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/util/eventbus"
)

func TestDERPPolicyRemovesCachedAndReportedHome(t *testing.T) {
	t.Cleanup(derphttp.HookMapPolicy.SetForTest(func(dm *tailcfg.DERPMap) *tailcfg.DERPMap {
		filtered := dm.Clone()
		delete(filtered.Regions, 999)
		return filtered
	}))
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		17: {RegionID: 17}, 999: {RegionID: 999},
	}}
	c := newConn(t.Logf)
	bus := eventbus.New()
	c.health = health.NewTracker(bus)
	client := bus.Client("policy-test")
	defer client.Close()
	c.homeDERPChangedPub = eventbus.Publish[HomeDERPChanged](client)
	c.myDerp = 999
	c.SetDERPMapWithoutReSTUN(dm)
	if c.myDerp != 0 || c.derpMap.Regions[999] != nil || dm.Regions[999] == nil {
		t.Fatal("policy retained cached home or mutated the control map")
	}
	if got := c.maybeSetNearestDERP(&netcheck.Report{PreferredDERP: 999}, true); got != 17 {
		t.Fatalf("unapproved reported home selected: %d", got)
	}
	// Even a stale cached value cannot escape through fallback selection.
	c.myDerp = 999
	if got := c.pickDERPFallback(); got != 17 {
		t.Fatalf("unapproved cached fallback selected: %d", got)
	}
	c.SetDERPMapWithoutReSTUN(&tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{999: {RegionID: 999}}})
	if got := c.maybeSetNearestDERP(&netcheck.Report{PreferredDERP: 999}, true); got != 0 {
		t.Fatalf("empty approved map did not fail closed: %d", got)
	}
}
