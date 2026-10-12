package magicsock

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/util/eventbus"
	"github.com/sagernet/tailscale/util/usermetric"
)

// failingListener refuses to listen while fail is set, standing in for a
// socket bound to a default interface that is briefly absent.
type failingListener struct{ fail atomic.Bool }

func (l *failingListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if l.fail.Load() {
		return nil, errors.New("no route to default interface")
	}
	return (&net.ListenConfig{}).ListenPacket(ctx, network, "127.0.0.1:0")
}

func TestFailedRebindIsRetriedWithoutALinkChange(t *testing.T) {
	previousMin, previousMax := rebindRetryMin, rebindRetryMax
	rebindRetryMin, rebindRetryMax = 20*time.Millisecond, 80*time.Millisecond
	t.Cleanup(func() { rebindRetryMin, rebindRetryMax = previousMin, previousMax })
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	listener := &failingListener{}
	conn, err := NewConn(Options{Logf: t.Logf, NetMon: netmon.NewStatic(), EventBus: bus, TestOnlyPacketListener: listener, DisablePortMapper: true, Metrics: new(usermetric.Registry)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if conn.udp4Unbound() {
		t.Fatal("initial bind failed")
	}
	listener.fail.Store(true)
	conn.Rebind()
	if !conn.udp4Unbound() {
		t.Fatal("a failed rebind did not leave the placeholder socket")
	}
	// The interface returns without any further network event.
	time.Sleep(100 * time.Millisecond)
	listener.fail.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for conn.udp4Unbound() {
		if time.Now().After(deadline) {
			t.Fatal("native UDP stayed unbound after the interface returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn.mu.Lock()
	pending, delay := conn.rebindRetry != nil, conn.rebindRetryDelay
	conn.mu.Unlock()
	if pending || delay != 0 {
		t.Fatalf("retry state not cleared after success: pending=%v delay=%v", pending, delay)
	}
}

func TestCloseStopsRebindRetries(t *testing.T) {
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	listener := &failingListener{}
	conn, err := NewConn(Options{Logf: t.Logf, NetMon: netmon.NewStatic(), EventBus: bus, TestOnlyPacketListener: listener, DisablePortMapper: true, Metrics: new(usermetric.Registry)})
	if err != nil {
		t.Fatal(err)
	}
	listener.fail.Store(true)
	conn.Rebind()
	conn.Close()
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.rebindRetry != nil {
		t.Fatal("Close left a rebind retry armed")
	}
}
