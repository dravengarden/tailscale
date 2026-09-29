package derphttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/tailscale/feature"
	"github.com/sagernet/tailscale/feature/buildfeatures"
	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/tailcfg"
)

func TestNetcheckProxyBoundary(t *testing.T) {
	if !buildfeatures.HasUseProxy {
		t.Skip("proxy feature excluded")
	}
	for _, mode := range []string{"deny", "lookup-error", "allow"} {
		t.Run(mode, func(t *testing.T) {
			var targetConnections, proxyRequests atomic.Int32
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					targetConnections.Add(1)
				}
			}
			target.StartTLS()
			defer target.Close()
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyRequests.Add(1)
				if mode != "allow" || r.Method != http.MethodConnect {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				upstream, err := net.Dial("tcp", target.Listener.Addr().String())
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer upstream.Close()
				client, buffer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer client.Close()
				_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
				_ = buffer.Flush()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, buffer); close(done) }()
				_, _ = io.Copy(client, upstream)
				_ = client.Close()
				<-done
			}))
			defer proxy.Close()
			proxyURL, _ := url.Parse(proxy.URL)
			t.Cleanup(feature.HookProxyFromEnvironment.SetForTest(func(*http.Request) (*url.URL, error) {
				if mode == "lookup-error" {
					return nil, errors.New("proxy resolution unavailable")
				}
				return proxyURL, nil
			}))
			host, portText, _ := net.SplitHostPort(target.Listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			if mode == "allow" {
				// Only the proxy can reach the fixture; a native fallback fails.
				host = "192.0.2.1"
			}
			client := NewNetcheckClient(t.Logf, netmon.NewStatic())
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, closer, _, err := client.DialRegionTLS(ctx, &tailcfg.DERPRegion{
				RegionID: 901, Nodes: []*tailcfg.DERPNode{{
					Name: "fixture", RegionID: 901, HostName: "fixture.example.test",
					IPv4: host, IPv6: "none", DERPPort: port, InsecureForTests: true,
				}},
			})
			if closer != nil {
				_ = closer.Close()
			}
			if mode == "allow" {
				if err != nil || proxyRequests.Load() != 1 || targetConnections.Load() != 1 {
					t.Fatalf("approved proxy: err=%v proxy=%d target=%d", err, proxyRequests.Load(), targetConnections.Load())
				}
			} else if err == nil || targetConnections.Load() != 0 {
				t.Fatalf("native escape: err=%v target=%d", err, targetConnections.Load())
			}
		})
	}
}

func TestNetcheckCancelledHandshakeClosesNativeSocket(t *testing.T) {
	t.Cleanup(feature.HookProxyFromEnvironment.SetForTest(func(*http.Request) (*url.URL, error) {
		return nil, nil
	}))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = io.Copy(io.Discard, conn)
		if err == nil {
			close(closed)
		}
	}()
	client := NewNetcheckClient(t.Logf, netmon.NewStatic())
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = client.dialNodeTLS(ctx, &tailcfg.DERPNode{
		HostName: "fixture.example.test", IPv4: "127.0.0.1", IPv6: "none",
		DERPPort: listener.Addr().(*net.TCPAddr).Port, InsecureForTests: true,
	})
	if err == nil {
		t.Fatal("silent TLS peer unexpectedly connected")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake retained a native socket")
	}
}
