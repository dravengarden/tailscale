package derphttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/tailcfg"
)

func TestDialPolicyRejectsBeforeSocket(t *testing.T) {
	denied := errors.New("authority denied")
	t.Cleanup(HookDialPolicy.SetForTest(func(hostname string, port int) error {
		if hostname != "control.example" || port != 443 {
			t.Fatalf("unexpected authority %s:%d", hostname, port)
		}
		return denied
	}))
	client := NewNetcheckClient(t.Logf, netmon.NewStatic())
	defer client.Close()
	client.dialer = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("policy denial opened a socket")
		return nil, denied
	}
	node := &tailcfg.DERPNode{HostName: "control.example"}
	if _, err := client.dialNode(context.Background(), node); !errors.Is(err, denied) {
		t.Fatalf("DERP: %v", err)
	}
	if _, err := client.dialNodeTLS(context.Background(), node); !errors.Is(err, denied) {
		t.Fatalf("netcheck: %v", err)
	}
	client.url, _ = url.Parse("https://control.example/derp")
	if _, err := client.dialURL(context.Background()); !errors.Is(err, denied) {
		t.Fatalf("URL: %v", err)
	}
}

func TestDialPolicyBlocksRedirectBeforeDestinationSocket(t *testing.T) {
	var destinationConnections atomic.Int32
	destination := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	destination.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			destinationConnections.Add(1)
		}
	}
	destination.Start()
	defer destination.Close()
	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer initial.Close()
	allowedURL, _ := url.Parse(initial.URL)
	allowedPort, _ := strconv.Atoi(allowedURL.Port())
	denied := errors.New("redirect authority denied")
	t.Cleanup(HookDialPolicy.SetForTest(func(host string, port int) error {
		if host == allowedURL.Hostname() && port == allowedPort {
			return nil
		}
		return denied
	}))
	client := &http.Client{Transport: policyRoundTripper{base: http.DefaultTransport}}
	response, err := client.Get(initial.URL)
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, denied) || destinationConnections.Load() != 0 {
		t.Fatalf("redirect: %v, destination connections=%d", err, destinationConnections.Load())
	}
}

func TestDialPolicyPermitsCustomPort(t *testing.T) {
	called := false
	t.Cleanup(HookDialPolicy.SetForTest(func(host string, port int) error {
		called = true
		if host != "relay.example" || port != 8443 {
			t.Fatalf("authority %s:%d", host, port)
		}
		return nil
	}))
	u, _ := url.Parse("https://relay.example:8443/derp")
	if err := checkURLDialPolicy(u); err != nil || !called {
		t.Fatalf("policy: %v, called=%v", err, called)
	}
}
