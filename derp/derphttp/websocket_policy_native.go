//go:build (linux || darwin) && ts_debug_websockets

package derphttp

import (
	"errors"
	"net/http"

	"github.com/coder/websocket"
	"github.com/sagernet/tailscale/feature"
)

func policyWebsocketOptions() (*websocket.DialOptions, error) {
	options := &websocket.DialOptions{Subprotocols: []string{"derp"}}
	if !HookDialPolicy.IsSet() {
		return options, nil
	}
	client := *http.DefaultClient
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if proxy, ok := feature.HookProxyFromEnvironment.GetOk(); ok {
		standard, ok := base.(*http.Transport)
		if !ok {
			return nil, errors.New("custom WebSocket transport cannot enforce DERP proxy policy")
		}
		transport := standard.Clone()
		transport.Proxy = proxy
		base = transport
	}
	client.Transport = policyRoundTripper{base: base}
	options.HTTPClient = &client
	return options, nil
}
