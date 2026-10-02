package derphttp

import (
	"errors"

	"github.com/coder/websocket"
)

func policyWebsocketOptions() (*websocket.DialOptions, error) {
	// Browser WebSockets cannot authorize each redirected destination. Preserve
	// stock behavior without an embedding policy; otherwise fail closed.
	if HookDialPolicy.IsSet() {
		return nil, errors.New("browser WebSocket cannot enforce DERP dial policy")
	}
	return &websocket.DialOptions{Subprotocols: []string{"derp"}}, nil
}
