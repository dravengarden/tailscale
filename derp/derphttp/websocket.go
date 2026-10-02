// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || ((linux || darwin) && ts_debug_websockets)

package derphttp

import (
	"context"
	"log"
	"net"

	"github.com/coder/websocket"
	"github.com/sagernet/tailscale/net/wsconn"
)

const canWebsockets = true

func init() {
	dialWebsocketFunc = dialWebsocket
}

func dialWebsocket(ctx context.Context, urlStr string) (net.Conn, error) {
	options, err := policyWebsocketOptions()
	if err != nil {
		return nil, err
	}
	c, res, err := websocket.Dial(ctx, urlStr, options)
	if err != nil {
		log.Printf("websocket Dial: %v, %+v", err, res)
		return nil, err
	}
	log.Printf("websocket: connected to %v", urlStr)
	netConn := wsconn.NetConn(context.Background(), c, websocket.MessageBinary, urlStr)
	return netConn, nil
}
