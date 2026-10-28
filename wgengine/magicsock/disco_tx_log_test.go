// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/sagernet/tailscale/disco"
	"github.com/sagernet/tailscale/net/netcheck"
)

func TestShouldLogDiscoTxErrSkipsPolicyDenial(t *testing.T) {
	ping := &disco.Ping{}
	denied := &net.OpError{Op: "write", Net: "udp", Err: fmt.Errorf("send: %w", netcheck.ErrPacketPolicyDenied)}
	if shouldLogDiscoTxErr(ping, netcheck.ErrPacketPolicyDenied) {
		t.Fatal("a policy denial was logged")
	}
	if shouldLogDiscoTxErr(ping, denied) {
		t.Fatal("a wrapped policy denial was logged")
	}
	if !shouldLogDiscoTxErr(ping, errors.New("network is unreachable")) {
		t.Fatal("an ordinary send failure was not logged")
	}
}
