package derphttp

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/sagernet/tailscale/feature"
)

// HookDialPolicy optionally authorizes a DERP authority before any socket is
// opened. Control-plane HTTPS authorization does not imply DERP authorization,
// even when both services use the same hostname and port. The embedding runtime
// owns the policy; an absent hook preserves upstream behavior.
var HookDialPolicy feature.Hook[func(hostname string, port int) error]

func checkDialPolicy(hostname string, port int) error {
	if policy, ok := HookDialPolicy.GetOk(); ok {
		return policy(hostname, port)
	}
	return nil
}

// RoundTrip checks every request, including redirects followed by http.Client.
type policyRoundTripper struct {
	base http.RoundTripper
}

func (transport policyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := checkURLDialPolicy(request.URL); err != nil {
		return nil, err
	}
	return transport.base.RoundTrip(request)
}

func checkURLDialPolicy(u *url.URL) error {
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if u.Port() != "" {
		var err error
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return err
		}
	}
	return checkDialPolicy(u.Hostname(), port)
}
