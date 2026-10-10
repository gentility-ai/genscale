// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"net/netip"
	"testing"

	"tailscale.com/net/tsaddr"
)

// genscale: a utun on Tailscale's own ULA counts as a Tailscale interface,
// so a co-installed Tailscale.app is never taken for a host interface.
func TestHasTailscaleIPMatchesUpstreamULA(t *testing.T) {
	tests := []struct {
		name string
		pfx  string
		want bool
	}{
		{"ours", "fd06:6e7::1/128", true},
		{"upstream Tailscale", "fd7a:115c:a1e0::1/128", true},
		{"cgnat", "100.64.0.1/32", true},
		{"other ULA", "fd00::1/64", false},
		{"global", "2001:db8::1/64", false},
	}
	for _, tt := range tests {
		pfxs := []netip.Prefix{netip.MustParsePrefix(tt.pfx)}
		if got := hasTailscaleIP(pfxs); got != tt.want {
			t.Errorf("%s: hasTailscaleIP(%s) = %v, want %v", tt.name, tt.pfx, got, tt.want)
		}
	}

	if tsaddr.IsTailscaleIP(netip.MustParseAddr("fd7a:115c:a1e0::1")) {
		t.Error("IsTailscaleIP claims Tailscale's ULA; it must stay ours alone")
	}
}
