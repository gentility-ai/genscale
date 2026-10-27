// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net"
	"net/netip"
	"testing"
)

// genscale: a local endpoint's port is its own family's socket's; an IPv6
// address with no IPv6 socket is not offered (GENSCALE.md).
func TestLocalEndpointPortIsTheFamilysSocket(t *testing.T) {
	v4 := &net.UDPAddr{IP: net.IPv4zero, Port: 41641}
	v6 := &net.UDPAddr{IP: net.IPv6unspecified, Port: 51820}
	unbound := new(net.UDPAddr) // what blockForeverConn.LocalAddr returns
	tests := []struct {
		name        string
		ip          string
		addr4       *net.UDPAddr
		addr6       *net.UDPAddr
		wantPort    uint16
		wantOffered bool
	}{
		{"IPv4 takes the v4 socket's port", "192.168.50.183", v4, v6, 41641, true},
		{"a ULA takes the v6 socket's port", "fd8c:e0a9:e3b4:4bb2::1", v4, v6, 51820, true},
		{"a global v6 takes the v6 socket's port", "2001:db8::1", v4, v6, 51820, true},
		{"::1 takes the v6 socket's port", "::1", v4, v6, 51820, true},
		{"v6 with no v6 socket is not offered", "fd8c::1", v4, unbound, 0, false},
		{"v6 with a nil v6 socket is not offered", "fd8c::1", v4, nil, 0, false},
		{"v4 with no v4 socket is not offered", "192.168.50.183", unbound, v6, 0, false},
	}
	for _, tt := range tests {
		port, offered := localEndpointPort(netip.MustParseAddr(tt.ip), tt.addr4, tt.addr6)
		if port != tt.wantPort || offered != tt.wantOffered {
			t.Errorf("%s: localEndpointPort = (%d, %v), want (%d, %v)", tt.name, port, offered, tt.wantPort, tt.wantOffered)
		}
	}
}
