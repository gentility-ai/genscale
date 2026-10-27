// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tstest"
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

// genscale: a Mac's VM bridges and taps are never endpoints (GENSCALE.md).
func TestProblematicInterfaceNameExcludesMacVMNetworks(t *testing.T) {
	tests := []struct {
		goos, name string
		want       bool
	}{
		{"darwin", "bridge100", true},
		{"darwin", "bridge101", true},
		{"ios", "bridge100", false}, // the Personal Hotspot, a real path to a tethered Mac
		{"ios", "vmenet0", false},
		{"darwin", "vmenet0", true},
		{"darwin", "vmenet12", true},
		{"darwin", "bridge0", false}, // the Thunderbolt bridge
		{"darwin", "bridge99", false},
		{"darwin", "bridge", false},
		{"darwin", "bridgeX", false},
		{"darwin", "en0", false},
		{"darwin", "utun3", false},
		{"ios", "pdp_ip0", false}, // cellular is the phone's real path away from home
		{"linux", "bridge100", false},
		{"linux", "vmenet0", false},
		{"linux", "zt0", true},
		{"linux", "wt0", true},
		{"windows", "ZeroTier One", true},
	}
	for _, tt := range tests {
		if got := problematicInterfaceName(tt.goos, tt.name); got != tt.want {
			t.Errorf("problematicInterfaceName(%q, %q) = %v, want %v", tt.goos, tt.name, got, tt.want)
		}
	}
}

// cidr parses "ip/len" into the *net.IPNet an interface listing carries, with
// the host address kept (ParseCIDR alone zeroes it).
func cidr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	ipnet.IP = ip
	return ipnet
}

const upFlags = net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning

// On a Mac, LocalAddresses skips bridge100 by isProblematicInterface's use in
// LocalAddresses, not only by the rule; this runs where it matters and skips
// elsewhere.
func TestLocalAddressesSkipsMacVMBridges(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the rule is darwin's; TestProblematicInterfaceNameExcludesMacVMNetworks covers it elsewhere")
	}
	ifaces := []Interface{
		{Interface: &net.Interface{Index: 1, Name: "en0", Flags: upFlags},
			AltAddrs: []net.Addr{cidr(t, "192.168.50.183/24")}},
		{Interface: &net.Interface{Index: 2, Name: "bridge100", Flags: upFlags},
			AltAddrs: []net.Addr{cidr(t, "192.168.64.1/24")}},
	}
	tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) { return ifaces, nil })
	regular, _, err := LocalAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(regular) != 1 || regular[0].String() != "192.168.50.183" {
		t.Fatalf("LocalAddresses = %v, want only en0's address", regular)
	}
}

// genscale: unique local addresses are offered with the rest, capped per
// subnet like global IPv6; 6net's own, Tailscale's own and link-local never.
func TestLocalAddressesOffersULAsWithTheRest(t *testing.T) {
	ifaces := []Interface{
		{Interface: &net.Interface{Index: 1, Name: "en0", Flags: upFlags},
			AltAddrs: []net.Addr{
				cidr(t, "192.168.50.183/24"),
				cidr(t, "fe80::1c6:9aff:fe12:3456/64"),
				cidr(t, "fd8c:e0a9:e3b4:4bb2:18c6:9aff:fe12:3456/64"),
				cidr(t, "fd8c:e0a9:e3b4:4bb2:a1b2:c3d4:e5f6:1/64"),
				cidr(t, "fd8c:e0a9:e3b4:4bb2:dead:beef:0:1/64"), // third in the /64: over the cap
				cidr(t, "2001:db8:1:2::42/64"),
			}},
		{Interface: &net.Interface{Index: 2, Name: "utun4", Flags: upFlags},
			AltAddrs: []net.Addr{
				cidr(t, "fd7a:115c:a1e0::1234/128"), // a co-installed Tailscale
				cidr(t, "fd06:6e7:0:2::a/128"),      // 6net itself
			}},
	}
	tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) { return ifaces, nil })

	regular, _, err := LocalAddresses()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(regular))
	for i, a := range regular {
		got[i] = a.String()
	}
	want := []string{
		"192.168.50.183",
		"2001:db8:1:2::42",
		"fd8c:e0a9:e3b4:4bb2:18c6:9aff:fe12:3456",
		"fd8c:e0a9:e3b4:4bb2:a1b2:c3d4:e5f6:1",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("LocalAddresses = %v, want %v (v4, global, two ULAs; no link-local, no third ULA, no tunnel)", got, want)
	}
}

// The link-local IPv4 fallback is as upstream left it: 169.254 is offered only
// when there is no regular IPv4 and no global IPv6; a ULA beside it does not
// hide it (upstream offered both too), a global address does.
func TestLocalAddressesStillFallsBackToLinkLocalIPv4(t *testing.T) {
	addrs := func(cidrs ...string) []net.Addr {
		out := make([]net.Addr, len(cidrs))
		for i, c := range cidrs {
			out[i] = cidr(t, c)
		}
		return out
	}
	tests := []struct {
		name  string
		addrs []net.Addr
		want  string
	}{
		{"169.254 and a ULA", addrs("169.254.10.5/16", "fd00:1::5/64"), "169.254.10.5 fd00:1::5"},
		{"169.254 and a global", addrs("169.254.10.5/16", "2001:db8::5/64"), "2001:db8::5"},
		{"169.254 alone", addrs("169.254.10.5/16"), "169.254.10.5"},
		{"169.254 and a regular v4", addrs("169.254.10.5/16", "10.0.0.5/8"), "10.0.0.5"},
	}
	for _, tt := range tests {
		ifaces := []Interface{{Interface: &net.Interface{Index: 1, Name: "eth0", Flags: upFlags}, AltAddrs: tt.addrs}}
		tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) { return ifaces, nil })
		regular, _, err := LocalAddresses()
		if err != nil {
			t.Fatal(err)
		}
		parts := make([]string, len(regular))
		for i, a := range regular {
			parts[i] = a.String()
		}
		if got := strings.Join(parts, " "); got != tt.want {
			t.Errorf("%s: LocalAddresses = %q, want %q", tt.name, got, tt.want)
		}
	}
}
