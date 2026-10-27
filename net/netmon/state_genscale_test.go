// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"net"
	"net/netip"
	"runtime"
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
