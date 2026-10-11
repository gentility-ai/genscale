// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/types/key"
)

// genscale: OnNoPeer fires for an outbound packet no peer owns, and only then.
func TestPeerForPacketTellsOnNoPeerOnlyWithoutAPeer(t *testing.T) {
	var told []netip.Addr
	e := &userspaceEngine{onNoPeer: func(_, dst netip.Addr, _ []byte) { told = append(told, dst) }}
	known := key.NewNode().Public()
	rt := &bart.Table[key.NodePublic]{}
	rt.Insert(netip.MustParsePrefix("fd06:6e7:0:2::5/128"), known)
	e.peerByIPRoute.Store(rt)

	src := netip.MustParseAddr("fd06:6e7:0:2::4")
	peer := netip.MustParseAddr("fd06:6e7:0:2::5")
	stranger := netip.MustParseAddr("fd06:6e7:0:2::9")

	if pk, ok := e.peerForPacket(nil, src, peer, nil); !ok || pk != device.NoisePublicKey(known.Raw32()) {
		t.Fatalf("the routed peer was not found")
	}
	if _, ok := e.peerForPacket(nil, src, stranger, []byte{0x60}); ok {
		t.Fatalf("a stranger had a peer")
	}
	fast := func(netip.Addr) (key.NodePublic, bool) { return known, true }
	if _, ok := e.peerForPacket(fast, src, stranger, nil); !ok {
		t.Fatalf("the fast path's answer was not used")
	}
	if len(told) != 1 || told[0] != stranger {
		t.Fatalf("OnNoPeer told %v; want [%v]", told, stranger)
	}

	// No hook, no panic.
	(&userspaceEngine{}).peerForPacket(nil, src, stranger, nil)
}
