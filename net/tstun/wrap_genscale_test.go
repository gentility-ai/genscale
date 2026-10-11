// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"net/netip"
	"testing"

	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine/filter"
)

// genscale: 6net is IPv6-only, so a SYN its filter refuses must be answered
// with the TSMP rejected notice over IPv6 too, or the sender only times out.
func TestRefusedIPv6SYNIsAnsweredWithTSMPRejected(t *testing.T) {
	bus := eventbustest.NewBus(t)
	_, w := newFakeTUN(t.Logf, bus, false)
	defer w.Close()
	w.SetFilter(filter.NewAllowNone(logger.Discard, new(netipx.IPSet)))

	src := netip.MustParseAddr("fd06:6e7:0:2::4")
	dst := netip.MustParseAddr("fd06:6e7:0:2::5")
	p := new(packet.Parsed)
	p.Decode(tcp6syn(src, dst, 51000, 8080))

	if got, _ := w.filterPacketInboundFromWireGuard(p, nil, nil, nil); got != filter.Drop {
		t.Fatalf("got %v; want Drop", got)
	}

	select {
	case r := <-w.vectorOutbound:
		var back packet.Parsed
		back.Decode(r.injected.data)
		if back.IPProto != ipproto.TSMP {
			t.Fatalf("injected %v; want TSMP", back.IPProto)
		}
		h, ok := back.AsTailscaleRejectedHeader()
		want := packet.TailscaleRejectedHeader{
			IPSrc:  dst,
			IPDst:  src,
			Src:    netip.AddrPortFrom(src, 51000),
			Dst:    netip.AddrPortFrom(dst, 8080),
			Proto:  ipproto.TCP,
			Reason: packet.RejectedDueToACLs,
		}
		if !ok || h != want {
			t.Fatalf("rejected header %+v (ok %v); want %+v", h, ok, want)
		}
	default:
		t.Fatal("no TSMP rejected notice was injected for a refused IPv6 SYN")
	}
}

func tcp6syn(src, dst netip.Addr, sport, dport uint16) []byte {
	tcp := make([]byte, 20)
	tcp[0], tcp[1] = byte(sport>>8), byte(sport)
	tcp[2], tcp[3] = byte(dport>>8), byte(dport)
	tcp[12] = 5 << 4 // a 20-byte header
	tcp[13] = byte(packet.TCPSyn)
	return packet.Generate(packet.IP6Header{IPProto: ipproto.TCP, Src: src, Dst: dst}, tcp)
}
