//go:build linux

package system

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"

	"github.com/goss-org/goss/util"
	"golang.org/x/sys/unix"
)

func TestParseRouteSpec(t *testing.T) {
	cases := []struct {
		in   string
		want string
		bits int
		err  bool
	}{
		{in: "192.168.1.0/24", want: "192.168.1.0/24", bits: 24},
		{in: "192.168.1.5/24", want: "192.168.1.0/24", bits: 24},
		{in: "10.0.0.1", want: "10.0.0.1/32", bits: 32},
		{in: "0.0.0.0/0", want: "0.0.0.0/0", bits: 0},
		{in: "default", want: "0.0.0.0/0", bits: 0},
		{in: "::1", want: "::1/128", bits: 128},
		{in: "::/0", want: "::/0", bits: 0},
		{in: "2001:db8::/64", want: "2001:db8::/64", bits: 64},
		{in: "not-an-ip", err: true},
		{in: "10.0.0.1/33", err: true},
		{in: "10.0.0.1/x", err: true},
		{in: "2001:db8::1/129", err: true},
	}
	for _, tc := range cases {
		got, err := parseRouteSpec(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("parseRouteSpec(%q) = %s, want error", tc.in, got.String())
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRouteSpec(%q) error: %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("parseRouteSpec(%q) = %s, want %s", tc.in, got.String(), tc.want)
		}
		if ones, _ := got.Mask.Size(); ones != tc.bits {
			t.Errorf("parseRouteSpec(%q) bits = %d, want %d", tc.in, ones, tc.bits)
		}
	}
}

// rtAttr encodes one struct rtattr with its payload, padded to 4 bytes.
func rtAttr(typ uint16, value []byte) []byte {
	b := make([]byte, 4, 4+(len(value)+3)&^3)
	binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(value)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	b = append(b, value...)
	return b[:cap(b)]
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

// newRouteMessage builds an RTM_NEWROUTE message the way the kernel does.
func newRouteMessage(family, dstLen, table, proto, scope, typ byte, flags uint32, attrs ...[]byte) *syscall.NetlinkMessage {
	data := []byte{family, dstLen, 0, 0, table, proto, scope, typ}
	data = append(data, u32(flags)...)
	for _, a := range attrs {
		data = append(data, a...)
	}
	return &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE, Len: uint32(unix.NLMSG_HDRLEN + len(data))},
		Data:   data,
	}
}

func TestParseRouteMessage(t *testing.T) {
	cases := []struct {
		name string
		msg  *syscall.NetlinkMessage
		skip bool
		dst  string
		gw   string
		oif  int
		met  int
		tbl  int
	}{
		{
			// The kernel omits RTA_DST for a zero-length prefix.
			name: "ipv4 default route without RTA_DST",
			msg: newRouteMessage(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTPROT_STATIC, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0,
				rtAttr(unix.RTA_GATEWAY, []byte{10, 0, 0, 1}),
				rtAttr(unix.RTA_OIF, u32(2)),
				rtAttr(unix.RTA_PRIORITY, u32(300)),
			),
			dst: "0.0.0.0/0", gw: "10.0.0.1", oif: 2, met: 300, tbl: unix.RT_TABLE_MAIN,
		},
		{
			name: "ipv6 default route without RTA_DST",
			msg: newRouteMessage(unix.AF_INET6, 0, unix.RT_TABLE_MAIN, unix.RTPROT_RA, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0,
				rtAttr(unix.RTA_GATEWAY, net.ParseIP("fe80::1")),
				rtAttr(unix.RTA_OIF, u32(3)),
			),
			dst: "::/0", gw: "fe80::1", oif: 3, tbl: unix.RT_TABLE_MAIN,
		},
		{
			name: "prefix route masks host bits",
			msg: newRouteMessage(unix.AF_INET, 24, unix.RT_TABLE_MAIN, unix.RTPROT_KERNEL, unix.RT_SCOPE_LINK, unix.RTN_UNICAST, 0,
				rtAttr(unix.RTA_DST, []byte{192, 168, 1, 7}),
				rtAttr(unix.RTA_OIF, u32(2)),
			),
			dst: "192.168.1.0/24", oif: 2, tbl: unix.RT_TABLE_MAIN,
		},
		{
			// Table ids above 255 arrive as RT_TABLE_COMPAT plus RTA_TABLE.
			name: "large table id from RTA_TABLE",
			msg: newRouteMessage(unix.AF_INET, 8, unix.RT_TABLE_COMPAT, unix.RTPROT_STATIC, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0,
				rtAttr(unix.RTA_DST, []byte{10, 0, 0, 0}),
				rtAttr(unix.RTA_TABLE, u32(1000)),
			),
			dst: "10.0.0.0/8", tbl: 1000,
		},
		{
			name: "cloned route is skipped",
			msg: newRouteMessage(unix.AF_INET, 32, unix.RT_TABLE_MAIN, unix.RTPROT_KERNEL, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, unix.RTM_F_CLONED,
				rtAttr(unix.RTA_DST, []byte{10, 0, 0, 5}),
			),
			skip: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ok, err := parseRouteMessage(tc.msg)
			if err != nil {
				t.Fatalf("parseRouteMessage error: %v", err)
			}
			if ok == tc.skip {
				t.Fatalf("parseRouteMessage ok = %v, want %v", ok, !tc.skip)
			}
			if tc.skip {
				return
			}
			if got := r.dst.String(); got != tc.dst {
				t.Errorf("dst = %s, want %s", got, tc.dst)
			}
			if got := r.gw.String(); tc.gw != "" && got != tc.gw {
				t.Errorf("gw = %s, want %s", got, tc.gw)
			}
			if r.ifIndex != tc.oif {
				t.Errorf("ifIndex = %d, want %d", r.ifIndex, tc.oif)
			}
			if r.metric != tc.met {
				t.Errorf("metric = %d, want %d", r.metric, tc.met)
			}
			if r.table != tc.tbl {
				t.Errorf("table = %d, want %d", r.table, tc.tbl)
			}
		})
	}
}

func TestParseRouteMessageTooShort(t *testing.T) {
	m := &syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE}, Data: []byte{unix.AF_INET, 0}}
	if _, _, err := parseRouteMessage(m); err == nil {
		t.Error("parseRouteMessage on a truncated rtmsg, want error")
	}
}

func TestRouteNames(t *testing.T) {
	types := map[int]string{
		unix.RTN_UNICAST: "unicast", unix.RTN_LOCAL: "local", unix.RTN_BROADCAST: "broadcast",
		unix.RTN_ANYCAST: "anycast", unix.RTN_MULTICAST: "multicast", unix.RTN_BLACKHOLE: "blackhole",
		unix.RTN_UNREACHABLE: "unreachable", unix.RTN_PROHIBIT: "prohibit", unix.RTN_THROW: "throw",
		99: "99",
	}
	for in, want := range types {
		if got := routeTypeName(in); got != want {
			t.Errorf("routeTypeName(%d) = %q, want %q", in, got, want)
		}
	}
	scopes := map[int]string{
		unix.RT_SCOPE_UNIVERSE: "global", unix.RT_SCOPE_LINK: "link", unix.RT_SCOPE_HOST: "host", 7: "7",
	}
	for in, want := range scopes {
		if got := routeScopeName(in); got != want {
			t.Errorf("routeScopeName(%d) = %q, want %q", in, got, want)
		}
	}
	protos := map[int]string{
		unix.RTPROT_KERNEL: "kernel", unix.RTPROT_STATIC: "static", unix.RTPROT_DHCP: "dhcp",
		unix.RTPROT_BGP: "bgp", unix.RTPROT_OPENR: "openr", 250: "250",
	}
	for in, want := range protos {
		if got := routeProtocolName(in); got != want {
			t.Errorf("routeProtocolName(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestDefRouteLocalTableRoute verifies the dump covers non-main tables: the
// loopback range lives in the local table (255), which a main-table-only dump
// would miss.
func TestDefRouteLocalTableRoute(t *testing.T) {
	sys := &System{}

	r := NewDefRoute(t.Context(), "127.0.0.0/8", sys, util.Config{})
	exists, err := r.Exists()
	if err != nil {
		t.Fatalf("Exists returned error: %v", err)
	}
	if !exists {
		t.Fatal("127.0.0.0/8 should exist in the local table")
	}

	if iface, _ := r.Interface(); iface != "lo" {
		t.Errorf("Interface = %q, want lo", iface)
	}
	if scope, _ := r.Scope(); scope != "host" {
		t.Errorf("Scope = %q, want host", scope)
	}
	if rtype, _ := r.Type(); rtype != "local" {
		t.Errorf("Type = %q, want local", rtype)
	}
	if table, _ := r.Table(); table != unix.RT_TABLE_LOCAL {
		t.Errorf("Table = %d, want %d (local)", table, unix.RT_TABLE_LOCAL)
	}
}

func TestDefRouteMissing(t *testing.T) {
	sys := &System{}

	r := NewDefRoute(t.Context(), "192.0.2.0/24", sys, util.Config{})
	exists, err := r.Exists()
	if err != nil {
		t.Fatalf("Exists returned error: %v", err)
	}
	if exists {
		t.Fatal("192.0.2.0/24 (TEST-NET-1) should not be routed")
	}
	if _, err := NewDefRoute(t.Context(), "bogus", sys, util.Config{}).Exists(); err == nil {
		t.Error("Exists on an invalid destination, want error")
	}
}

// TestDefRouteDefaultRoute pins the RTA_DST-less default route against the
// live table when the host has one.
func TestDefRouteDefaultRoute(t *testing.T) {
	sys := &System{}
	routes, err := sys.Routes()
	if err != nil {
		t.Fatalf("Routes returned error: %v", err)
	}
	found := false
	for i := range routes {
		if routes[i].table == unix.RT_TABLE_MAIN && routes[i].dst.String() == "0.0.0.0/0" {
			found = true
			break
		}
	}
	if !found {
		t.Skip("no IPv4 default route in main table; nothing to assert")
	}
	for _, key := range []string{"0.0.0.0/0", "default"} {
		r := NewDefRoute(t.Context(), key, sys, util.Config{})
		exists, err := r.Exists()
		if err != nil {
			t.Fatalf("Exists(%s) returned error: %v", key, err)
		}
		if !exists {
			t.Errorf("Exists(%s) = false, want true", key)
		}
		if gw, _ := r.Gateway(); gw == "" {
			t.Errorf("Gateway(%s) is empty, want the next hop", key)
		}
	}
}
