//go:build linux

package system

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/goss-org/goss/util"
	"golang.org/x/sys/unix"
)

// igmpHexFor renders an IP the way the kernel prints it in /proc/net/igmp:
// the network-order value as a native integer, so the fixture works on both
// little- and big-endian architectures.
func igmpHexFor(t *testing.T, ip string) string {
	t.Helper()
	p := net.ParseIP(ip).To4()
	if p == nil {
		t.Fatalf("not an IPv4 address: %q", ip)
	}
	return fmt.Sprintf("%08X", binary.NativeEndian.Uint32(p))
}

const igmpHeader = "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n"

func igmpFixture(t *testing.T) []byte {
	t.Helper()
	return []byte(igmpHeader +
		"1\tlo        :     2      V3\n" +
		"\t\t\t\t" + igmpHexFor(t, "233.252.251.250") + "     1 0:00000000\t\t0\n" +
		"\t\t\t\t" + igmpHexFor(t, "224.0.0.1") + "     2 0:00000000\t\t0\n" +
		"2\teth0      :     2      V2\n" +
		"\t\t\t\t" + igmpHexFor(t, "224.0.0.251") + "     1 0:00000000\t\t0\n" +
		"\t\t\t\t" + igmpHexFor(t, "224.0.0.1") + "     1 0:00000000\t\t0\n")
}

// sysWithIGMP returns a System whose membership cache is primed with data
// instead of /proc/net/igmp.
func sysWithIGMP(t *testing.T, data []byte) *System {
	t.Helper()
	entries, err := parseIGMPData(data)
	if err != nil {
		t.Fatalf("parseIGMPData returned error: %v", err)
	}
	sys := &System{}
	sys.igmpOnce.Do(func() { sys.igmp = entries })
	return sys
}

func TestIGMPHexToIP(t *testing.T) {
	for _, ip := range []string{"224.0.0.1", "224.0.0.251", "233.252.251.250", "239.1.2.3"} {
		got, err := igmpHexToIP(igmpHexFor(t, ip))
		if err != nil {
			t.Errorf("igmpHexToIP(%s) error: %v", ip, err)
			continue
		}
		if got != ip {
			t.Errorf("igmpHexToIP(%s) = %s, want %s", igmpHexFor(t, ip), got, ip)
		}
	}
	for _, bad := range []string{"E0", "0100zz0E0", "010000E00"} {
		if _, err := igmpHexToIP(bad); err == nil {
			t.Errorf("igmpHexToIP(%q) succeeded, want error", bad)
		}
	}
}

func TestParseIGMPData(t *testing.T) {
	entries, err := parseIGMPData(igmpFixture(t))
	if err != nil {
		t.Fatalf("parseIGMPData returned error: %v", err)
	}
	want := []igmpEntry{
		{group: "233.252.251.250", ifName: "lo", version: 3, users: 1},
		{group: "224.0.0.1", ifName: "lo", version: 3, users: 2},
		{group: "224.0.0.251", ifName: "eth0", version: 2, users: 1},
		{group: "224.0.0.1", ifName: "eth0", version: 2, users: 1},
	}
	if len(entries) != len(want) {
		t.Fatalf("parseIGMPData returned %d entries, want %d: %#v", len(entries), len(want), entries)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entry %d = %#v, want %#v", i, entries[i], want[i])
		}
	}
}

func TestParseIGMPDataMalformed(t *testing.T) {
	for _, data := range []string{
		igmpHeader + "1\tlo        :     2      VX\n",
		igmpHeader + "1\tlo        :     2      V3\n\t\t\t\tzz0000E0     1 0:00000000\t\t0\n",
		igmpHeader + "1\tlo        :     2      V3\n\t\t\t\t010000E0     x 0:00000000\t\t0\n",
		igmpHeader + "\t\t\t\t010000E0     1 0:00000000\t\t0\n", // group before any interface
		igmpHeader + "garbage\n",
	} {
		if _, err := parseIGMPData([]byte(data)); err == nil {
			t.Errorf("parseIGMPData(%q) succeeded, want error", data)
		}
	}
}

func TestParseIGMPDataHeaderOnly(t *testing.T) {
	for _, data := range []string{"", igmpHeader, igmpHeader + "\n"} {
		entries, err := parseIGMPData([]byte(data))
		if err != nil {
			t.Errorf("parseIGMPData(%q) error: %v", data, err)
			continue
		}
		if len(entries) != 0 {
			t.Errorf("parseIGMPData(%q) returned %d entries, want 0", data, len(entries))
		}
	}
}

func TestParseIGMPKey(t *testing.T) {
	cases := []struct {
		in     string
		ifName string
		group  string
		err    bool
	}{
		{in: "224.1.2.3", group: "224.1.2.3"},
		{in: "eth0:224.1.2.3", ifName: "eth0", group: "224.1.2.3"},
		{in: "eth0:1:224.1.2.3", ifName: "eth0:1", group: "224.1.2.3"},
		{in: ":224.1.2.3", err: true},
		{in: "not-an-ip", err: true},
		{in: "eth0:fe80::1", err: true},
		{in: "eth0:", err: true},
	}
	for _, tc := range cases {
		ifName, group, err := parseIGMPKey(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("parseIGMPKey(%q) = (%q, %q), want error", tc.in, ifName, group)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseIGMPKey(%q) error: %v", tc.in, err)
			continue
		}
		if ifName != tc.ifName || group != tc.group {
			t.Errorf("parseIGMPKey(%q) = (%q, %q), want (%q, %q)", tc.in, ifName, group, tc.ifName, tc.group)
		}
	}
}

func TestDefIGMPByInterface(t *testing.T) {
	sys := sysWithIGMP(t, igmpFixture(t))

	r := NewDefIGMP(t.Context(), "eth0:224.0.0.1", sys, util.Config{})
	if exists, err := r.Exists(); err != nil || !exists {
		t.Fatalf("Exists = (%v, %v), want (true, nil)", exists, err)
	}
	if name, err := r.Interface(); err != nil || name != "eth0" {
		t.Errorf("Interface = (%q, %v), want eth0", name, err)
	}
	if v, err := r.Version(); err != nil || v != 2 {
		t.Errorf("Version = (%d, %v), want 2", v, err)
	}
	if u, err := r.Users(); err != nil || u != 1 {
		t.Errorf("Users = (%d, %v), want 1", u, err)
	}

	r = NewDefIGMP(t.Context(), "eth1:224.0.0.1", sys, util.Config{})
	if exists, err := r.Exists(); err != nil || exists {
		t.Errorf("Exists on an interface without the group = (%v, %v), want (false, nil)", exists, err)
	}
	if name, err := r.Interface(); err != nil || name != "" {
		t.Errorf("Interface on a missing group = (%q, %v), want empty", name, err)
	}
}

func TestDefIGMPAnyInterface(t *testing.T) {
	sys := sysWithIGMP(t, igmpFixture(t))

	// Joined on exactly one interface: attributes resolve.
	r := NewDefIGMP(t.Context(), "224.0.0.251", sys, util.Config{})
	if exists, err := r.Exists(); err != nil || !exists {
		t.Fatalf("Exists = (%v, %v), want (true, nil)", exists, err)
	}
	if name, err := r.Interface(); err != nil || name != "eth0" {
		t.Errorf("Interface = (%q, %v), want eth0", name, err)
	}

	// Joined on several interfaces: exists, but attributes are ambiguous.
	r = NewDefIGMP(t.Context(), "224.0.0.1", sys, util.Config{})
	if exists, err := r.Exists(); err != nil || !exists {
		t.Fatalf("Exists = (%v, %v), want (true, nil)", exists, err)
	}
	_, err := r.Interface()
	if err == nil {
		t.Fatal("Interface on a group joined on two interfaces, want error")
	}
	for _, want := range []string{"eth0", "lo", "eth0:224.0.0.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if _, err := r.Users(); err == nil {
		t.Error("Users on a group joined on two interfaces, want error")
	}

	r = NewDefIGMP(t.Context(), "239.9.9.9", sys, util.Config{})
	if exists, err := r.Exists(); err != nil || exists {
		t.Errorf("Exists on an unjoined group = (%v, %v), want (false, nil)", exists, err)
	}
	if _, err := NewDefIGMP(t.Context(), "bogus", sys, util.Config{}).Exists(); err == nil {
		t.Error("Exists on an invalid key, want error")
	}
}

// TestDefIGMPLiveMembership joins a multicast group on the loopback interface
// and verifies the membership is visible through a fresh System.
func TestDefIGMPLiveMembership(t *testing.T) {
	const group = "233.252.251.250" // MCAST-TEST-NET, safe to join
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("no loopback interface: %v", err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("cannot create socket: %v", err)
	}
	defer unix.Close(fd)

	mreq := &unix.IPMreq{Multiaddr: [4]byte{233, 252, 251, 250}, Interface: [4]byte{127, 0, 0, 1}}
	if err := unix.SetsockoptIPMreq(fd, unix.SOL_IP, unix.IP_ADD_MEMBERSHIP, mreq); err != nil {
		t.Skipf("cannot join multicast group: %v", err)
	}
	defer unix.SetsockoptIPMreq(fd, unix.SOL_IP, unix.IP_DROP_MEMBERSHIP, mreq)

	r := NewDefIGMP(t.Context(), "lo:"+group, &System{}, util.Config{})
	exists, err := r.Exists()
	if err != nil {
		t.Fatalf("Exists returned error: %v", err)
	}
	if !exists {
		t.Fatalf("joined group should exist in %s", igmpProcPath)
	}
	if name, _ := r.Interface(); name != "lo" {
		t.Errorf("Interface = %q, want lo", name)
	}
	if version, _ := r.Version(); version < 1 || version > 3 {
		t.Errorf("Version = %d, want 1..3", version)
	}
	if users, _ := r.Users(); users < 1 {
		t.Errorf("Users = %d, want >= 1", users)
	}
}
