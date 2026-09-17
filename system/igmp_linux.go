//go:build linux

package system

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/goss-org/goss/util"
)

const igmpProcPath = "/proc/net/igmp"

type DefIGMP struct {
	key     string
	sys     *System
	loaded  bool
	entries []igmpEntry
	err     error
}

func NewDefIGMP(_ context.Context, key string, sys *System, _ util.Config) IGMP {
	return &DefIGMP{
		key: key,
		sys: sys,
	}
}

func (r *DefIGMP) setup() error {
	if r.loaded {
		return r.err
	}
	r.loaded = true

	ifName, group, err := parseIGMPKey(r.key)
	if err != nil {
		r.err = err
		return r.err
	}

	all, err := r.sys.IGMPGroups()
	if err != nil {
		r.err = err
		return r.err
	}

	for _, e := range all {
		if e.group == group && (ifName == "" || e.ifName == ifName) {
			r.entries = append(r.entries, e)
		}
	}
	return nil
}

// entry returns the single matching membership, or an error when the key
// names a group that is joined on more than one interface.
func (r *DefIGMP) entry() (*igmpEntry, error) {
	if err := r.setup(); err != nil {
		return nil, err
	}
	switch len(r.entries) {
	case 0:
		return nil, nil
	case 1:
		return &r.entries[0], nil
	}
	names := make([]string, len(r.entries))
	for i, e := range r.entries {
		names[i] = e.ifName
	}
	sort.Strings(names)
	return nil, fmt.Errorf("multicast group %s is joined on %d interfaces (%s); use %s:%s as the key to select one",
		r.entries[0].group, len(names), strings.Join(names, ", "), names[0], r.entries[0].group)
}

func (r *DefIGMP) Group() string { return r.key }

func (r *DefIGMP) Exists() (bool, error) {
	if err := r.setup(); err != nil {
		return false, err
	}
	return len(r.entries) > 0, nil
}

func (r *DefIGMP) Interface() (string, error) {
	e, err := r.entry()
	if err != nil || e == nil {
		return "", err
	}
	return e.ifName, nil
}

func (r *DefIGMP) Version() (int, error) {
	e, err := r.entry()
	if err != nil || e == nil {
		return 0, err
	}
	return e.version, nil
}

func (r *DefIGMP) Users() (int, error) {
	e, err := r.entry()
	if err != nil || e == nil {
		return 0, err
	}
	return e.users, nil
}

// parseIGMPKey splits an `[interface:]group` key and canonicalizes the group
// address.
func parseIGMPKey(key string) (ifName, group string, err error) {
	group = key
	if i := strings.LastIndexByte(key, ':'); i >= 0 {
		ifName, group = key[:i], key[i+1:]
		if ifName == "" {
			return "", "", fmt.Errorf("invalid igmp key %q: empty interface name", key)
		}
	}
	ip := net.ParseIP(group)
	if ip == nil {
		return "", "", fmt.Errorf("invalid multicast group address: %q", group)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", fmt.Errorf("multicast group must be IPv4: %q", group)
	}
	return ifName, ip4.String(), nil
}

// IGMPGroups returns every IPv4 multicast group membership on the host. The
// file is read once per System, like Ports and ProcMap.
func (s *System) IGMPGroups() ([]igmpEntry, error) {
	s.igmpOnce.Do(func() {
		var data []byte
		data, s.igmpErr = os.ReadFile(igmpProcPath)
		if s.igmpErr != nil {
			return
		}
		s.igmp, s.igmpErr = parseIGMPData(data)
	})
	return s.igmp, s.igmpErr
}

// parseIGMPData parses the contents of /proc/net/igmp, which the kernel's
// igmp_mc_seq_show prints as:
//
//	Idx	Device    : Count Querier	Group    Users Timer	Reporter
//	1	lo        :     2      V3
//				FAFBFCE9     1 0:00000000		0
//
// An interface line carries the interface name and the IGMP version in use
// on it; each following indented line is one group with its user count.
func parseIGMPData(data []byte) ([]igmpEntry, error) {
	var entries []igmpEntry
	var ifName string
	var version int
	for i, raw := range strings.Split(string(data), "\n") {
		if i == 0 || strings.TrimSpace(raw) == "" {
			continue
		}
		fields := strings.Fields(raw)
		switch {
		case len(fields) >= 5 && fields[2] == ":":
			// Interface line: idx device : count Vn
			v, err := strconv.Atoi(strings.TrimPrefix(fields[4], "V"))
			if err != nil {
				return nil, fmt.Errorf("invalid IGMP version in %s line %q: %w", igmpProcPath, raw, err)
			}
			ifName, version = fields[1], v
		case len(fields) >= 2 && ifName != "":
			// Group line: group users timer reporter
			group, err := igmpHexToIP(fields[0])
			if err != nil {
				return nil, fmt.Errorf("invalid group address in %s line %q: %w", igmpProcPath, raw, err)
			}
			users, err := strconv.Atoi(fields[1])
			if err != nil {
				return nil, fmt.Errorf("invalid user count in %s line %q: %w", igmpProcPath, raw, err)
			}
			entries = append(entries, igmpEntry{
				group:   group,
				ifName:  ifName,
				version: version,
				users:   users,
			})
		default:
			return nil, fmt.Errorf("malformed %s line: %q", igmpProcPath, raw)
		}
	}
	return entries, nil
}

// igmpHexToIP converts the 8 hex digit group address printed by the kernel
// to dotted quad. The kernel prints the in-memory (network order) value as a
// native integer, so writing it back out with native endianness recovers the
// octets on both little- and big-endian hosts.
func igmpHexToIP(hex string) (string, error) {
	if len(hex) != 8 {
		return "", fmt.Errorf("want 8 hex digits, got %q", hex)
	}
	v, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return "", err
	}
	var buf [4]byte
	binary.NativeEndian.PutUint32(buf[:], uint32(v))
	return net.IP(buf[:]).String(), nil
}
