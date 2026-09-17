//go:build linux

package system

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/goss-org/goss/util"
	"golang.org/x/sys/unix"
)

type DefRoute struct {
	dest   string
	sys    *System
	loaded bool
	exists bool
	route  *routeEntry
	err    error
}

func NewDefRoute(_ context.Context, dest string, sys *System, _ util.Config) Route {
	return &DefRoute{
		dest: dest,
		sys:  sys,
	}
}

func (r *DefRoute) setup() error {
	if r.loaded {
		return r.err
	}
	r.loaded = true

	want, err := parseRouteSpec(r.dest)
	if err != nil {
		r.err = err
		return r.err
	}

	routes, err := r.sys.Routes()
	if err != nil {
		r.err = err
		return r.err
	}

	for i := range routes {
		if routeMatches(&routes[i], want) {
			r.route = &routes[i]
			r.exists = true
			return nil
		}
	}
	return nil
}

func (r *DefRoute) Destination() string { return r.dest }

func (r *DefRoute) Exists() (bool, error) {
	if err := r.setup(); err != nil {
		return false, err
	}
	return r.exists, nil
}

func (r *DefRoute) Gateway() (string, error) {
	if err := r.setup(); err != nil {
		return "", err
	}
	if !r.exists || r.route.gw == nil {
		return "", nil
	}
	return r.route.gw.String(), nil
}

func (r *DefRoute) Interface() (string, error) {
	if err := r.setup(); err != nil {
		return "", err
	}
	if !r.exists || r.route.ifIndex == 0 {
		return "", nil
	}
	iface, err := net.InterfaceByIndex(r.route.ifIndex)
	if err != nil {
		return "", err
	}
	return iface.Name, nil
}

func (r *DefRoute) Metric() (int, error) {
	if err := r.setup(); err != nil {
		return 0, err
	}
	if !r.exists {
		return 0, nil
	}
	return r.route.metric, nil
}

func (r *DefRoute) Protocol() (string, error) {
	if err := r.setup(); err != nil {
		return "", err
	}
	if !r.exists {
		return "", nil
	}
	return routeProtocolName(r.route.protocol), nil
}

func (r *DefRoute) Scope() (string, error) {
	if err := r.setup(); err != nil {
		return "", err
	}
	if !r.exists {
		return "", nil
	}
	return routeScopeName(r.route.scope), nil
}

func (r *DefRoute) Type() (string, error) {
	if err := r.setup(); err != nil {
		return "", err
	}
	if !r.exists {
		return "", nil
	}
	return routeTypeName(r.route.rtype), nil
}

func (r *DefRoute) Table() (int, error) {
	if err := r.setup(); err != nil {
		return 0, err
	}
	if !r.exists {
		return 0, nil
	}
	return r.route.table, nil
}

// Routes returns every entry in every routing table, equivalent to
// `ip route show table all` minus cached (cloned) routes. The dump is taken
// once per System, like Ports and ProcMap.
func (s *System) Routes() ([]routeEntry, error) {
	s.routesOnce.Do(func() {
		var data []byte
		data, s.routesErr = syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_UNSPEC)
		if s.routesErr != nil {
			return
		}
		s.routes, s.routesErr = parseRouteDump(data)
	})
	return s.routes, s.routesErr
}

// parseRouteDump decodes the RTM_NEWROUTE messages in a RTM_GETROUTE dump.
func parseRouteDump(data []byte) ([]routeEntry, error) {
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	var routes []routeEntry
	for i := range msgs {
		m := &msgs[i]
		switch m.Header.Type {
		case unix.NLMSG_DONE:
			return routes, nil
		case unix.NLMSG_ERROR:
			if len(m.Data) < 4 {
				return nil, fmt.Errorf("invalid netlink error message")
			}
			if code := int32(binary.NativeEndian.Uint32(m.Data)); code != 0 {
				return nil, fmt.Errorf("netlink error: %w", unix.Errno(-code))
			}
			return routes, nil
		case unix.RTM_NEWROUTE:
			r, ok, err := parseRouteMessage(m)
			if err != nil {
				return nil, err
			}
			if ok {
				routes = append(routes, r)
			}
		}
	}
	return routes, nil
}

// parseRouteMessage decodes one RTM_NEWROUTE message. ok is false for cached
// routes, which are per-destination lookup results rather than table entries.
func parseRouteMessage(m *syscall.NetlinkMessage) (r routeEntry, ok bool, err error) {
	if len(m.Data) < unix.SizeofRtMsg {
		return r, false, fmt.Errorf("invalid netlink route message length %d", len(m.Data))
	}
	// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
	family := int(m.Data[0])
	dstLen := int(m.Data[1])
	if binary.NativeEndian.Uint32(m.Data[8:12])&unix.RTM_F_CLONED != 0 {
		return r, false, nil
	}
	r = routeEntry{
		table:    int(m.Data[4]),
		protocol: int(m.Data[5]),
		scope:    int(m.Data[6]),
		rtype:    int(m.Data[7]),
	}

	attrs, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return r, false, err
	}
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.RTA_DST:
			if ip := parseRouteIP(a.Value); ip != nil {
				r.dst = prefixOf(ip, dstLen)
			}
		case unix.RTA_GATEWAY:
			r.gw = parseRouteIP(a.Value)
		case unix.RTA_OIF:
			if len(a.Value) >= 4 {
				r.ifIndex = int(binary.NativeEndian.Uint32(a.Value))
			}
		case unix.RTA_PRIORITY:
			if len(a.Value) >= 4 {
				r.metric = int(binary.NativeEndian.Uint32(a.Value))
			}
		case unix.RTA_TABLE:
			// Table ids above 255 do not fit rtm_table; the kernel sets it to
			// RT_TABLE_COMPAT and carries the real id here.
			if len(a.Value) >= 4 {
				r.table = int(binary.NativeEndian.Uint32(a.Value))
			}
		}
	}

	// The kernel omits RTA_DST when dst_len is 0, so default routes arrive
	// with no destination attribute at all.
	if r.dst.IP == nil {
		switch family {
		case unix.AF_INET:
			r.dst = prefixOf(net.IPv4zero.To4(), 0)
		case unix.AF_INET6:
			r.dst = prefixOf(net.IPv6zero, 0)
		default:
			return r, false, nil
		}
	}
	return r, true, nil
}

// prefixOf masks ip to a prefix of the given length, sized to the address
// family. ones beyond the address length are clamped.
func prefixOf(ip net.IP, ones int) net.IPNet {
	bits := len(ip) * 8
	if ones > bits {
		ones = bits
	}
	mask := net.CIDRMask(ones, bits)
	return net.IPNet{IP: ip.Mask(mask), Mask: mask}
}

// parseRouteIP copies a 4 or 16 byte netlink address attribute.
func parseRouteIP(data []byte) net.IP {
	if len(data) != net.IPv4len && len(data) != net.IPv6len {
		return nil
	}
	return net.IP(append([]byte(nil), data...))
}

// parseRouteSpec normalizes a destination spec to a masked network. A bare IP
// address is treated as a host route (/32 or /128). "default" is accepted as
// an alias for 0.0.0.0/0, matching `ip route`.
func parseRouteSpec(spec string) (net.IPNet, error) {
	spec = strings.TrimSpace(spec)
	if spec == "default" {
		spec = "0.0.0.0/0"
	}
	var ip net.IP
	ones := -1
	if addr, length, found := strings.Cut(spec, "/"); found {
		ip = net.ParseIP(addr)
		var err error
		if ones, err = strconv.Atoi(length); err != nil {
			return net.IPNet{}, fmt.Errorf("invalid route destination %q", spec)
		}
	} else {
		ip = net.ParseIP(spec)
	}
	if ip == nil {
		return net.IPNet{}, fmt.Errorf("invalid route destination %q", spec)
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	bits := len(ip) * 8
	if ones < 0 {
		ones = bits
	}
	if ones > bits {
		return net.IPNet{}, fmt.Errorf("invalid route destination %q", spec)
	}
	return prefixOf(ip, ones), nil
}

func routeMatches(r *routeEntry, want net.IPNet) bool {
	return r.dst.IP.Equal(want.IP) && len(r.dst.Mask) == len(want.Mask) &&
		string(r.dst.Mask) == string(want.Mask)
}

// routeScopeName maps rtm_scope to the names used by `ip route`.
func routeScopeName(scope int) string {
	switch scope {
	case unix.RT_SCOPE_UNIVERSE:
		return "global"
	case unix.RT_SCOPE_SITE:
		return "site"
	case unix.RT_SCOPE_LINK:
		return "link"
	case unix.RT_SCOPE_HOST:
		return "host"
	case unix.RT_SCOPE_NOWHERE:
		return "nowhere"
	}
	return strconv.Itoa(scope)
}

// routeTypeName maps rtm_type to the names used by `ip route`.
func routeTypeName(t int) string {
	switch t {
	case unix.RTN_UNSPEC:
		return "unspec"
	case unix.RTN_UNICAST:
		return "unicast"
	case unix.RTN_LOCAL:
		return "local"
	case unix.RTN_BROADCAST:
		return "broadcast"
	case unix.RTN_ANYCAST:
		return "anycast"
	case unix.RTN_MULTICAST:
		return "multicast"
	case unix.RTN_BLACKHOLE:
		return "blackhole"
	case unix.RTN_UNREACHABLE:
		return "unreachable"
	case unix.RTN_PROHIBIT:
		return "prohibit"
	case unix.RTN_THROW:
		return "throw"
	case unix.RTN_NAT:
		return "nat"
	case unix.RTN_XRESOLVE:
		return "xresolve"
	}
	return strconv.Itoa(t)
}

// routeProtocolName maps rtm_protocol to the names used by `ip route`.
func routeProtocolName(p int) string {
	switch p {
	case unix.RTPROT_UNSPEC:
		return "unspec"
	case unix.RTPROT_REDIRECT:
		return "redirect"
	case unix.RTPROT_KERNEL:
		return "kernel"
	case unix.RTPROT_BOOT:
		return "boot"
	case unix.RTPROT_STATIC:
		return "static"
	case unix.RTPROT_GATED:
		return "gated"
	case unix.RTPROT_RA:
		return "ra"
	case unix.RTPROT_MRT:
		return "mrt"
	case unix.RTPROT_ZEBRA:
		return "zebra"
	case unix.RTPROT_BIRD:
		return "bird"
	case unix.RTPROT_DNROUTED:
		return "dnrouted"
	case unix.RTPROT_XORP:
		return "xorp"
	case unix.RTPROT_NTK:
		return "ntk"
	case unix.RTPROT_DHCP:
		return "dhcp"
	case unix.RTPROT_MROUTED:
		return "mrouted"
	case unix.RTPROT_KEEPALIVED:
		return "keepalived"
	case unix.RTPROT_BABEL:
		return "babel"
	case unix.RTPROT_OPENR:
		return "openr"
	case unix.RTPROT_BGP:
		return "bgp"
	case unix.RTPROT_ISIS:
		return "isis"
	case unix.RTPROT_OSPF:
		return "ospf"
	case unix.RTPROT_RIP:
		return "rip"
	case unix.RTPROT_EIGRP:
		return "eigrp"
	}
	return strconv.Itoa(p)
}
