package system

import (
	"errors"
	"net"
)

// ErrRouteUnsupported is returned by every method of the route resource on
// platforms other than Linux, where the kernel routing table is read over
// netlink.
var ErrRouteUnsupported = errors.New("route resource is only supported on Linux")

// Route is the state of a single entry in the kernel routing table, as shown
// by `ip route show table all`.
type Route interface {
	Destination() string
	Exists() (bool, error)
	Gateway() (string, error)
	Interface() (string, error)
	Metric() (int, error)
	Protocol() (string, error)
	Scope() (string, error)
	Type() (string, error)
	Table() (int, error)
}

// routeEntry is one RTM_NEWROUTE message decoded into Go types. It is kept
// platform-neutral so the per-System cache can live on the System struct.
type routeEntry struct {
	dst      net.IPNet
	gw       net.IP
	ifIndex  int
	metric   int
	protocol int
	scope    int
	rtype    int
	table    int
}
