package system

import "errors"

// ErrIGMPUnsupported is returned by every method of the igmp resource on
// platforms other than Linux, where membership is read from /proc/net/igmp.
var ErrIGMPUnsupported = errors.New("igmp resource is only supported on Linux")

// IGMP is the membership of a single IPv4 multicast group, as shown by
// /proc/net/igmp. The key is `[interface:]group`; without an interface the
// group is looked up on every interface.
type IGMP interface {
	Group() string
	Exists() (bool, error)
	Interface() (string, error)
	Version() (int, error)
	Users() (int, error)
}

// igmpEntry is one multicast group membership from /proc/net/igmp. It is kept
// platform-neutral so the per-System cache can live on the System struct.
type igmpEntry struct {
	group   string
	ifName  string
	version int
	users   int
}
