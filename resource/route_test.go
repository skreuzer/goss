package resource

import (
	"context"
	"strings"
	"testing"

	"github.com/goss-org/goss/system"
	"github.com/goss-org/goss/util"
	"gopkg.in/yaml.v3"
)

// fakeSysRoute is a minimal system.Route implementation used to drive the
// Route resource without touching the kernel routing table.
type fakeSysRoute struct {
	dest     string
	exists   bool
	err      error
	gateway  string
	iface    string
	metric   int
	protocol string
	scope    string
	rtype    string
	table    int
}

func (f *fakeSysRoute) Destination() string        { return f.dest }
func (f *fakeSysRoute) Exists() (bool, error)      { return f.exists, f.err }
func (f *fakeSysRoute) Gateway() (string, error)   { return f.gateway, nil }
func (f *fakeSysRoute) Interface() (string, error) { return f.iface, nil }
func (f *fakeSysRoute) Metric() (int, error)       { return f.metric, nil }
func (f *fakeSysRoute) Protocol() (string, error)  { return f.protocol, nil }
func (f *fakeSysRoute) Scope() (string, error)     { return f.scope, nil }
func (f *fakeSysRoute) Type() (string, error)      { return f.rtype, nil }
func (f *fakeSysRoute) Table() (int, error)        { return f.table, nil }

func sysWithRoute(r *fakeSysRoute) *system.System {
	return &system.System{
		NewRoute: func(context.Context, string, *system.System, util.Config) system.Route {
			return r
		},
	}
}

func TestRouteValidateAllPass(t *testing.T) {
	r := &Route{
		id:        "0.0.0.0/0",
		Exists:    true,
		Gateway:   "192.168.1.1",
		Interface: "eth0",
		Metric:    100,
		Protocol:  "static",
		Scope:     "global",
		Type:      "unicast",
		Table:     254,
	}
	sys := sysWithRoute(&fakeSysRoute{
		dest: "0.0.0.0/0", exists: true,
		gateway: "192.168.1.1", iface: "eth0", metric: 100,
		protocol: "static", scope: "global", rtype: "unicast", table: 254,
	})

	for _, res := range r.Validate(context.Background(), sys) {
		if res.Result != SUCCESS {
			t.Errorf("property %s: result = %s, want pass: %v", res.Property, res.ToOutcome(), res.Err)
		}
	}
}

func TestRouteValidateSkipsAttributesWhenMissing(t *testing.T) {
	r := &Route{
		id:      "192.0.2.0/24",
		Exists:  true,
		Gateway: "192.0.2.1",
		Metric:  50,
	}
	sys := sysWithRoute(&fakeSysRoute{dest: "192.0.2.0/24", exists: false})

	results := r.Validate(context.Background(), sys)
	if results[0].Result != FAIL {
		t.Fatalf("exists: result = %s, want fail", results[0].ToOutcome())
	}
	for _, res := range results[1:] {
		if !res.Skipped {
			t.Errorf("property %s: skipped = false, want true when exists fails", res.Property)
		}
	}
}

func TestRouteValidateFailsOnMismatch(t *testing.T) {
	r := &Route{
		id:      "0.0.0.0/0",
		Exists:  true,
		Gateway: "10.0.0.1",
	}
	sys := sysWithRoute(&fakeSysRoute{dest: "0.0.0.0/0", exists: true, gateway: "192.168.1.1"})

	results := r.Validate(context.Background(), sys)
	if results[0].Result != SUCCESS {
		t.Fatalf("exists: result = %s, want pass", results[0].ToOutcome())
	}
	if results[1].Result != FAIL {
		t.Errorf("gateway: result = %s, want fail", results[1].ToOutcome())
	}
}

func TestRouteValidateSystemErrorFails(t *testing.T) {
	r := &Route{id: "bogus", Exists: true}
	sys := sysWithRoute(&fakeSysRoute{dest: "bogus", err: errTestRoute})

	results := r.Validate(context.Background(), sys)
	if results[0].Result != FAIL || results[0].Err == nil {
		t.Errorf("exists: result = %s, want fail with error", results[0].ToOutcome())
	}
}

func TestRouteValidateFlexibleMatchers(t *testing.T) {
	r := &Route{
		id:       "0.0.0.0/0",
		Exists:   true,
		Metric:   map[string]any{"gt": 100},
		Protocol: map[string]any{"match-regexp": "^sta"},
		Gateway:  map[string]any{"not": "1.1.1.1"},
	}
	sys := sysWithRoute(&fakeSysRoute{
		dest: "0.0.0.0/0", exists: true,
		gateway: "10.202.142.246", metric: 300, protocol: "static",
	})

	for _, res := range r.Validate(context.Background(), sys) {
		if res.Result != SUCCESS {
			t.Errorf("property %s: result = %s, want pass: %v", res.Property, res.ToOutcome(), res.Err)
		}
	}
}

func TestNewRouteCapturesAttributes(t *testing.T) {
	r, err := NewRoute(&fakeSysRoute{
		dest: "127.0.0.0/8", exists: true,
		iface: "lo", protocol: "kernel", scope: "host", rtype: "local", table: 255,
	}, util.Config{})
	if err != nil {
		t.Fatalf("NewRoute returned error: %v", err)
	}
	if r.Exists != true {
		t.Errorf("Exists = %v, want true", r.Exists)
	}
	if r.Gateway != nil {
		t.Errorf("Gateway = %#v, want nil (empty gateway omitted)", r.Gateway)
	}
	if r.Metric != nil {
		t.Errorf("Metric = %#v, want nil (zero metric omitted)", r.Metric)
	}
	if r.Interface != "lo" {
		t.Errorf("Interface = %#v, want lo", r.Interface)
	}
	if r.Protocol != "kernel" {
		t.Errorf("Protocol = %#v, want kernel", r.Protocol)
	}
	if r.Scope != "host" {
		t.Errorf("Scope = %#v, want host", r.Scope)
	}
	if r.Type != "local" {
		t.Errorf("Type = %#v, want local", r.Type)
	}
	if r.Table != 255 {
		t.Errorf("Table = %#v, want 255", r.Table)
	}

	out, err := yaml.Marshal(r)
	if err != nil {
		t.Fatalf("yaml.Marshal returned error: %v", err)
	}
	for _, want := range []string{"lo", "kernel", "host", "local", "255"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("marshalled YAML missing %q:\n%s", want, out)
		}
	}
}

func TestNewRouteMissing(t *testing.T) {
	r, err := NewRoute(&fakeSysRoute{dest: "192.0.2.0/24", exists: false}, util.Config{})
	if err != nil {
		t.Fatalf("NewRoute returned error: %v", err)
	}
	if r.Exists != false {
		t.Errorf("Exists = %v, want false", r.Exists)
	}
	if r.Gateway != nil || r.Interface != nil || r.Metric != nil ||
		r.Protocol != nil || r.Scope != nil || r.Type != nil || r.Table != nil {
		t.Errorf("NewRoute on a missing route captured attributes: %#v", r)
	}
}

func TestRouteUnmarshalYAML(t *testing.T) {
	data := []byte(`
route:
  0.0.0.0/0:
    exists: true
    gateway: 192.168.1.1
    interface: eth0
    metric: 100
    protocol: static
    scope: global
    type: unicast
    table: 254
`)
	var c struct {
		Routes RouteMap `yaml:"route"`
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		t.Fatalf("yaml.Unmarshal returned error: %v", err)
	}
	m := c.Routes
	r, ok := m["0.0.0.0/0"]
	if !ok {
		t.Fatalf("route 0.0.0.0/0 not parsed, got: %#v", m)
	}
	if r.ID() != "0.0.0.0/0" {
		t.Errorf("ID() = %q, want 0.0.0.0/0", r.ID())
	}
	if r.Exists != true || r.Gateway != "192.168.1.1" || r.Interface != "eth0" ||
		r.Protocol != "static" || r.Scope != "global" || r.Type != "unicast" || r.Table != 254 {
		t.Errorf("unexpected parsed values: %#v", r)
	}
	if r.Metric == nil {
		t.Errorf("Metric not parsed")
	}
}

func TestRouteUnmarshalYAMLRejectsUnknownAttribute(t *testing.T) {
	data := []byte(`
route:
  0.0.0.0/0:
    exists: true
    bogus: 1
`)
	var c struct {
		Routes RouteMap `yaml:"route"`
	}
	if err := yaml.Unmarshal(data, &c); err == nil {
		t.Fatal("yaml.Unmarshal with an unknown attribute, want error")
	}
}

func TestRouteUnmarshalJSON(t *testing.T) {
	data := []byte(`{"0.0.0.0/0": {"exists": true, "gateway": "192.168.1.1"}}`)
	var m RouteMap
	if err := m.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON returned error: %v", err)
	}
	r := m["0.0.0.0/0"]
	if r == nil || r.Gateway != "192.168.1.1" {
		t.Errorf("unexpected parsed values: %#v", m)
	}
}

var errTestRoute = &testRouteError{}

type testRouteError struct{}

func (e *testRouteError) Error() string { return "route lookup failed" }
