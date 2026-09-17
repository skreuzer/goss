package resource

import (
	"context"
	"strings"
	"testing"

	"github.com/goss-org/goss/system"
	"github.com/goss-org/goss/util"
	"gopkg.in/yaml.v3"
)

// fakeSysIGMP is a minimal system.IGMP implementation used to drive the IGMP
// resource without touching /proc/net/igmp.
type fakeSysIGMP struct {
	group   string
	exists  bool
	err     error
	iface   string
	version int
	users   int
}

func (f *fakeSysIGMP) Group() string              { return f.group }
func (f *fakeSysIGMP) Exists() (bool, error)      { return f.exists, f.err }
func (f *fakeSysIGMP) Interface() (string, error) { return f.iface, nil }
func (f *fakeSysIGMP) Version() (int, error)      { return f.version, nil }
func (f *fakeSysIGMP) Users() (int, error)        { return f.users, nil }

func sysWithIGMP(r *fakeSysIGMP) *system.System {
	return &system.System{
		NewIGMP: func(context.Context, string, *system.System, util.Config) system.IGMP {
			return r
		},
	}
}

func TestIGMPValidateAllPass(t *testing.T) {
	r := &IGMP{
		id:        "224.0.0.251",
		Exists:    true,
		Interface: "wlan0",
		Version:   3,
		Users:     2,
	}
	sys := sysWithIGMP(&fakeSysIGMP{
		group: "224.0.0.251", exists: true,
		iface: "wlan0", version: 3, users: 2,
	})

	for _, res := range r.Validate(context.Background(), sys) {
		if res.Result != SUCCESS {
			t.Errorf("property %s: result = %s, want pass: %v", res.Property, res.ToOutcome(), res.Err)
		}
	}
}

func TestIGMPValidateSkipsAttributesWhenMissing(t *testing.T) {
	r := &IGMP{
		id:        "239.1.2.3",
		Exists:    true,
		Interface: "eth0",
		Version:   3,
	}
	sys := sysWithIGMP(&fakeSysIGMP{group: "239.1.2.3", exists: false})

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

func TestIGMPValidateFailsOnMismatch(t *testing.T) {
	r := &IGMP{
		id:      "224.0.0.1",
		Exists:  true,
		Version: 1,
	}
	sys := sysWithIGMP(&fakeSysIGMP{group: "224.0.0.1", exists: true, version: 3})

	results := r.Validate(context.Background(), sys)
	if results[0].Result != SUCCESS {
		t.Fatalf("exists: result = %s, want pass", results[0].ToOutcome())
	}
	if results[1].Result != FAIL {
		t.Errorf("version: result = %s, want fail", results[1].ToOutcome())
	}
}

func TestIGMPValidateSystemErrorFails(t *testing.T) {
	r := &IGMP{id: "bogus", Exists: true}
	sys := sysWithIGMP(&fakeSysIGMP{group: "bogus", err: errTestIGMP})

	results := r.Validate(context.Background(), sys)
	if results[0].Result != FAIL || results[0].Err == nil {
		t.Errorf("exists: result = %s, want fail with error", results[0].ToOutcome())
	}
}

func TestIGMPValidateFlexibleMatchers(t *testing.T) {
	r := &IGMP{
		id:      "224.0.0.251",
		Exists:  true,
		Users:   map[string]any{"gt": 0},
		Version: map[string]any{"not": 1},
	}
	sys := sysWithIGMP(&fakeSysIGMP{
		group: "224.0.0.251", exists: true,
		version: 3, users: 5,
	})

	for _, res := range r.Validate(context.Background(), sys) {
		if res.Result != SUCCESS {
			t.Errorf("property %s: result = %s, want pass: %v", res.Property, res.ToOutcome(), res.Err)
		}
	}
}

func TestNewIGMPCapturesAttributes(t *testing.T) {
	r, err := NewIGMP(&fakeSysIGMP{
		group: "224.0.0.251", exists: true,
		iface: "eth0", version: 3, users: 1,
	}, util.Config{})
	if err != nil {
		t.Fatalf("NewIGMP returned error: %v", err)
	}
	if r.Exists != true {
		t.Errorf("Exists = %v, want true", r.Exists)
	}
	if r.Interface != "eth0" {
		t.Errorf("Interface = %#v, want eth0", r.Interface)
	}
	if r.Version != 3 {
		t.Errorf("Version = %#v, want 3", r.Version)
	}
	if r.Users != 1 {
		t.Errorf("Users = %#v, want 1", r.Users)
	}

	out, err := yaml.Marshal(r)
	if err != nil {
		t.Fatalf("yaml.Marshal returned error: %v", err)
	}
	for _, want := range []string{"eth0", "3", "1"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("marshalled YAML missing %q:\n%s", want, out)
		}
	}
}

func TestNewIGMPMissing(t *testing.T) {
	r, err := NewIGMP(&fakeSysIGMP{group: "239.1.2.3", exists: false}, util.Config{})
	if err != nil {
		t.Fatalf("NewIGMP returned error: %v", err)
	}
	if r.Exists != false {
		t.Errorf("Exists = %v, want false", r.Exists)
	}
	if r.Interface != nil || r.Version != nil || r.Users != nil {
		t.Errorf("NewIGMP on a missing group captured attributes: %#v", r)
	}
}

func TestIGMPUnmarshalYAML(t *testing.T) {
	data := []byte(`
igmp:
  "224.0.0.251":
    exists: true
    interface: wlan0
    version: 3
    users: 1
`)
	var c struct {
		IGMPs IGMPMap `yaml:"igmp"`
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		t.Fatalf("yaml.Unmarshal returned error: %v", err)
	}
	r, ok := c.IGMPs["224.0.0.251"]
	if !ok {
		t.Fatalf("igmp group 224.0.0.251 not parsed, got: %#v", c.IGMPs)
	}
	if r.ID() != "224.0.0.251" {
		t.Errorf("ID() = %q, want 224.0.0.251", r.ID())
	}
	if r.Exists != true || r.Interface != "wlan0" || r.Version != 3 || r.Users != 1 {
		t.Errorf("unexpected parsed values: %#v", r)
	}
}

func TestIGMPUnmarshalYAMLRejectsUnknownAttribute(t *testing.T) {
	data := []byte(`
igmp:
  "224.0.0.1":
    exists: true
    interface: eth0
    bogus: 1
`)
	var c struct {
		IGMPs IGMPMap `yaml:"igmp"`
	}
	if err := yaml.Unmarshal(data, &c); err == nil {
		t.Fatal("yaml.Unmarshal with an unknown attribute, want error")
	}
}

func TestIGMPUnmarshalJSON(t *testing.T) {
	data := []byte(`{"224.0.0.1": {"exists": true, "interface": "eth0", "users": 2}}`)
	var m IGMPMap
	if err := m.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON returned error: %v", err)
	}
	r := m["224.0.0.1"]
	if r == nil || r.Interface != "eth0" {
		t.Errorf("unexpected parsed values: %#v", m)
	}
}

var errTestIGMP = &testIGMPError{}

type testIGMPError struct{}

func (e *testIGMPError) Error() string { return "igmp lookup failed" }
