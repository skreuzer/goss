package resource

import (
	"context"

	"github.com/goss-org/goss/system"
	"github.com/goss-org/goss/util"
)

type IGMP struct {
	Title     string  `json:"title,omitempty" yaml:"title,omitempty"`
	Meta      meta    `json:"meta,omitempty" yaml:"meta,omitempty"`
	id        string  `json:"-" yaml:"-"`
	Exists    matcher `json:"exists" yaml:"exists"`
	Interface matcher `json:"interface,omitempty" yaml:"interface,omitempty"`
	Version   matcher `json:"version,omitempty" yaml:"version,omitempty"`
	Users     matcher `json:"users,omitempty" yaml:"users,omitempty"`
	Skip      bool    `json:"skip,omitempty" yaml:"skip,omitempty"`
}

const (
	IGMPResourceKey  = "igmp"
	IGMPResourceName = "IGMP"
)

func init() {
	registerResource(IGMPResourceKey, &IGMP{})
}

func (r *IGMP) ID() string       { return r.id }
func (r *IGMP) SetID(id string)  { r.id = id }
func (r *IGMP) SetSkip()         { r.Skip = true }
func (r *IGMP) TypeKey() string  { return IGMPResourceKey }
func (r *IGMP) TypeName() string { return IGMPResourceName }

func (r *IGMP) GetTitle() string { return r.Title }
func (r *IGMP) GetMeta() meta    { return r.Meta }
func (r *IGMP) GetName() string  { return r.id }

func (r *IGMP) Validate(ctx context.Context, sys *system.System) []TestResult {
	ctx = context.WithValue(ctx, idKey{}, r.ID())
	skip := r.Skip
	sysIGMP := sys.NewIGMP(ctx, r.ID(), sys, util.Config{})

	var results []TestResult
	results = append(results, ValidateValue(r, "exists", r.Exists, sysIGMP.Exists, skip))
	if shouldSkip(results) {
		skip = true
	}
	if r.Interface != nil {
		results = append(results, ValidateValue(r, "interface", r.Interface, sysIGMP.Interface, skip))
	}
	if r.Version != nil {
		results = append(results, ValidateValue(r, "version", r.Version, sysIGMP.Version, skip))
	}
	if r.Users != nil {
		results = append(results, ValidateValue(r, "users", r.Users, sysIGMP.Users, skip))
	}
	return results
}

func NewIGMP(sysIGMP system.IGMP, config util.Config) (*IGMP, error) {
	group := sysIGMP.Group()
	exists, err := sysIGMP.Exists()
	if err != nil {
		return nil, err
	}
	r := &IGMP{
		id:     group,
		Exists: exists,
	}
	if !exists {
		return r, nil
	}
	if !contains(config.IgnoreList, "interface") {
		if name, err := sysIGMP.Interface(); err == nil && name != "" {
			r.Interface = name
		}
	}
	if !contains(config.IgnoreList, "version") {
		if v, err := sysIGMP.Version(); err == nil && v > 0 {
			r.Version = v
		}
	}
	if !contains(config.IgnoreList, "users") {
		if u, err := sysIGMP.Users(); err == nil && u > 0 {
			r.Users = u
		}
	}
	return r, nil
}
