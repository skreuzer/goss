package resource

import (
	"context"

	"github.com/goss-org/goss/system"
	"github.com/goss-org/goss/util"
)

type Route struct {
	Title     string  `json:"title,omitempty" yaml:"title,omitempty"`
	Meta      meta    `json:"meta,omitempty" yaml:"meta,omitempty"`
	id        string  `json:"-" yaml:"-"`
	Exists    matcher `json:"exists" yaml:"exists"`
	Gateway   matcher `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	Interface matcher `json:"interface,omitempty" yaml:"interface,omitempty"`
	Metric    matcher `json:"metric,omitempty" yaml:"metric,omitempty"`
	Protocol  matcher `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Scope     matcher `json:"scope,omitempty" yaml:"scope,omitempty"`
	Type      matcher `json:"type,omitempty" yaml:"type,omitempty"`
	Table     matcher `json:"table,omitempty" yaml:"table,omitempty"`
	Skip      bool    `json:"skip,omitempty" yaml:"skip,omitempty"`
}

const (
	RouteResourceKey  = "route"
	RouteResourceName = "Route"
)

func init() {
	registerResource(RouteResourceKey, &Route{})
}

func (r *Route) ID() string       { return r.id }
func (r *Route) SetID(id string)  { r.id = id }
func (r *Route) SetSkip()         { r.Skip = true }
func (r *Route) TypeKey() string  { return RouteResourceKey }
func (r *Route) TypeName() string { return RouteResourceName }

func (r *Route) GetTitle() string { return r.Title }
func (r *Route) GetMeta() meta    { return r.Meta }
func (r *Route) GetName() string  { return r.id }

func (r *Route) Validate(ctx context.Context, sys *system.System) []TestResult {
	ctx = context.WithValue(ctx, idKey{}, r.ID())
	skip := r.Skip
	sysRoute := sys.NewRoute(ctx, r.ID(), sys, util.Config{})

	var results []TestResult
	results = append(results, ValidateValue(r, "exists", r.Exists, sysRoute.Exists, skip))
	if shouldSkip(results) {
		skip = true
	}
	if r.Gateway != nil {
		results = append(results, ValidateValue(r, "gateway", r.Gateway, sysRoute.Gateway, skip))
	}
	if r.Interface != nil {
		results = append(results, ValidateValue(r, "interface", r.Interface, sysRoute.Interface, skip))
	}
	if r.Metric != nil {
		results = append(results, ValidateValue(r, "metric", r.Metric, sysRoute.Metric, skip))
	}
	if r.Protocol != nil {
		results = append(results, ValidateValue(r, "protocol", r.Protocol, sysRoute.Protocol, skip))
	}
	if r.Scope != nil {
		results = append(results, ValidateValue(r, "scope", r.Scope, sysRoute.Scope, skip))
	}
	if r.Type != nil {
		results = append(results, ValidateValue(r, "type", r.Type, sysRoute.Type, skip))
	}
	if r.Table != nil {
		results = append(results, ValidateValue(r, "table", r.Table, sysRoute.Table, skip))
	}
	return results
}

func NewRoute(sysRoute system.Route, config util.Config) (*Route, error) {
	dest := sysRoute.Destination()
	exists, err := sysRoute.Exists()
	if err != nil {
		return nil, err
	}
	r := &Route{
		id:     dest,
		Exists: exists,
	}
	if !exists {
		return r, nil
	}
	if !contains(config.IgnoreList, "gateway") {
		if gw, err := sysRoute.Gateway(); err == nil && gw != "" {
			r.Gateway = gw
		}
	}
	if !contains(config.IgnoreList, "interface") {
		if name, err := sysRoute.Interface(); err == nil && name != "" {
			r.Interface = name
		}
	}
	if !contains(config.IgnoreList, "metric") {
		if m, err := sysRoute.Metric(); err == nil && m > 0 {
			r.Metric = m
		}
	}
	if !contains(config.IgnoreList, "protocol") {
		if p, err := sysRoute.Protocol(); err == nil && p != "" && p != "unspec" {
			r.Protocol = p
		}
	}
	if !contains(config.IgnoreList, "scope") {
		if s, err := sysRoute.Scope(); err == nil && s != "" && s != "global" {
			r.Scope = s
		}
	}
	if !contains(config.IgnoreList, "type") {
		if t, err := sysRoute.Type(); err == nil && t != "" && t != "unicast" {
			r.Type = t
		}
	}
	if !contains(config.IgnoreList, "table") {
		// 254 is RT_TABLE_MAIN, the default table
		if tb, err := sysRoute.Table(); err == nil && tb != 254 {
			r.Table = tb
		}
	}
	return r, nil
}
