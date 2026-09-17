//go:build !linux

package system

import (
	"context"

	"github.com/goss-org/goss/util"
)

type defRoute struct {
	dest string
}

func NewDefRoute(_ context.Context, dest string, _ *System, _ util.Config) Route {
	return &defRoute{dest: dest}
}

func (r *defRoute) Destination() string        { return r.dest }
func (r *defRoute) Exists() (bool, error)      { return false, ErrRouteUnsupported }
func (r *defRoute) Gateway() (string, error)   { return "", ErrRouteUnsupported }
func (r *defRoute) Interface() (string, error) { return "", ErrRouteUnsupported }
func (r *defRoute) Metric() (int, error)       { return 0, ErrRouteUnsupported }
func (r *defRoute) Protocol() (string, error)  { return "", ErrRouteUnsupported }
func (r *defRoute) Scope() (string, error)     { return "", ErrRouteUnsupported }
func (r *defRoute) Type() (string, error)      { return "", ErrRouteUnsupported }
func (r *defRoute) Table() (int, error)        { return 0, ErrRouteUnsupported }
