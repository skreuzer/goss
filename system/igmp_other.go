//go:build !linux

package system

import (
	"context"

	"github.com/goss-org/goss/util"
)

type defIGMP struct {
	key string
}

func NewDefIGMP(_ context.Context, key string, _ *System, _ util.Config) IGMP {
	return &defIGMP{key: key}
}

func (r *defIGMP) Group() string              { return r.key }
func (r *defIGMP) Exists() (bool, error)      { return false, ErrIGMPUnsupported }
func (r *defIGMP) Interface() (string, error) { return "", ErrIGMPUnsupported }
func (r *defIGMP) Version() (int, error)      { return 0, ErrIGMPUnsupported }
func (r *defIGMP) Users() (int, error)        { return 0, ErrIGMPUnsupported }
