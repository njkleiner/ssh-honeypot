package sandbox

import (
	"context"

	"github.com/njkleiner/ssh-honeypot/internal/control"
	gossh "golang.org/x/crypto/ssh"
)

type Backend interface {
	Acquire(ctx context.Context) (Ref, error)
	Usage(ctx context.Context, ref Ref) (SystemUsage, error)
	Destroy(ref Ref) error

	Connect(ctx context.Context, ref Ref, user, password string) (*gossh.Client, error)
	ControlClient(ref Ref) *control.Client
}
