package fakeshell

import (
	"context"

	gossh "golang.org/x/crypto/ssh"
)

type SessionFunc func(*gossh.Session) error

type SessionExecutor interface {
	ExecuteSession(ctx context.Context, fn SessionFunc) error
}
