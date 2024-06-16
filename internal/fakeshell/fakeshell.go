package fakeshell

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/log"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Term struct {
	session ssh.Session

	stdin *unreader

	executor SessionExecutor

	tty *term.Terminal

	win chan ssh.Window

	mu sync.Mutex

	input bool

	size ssh.Window
}

func NewTerm(ss ssh.Session, executor SessionExecutor) *Term {
	return &Term{
		session: ss,
		stdin:   &unreader{from: ss},

		executor: executor,

		win: make(chan ssh.Window),
	}
}

func (t *Term) Wait(ctx context.Context) error {
	if _, wins, isPty := t.session.Pty(); isPty {
		go t.resize(wins)
	}

	quit := make(chan error)

	go func() {
		quit <- t.run(ctx) // process incoming commands
	}()

	return <-quit
}

func (t *Term) resize(ch <-chan ssh.Window) {
	for size := range ch {
		t.mu.Lock()
		input := t.input
		t.size = size
		t.mu.Unlock()

		if input {
			// An error can only happen here when the session is over,
			// so we just ignore the error since we're exiting anyway.
			_ = t.tty.SetSize(size.Width, size.Height)
		} else {
			// When not in user input mode, i.e. when we're currently executing an
			// interactive session, we forward the size update to that session.
			t.win <- size
		}
	}
}

func (t *Term) run(ctx context.Context) error {
	t.tty = term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{t.stdin, t.session}, "localhost $ ")

	for {
		line, err := t.tty.ReadLine()

		if err != nil {
			return err
		}

		if line == "" {
			continue
		}

		log.Info(ctx, "handle command", slog.String("command", line))

		exit := strings.Contains(line, "exit")

		if err := t.handle(ctx, line); err != nil {
			log.Error(ctx, "cannot handle command", slog.String("command", line), slog.Any("error", err))
		}

		if exit {
			return nil
		}
	}
}

func (t *Term) handle(ctx context.Context, line string) error {
	t.mu.Lock()
	t.input = false
	size := t.size
	t.mu.Unlock()

	err := t.executor.ExecuteSession(ctx, func(cs *gossh.Session) error {
		cs.Stdout = t.session
		cs.Stderr = t.session.Stderr()

		if pty, _, isPty := t.session.Pty(); isPty {
			// Note that ordinary signals (e.g., CTRL+C input from attacker) are automatically forwarded
			// (via stdin, I guess) once we've successfully requested a downstream PTY.

			err := cs.RequestPty(pty.Term, size.Height, size.Width, gossh.TerminalModes{})

			if err != nil {
				return fmt.Errorf("cannot request pty: %w", err)
			}
		}

		stdin, err := cs.StdinPipe()

		if err != nil {
			return fmt.Errorf("cannot create stdin pipe: %w", err)
		}

		go func() {
			t.stdin.lock()
			defer t.stdin.unlock()

			buf := make([]byte, 1024) // allocate once and reuse

			for {
				n, err := t.session.Read(buf)

				if err != nil {
					// If we can no longer read from the server session stdin,
					// the upstream session is over anyway, so we just return.
					return
				}

				m, err := stdin.Write(buf[:n])

				if err != nil {
					// This is the more interesting case that requires special handling.
					//
					// At some point, when the client session is done, writing will fail
					// here, which makes absolute sense if you think about it.
					//
					// The problem is that we always need to read into some buffer if we
					// want to copy data from a reader to a writer.
					//
					// This means that when the write call returns an error, we have
					// already and irrevocably read some bytes from the reader.
					//
					// But, and this is important, when we continue reading user input
					// via the emulated TTY, we want those bytes to be the first thing
					// that the emulated TTY reads, since these bytes may plausibly be
					// part of the next user input line (i.e. command to execute).
					//
					// This means that the emulated TTY needs to be able to either read
					// from these buffered bytes, if there are any, or from the server
					// session stdin, which is the regular case for subsequent reads.
					//
					// This is the entire reason why we implemented the [unreader] type.
					t.stdin.unread(buf[m:n])

					return
				}
			}
		}()

		stop := make(chan struct{})
		defer close(stop)

		go func() {
			for {
				select {
				case size := <-t.win:
					_ = cs.WindowChange(size.Height, size.Width)
				case <-stop:
					return
				}
			}
		}()

		if err := cs.Run(line); err != nil {
			return err
		}

		return nil
	})

	t.mu.Lock()
	t.wake() // reset state
	t.mu.Unlock()

	if err != nil {
		return err
	}

	return nil
}

func (t *Term) wake() {
	t.input = true

	select {
	case <-t.win:
		// Note that there may have been a single size update that has been read
		// in t.resize when the term was still in non-input mode,
		// meaning that t.resize is currently blocked due to attempting to send
		// that size update to t.win, but since the client session is over,
		// there is no longer a forwarding goroutine that receives from t.win.
		//
		// Thus, we unblock the t.resize goroutine by reading from t.win here.
		//
		// Note that t.size has already been set by t.resize.
	default:
		// no "buffered" size update
	}

	// Update the current window size of t.tty to the most recent
	// window size update received from the server session.
	_ = t.tty.SetSize(t.size.Width, t.size.Height)
}
