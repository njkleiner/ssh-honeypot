package sandbox

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/config"
	"github.com/docker/docker/client"
)

// TestSession tests that the entire container lifecycle is working as intended,
// i.e. that [Driver.Acquire], [Driver.WithSession] and [Driver.Destroy] work.
func TestSession(t *testing.T) {
	if v := os.Getenv("CI_SKIP_TEST"); strings.Contains(v, "docker") {
		t.Skipf("skipping test: CI_SKIP_TEST=%q", v)
	}

	// The [Driver] does internal logging, so make sure the default logger is set.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug, // makes sense during testing
	})))

	dc, err := client.NewClientWithOpts(client.FromEnv)

	if err != nil {
		t.Fatalf("cannot connect to Docker daemon: %v", err)
	}

	var cfg config.File

	cfg.SetDefaults()

	dv := NewDriver(cfg, dc)

	// We want to always call [Driver.Close] at the end of the test,
	// to clean up (remove) all running containers, regardless of
	// whether the test succeeds or fails early.
	t.Cleanup(dv.Close)

	// Note that [Driver.Acquire] uses a timeout for how long
	// acquiring may take at most, which is convenient here.
	//
	// If [Driver.Acquire] times out, we fail the test.
	ref, err := dv.Acquire(context.Background())

	if err != nil {
		t.Fatalf("cannot acquire container: %v", err)
	}

	cc := dv.ControlClient(ref)

	if err := cc.Ping(context.Background()); err != nil {
		t.Fatalf("cannot ping container: %v", err)
	}

	conn, err := dv.Connect(context.Background(), ref, "root", "root")

	if err != nil {
		t.Fatalf("cannot connect into container: %v", err)
	}

	defer conn.Close()

	cs, err := conn.NewSession()

	if err != nil {
		t.Fatalf("cannot start session: %v", err)
	}

	defer cs.Close()

	var buf bytes.Buffer

	cs.Stdout = &buf

	if err := cs.Run("echo -n 'Hello World'"); err != nil {
		t.Errorf("cannot execute session (ref=%s): %v", ref, err)
	}

	if got, want := buf.String(), "Hello World"; got != want {
		t.Errorf("invalid command output: got=%q; want=%q", got, want)
	}

	if err := dv.Destroy(ref); err != nil {
		t.Errorf("cannot destroy container (ref=%s): %v", ref, err)
	}
}
