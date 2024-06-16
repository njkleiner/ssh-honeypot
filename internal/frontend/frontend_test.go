package frontend

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/config"
	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/sandbox"
	"github.com/docker/docker/client"
	gossh "golang.org/x/crypto/ssh"
)

func TestRemoteConnectionLimit(t *testing.T) {
	if v := os.Getenv("CI_SKIP_TEST"); strings.Contains(v, "docker") {
		t.Skipf("skipping test: CI_SKIP_TEST=%q", v)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug, // makes sense during testing
	})))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cfg config.File

	cfg.SetDefaults()

	// Note that we have to configure the server to allow more than one connection
	// at the same time to make sure that a second connection from the same remote
	// IP address is not denied due to insufficient capacity.
	cfg.Frontend.MaxActiveConnections = 2 // arbitrary number > 1

	dc, err := client.NewClientWithOpts(client.FromEnv)

	if err != nil {
		t.Fatal(err)
	}

	dv := sandbox.NewDriver(cfg, dc)

	t.Cleanup(dv.Close)

	srv := NewServer(cfg, dv)

	fatal := make(chan error, 1)

	go func() {
		fatal <- srv.ListenAndServe(ctx)
	}()

	// Note that we need to wait some time to allow the server to actually start before we can connect to it,
	// otherwise the test will fail because any connection attempt will result in an immediate error.
	time.Sleep(3 * time.Second)

	select {
	case err := <-fatal:
		t.Fatal(err) // propagate fatal error
	default:
		// proceed
	}

	conn1, err := gossh.Dial("tcp", "127.0.0.1:2022", &gossh.ClientConfig{
		User: "root",
		Auth: []gossh.AuthMethod{gossh.Password("secret")},

		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})

	if err != nil {
		t.Fatalf("cannot connect: err=%v", err)
	}

	defer conn1.Close()

	s1, err := conn1.NewSession()

	if err != nil {
		t.Fatalf("cannot start first session: err=%v", err)
	}

	defer s1.Close()

	// done is used to detect when the first session has finished.
	done := make(chan error, 1)

	// ready is used to detect when the first session has been established.
	ready := make(chan struct{})

	go func() {
		// TEST INVARIANT: we assume that the "top" command
		// is available within the guest container.

		err := s1.Start("top")

		time.Sleep(3 * time.Second)

		close(ready)

		if err != nil {
			done <- err

			return
		}

		done <- s1.Wait() // block until the end of the test
	}()

	select {
	case err := <-done:
		t.Fatalf("cannot start first session command: err=%v", err)
	case <-ready:
		// wait for the first session to be established
	}

	conn2, err := gossh.Dial("tcp", "127.0.0.1:2022", &gossh.ClientConfig{
		User: "ubuntu",
		Auth: []gossh.AuthMethod{gossh.Password("ubuntu")},

		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})

	if err == nil {
		t.Errorf("should not be able to open the second connection")

		_ = conn2.Close()
	}

	cancel() // stop server

	if err := <-fatal; err != nil {
		t.Fatal(err) // propagate fatal error
	}
}

func TestActiveConnectionLimit(t *testing.T) {
	if v := os.Getenv("CI_SKIP_TEST"); strings.Contains(v, "docker") {
		t.Skipf("skipping test: CI_SKIP_TEST=%q", v)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug, // makes sense during testing
	})))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cfg config.File

	cfg.SetDefaults()

	cfg.Frontend.MaxActiveConnections = 0

	dc, err := client.NewClientWithOpts(client.FromEnv)

	if err != nil {
		t.Fatal(err)
	}

	dv := sandbox.NewDriver(cfg, dc)

	t.Cleanup(dv.Close)

	srv := NewServer(cfg, dv)

	fatal := make(chan error, 1)

	go func() {
		fatal <- srv.ListenAndServe(ctx)
	}()

	// Note that we need to wait some time to allow the server to actually start before we can connect to it,
	// otherwise the test will fail because any connection attempt will result in an immediate error.
	time.Sleep(3 * time.Second)

	select {
	case err := <-fatal:
		t.Fatal(err) // propagate fatal error
	default:
		// proceed
	}

	conn, err := gossh.Dial("tcp", "127.0.0.1:2022", &gossh.ClientConfig{
		User: "root",
		Auth: []gossh.AuthMethod{gossh.Password("secret")},

		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})

	if err == nil {
		t.Errorf("should not be able to connect")

		_ = conn.Close()
	}

	if err != nil && !strings.Contains(err.Error(), "unable to authenticate") {
		t.Errorf("should reject password authentification attempt: err=%v", err)
	}

	cancel() // stop server

	if err := <-fatal; err != nil {
		t.Fatal(err) // propagate fatal error
	}
}

func TestKillSwitchMaxConnectionTime(t *testing.T) {
	if v := os.Getenv("CI_SKIP_TEST"); strings.Contains(v, "docker") {
		t.Skipf("skipping test: CI_SKIP_TEST=%q", v)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug, // makes sense during testing
	})))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cfg config.File

	cfg.SetDefaults()

	cfg.Frontend.MaxActiveConnections = 1 // arbitrary number > 0

	cfg.Frontend.MaxConnectionTime = 5 // in seconds

	dc, err := client.NewClientWithOpts(client.FromEnv)

	if err != nil {
		t.Fatal(err)
	}

	dv := sandbox.NewDriver(cfg, dc)

	t.Cleanup(dv.Close)

	srv := NewServer(cfg, dv)

	fatal := make(chan error, 1)

	go func() {
		fatal <- srv.ListenAndServe(ctx)
	}()

	// Note that we need to wait some time to allow the server to actually start before we can connect to it,
	// otherwise the test will fail because any connection attempt will result in an immediate error.
	time.Sleep(3 * time.Second)

	select {
	case err := <-fatal:
		t.Fatal(err) // propagate fatal error
	default:
		// proceed
	}

	conn, err := gossh.Dial("tcp", "127.0.0.1:2022", &gossh.ClientConfig{
		User: "root",
		Auth: []gossh.AuthMethod{gossh.Password("secret")},

		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})

	if err != nil {
		t.Fatalf("should be able to connect: err=%v", err)
	}

	defer conn.Close()

	cs, err := conn.NewSession()

	if err != nil {
		t.Fatalf("should be able to start session: err=%v", err)
	}

	defer cs.Close()

	start := time.Now()

	// TEST INVARIANT: we assume that the "sleep" command
	// is available within the guest container.

	if err := cs.Run("sleep 30"); err == nil {
		t.Errorf("command should exit with error")
	}

	took := time.Since(start)

	if took < 3*time.Second {
		t.Errorf("should not have triggered kill switch yet: took=%dms", took.Milliseconds())
	}

	if took >= 15*time.Second {
		t.Errorf("should already have triggered kill switch: took=%dms", took.Milliseconds())
	}

	cancel() // stop server

	if err := <-fatal; err != nil {
		t.Fatal(err) // propagate fatal error
	}
}
