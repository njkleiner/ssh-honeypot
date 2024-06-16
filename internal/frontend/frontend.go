package frontend

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/config"
	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/control"
	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/fakeshell"
	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/log"
	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/sandbox"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type state struct {
	// password is the password used to authenticate.
	password string

	// since is the session start time.
	since time.Time

	// allowed indicates whether we have allocated
	// capacity for this connection.
	allowed bool

	// ref is the ID of the container acquired for this connection.
	ref sandbox.Ref

	// conn is the SSH client connection into the container.
	conn *gossh.Client
}

type Server struct {
	srv *ssh.Server

	cfg config.File

	dv *sandbox.Driver

	// guard limits the number of concurrent sessions.
	guard chan struct{}

	// quit is closed when the server is shut down.
	quit chan struct{}

	// mu protects access to state.
	mu sync.Mutex

	// state holds session metadata.
	state map[string]state
}

func NewServer(cfg config.File, dv *sandbox.Driver) *Server {
	s := &Server{
		srv: &ssh.Server{
			Addr: cfg.Frontend.ListenAddress,

			Version: "SSH-2.0-OpenSSH_9.0", // pretend that we are a real SSH server

			MaxTimeout: time.Duration(cfg.Frontend.MaxConnectionTime)*time.Minute + 5*time.Second,

			ConnectionFailedCallback: func(conn net.Conn, err error) {
				ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()

				log.Info(context.TODO(), "drop incoming connection",
					slog.String("ip", ip), slog.Any("error", err))
			},
		},

		cfg: cfg,

		dv: dv,

		guard: make(chan struct{}, cfg.Frontend.MaxActiveConnections),

		quit: make(chan struct{}),

		state: make(map[string]state),
	}

	s.srv.ConnCallback = func(ctx ssh.Context, conn net.Conn) net.Conn {
		s.mu.Lock()
		defer s.mu.Unlock()

		ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()

		if _, ok := s.state[ip]; ok {
			log.Info(ctx, "deny incoming connection", slog.String("ip", ip))

			return nil // deny any subsequent incoming connection from the same remote IP address
		}

		log.Info(ctx, "accept incoming connection", slog.String("ip", ip))

		s.state[ip] = state{
			since: time.Now(),
		}

		kill := make(chan struct{})

		go s.monitor(ctx, ip, kill)

		go s.track(ctx, conn, kill)

		return conn
	}

	s.srv.Handler = func(ss ssh.Session) {
		ip := ss.RemoteAddr().(*net.TCPAddr).IP.String()

		s.mu.Lock()
		st := s.state[ip]
		s.mu.Unlock()

		log.Info(ss.Context(), "connect",
			slog.String("command", ss.RawCommand()), slog.Any("env", ss.Environ()),
			slog.String("version", ss.Context().Value(ssh.ContextKeyClientVersion).(string)))

		err := s.handle(ss, st.conn) // block until the session has terminated

		if err != nil {
			log.Error(ss.Context(), "session terminated due to error", slog.Any("error", err))
		} else {
			log.Info(ss.Context(), "session terminated normally")
		}
	}

	s.srv.PublicKeyHandler = func(ctx ssh.Context, key ssh.PublicKey) bool {
		setSessionLogger(ctx)

		log.Info(ctx, "attempt public key", slog.String("key", gossh.FingerprintSHA256(key)))

		return false
	}

	s.srv.PasswordHandler = func(ctx ssh.Context, password string) bool {
		setSessionLogger(ctx)

		log.Info(ctx, "attempt password", slog.String("password", password))

		if password == "" {
			return false // disallow empty passwords
		}

		ip := ctx.RemoteAddr().(*net.TCPAddr).IP.String()

		s.mutate(ip, func(st state) state {
			st.password = password

			return st
		})

		select {
		case s.guard <- struct{}{}: // capacity available
			s.mutate(ip, func(st state) state {
				st.allowed = true

				return st
			})
		default:
			log.Info(ctx, "password attempt denied due to insufficient capacity available")

			return false // insufficient capacity (try again)
		}

		ref, err := s.dv.Acquire(ctx)

		if err != nil {
			log.Error(ctx, "cannot acquire container", slog.Any("error", err))

			return false // no container available
		}

		s.mutate(ip, func(st state) state {
			st.ref = ref

			return st
		})

		log.Info(ctx, "acquired container", slog.String("ref", string(ref)))

		cc := s.dv.ControlClient(ref)

		if err := cc.Ping(ctx); err != nil {
			log.Error(ctx, "cannot ping container",
				slog.Any("error", err))

			return false // SSH server did not start in time
		}

		auth := control.AuthInfo{
			User:     ctx.User(),
			Password: password,
		}

		if err := cc.Claim(ctx, auth); err != nil {
			log.Error(ctx, "cannot claim container",
				slog.Any("auth", auth),
				slog.Any("error", err))

			return false // could not set up local user account
		}

		log.Info(ctx, "claimed container",
			slog.Any("auth", auth),
			slog.String("ref", string(ref)))

		conn, err := s.dv.Connect(ctx, ref, ctx.User(), password)

		if err != nil {
			log.Error(ctx, "cannot connect into container",
				slog.Any("error", err))

			return false // cannot connect into container
		}

		s.mutate(ip, func(st state) state {
			st.conn = conn

			return st
		})

		go s.listen(ctx, cc) // listen to control events

		return true
	}

	return s
}

func setSessionLogger(ctx ssh.Context) {
	if ctx.Value(log.ContextKey{}) != nil {
		return
	}

	ip := ctx.RemoteAddr().(*net.TCPAddr).IP.String()

	group := slog.GroupValue(
		slog.String("id", ctx.SessionID()),
		slog.String("user", ctx.User()),
		slog.String("ip", ip),
	)

	ctx.SetValue(log.ContextKey{},
		slog.With(slog.Any("session", group)))
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	done := make(chan error, 1)

	go func() {
		defer close(done)
		done <- s.srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		close(s.quit) // disconnect attackers (via kill switch)

		log.Info(context.TODO(), "shutting down server")

		err := s.srv.Shutdown(context.Background())

		log.Info(context.TODO(), "finished shutting down server")

		return err
	case err := <-done:
		close(s.quit) // disconnect attackers (via kill switch)

		return err
	}
}

func (s *Server) mutate(ip string, fn func(state) state) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state[ip] = fn(s.state[ip])
}

func (s *Server) track(ctx ssh.Context, conn net.Conn, kill <-chan struct{}) {
	ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	select {
	case <-ctx.Done(): // session terminated due to disconnect
		log.Info(ctx, "connection terminated due to disconnect")
	case <-kill: // kill switch triggered
		_ = conn.Close() // forcefully close the connection (disconnect attacker)

		log.Info(ctx, "connection terminated due to kill switch")
	}

	s.mu.Lock()
	st := s.state[ip]
	delete(s.state, ip)
	s.mu.Unlock()

	if st.allowed {
		<-s.guard // free capacity
	}

	if st.conn != nil {
		err := st.conn.Close()

		if err != nil {
			log.Error(ctx, "cannot disconnect from container",
				slog.Any("error", err), slog.String("ref", string(st.ref)))
		}
	}

	if st.ref != "" {
		err := s.dv.Destroy(st.ref)

		if err != nil {
			log.Error(ctx, "cannot destroy container",
				slog.Any("error", err), slog.String("ref", string(st.ref)))
		}
	}
}

func (s *Server) monitor(ctx ssh.Context, ip string, kill chan struct{}) {
	defer close(kill)

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		now := time.Now()

		s.mu.Lock()
		st := s.state[ip]
		s.mu.Unlock()

		if now.Sub(st.since) >= time.Duration(s.cfg.Frontend.MaxConnectionTime)*time.Second {
			log.Info(ctx, "trigger kill switch due to session age")
			return // trigger kill switch
		}

		if st.ref != "" {
			usage, err := s.dv.Usage(ctx, st.ref)

			if err == nil {
				log.Info(ctx, "system usage", slog.Any("usage", usage))
			}

			switch {
			case s.cfg.Frontend.MaxCPU > 0 && usage.CPU > s.cfg.Frontend.MaxCPU:
				log.Info(ctx, "trigger kill switch due to CPU usage limit exceeded", slog.Any("usage", usage))
				return // trigger kill switch
			case s.cfg.Frontend.MaxMemory > 0 && usage.Memory > s.cfg.Frontend.MaxMemory:
				log.Info(ctx, "trigger kill switch due to memory usage limit exceeded", slog.Any("usage", usage))
				return // trigger kill switch
			case s.cfg.Frontend.MaxBytesSent > 0 && usage.BytesSent > s.cfg.Frontend.MaxBytesSent:
				log.Info(ctx, "trigger kill switch due to network bytes sent limit exceeded", slog.Any("usage", usage))
				return // trigger kill switch
			case s.cfg.Frontend.MaxBytesReceived > 0 && usage.BytesReceived > s.cfg.Frontend.MaxBytesReceived:
				log.Info(ctx, "trigger kill switch due to network bytes received limit exceeded", slog.Any("usage", usage))
				return // trigger kill switch
			case s.cfg.Frontend.MaxPacketsSent > 0 && usage.PacketsSent > s.cfg.Frontend.MaxPacketsSent:
				log.Info(ctx, "trigger kill switch due to network packets sent limit exceeded", slog.Any("usage", usage))
				return // trigger kill switch
			case s.cfg.Frontend.MaxPacketsReceived > 0 && usage.PacketsReceived > s.cfg.Frontend.MaxPacketsReceived:
				log.Info(ctx, "trigger kill switch due to network packets received limit exceeded", slog.Any("usage", usage))
				return // trigger kill switch
			}
		}

		tick.Reset(5 * time.Second)

		select {
		case <-tick.C:
			continue
		case <-ctx.Done():
			return
		case <-s.quit:
			log.Info(ctx, "trigger kill switch due to server shutdown")

			return
		}
	}
}

func (s *Server) listen(ctx context.Context, cc *control.Client) {
	ch := make(chan control.Event)

	done := make(chan error, 1)

	go func() {
		done <- cc.Subscribe(ctx, ch)
	}()

	for evt := range ch {
		log.Info(ctx, "received control event", slog.Any("event", evt))
	}

	if err := <-done; err != nil {
		log.Error(ctx, "cannot listen to control events", slog.Any("error", err))
	}
}

func (s *Server) handle(ss ssh.Session, conn *gossh.Client) error {
	if cmd := ss.RawCommand(); cmd != "" {
		log.Info(ss.Context(), "handle oneshot session",
			slog.String("command", cmd))

		return s.oneshot(ss, conn)
	}

	log.Info(ss.Context(), "handle interactive session")

	return s.interactive(ss, conn)
}

func (s *Server) oneshot(ss ssh.Session, conn *gossh.Client) error {
	cs, err := conn.NewSession()

	if err != nil {
		return err
	}

	defer cs.Close()

	if pty, wins, isPty := ss.Pty(); isPty {
		err := cs.RequestPty(pty.Term, pty.Window.Height, pty.Window.Width, gossh.TerminalModes{})

		if err != nil {
			return fmt.Errorf("cannot request pty: %w", err)
		}

		go func() {
			for size := range wins {
				_ = cs.WindowChange(size.Height, size.Width)
			}
		}()
	}

	cs.Stdout = ss
	cs.Stderr = ss.Stderr()

	cs.Stdin = ss

	if err := cs.Run(ss.RawCommand()); err != nil {
		return err
	}

	return nil

}

type connSessionExecutor struct {
	conn *gossh.Client
}

var _ fakeshell.SessionExecutor = (*connSessionExecutor)(nil)

func (cse *connSessionExecutor) ExecuteSession(ctx context.Context, fn fakeshell.SessionFunc) error {
	cs, err := cse.conn.NewSession()

	if err != nil {
		return err
	}

	defer cs.Close()

	if err := fn(cs); err != nil {
		return err
	}

	return nil
}

func (s *Server) interactive(ss ssh.Session, conn *gossh.Client) error {
	term := fakeshell.NewTerm(ss, &connSessionExecutor{conn: conn})

	if err := term.Wait(ss.Context()); err != nil {
		return err
	}

	return nil
}
