package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/flow"
	"github.com/gorilla/websocket"
)

var upgrader = &websocket.Upgrader{}

type Server struct {
	// mu protects access to the fields below.
	mu sync.Mutex

	// subs is the list of active subscribers.
	subs []*websocket.Conn
}

func NewServer() *Server {
	return &Server{}
}

// Submit dispatches evt to all active subscribers.
//
// Submit also removes any subscriber and closes the underlying connection
// the first time dispatching an event to that subscriber fails.
func (s *Server) Submit(evt Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	drop := make([]int, 0, len(s.subs))

	for idx, conn := range s.subs {
		err := conn.WriteJSON(evt)

		if err != nil {
			drop = append(drop, idx)
		}
	}

	for _, idx := range drop {
		conn := s.subs[idx]

		_ = conn.Close()

		s.subs[idx] = s.subs[len(s.subs)-1]
		s.subs = s.subs[:len(s.subs)-1]
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := flow.New()

	mux.HandleFunc("/ping", s.ping)
	mux.HandleFunc("/claim", s.claim)
	mux.HandleFunc("/subscribe", s.subscribe)

	srv := &http.Server{
		Addr: ":2023",

		Handler: mux,
	}

	quit := make(chan error, 1)

	go func() {
		quit <- srv.ListenAndServe()
	}()

	select {
	case err := <-quit:
		return err
	case <-ctx.Done():
		s.mu.Lock()
		defer s.mu.Unlock()

		for _, conn := range s.subs {
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""), time.Time{})
			_ = conn.Close()
		}

		s.subs = s.subs[:0]

		return srv.Shutdown(context.Background())
	}
}

func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	// Attempt to establish a TCP connection to the local port
	// where the SSH server listens inside the container.
	//
	// Note that we do not care about any SSH protocol details
	// at this point, we only check whether the SSH server has
	// started accepting incoming TCP connections.
	//
	// If a TCP connection can be established at all, the SSH
	// client will use a timeout to wait until the SSH server
	// is actually ready before attempting to authenticate.
	//
	// However, if a client attempts to connect before the SSH
	// server has started listening for TCP connections,
	// the client connection attempt will fail immediately.
	//
	// We provide this endpoint so that clients can determine
	// when it is safe to establish an SSH connection and rely
	// on the client timeout wait for the SSH server to finish
	// starting, if necessary, without failing immediately.
	conn, err := net.Dial("tcp", "127.0.0.1:22")

	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	_ = conn.Close()

	w.WriteHeader(http.StatusOK)
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	var info AuthInfo

	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if info.User != "root" {
		adduser := exec.Command("adduser", "-D", info.User)

		if err := adduser.Run(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	stdin := fmt.Sprintf("%s:%s", info.User, info.Password)

	chpasswd := exec.Command("chpasswd")
	chpasswd.Stdin = strings.NewReader(stdin)

	if err := chpasswd.Run(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) subscribe(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)

	if err != nil {
		return
	}

	s.mu.Lock()
	s.subs = append(s.subs, conn)
	s.mu.Unlock()
}
