package ipc

import (
	"encoding/json"
	"log"
	"net"
	"os"
)

// DaemonInfo is the subset of Daemon that the IPC server needs.
type DaemonInfo interface {
	Status() map[string]interface{}
}

// Server listens on the Unix socket and dispatches IPC requests.
type Server struct {
	ln     net.Listener
	daemon DaemonInfo
	// stopCh is closed/sent-to when a "stop" command arrives, signalling Run()
	// to begin shutdown.
	stopCh chan<- struct{}
}

// NewServer creates a listener on socketPath and returns a ready-to-serve Server.
// Any stale socket file from a previous run is removed first.
func NewServer(socketPath string, daemon DaemonInfo, stopCh chan<- struct{}) (*Server, error) {
	// Remove a stale socket from a previous crash.
	os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	// Allow any user to connect without sudo.
	os.Chmod(socketPath, 0666)

	return &Server{ln: ln, daemon: daemon, stopCh: stopCh}, nil
}

// Serve accepts connections in a loop until the listener is closed.
// Call it in a goroutine.
func (s *Server) Serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			// Listener was closed during shutdown — normal exit.
			return
		}
		go s.handle(conn)
	}
}

// Close shuts down the listener and removes the socket file.
func (s *Server) Close(socketPath string) {
	s.ln.Close()
	os.Remove(socketPath)
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		log.Printf("IPC: malformed request: %v", err)
		return
	}

	enc := json.NewEncoder(conn)

	switch req.Cmd {
	case "status":
		enc.Encode(Response{OK: true, Payload: s.daemon.Status()})

	case "stop":
		// Acknowledge before triggering shutdown so the client receives the reply
		// before the socket disappears.
		enc.Encode(Response{OK: true})
		s.stopCh <- struct{}{}

	default:
		enc.Encode(Response{OK: false, Error: "unknown command: " + req.Cmd})
	}
}
