package ipc

import (
	"encoding/json"
	"fmt"
	"net"
)

// Send dials the Unix socket, sends cmd, and returns the daemon's Response.
// Returns a descriptive error if the daemon is not running.
func Send(cmd string) (*Response, error) {
	conn, err := net.Dial("unix", SocketPath)
	if err != nil {
		return nil, fmt.Errorf("daemon is not running (cannot connect to %s)", SocketPath)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(Request{Cmd: cmd}); err != nil {
		return nil, fmt.Errorf("IPC send: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("IPC recv: %w", err)
	}
	return &resp, nil
}
