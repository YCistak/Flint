// Package ipc defines the Unix-socket IPC protocol shared by the daemon and CLI.
package ipc

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	SocketPath = "/tmp/flint.sock"
	PIDPath    = "/tmp/flint.pid"
)

// Request is the message sent by a CLI command to the daemon.
type Request struct {
	Cmd string `json:"cmd"` // "status" | "stop"
}

// Response is the daemon's reply.
type Response struct {
	OK      bool                   `json:"ok"`
	Error   string                 `json:"error,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// WritePID writes the current process PID to PIDPath.
func WritePID(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
}

// RemovePID deletes the PID file (best-effort; ignores missing-file errors).
func RemovePID(path string) {
	os.Remove(path)
}

// ReadPID reads the PID stored in path and returns it, or an error if the
// file is absent or malformed.
func ReadPID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("daemon does not appear to be running (no PID file)")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("malformed PID file: %w", err)
	}
	return pid, nil
}
