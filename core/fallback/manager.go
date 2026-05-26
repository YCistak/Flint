package fallback

import (
	"context"
	"fmt"
	"log"
)

// Method represents a bypass/tunnel method.
type Method string

const (
	MethodDPI    Method = "dpi"
	MethodVLESS  Method = "vless"
	MethodPheron Method = "pheron"
	MethodTor    Method = "tor"
)

// Status represents the health of a method.
type Status string

const (
	StatusUnknown Status = "unknown"
	StatusWorking Status = "working"
	StatusFailed  Status = "failed"
)

// MethodEntry tracks the state of a single fallback method.
type MethodEntry struct {
	Method    Method
	Status    Status
	LastError string
	Handler   Handler
}

// Handler is the interface that each method must implement.
type Handler interface {
	// Start initializes the handler.
	Start(ctx context.Context) error
	// Stop cleanly shuts down the handler.
	Stop(ctx context.Context) error
	// Health checks if the method is currently working.
	Health(ctx context.Context) error
	// Name returns a human-readable name.
	Name() string
}

// Manager orchestrates the fallback chain.
type Manager struct {
	// methods: ordered list of methods to try
	methods []MethodEntry
	// current: the currently active method (may be nil)
	current *MethodEntry
	// forceMethod: if set, only use this method (for testing/debugging)
	forceMethod Method
}

// New creates a new fallback manager with the given handlers.
// The order of handlers determines the fallback priority.
func New(handlers []Handler) *Manager {
	m := &Manager{
		methods: make([]MethodEntry, len(handlers)),
	}
	for i, h := range handlers {
		m.methods[i] = MethodEntry{
			Status:  StatusUnknown,
			Handler: h,
		}
	}
	return m
}

// SetForcedMethod forces the manager to use only a specific method.
// Useful for debugging. Pass empty string to clear.
func (m *Manager) SetForcedMethod(method Method) {
	m.forceMethod = method
}

// Start initializes the manager and attempts to bring up a working method.
func (m *Manager) Start(ctx context.Context) error {
	log.Printf("Starting fallback manager with %d methods", len(m.methods))

	// If a method is forced, try only that one.
	if m.forceMethod != "" {
		for i := range m.methods {
			h := m.methods[i].Handler
			if Method(h.Name()) == m.forceMethod {
				if err := h.Start(ctx); err != nil {
					m.methods[i].Status = StatusFailed
					m.methods[i].LastError = err.Error()
					return fmt.Errorf("forced method %s failed: %w", m.forceMethod, err)
				}
				m.methods[i].Status = StatusWorking
				m.current = &m.methods[i]
				log.Printf("Fallback: using forced method %s", m.forceMethod)
				return nil
			}
		}
		return fmt.Errorf("forced method %s not found", m.forceMethod)
	}

	// Try methods in order until one works.
	for i := range m.methods {
		h := m.methods[i].Handler
		log.Printf("Fallback: trying %s...", h.Name())

		if err := h.Start(ctx); err != nil {
			m.methods[i].Status = StatusFailed
			m.methods[i].LastError = err.Error()
			log.Printf("Fallback: %s failed: %v", h.Name(), err)
			continue
		}

		// Health check to confirm it's working.
		if err := h.Health(ctx); err != nil {
			m.methods[i].Status = StatusFailed
			m.methods[i].LastError = fmt.Sprintf("health check: %v", err)
			log.Printf("Fallback: %s health check failed: %v", h.Name(), err)
			_ = h.Stop(ctx) // best effort cleanup
			continue
		}

		m.methods[i].Status = StatusWorking
		m.current = &m.methods[i]
		log.Printf("Fallback: %s is active", h.Name())
		return nil
	}

	return fmt.Errorf("all fallback methods failed")
}

// Stop cleanly shuts down the current active method.
func (m *Manager) Stop(ctx context.Context) error {
	if m.current == nil {
		return nil
	}

	log.Printf("Stopping current method: %s", m.current.Handler.Name())
	err := m.current.Handler.Stop(ctx)
	m.current = nil
	return err
}

// Current returns the name of the currently active method, or "none" if idle.
func (m *Manager) Current() string {
	if m.current == nil {
		return "none"
	}
	return m.current.Handler.Name()
}

// Status returns the status of all methods.
func (m *Manager) Status() map[string]interface{} {
	methods := make([]map[string]interface{}, len(m.methods))
	for i, e := range m.methods {
		methods[i] = map[string]interface{}{
			"name":   e.Handler.Name(),
			"status": string(e.Status),
			"error":  e.LastError,
		}
	}

	return map[string]interface{}{
		"current": m.Current(),
		"methods": methods,
	}
}

// Failover attempts to switch to the next available method.
// Called when the current method fails.
func (m *Manager) Failover(ctx context.Context) error {
	log.Printf("Failover triggered from %s", m.Current())

	if m.current != nil {
		_ = m.current.Handler.Stop(ctx) // best effort cleanup
		m.current = nil
	}

	// Try remaining methods.
	for i := range m.methods {
		h := m.methods[i].Handler
		if m.methods[i].Status == StatusWorking {
			continue // skip the one we just failed from
		}

		log.Printf("Failover: trying %s...", h.Name())
		if err := h.Start(ctx); err != nil {
			m.methods[i].Status = StatusFailed
			m.methods[i].LastError = err.Error()
			log.Printf("Failover: %s failed: %v", h.Name(), err)
			continue
		}

		if err := h.Health(ctx); err != nil {
			m.methods[i].Status = StatusFailed
			m.methods[i].LastError = fmt.Sprintf("health check: %v", err)
			log.Printf("Failover: %s health check failed: %v", h.Name(), err)
			_ = h.Stop(ctx)
			continue
		}

		m.methods[i].Status = StatusWorking
		m.current = &m.methods[i]
		log.Printf("Failover: %s is now active", h.Name())
		return nil
	}

	return fmt.Errorf("no available fallback methods")
}
