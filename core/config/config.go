package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config represents the Flint daemon configuration.
type Config struct {
	// Daemon settings
	Daemon DaemonConfig `toml:"daemon"`
	// VPS tunnel configuration
	Tunnel TunnelConfig `toml:"tunnel"`
	// Pheron P2P relay settings
	Pheron PheronConfig `toml:"pheron"`
}

// DaemonConfig contains daemon-level settings.
type DaemonConfig struct {
	// LogLevel: "debug", "info", "warn", "error"
	LogLevel string `toml:"log_level"`
	// PidFile: where to store the daemon PID
	PidFile string `toml:"pid_file"`
	// DetectionCacheTTL in seconds (default 86400 = 24h)
	DetectionCacheTTL int `toml:"detection_cache_ttl"`
}

// TunnelConfig contains VLESS tunnel settings.
type TunnelConfig struct {
	// Servers: list of VLESS server configurations
	Servers []ServerConfig `toml:"servers"`
}

// ServerConfig represents a single VPS/VLESS server.
type ServerConfig struct {
	Name     string `toml:"name"`
	Address  string `toml:"address"`
	Port     int    `toml:"port"`
	UUID     string `toml:"uuid"`
	Enabled  bool   `toml:"enabled"`
}

// PheronConfig contains P2P relay settings.
type PheronConfig struct {
	// Enabled: whether to participate as a node
	Enabled bool `toml:"enabled"`
	// BootstrapNodes: hardcoded list of nodes to connect to initially
	BootstrapNodes []string `toml:"bootstrap_nodes"`
	// LocalPort: port to listen on for incoming connections
	LocalPort int `toml:"local_port"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Daemon: DaemonConfig{
			LogLevel:          "info",
			PidFile:           filepath.Join(os.Getenv("HOME"), ".flint", "flint.pid"),
			DetectionCacheTTL: 86400,
		},
		Tunnel: TunnelConfig{
			Servers: nil,
		},
		Pheron: PheronConfig{
			Enabled:        true,
			BootstrapNodes: nil,
			LocalPort:      9999,
		},
	}
}

// Load reads configuration from the default path or from a custom path.
// If the file doesn't exist, returns the default config.
func Load() (*Config, error) {
	path := configPath()
	return LoadFrom(path)
}

// LoadFrom reads configuration from the specified path.
// If the file doesn't exist, returns the default config.
func LoadFrom(path string) (*Config, error) {
	cfg := DefaultConfig()

	// If file doesn't exist, return defaults.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// configPath returns the default config file path.
func configPath() string {
	home := os.Getenv("HOME")
	if home == "" {
		home = "."
	}
	return filepath.Join(home, ".config", "flint", "config.toml")
}

// Save writes the configuration to the default path.
func (c *Config) Save() error {
	path := configPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	data, err := toml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}
