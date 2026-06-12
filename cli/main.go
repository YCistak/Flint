package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/YCistak/flint/core"
	"github.com/YCistak/flint/core/config"
	"github.com/YCistak/flint/core/ipc"
)

var (
	configPath string
	verbose    bool
)

var rootCmd = &cobra.Command{
	Use:   "flint",
	Short: "Flint — zero-config censorship bypass tool",
	Long: `Flint automatically detects blocked or throttled traffic and routes it through the best available method.
No VPS required, no manual configuration.`,
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Flint daemon (foreground)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		daemon, err := core.NewDaemon(cfg)
		if err != nil {
			return fmt.Errorf("failed to create daemon: %w", err)
		}
		// Run blocks until shutdown (signal or `flint stop`).
		return daemon.Run(context.Background())
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running Flint daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		pid, err := ipc.ReadPID(ipc.PIDPath)
		if err != nil {
			return err
		}

		resp, err := ipc.Send("stop")
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("daemon error: %s", resp.Error)
		}

		fmt.Printf("Daemon (pid %d) is stopping.\n", pid)
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current connection method and stats",
	RunE: func(cmd *cobra.Command, args []string) error {
		pid, err := ipc.ReadPID(ipc.PIDPath)
		if err != nil {
			return err
		}

		resp, err := ipc.Send("status")
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("daemon error: %s", resp.Error)
		}

		data, err := json.MarshalIndent(resp.Payload, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format status: %w", err)
		}

		fmt.Printf("Flint daemon (pid %d)\n\n%s\n", pid, data)
		return nil
	},
}

var (
	vpsName    string
	vpsSNI     string
	vpsNoTLS   bool
	vpsDisable bool
)

var addVpsCmd = &cobra.Command{
	Use:   "add-vps <address:port> <uuid>",
	Short: "Add a VPS server (VLESS)",
	Long: `Add a VLESS VPS server to the fallback chain and save it to the Flint config.

The server is tried after DPI bypass and before Pheron/Tor. TLS is enabled by
default (the standard VLESS-over-TLS setup); pass --no-tls to disable it.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		host, portStr, err := net.SplitHostPort(args[0])
		if err != nil {
			return fmt.Errorf("invalid address %q (want host:port): %w", args[0], err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid port %q", portStr)
		}
		uuid := args[1]

		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		name := vpsName
		if name == "" {
			name = host
		}

		server := config.ServerConfig{
			Name:    name,
			Address: host,
			Port:    port,
			UUID:    uuid,
			TLS:     !vpsNoTLS,
			SNI:     vpsSNI,
			Enabled: !vpsDisable,
		}

		// Replace an existing server with the same name, otherwise append.
		replaced := false
		for i := range cfg.Tunnel.Servers {
			if cfg.Tunnel.Servers[i].Name == name {
				cfg.Tunnel.Servers[i] = server
				replaced = true
				break
			}
		}
		if !replaced {
			cfg.Tunnel.Servers = append(cfg.Tunnel.Servers, server)
		}

		if err := cfg.Save(); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		action := "Added"
		if replaced {
			action = "Updated"
		}
		fmt.Printf("%s VPS server %q (%s:%d, TLS=%v, enabled=%v)\n",
			action, name, host, port, server.TLS, server.Enabled)
		fmt.Println("Restart the daemon (flint stop && flint start) to apply.")
		return nil
	},
}

var blocklistCmd = &cobra.Command{
	Use:   "blocklist",
	Short: "Manage the blocklist",
}

var blocklistUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update bundled blocklist",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("TODO: Implement blocklist update")
		return nil
	},
}

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Show node pool status",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("TODO: Implement node pool status")
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Config file path")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Verbose logging")

	addVpsCmd.Flags().StringVar(&vpsName, "name", "", "Friendly name for the server (defaults to its address)")
	addVpsCmd.Flags().StringVar(&vpsSNI, "sni", "", "TLS server name to present (defaults to the address)")
	addVpsCmd.Flags().BoolVar(&vpsNoTLS, "no-tls", false, "Disable TLS (plain VLESS)")
	addVpsCmd.Flags().BoolVar(&vpsDisable, "disabled", false, "Save the server but leave it out of the fallback chain")

	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(addVpsCmd)
	rootCmd.AddCommand(nodeCmd)

	blocklistCmd.AddCommand(blocklistUpdateCmd)
	rootCmd.AddCommand(blocklistCmd)
}

func loadConfig() (*config.Config, error) {
	if configPath != "" {
		return config.LoadFrom(configPath)
	}
	return config.Load()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
