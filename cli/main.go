package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

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

var addVpsCmd = &cobra.Command{
	Use:   "add-vps <address:port> <uuid>",
	Short: "Add a VPS server (VLESS)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("TODO: Add VPS server %s with UUID %s\n", args[0], args[1])
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
