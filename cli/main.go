package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"

	"github.com/YCistak/flint/core"
	"github.com/YCistak/flint/core/config"
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
	Short: "Start the Flint daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		daemon, err := core.NewDaemon(cfg)
		if err != nil {
			return fmt.Errorf("failed to create daemon: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		return daemon.Run(ctx)
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the Flint daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: Implement daemon IPC to signal the running instance.
		fmt.Println("TODO: Implement daemon stop via IPC")
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current connection method and stats",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		daemon, err := core.NewDaemon(cfg)
		if err != nil {
			return fmt.Errorf("failed to create daemon: %w", err)
		}

		status := daemon.Status()
		data, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal status: %w", err)
		}

		fmt.Println(string(data))
		return nil
	},
}

var addVpsCmd = &cobra.Command{
	Use:   "add-vps <address:port> <uuid>",
	Short: "Add a VPS server (VLESS)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: Parse address:port and UUID, add to config, save.
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
