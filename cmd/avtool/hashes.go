package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jbrahy/AntiVirus/internal/hashdb"
	"github.com/spf13/cobra"
)

var sha256HashPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

var hashesCmd = &cobra.Command{
	Use:   "hashes",
	Short: "Manage manually-added known-bad hashes",
}

var hashesAddCmd = &cobra.Command{
	Use:   "add <sha256> <name>",
	Short: "Add a known-bad hash",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := strings.TrimSpace(args[0])
		if !sha256HashPattern.MatchString(hash) {
			return fmt.Errorf("invalid sha256 hash %q: must be 64 hex characters", args[0])
		}
		return hashdb.Upsert(dbFromCmd(cmd), []hashdb.Entry{
			{Hash: hash, Name: args[1], Source: "manual", AddedAt: time.Now()},
		})
	},
}

var hashesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List known-bad hashes",
	RunE: func(cmd *cobra.Command, args []string) error {
		entries, err := hashdb.List(dbFromCmd(cmd))
		if err != nil {
			return err
		}
		for _, e := range entries {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", e.Hash, e.Name, e.Source, e.AddedAt.Format(time.RFC3339))
		}
		return nil
	},
}

var hashesRmCmd = &cobra.Command{
	Use:   "rm <sha256>",
	Short: "Remove a hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return hashdb.Remove(dbFromCmd(cmd), args[0])
	},
}

func init() {
	hashesCmd.AddCommand(hashesAddCmd, hashesListCmd, hashesRmCmd)
	rootCmd.AddCommand(hashesCmd)
}
