package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jbrahy/AntiVirus/internal/feed"
	"github.com/jbrahy/AntiVirus/internal/hashdb"
	"github.com/spf13/cobra"
)

var syncFeedURL string

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync known-bad hashes from the public threat intel feed",
	RunE:  runSync,
}

func init() {
	syncCmd.Flags().StringVar(&syncFeedURL, "feed-url", feed.DefaultURL, "override the feed URL")
	rootCmd.AddCommand(syncCmd)
}

func runSync(cmd *cobra.Command, args []string) error {
	db := dbFromCmd(cmd)
	client := &http.Client{Timeout: 30 * time.Second}
	entries, err := feed.Fetch(client, syncFeedURL)
	if err != nil {
		return fmt.Errorf("sync failed, existing hash database left untouched: %w", err)
	}
	if err := hashdb.Upsert(db, entries); err != nil {
		return fmt.Errorf("storing synced entries: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "synced %d entries\n", len(entries))
	return nil
}
