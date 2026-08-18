package main

import (
	"bufio"
	"fmt"

	"github.com/jbrahy/AntiVirus/internal/config"
	"github.com/jbrahy/AntiVirus/internal/detections"
	"github.com/jbrahy/AntiVirus/internal/hashdb"
	"github.com/jbrahy/AntiVirus/internal/prompt"
	"github.com/jbrahy/AntiVirus/internal/scanner"
	"github.com/spf13/cobra"
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Interactively resolve detections queued by the watcher",
	RunE:  runReview,
}

func init() {
	rootCmd.AddCommand(reviewCmd)
}

func runReview(cmd *cobra.Command, args []string) error {
	db := dbFromCmd(cmd)
	pending, err := detections.ListPending(db)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no pending detections")
		return nil
	}

	qDir, err := config.QuarantineDir()
	if err != nil {
		return err
	}
	logPath, err := config.ReportLogPath()
	if err != nil {
		return err
	}
	deps := prompt.Deps{
		DB:            db,
		QuarantineDir: qDir,
		ReportLogPath: logPath,
		In:            bufio.NewReader(cmd.InOrStdin()),
		Out:           cmd.OutOrStdout(),
	}

	for _, d := range pending {
		entry, err := hashdb.Lookup(db, d.Hash)
		if err != nil {
			return err
		}
		if entry == nil {
			entry = &hashdb.Entry{Hash: d.Hash, Name: d.MatchedName, Source: "unknown"}
		}
		m := scanner.Match{Path: d.Path, Hash: d.Hash, Entry: *entry}
		action, err := prompt.Resolve(deps, m)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "resolving %s: %v\n", d.Path, err)
			continue
		}
		if err := detections.Resolve(db, d.ID, string(action)); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", d.Path, action)
	}
	return nil
}
