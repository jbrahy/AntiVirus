package main

import (
	"bufio"
	"fmt"

	"github.com/jbrahy/AntiVirus/internal/config"
	"github.com/jbrahy/AntiVirus/internal/detections"
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

	qDir, err := getQuarantineDir()
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
		// Re-verify against the live file before acting: the queued path/hash
		// come from when the watcher first detected it, and the file may have
		// changed or been replaced since. Never act on a Match whose hash
		// doesn't match what's on disk right now.
		fresh, err := scanner.ScanFile(db, d.Path)
		switch {
		case err != nil:
			fmt.Fprintf(cmd.ErrOrStderr(), "skipping %s: %v\n", d.Path, err)
			if err := detections.Resolve(db, d.ID, "skipped-stale"); err != nil {
				return err
			}
			continue
		case fresh == nil:
			fmt.Fprintf(cmd.ErrOrStderr(), "skipping %s: no longer matches any known-bad hash\n", d.Path)
			if err := detections.Resolve(db, d.ID, "skipped-stale"); err != nil {
				return err
			}
			continue
		case fresh.Hash != d.Hash:
			fmt.Fprintf(cmd.ErrOrStderr(), "skipping %s: content changed since detection (queued hash %s, now %s)\n", d.Path, d.Hash, fresh.Hash)
			if err := detections.Resolve(db, d.ID, "skipped-stale"); err != nil {
				return err
			}
			continue
		}

		action, err := prompt.Resolve(deps, *fresh)
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
