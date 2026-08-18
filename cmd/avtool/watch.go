package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jbrahy/AntiVirus/internal/detections"
	"github.com/jbrahy/AntiVirus/internal/notify"
	"github.com/jbrahy/AntiVirus/internal/scanner"
	"github.com/jbrahy/AntiVirus/internal/watcher"
	"github.com/spf13/cobra"
)

var watchCmd = &cobra.Command{
	Use:   "watch <path> [path...]",
	Short: "Watch directories in real time and queue any matches for review",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runWatch,
}

func init() {
	rootCmd.AddCommand(watchCmd)
}

func newFileHandler(db *sql.DB, n notify.Notifier, errOut io.Writer) func(path string) {
	return func(path string) {
		m, err := scanner.ScanFile(db, path)
		if err != nil {
			fmt.Fprintf(errOut, "scanning %s: %v\n", path, err)
			return
		}
		if m == nil {
			return
		}
		if _, err := detections.Enqueue(db, *m); err != nil {
			fmt.Fprintf(errOut, "queueing detection for %s: %v\n", path, err)
			return
		}
		if err := n.Notify("avtool: match found", fmt.Sprintf("%s matched %s", path, m.Entry.Name)); err != nil {
			fmt.Fprintf(errOut, "notifying: %v\n", err)
		}
	}
}

func runWatch(cmd *cobra.Command, args []string) error {
	db := dbFromCmd(cmd)
	handler := newFileHandler(db, notify.MacOSNotifier{}, cmd.ErrOrStderr())

	stop := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		close(stop)
	}()

	fmt.Fprintf(cmd.OutOrStdout(), "watching %d path(s), press Ctrl+C to stop\n", len(args))
	return watcher.Watch(args, handler, stop)
}
