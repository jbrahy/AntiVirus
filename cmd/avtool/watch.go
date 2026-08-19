package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jbrahy/AntiVirus/internal/detections"
	"github.com/jbrahy/AntiVirus/internal/notify"
	"github.com/jbrahy/AntiVirus/internal/scanner"
	"github.com/jbrahy/AntiVirus/internal/watcher"
	"github.com/spf13/cobra"
)

const heartbeatInterval = 60 * time.Second

var watchQuiet bool

var watchCmd = &cobra.Command{
	Use:   "watch <path> [path...]",
	Short: "Watch directories in real time and queue any matches for review",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runWatch,
}

func init() {
	watchCmd.Flags().BoolVar(&watchQuiet, "quiet", false, "suppress the periodic heartbeat status line")
	rootCmd.AddCommand(watchCmd)
}

type watchStats struct {
	mu      sync.Mutex
	scanned int
	matches int
}

func (s *watchStats) recordScan() {
	s.mu.Lock()
	s.scanned++
	s.mu.Unlock()
}

func (s *watchStats) recordMatch() {
	s.mu.Lock()
	s.matches++
	s.mu.Unlock()
}

func (s *watchStats) snapshot() (scanned, matches int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scanned, s.matches
}

func newFileHandler(db *sql.DB, n notify.Notifier, errOut io.Writer, stats *watchStats) func(path string) {
	return func(path string) {
		stats.recordScan()
		m, err := scanner.ScanFile(db, path)
		if err != nil {
			fmt.Fprintf(errOut, "scanning %s: %v\n", path, err)
			return
		}
		if m == nil {
			return
		}
		stats.recordMatch()
		if _, err := detections.Enqueue(db, *m); err != nil {
			fmt.Fprintf(errOut, "queueing detection for %s: %v\n", path, err)
			return
		}
		if err := n.Notify("avtool: match found", fmt.Sprintf("%s matched %s", path, m.Entry.Name)); err != nil {
			fmt.Fprintf(errOut, "notifying: %v\n", err)
		}
	}
}

// runHeartbeat prints a periodic status line until stop is closed.
func runHeartbeat(out io.Writer, stats *watchStats, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			scanned, matches := stats.snapshot()
			fmt.Fprintf(out, "watching: %d files scanned, %d matches (as of %s)\n", scanned, matches, time.Now().Format("15:04:05"))
		}
	}
}

func runWatch(cmd *cobra.Command, args []string) error {
	db := dbFromCmd(cmd)
	stats := &watchStats{}
	handler := newFileHandler(db, notify.MacOSNotifier{}, cmd.ErrOrStderr(), stats)

	// Pre-validate paths so the startup message reports how many paths
	// actually exist and will be watched, not just how many were passed.
	// watcher.Watch's own zero-success check still catches paths that
	// exist but fail to add for other reasons (e.g. permissions).
	existing := 0
	for _, p := range args {
		if _, err := os.Stat(p); err == nil {
			existing++
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "watch: %s does not exist, will not be watched: %v\n", p, err)
		}
	}

	stop := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		close(stop)
	}()

	fmt.Fprintf(cmd.OutOrStdout(), "watching %d path(s), press Ctrl+C to stop\n", existing)

	if !watchQuiet {
		go runHeartbeat(cmd.OutOrStdout(), stats, heartbeatInterval, stop)
	}

	return watcher.Watch(args, handler, stop)
}
