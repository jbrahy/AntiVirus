// internal/prompt/prompt.go
package prompt

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jbrahy/AntiVirus/internal/quarantine"
	"github.com/jbrahy/AntiVirus/internal/reportlog"
	"github.com/jbrahy/AntiVirus/internal/scanner"
)

type Action string

const (
	ActionQuarantine Action = "quarantine"
	ActionDelete     Action = "delete"
	ActionIgnore     Action = "ignore"
	ActionReport     Action = "report"
)

type Deps struct {
	DB            *sql.DB
	QuarantineDir string
	ReportLogPath string
	In            *bufio.Reader
	Out           io.Writer
}

func Resolve(d Deps, m scanner.Match) (Action, error) {
	fmt.Fprintf(d.Out, "MATCH: %s\n  hash:   %s\n  known:  %s\n  source: %s\n\n[q]uarantine  [d]elete  [i]gnore  [r]eport-only: ",
		m.Path, m.Hash, m.Entry.Name, m.Entry.Source)

	line, err := d.In.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("reading choice: %w", err)
	}
	if err == io.EOF && strings.TrimSpace(line) == "" {
		return "", fmt.Errorf("no input available to resolve %s (stdin closed): run interactively or use 'report' explicitly", m.Path)
	}
	choice := strings.ToLower(strings.TrimSpace(line))

	switch choice {
	case "q", "quarantine":
		if _, err := quarantine.Quarantine(d.DB, d.QuarantineDir, m.Path, m.Hash); err != nil {
			return "", err
		}
		return ActionQuarantine, nil
	case "d", "delete":
		fmt.Fprintf(d.Out, "Permanently delete %s? This cannot be undone. [y/N]: ", m.Path)
		confirmLine, _ := d.In.ReadString('\n')
		confirm := strings.ToLower(strings.TrimSpace(confirmLine))
		if confirm != "y" && confirm != "yes" {
			fmt.Fprintln(d.Out, "delete cancelled")
			return ActionIgnore, nil
		}
		if err := os.Remove(m.Path); err != nil {
			return "", fmt.Errorf("deleting %s: %w", m.Path, err)
		}
		return ActionDelete, nil
	case "i", "ignore":
		return ActionIgnore, nil
	default:
		if choice != "" && choice != "r" && choice != "report" {
			fmt.Fprintf(d.Out, "unrecognized choice %q, treating as report-only\n", choice)
		}
		if err := reportlog.Append(d.ReportLogPath, reportlog.Entry{
			Path: m.Path, Hash: m.Hash, Name: m.Entry.Name, ReportedAt: time.Now().UTC(),
		}); err != nil {
			return "", err
		}
		return ActionReport, nil
	}
}
