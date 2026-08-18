package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/jbrahy/AntiVirus/internal/config"
	"github.com/jbrahy/AntiVirus/internal/prompt"
	"github.com/jbrahy/AntiVirus/internal/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan a file or directory against known-bad hashes",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	db := dbFromCmd(cmd)
	matches, err := scanner.Scan(db, args[0])
	if err != nil {
		return fmt.Errorf("scanning %s: %w", args[0], err)
	}
	if len(matches) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no matches")
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
	for _, m := range matches {
		action, err := prompt.Resolve(deps, m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "resolving %s: %v\n", m.Path, err)
			continue
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", m.Path, action)
	}
	return nil
}
