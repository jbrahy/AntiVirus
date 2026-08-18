package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "avtool") {
		t.Errorf("output = %q, want it to mention avtool", buf.String())
	}
}

func TestDBPathFlagCreatesDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sub", "avtool.db")

	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--db-path", dbPath, "version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("expected db file at %s: %v", dbPath, err)
	}
}
