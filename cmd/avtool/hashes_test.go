package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, dbPath string, args ...string) string {
	t.Helper()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(append([]string{"--db-path", dbPath}, args...))
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute(%v): %v\noutput: %s", args, err, buf.String())
	}
	return buf.String()
}

func TestHashesAddListRm(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "avtool.db")

	runCLI(t, dbPath, "hashes", "add", "deadbeef", "TestVirus")

	out := runCLI(t, dbPath, "hashes", "list")
	if !strings.Contains(out, "deadbeef") || !strings.Contains(out, "TestVirus") {
		t.Fatalf("list output = %q", out)
	}

	runCLI(t, dbPath, "hashes", "rm", "deadbeef")

	out = runCLI(t, dbPath, "hashes", "list")
	if strings.Contains(out, "deadbeef") {
		t.Fatalf("expected deadbeef removed, got %q", out)
	}
}
