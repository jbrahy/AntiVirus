package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jbrahy/AntiVirus/internal/scanner"
)

func hashFileForTest(path string) (string, error) {
	return scanner.HashFile(path)
}

func TestScanReportsAndPromptsOnMatch(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "avtool.db")
	scanDir := t.TempDir()

	badFile := filepath.Join(scanDir, "bad.bin")
	if err := os.WriteFile(badFile, []byte("simulated malicious content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hash, err := hashFileForTest(badFile)
	if err != nil {
		t.Fatalf("hashFileForTest: %v", err)
	}
	runCLI(t, dbPath, "hashes", "add", hash, "TestVirus")

	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(strings.NewReader("i\n"))
	rootCmd.SetArgs([]string{"--db-path", dbPath, "scan", scanDir})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "MATCH") || !strings.Contains(out, "ignore") {
		t.Fatalf("output = %q", out)
	}
	if _, err := os.Stat(badFile); err != nil {
		t.Fatalf("expected file untouched after ignore: %v", err)
	}
}

func TestScanFindsMatchAddedAsUppercaseHash(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "avtool.db")
	scanDir := t.TempDir()

	badFile := filepath.Join(scanDir, "bad.bin")
	if err := os.WriteFile(badFile, []byte("simulated malicious content, uppercase case"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hash, err := hashFileForTest(badFile)
	if err != nil {
		t.Fatalf("hashFileForTest: %v", err)
	}
	// Simulate a hash added in uppercase (e.g. from PowerShell's Get-FileHash).
	runCLI(t, dbPath, "hashes", "add", strings.ToUpper(hash), "TestVirus")

	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(strings.NewReader("i\n"))
	rootCmd.SetArgs([]string{"--db-path", dbPath, "scan", scanDir})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "MATCH") {
		t.Fatalf("expected scan to find a match despite hash being stored uppercase, output = %q", out)
	}
}
