package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jbrahy/AntiVirus/internal/quarantine"
	"github.com/jbrahy/AntiVirus/internal/store"
)

func TestQuarantineListRestorePurge(t *testing.T) {
	dir := t.TempDir()
	qDir := filepath.Join(t.TempDir(), "quarantine")
	dbPath := filepath.Join(t.TempDir(), "avtool.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	restorePath := filepath.Join(dir, "restore-me.bin")
	if err := os.WriteFile(restorePath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	restoreID, err := quarantine.Quarantine(db, qDir, restorePath, "restorehash")
	if err != nil {
		t.Fatalf("Quarantine restore fixture: %v", err)
	}

	purgePath := filepath.Join(dir, "purge-me.bin")
	if err := os.WriteFile(purgePath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	purgeID, err := quarantine.Quarantine(db, qDir, purgePath, "purgehash")
	if err != nil {
		t.Fatalf("Quarantine purge fixture: %v", err)
	}
	db.Close()

	out := runCLI(t, dbPath, "--quarantine-dir", qDir, "quarantine", "list")
	if !strings.Contains(out, "restorehash") || !strings.Contains(out, "purgehash") {
		t.Fatalf("list output = %q", out)
	}

	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--db-path", dbPath, "--quarantine-dir", qDir, "quarantine", "restore", strconv.FormatInt(restoreID, 10)})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("restore Execute: %v", err)
	}
	if _, err := os.Stat(restorePath); err != nil {
		t.Fatalf("expected file restored: %v", err)
	}

	buf.Reset()
	rootCmd.SetArgs([]string{"--db-path", dbPath, "--quarantine-dir", qDir, "quarantine", "purge", strconv.FormatInt(purgeID, 10)})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("purge Execute: %v", err)
	}
	if _, err := os.Stat(filepath.Join(qDir, fmt.Sprintf("%d-purgehash", purgeID))); !os.IsNotExist(err) {
		t.Fatalf("expected purged file removed, err = %v", err)
	}
}
