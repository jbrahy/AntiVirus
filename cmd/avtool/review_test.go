package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jbrahy/AntiVirus/internal/detections"
	"github.com/jbrahy/AntiVirus/internal/hashdb"
	"github.com/jbrahy/AntiVirus/internal/scanner"
	"github.com/jbrahy/AntiVirus/internal/store"
)

func TestReviewResolvesQueuedDetection(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "avtool.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	badPath := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(badPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := hashdb.Upsert(db, []hashdb.Entry{{Hash: "deadbeef", Name: "TestVirus", Source: "manual", AddedAt: time.Now()}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := detections.Enqueue(db, scanner.Match{Path: badPath, Hash: "deadbeef", Entry: hashdb.Entry{Hash: "deadbeef", Name: "TestVirus"}}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	db.Close()

	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetIn(strings.NewReader("i\n"))
	rootCmd.SetArgs([]string{"--db-path", dbPath, "review"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "ignore") {
		t.Fatalf("output = %q", buf.String())
	}

	db2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("re-open store: %v", err)
	}
	defer db2.Close()
	pending, err := detections.ListPending(db2)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected queue drained, got %+v", pending)
	}
}
