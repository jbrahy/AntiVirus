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
	// review re-verifies the queued hash against the file's live content
	// (Important 8 fix), so the seeded hashdb entry and detection must use
	// the file's real hash, not a placeholder.
	hash, err := scanner.HashFile(badPath)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if err := hashdb.Upsert(db, []hashdb.Entry{{Hash: hash, Name: "TestVirus", Source: "manual", AddedAt: time.Now()}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := detections.Enqueue(db, scanner.Match{Path: badPath, Hash: hash, Entry: hashdb.Entry{Hash: hash, Name: "TestVirus"}}); err != nil {
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

func TestReviewSkipsStaleDetectionWithoutPrompting(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "avtool.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	badPath := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(badPath, []byte("original malicious content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	originalHash, err := scanner.HashFile(badPath)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if err := hashdb.Upsert(db, []hashdb.Entry{{Hash: originalHash, Name: "TestVirus", Source: "manual", AddedAt: time.Now()}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	detID, err := detections.Enqueue(db, scanner.Match{Path: badPath, Hash: originalHash, Entry: hashdb.Entry{Hash: originalHash, Name: "TestVirus"}})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	db.Close()

	// Content changes after the detection was queued -- its live hash no
	// longer matches the queued hash.
	if err := os.WriteFile(badPath, []byte("different content entirely"), 0o644); err != nil {
		t.Fatalf("rewriting badPath: %v", err)
	}

	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	// Empty/closed stdin: per Important 5's fix this now errors if the
	// interactive prompt is ever reached, making an accidental prompt-reach
	// loudly visible as a test failure instead of silently defaulting.
	rootCmd.SetIn(strings.NewReader(""))
	rootCmd.SetArgs([]string{"--db-path", dbPath, "review"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "skipping") {
		t.Fatalf("expected a skip message for the stale detection, output = %q", buf.String())
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
		t.Fatalf("expected queue drained (resolved as stale), got %+v", pending)
	}

	var resolution string
	if err := db2.QueryRow(`SELECT resolution FROM detections WHERE id = ?`, detID).Scan(&resolution); err != nil {
		t.Fatalf("querying resolution: %v", err)
	}
	if resolution != "skipped-stale" {
		t.Fatalf("resolution = %q, want %q", resolution, "skipped-stale")
	}
}
