package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jbrahy/AntiVirus/internal/detections"
	"github.com/jbrahy/AntiVirus/internal/hashdb"
	"github.com/jbrahy/AntiVirus/internal/store"
)

type fakeNotifier struct {
	calls []string
}

func (f *fakeNotifier) Notify(title, message string) error {
	f.calls = append(f.calls, title+": "+message)
	return nil
}

func TestFileHandlerEnqueuesAndNotifiesOnMatch(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(t.TempDir(), "avtool.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	badPath := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(badPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	hash, err := hashFileForTest(badPath)
	if err != nil {
		t.Fatalf("hashFileForTest: %v", err)
	}
	if err := hashdb.Upsert(db, []hashdb.Entry{{Hash: hash, Name: "TestVirus", Source: "manual", AddedAt: time.Now()}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	goodPath := filepath.Join(dir, "good.bin")
	if err := os.WriteFile(goodPath, []byte("harmless"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	n := &fakeNotifier{}
	handler := newFileHandler(db, n, os.Stderr)

	handler(badPath)
	handler(goodPath)

	pending, err := detections.ListPending(db)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 1 || pending[0].Path != badPath {
		t.Fatalf("pending = %+v", pending)
	}
	if len(n.calls) != 1 {
		t.Fatalf("notifier calls = %v, want 1", n.calls)
	}
}
