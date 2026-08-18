package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jbrahy/AntiVirus/internal/hashdb"
	"github.com/jbrahy/AntiVirus/internal/store"
)

func TestScanFindsSeededMatch(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "avtool.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	content := []byte("simulated malicious content")
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])

	if err := os.WriteFile(filepath.Join(dir, "bad.bin"), content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.bin"), []byte("harmless"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := hashdb.Upsert(db, []hashdb.Entry{{Hash: hash, Name: "TestVirus", Source: "manual", AddedAt: time.Now()}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	matches, err := Scan(db, dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(matches), matches)
	}
	if matches[0].Hash != hash || matches[0].Entry.Name != "TestVirus" {
		t.Fatalf("match = %+v", matches[0])
	}
}

func TestScanSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "avtool.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	target := filepath.Join(dir, "real.bin")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	m, err := ScanFile(db, link)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if m != nil {
		t.Fatalf("expected symlink to be skipped, got %+v", m)
	}
}
