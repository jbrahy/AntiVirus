package quarantine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jbrahy/AntiVirus/internal/store"
)

func TestQuarantineRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	qDir := filepath.Join(t.TempDir(), "quarantine")
	dbPath := filepath.Join(t.TempDir(), "avtool.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	original := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(original, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	id, err := Quarantine(db, qDir, original, "deadbeef")
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if _, err := os.Stat(original); !os.IsNotExist(err) {
		t.Fatalf("expected original removed, stat err = %v", err)
	}

	info, err := os.Stat(filepath.Join(qDir, "deadbeef"))
	if err != nil {
		t.Fatalf("expected quarantined file: %v", err)
	}
	if info.Mode().Perm()&0o111 != 0 {
		t.Fatalf("expected no execute bits, got %v", info.Mode())
	}

	if err := Restore(db, qDir, id); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	data, err := os.ReadFile(original)
	if err != nil {
		t.Fatalf("expected restored file: %v", err)
	}
	if string(data) != "payload" {
		t.Fatalf("restored content = %q", data)
	}

	if err := Restore(db, qDir, id); err == nil {
		t.Fatal("expected error restoring an already-restored record")
	}
}

func TestPurgeRemovesFileAndRecord(t *testing.T) {
	dir := t.TempDir()
	qDir := filepath.Join(t.TempDir(), "quarantine")
	dbPath := filepath.Join(t.TempDir(), "avtool.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	original := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(original, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	id, err := Quarantine(db, qDir, original, "cafebabe")
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if err := Purge(db, qDir, id); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if _, err := os.Stat(filepath.Join(qDir, "cafebabe")); !os.IsNotExist(err) {
		t.Fatalf("expected quarantined file removed, err = %v", err)
	}

	records, err := List(db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records after purge, got %+v", records)
	}
}

func TestPurgeAfterRestore(t *testing.T) {
	dir := t.TempDir()
	qDir := filepath.Join(t.TempDir(), "quarantine")
	dbPath := filepath.Join(t.TempDir(), "avtool.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	original := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(original, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	id, err := Quarantine(db, qDir, original, "deadc0de")
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if err := Restore(db, qDir, id); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if err := Purge(db, qDir, id); err != nil {
		t.Fatalf("Purge after Restore: %v", err)
	}

	records, err := List(db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records after purge-after-restore, got %+v", records)
	}
}
