package hashdb

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jbrahy/AntiVirus/internal/store"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "avtool.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestUpsertLookupRemove(t *testing.T) {
	db := openTestDB(t)

	err := Upsert(db, []Entry{{Hash: "aaa", Name: "TestVirus", Source: "manual", AddedAt: time.Now()}})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	e, err := Lookup(db, "aaa")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if e == nil || e.Name != "TestVirus" {
		t.Fatalf("Lookup = %+v", e)
	}

	if err := Remove(db, "aaa"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	e, err = Lookup(db, "aaa")
	if err != nil {
		t.Fatalf("Lookup after remove: %v", err)
	}
	if e != nil {
		t.Fatalf("expected nil after remove, got %+v", e)
	}
}

func TestFeedNeverOverwritesManual(t *testing.T) {
	db := openTestDB(t)

	if err := Upsert(db, []Entry{{Hash: "bbb", Name: "ManualName", Source: "manual", AddedAt: time.Now()}}); err != nil {
		t.Fatalf("manual Upsert: %v", err)
	}
	if err := Upsert(db, []Entry{{Hash: "bbb", Name: "FeedName", Source: "feed", AddedAt: time.Now()}}); err != nil {
		t.Fatalf("feed Upsert: %v", err)
	}

	e, err := Lookup(db, "bbb")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if e.Name != "ManualName" || e.Source != "manual" {
		t.Fatalf("expected manual entry preserved, got %+v", e)
	}
}

func TestHashCaseInsensitivity(t *testing.T) {
	db := openTestDB(t)

	// Upsert uppercase, look up lowercase.
	if err := Upsert(db, []Entry{{Hash: "AAAABBBBCCCC", Name: "UpperVirus", Source: "manual", AddedAt: time.Now()}}); err != nil {
		t.Fatalf("Upsert uppercase: %v", err)
	}
	e, err := Lookup(db, "aaaabbbbcccc")
	if err != nil {
		t.Fatalf("Lookup lowercase: %v", err)
	}
	if e == nil || e.Name != "UpperVirus" {
		t.Fatalf("Lookup lowercase after uppercase Upsert = %+v", e)
	}

	// Upsert lowercase, look up uppercase.
	if err := Upsert(db, []Entry{{Hash: "ddddeeeeffff", Name: "LowerVirus", Source: "manual", AddedAt: time.Now()}}); err != nil {
		t.Fatalf("Upsert lowercase: %v", err)
	}
	e, err = Lookup(db, "DDDDEEEEFFFF")
	if err != nil {
		t.Fatalf("Lookup uppercase: %v", err)
	}
	if e == nil || e.Name != "LowerVirus" {
		t.Fatalf("Lookup uppercase after lowercase Upsert = %+v", e)
	}

	// Remove using a differently-cased hash still removes the entry.
	if err := Remove(db, "AAAABBBBCCCC"); err != nil {
		t.Fatalf("Remove uppercase: %v", err)
	}
	e, err = Lookup(db, "aaaabbbbcccc")
	if err != nil {
		t.Fatalf("Lookup after Remove: %v", err)
	}
	if e != nil {
		t.Fatalf("expected nil after case-insensitive Remove, got %+v", e)
	}
}

func TestList(t *testing.T) {
	db := openTestDB(t)

	if err := Upsert(db, []Entry{
		{Hash: "ccc", Name: "One", Source: "manual", AddedAt: time.Now()},
		{Hash: "ddd", Name: "Two", Source: "feed", AddedAt: time.Now()},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	entries, err := List(db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(entries))
	}
}
