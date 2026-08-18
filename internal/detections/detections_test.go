package detections

import (
	"path/filepath"
	"testing"

	"github.com/jbrahy/AntiVirus/internal/hashdb"
	"github.com/jbrahy/AntiVirus/internal/scanner"
	"github.com/jbrahy/AntiVirus/internal/store"
)

func TestEnqueueListResolve(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "avtool.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	m1 := scanner.Match{Path: "/tmp/a", Hash: "aaa", Entry: hashdb.Entry{Name: "One"}}
	m2 := scanner.Match{Path: "/tmp/b", Hash: "bbb", Entry: hashdb.Entry{Name: "Two"}}

	id1, err := Enqueue(db, m1)
	if err != nil {
		t.Fatalf("Enqueue m1: %v", err)
	}
	if _, err := Enqueue(db, m2); err != nil {
		t.Fatalf("Enqueue m2: %v", err)
	}

	pending, err := ListPending(db)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("got %d pending, want 2", len(pending))
	}

	if err := Resolve(db, id1, "ignore"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	pending, err = ListPending(db)
	if err != nil {
		t.Fatalf("ListPending after resolve: %v", err)
	}
	if len(pending) != 1 || pending[0].Hash != "bbb" {
		t.Fatalf("pending after resolve = %+v", pending)
	}
}
