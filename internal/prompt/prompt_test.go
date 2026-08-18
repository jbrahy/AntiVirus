// internal/prompt/prompt_test.go
package prompt

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jbrahy/AntiVirus/internal/hashdb"
	"github.com/jbrahy/AntiVirus/internal/scanner"
	"github.com/jbrahy/AntiVirus/internal/store"
)

func setup(t *testing.T) (Deps, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "avtool.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	return Deps{
		DB:            db,
		QuarantineDir: filepath.Join(t.TempDir(), "quarantine"),
		ReportLogPath: filepath.Join(t.TempDir(), "detections.log"),
	}, dir
}

func testMatch(dir string) scanner.Match {
	return scanner.Match{
		Path:  filepath.Join(dir, "bad.bin"),
		Hash:  "deadbeef",
		Entry: hashdb.Entry{Hash: "deadbeef", Name: "TestVirus", Source: "manual"},
	}
}

func TestResolveQuarantine(t *testing.T) {
	deps, dir := setup(t)
	m := testMatch(dir)
	if err := os.WriteFile(m.Path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	deps.In = bufio.NewReader(strings.NewReader("q\n"))
	deps.Out = &bytes.Buffer{}

	action, err := Resolve(deps, m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if action != ActionQuarantine {
		t.Fatalf("action = %v, want quarantine", action)
	}
	if _, err := os.Stat(m.Path); !os.IsNotExist(err) {
		t.Fatalf("expected original file moved, stat err = %v", err)
	}
}

func TestResolveDelete(t *testing.T) {
	deps, dir := setup(t)
	m := testMatch(dir)
	if err := os.WriteFile(m.Path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	deps.In = bufio.NewReader(strings.NewReader("d\ny\n"))
	deps.Out = &bytes.Buffer{}

	action, err := Resolve(deps, m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if action != ActionDelete {
		t.Fatalf("action = %v, want delete", action)
	}
	if _, err := os.Stat(m.Path); !os.IsNotExist(err) {
		t.Fatalf("expected file deleted, stat err = %v", err)
	}
}

func TestResolveDeleteCancelled(t *testing.T) {
	deps, dir := setup(t)
	m := testMatch(dir)
	if err := os.WriteFile(m.Path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	deps.In = bufio.NewReader(strings.NewReader("d\nn\n"))
	deps.Out = &bytes.Buffer{}

	action, err := Resolve(deps, m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if action != ActionIgnore {
		t.Fatalf("action = %v, want ignore", action)
	}
	if _, err := os.Stat(m.Path); err != nil {
		t.Fatalf("expected file untouched after cancelled delete: %v", err)
	}
}

func TestResolveIgnore(t *testing.T) {
	deps, dir := setup(t)
	m := testMatch(dir)
	if err := os.WriteFile(m.Path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	deps.In = bufio.NewReader(strings.NewReader("i\n"))
	deps.Out = &bytes.Buffer{}

	action, err := Resolve(deps, m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if action != ActionIgnore {
		t.Fatalf("action = %v, want ignore", action)
	}
	if _, err := os.Stat(m.Path); err != nil {
		t.Fatalf("expected file untouched: %v", err)
	}
}

func TestResolveReportDefault(t *testing.T) {
	deps, dir := setup(t)
	m := testMatch(dir)
	if err := os.WriteFile(m.Path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	deps.In = bufio.NewReader(strings.NewReader("\n")) // empty line defaults to report-only
	deps.Out = &bytes.Buffer{}

	action, err := Resolve(deps, m)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if action != ActionReport {
		t.Fatalf("action = %v, want report", action)
	}
	if _, err := os.Stat(deps.ReportLogPath); err != nil {
		t.Fatalf("expected report log written: %v", err)
	}
}

func TestResolveEOFReturnsError(t *testing.T) {
	deps, dir := setup(t)
	m := testMatch(dir)
	if err := os.WriteFile(m.Path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	deps.In = bufio.NewReader(strings.NewReader("")) // closed/empty stdin
	deps.Out = &bytes.Buffer{}

	action, err := Resolve(deps, m)
	if err == nil {
		t.Fatalf("expected error on closed stdin, got action %v", action)
	}
}
