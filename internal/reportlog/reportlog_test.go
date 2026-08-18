// internal/reportlog/reportlog_test.go
package reportlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppendWritesJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "detections.log")

	if err := Append(path, Entry{Path: "/tmp/a", Hash: "aaa", Name: "One", ReportedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	if err := Append(path, Entry{Path: "/tmp/b", Hash: "bbb", Name: "Two", ReportedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("Append 2: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}

	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.Hash != "aaa" {
		t.Fatalf("first entry hash = %q, want aaa", e.Hash)
	}
}
