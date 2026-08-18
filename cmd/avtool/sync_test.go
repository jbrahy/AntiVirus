package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const syncFixtureCSV = `# first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature
"2026-08-17 10:00:00","feedhash1","m1","s1","reporter1","a.exe","exe","application/x-msdownload","TrojanA"
`

func TestSyncFetchesAndStoresEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(syncFixtureCSV))
	}))
	defer srv.Close()

	dbPath := filepath.Join(t.TempDir(), "avtool.db")
	runCLI(t, dbPath, "hashes", "add", "manualhash1", "ManualEntry")

	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--db-path", dbPath, "sync", "--feed-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "synced 1 entries") {
		t.Fatalf("output = %q", buf.String())
	}

	out := runCLI(t, dbPath, "hashes", "list")
	if !strings.Contains(out, "feedhash1") || !strings.Contains(out, "manualhash1") {
		t.Fatalf("expected both feed and manual entries, got %q", out)
	}
}
