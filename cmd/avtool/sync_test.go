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

func TestSyncNeverOverwritesManualEntry(t *testing.T) {
	// Feed fixture contains same hash as the manual entry we will add
	const feedFixtureWithCollision = `# first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature
"2026-08-17 10:00:00","collisionhash","m1","s1","reporter1","a.exe","exe","application/x-msdownload","TrojanFromFeed"
`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(feedFixtureWithCollision))
	}))
	defer srv.Close()

	dbPath := filepath.Join(t.TempDir(), "avtool.db")
	// Add manual entry with hash that matches feed entry
	runCLI(t, dbPath, "hashes", "add", "collisionhash", "ManualTrojan")

	// Sync from feed which has same hash but different name
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--db-path", dbPath, "sync", "--feed-url", srv.URL})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Verify manual entry was not overwritten
	out := runCLI(t, dbPath, "hashes", "list")
	if !strings.Contains(out, "collisionhash") {
		t.Fatalf("expected collisionhash in output, got %q", out)
	}
	if !strings.Contains(out, "ManualTrojan") {
		t.Fatalf("expected manual name 'ManualTrojan' to be preserved, got %q", out)
	}
	if strings.Contains(out, "TrojanFromFeed") {
		t.Fatalf("feed name should not be present (manual survives), got %q", out)
	}
	// Verify source is still manual
	if !strings.Contains(out, "collisionhash\tManualTrojan\tmanual") {
		t.Fatalf("expected source to be 'manual', output = %q", out)
	}
}

func TestSyncFetchFailureLeavesDBUntouched(t *testing.T) {
	// Server that returns 500 error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dbPath := filepath.Join(t.TempDir(), "avtool.db")
	// Seed database with manual entry
	runCLI(t, dbPath, "hashes", "add", "manualhash", "MyEntry")

	// Try to sync from failing feed
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--db-path", dbPath, "sync", "--feed-url", srv.URL})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("Expected Execute to return error on 500 response")
	}

	// Verify manual entry still exists and is unchanged
	out := runCLI(t, dbPath, "hashes", "list")
	if !strings.Contains(out, "manualhash") || !strings.Contains(out, "MyEntry") {
		t.Fatalf("expected manual entry to survive fetch failure, got %q", out)
	}
}
