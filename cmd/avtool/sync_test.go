package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// manualHash1, collisionHash, and manualHash are 64-char hex strings (valid
// sha256 shape) so they pass `hashes add`'s hash-format validation.
const manualHash1 = "a68139e37e176b87b891160828707615ad458da6b79973d20ef25b228a5163c5"
const collisionHash = "5ea1cd0ea7805e37a8607f0ba23192704dc4913ed8392deebf05b1b0bf885875"
const manualHash = "6b437aaf9de9bcac1f72cc5a59a57b4a27c3a073768aca68b4287532e35301f3"

var syncFixtureCSV = "# first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature\n" +
	`"2026-08-17 10:00:00", "feedhash1", "m1", "s1", "reporter1", "a.exe", "exe", "application/x-msdownload", "TrojanA"` + "\n"

func TestSyncFetchesAndStoresEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(syncFixtureCSV))
	}))
	defer srv.Close()

	dbPath := filepath.Join(t.TempDir(), "avtool.db")
	runCLI(t, dbPath, "hashes", "add", manualHash1, "ManualEntry")

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
	if !strings.Contains(out, "feedhash1") || !strings.Contains(out, manualHash1) {
		t.Fatalf("expected both feed and manual entries, got %q", out)
	}
}

func TestSyncNeverOverwritesManualEntry(t *testing.T) {
	// Feed fixture contains same hash as the manual entry we will add
	feedFixtureWithCollision := "# first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature\n" +
		`"2026-08-17 10:00:00", "` + collisionHash + `", "m1", "s1", "reporter1", "a.exe", "exe", "application/x-msdownload", "TrojanFromFeed"` + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(feedFixtureWithCollision))
	}))
	defer srv.Close()

	dbPath := filepath.Join(t.TempDir(), "avtool.db")
	// Add manual entry with hash that matches feed entry
	runCLI(t, dbPath, "hashes", "add", collisionHash, "ManualTrojan")

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
	if !strings.Contains(out, collisionHash) {
		t.Fatalf("expected collisionHash in output, got %q", out)
	}
	if !strings.Contains(out, "ManualTrojan") {
		t.Fatalf("expected manual name 'ManualTrojan' to be preserved, got %q", out)
	}
	if strings.Contains(out, "TrojanFromFeed") {
		t.Fatalf("feed name should not be present (manual survives), got %q", out)
	}
	// Verify source is still manual
	if !strings.Contains(out, collisionHash+"\tManualTrojan\tmanual") {
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
	runCLI(t, dbPath, "hashes", "add", manualHash, "MyEntry")

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
	if !strings.Contains(out, manualHash) || !strings.Contains(out, "MyEntry") {
		t.Fatalf("expected manual entry to survive fetch failure, got %q", out)
	}
}
