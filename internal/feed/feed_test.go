package feed

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const fixtureCSV = `# first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature
"2026-08-17 10:00:00","aaa111","m1","s1","reporter1","a.exe","exe","application/x-msdownload","TrojanA"
"2026-08-17 11:00:00","bbb222","m2","s2","reporter2","b.exe","exe","application/x-msdownload","TrojanB"
`

func TestParse(t *testing.T) {
	entries, err := Parse(strings.NewReader(fixtureCSV))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	if entries[0].Hash != "aaa111" || entries[0].Name != "TrojanA" || entries[0].Source != "feed" {
		t.Fatalf("entries[0] = %+v", entries[0])
	}
}

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixtureCSV))
	}))
	defer srv.Close()

	entries, err := Fetch(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
}

func TestFetchErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := Fetch(srv.Client(), srv.URL); err == nil {
		t.Fatal("expected error on 500 response")
	}
}
