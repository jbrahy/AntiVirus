// internal/web/handlers/consent_test.go
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizePhone(t *testing.T) {
	cases := []struct{ in, want string }{
		{"(512) 555-0134", "+15125550134"},
		{"512-555-0134", "+15125550134"},
		{"5125550134", "+15125550134"},
		{"1 512 555 0134", "+15125550134"},
		{"+1 (512) 555-0134", "+15125550134"},
		{"", ""},
		{"555-0134", ""},    // too short
		{"25125550134", ""}, // 11 digits not starting with 1
		{"not a phone", ""},
	}
	for _, c := range cases {
		if got := normalizePhone(c.in); got != c.want {
			t.Errorf("normalizePhone(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCheckedTreatsAbsentBoxAsNoConsent(t *testing.T) {
	// An unticked HTML checkbox is omitted from the POST body entirely, so
	// absence must read as "did not consent" rather than as a missing value.
	r := httptest.NewRequest(http.MethodPost, "/signup", nil)
	if checked(r, "sms_marketing_consent") {
		t.Error("absent checkbox reported as checked")
	}
}

func TestClientIPTrustsOnlyTheProxyAppendedRightmostEntry(t *testing.T) {
	// The app sits behind exactly one Apache reverse proxy hop, which
	// appends its own observed connection IP to X-Forwarded-For rather
	// than replacing it — so the rightmost entry is the one Apache itself
	// set. Everything before it is client-supplied.
	r := httptest.NewRequest(http.MethodPost, "/signup", nil)
	r.RemoteAddr = "127.0.0.1:44321"
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.7")
	if got := clientIP(r); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want 203.0.113.7 (the proxy-appended entry)", got)
	}
}

func TestClientIPIsNotSpoofableViaLeftmostForwardedForEntry(t *testing.T) {
	// A caller can set any X-Forwarded-For header it likes. If clientIP
	// trusted the leftmost entry, a consenting user (or anyone hitting
	// /signup) could claim any IP address for the compliance audit trail
	// simply by sending "X-Forwarded-For: <whatever>, <real proxy hop>".
	r := httptest.NewRequest(http.MethodPost, "/signup", nil)
	r.RemoteAddr = "127.0.0.1:44321"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
	if got := clientIP(r); got == "6.6.6.6" {
		t.Fatal("clientIP trusted a client-spoofed leftmost entry")
	}
	if got := clientIP(r); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want 203.0.113.7 (the real proxy-observed client)", got)
	}
}

func TestClientIPFallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/signup", nil)
	r.RemoteAddr = "198.51.100.4:9999"
	if got := clientIP(r); got != "198.51.100.4" {
		t.Errorf("clientIP = %q, want 198.51.100.4", got)
	}
}
