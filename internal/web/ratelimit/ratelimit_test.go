// internal/web/ratelimit/ratelimit_test.go
package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAllowsUpToMaxThenBlocks(t *testing.T) {
	l := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("attempt %d: expected allowed", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("4th attempt within window: expected blocked")
	}
}

func TestDistinctKeysHaveIndependentLimits(t *testing.T) {
	l := New(1, time.Minute)
	if !l.Allow("a") {
		t.Fatal("first attempt for key a: expected allowed")
	}
	if !l.Allow("b") {
		t.Fatal("first attempt for key b: expected allowed, independent of key a")
	}
	if l.Allow("a") {
		t.Fatal("second attempt for key a: expected blocked")
	}
}

func TestOldAttemptsExpireOutOfWindow(t *testing.T) {
	l := New(1, 20*time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("first attempt: expected allowed")
	}
	if l.Allow("k") {
		t.Fatal("immediate second attempt: expected blocked")
	}
	time.Sleep(30 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("attempt after window elapsed: expected allowed")
	}
}

func TestMiddlewareReturns429WhenExceeded(t *testing.T) {
	l := New(1, time.Minute)
	handler := Middleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "203.0.113.9:5555"

	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: status = %d, want 429", rec2.Code)
	}
}

func TestMiddlewareCannotBeBypassedBySpoofingLeftmostForwardedFor(t *testing.T) {
	// Regression test for the actual exploit the leftmost-XFF bug enabled:
	// hammer the same real proxy hop while sending a different fake
	// leftmost X-Forwarded-For value on every request. If ClientIP ever
	// keys on that spoofable part again, this passes when it shouldn't.
	l := New(1, time.Minute)
	handler := Middleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	fakeLeftmostIPs := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	var lastCode int
	for _, fake := range fakeLeftmostIPs {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:9999" // same real proxy hop every time
		req.Header.Set("X-Forwarded-For", fake+", 203.0.113.7")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("after %d requests from the same real client with spoofed leftmost XFF values, status = %d, want 429", len(fakeLeftmostIPs), lastCode)
	}
}

func TestClientIPTrustsOnlyTheProxyAppendedRightmostEntry(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.7")
	if got := ClientIP(req); got != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want 203.0.113.7 (the proxy-appended entry)", got)
	}
}

func TestClientIPIsNotSpoofableViaLeftmostForwardedForEntry(t *testing.T) {
	// A caller could otherwise defeat rate limiting entirely by sending a
	// different fake leftmost X-Forwarded-For value on every request.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
	if got := ClientIP(req); got == "6.6.6.6" {
		t.Fatal("ClientIP trusted a client-spoofed leftmost entry")
	}
}

func TestClientIPFallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.4:1234"
	if got := ClientIP(req); got != "198.51.100.4" {
		t.Errorf("ClientIP = %q, want 198.51.100.4", got)
	}
}
