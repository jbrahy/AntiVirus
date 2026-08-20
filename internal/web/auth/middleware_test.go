// internal/web/auth/middleware_test.go
package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequireAuthRedirectsWithoutSession(t *testing.T) {
	d := testDB(t)

	handler := RequireAuth(d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not run without a valid session")
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 redirect to /login", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("Location = %q, want /login", loc)
	}
}

func TestRequireAuthAllowsValidSession(t *testing.T) {
	d := testDB(t)

	u, err := CreateUser(d, uniqueEmail(t, "middleware-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token, err := CreateSession(d, u.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	called := false
	handler := RequireAuth(d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got, ok := UserFromContext(r.Context())
		if !ok || got.ID != u.ID {
			t.Fatalf("UserFromContext = %+v, %v", got, ok)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected inner handler to run with a valid session")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestOptionalAuthPassesThroughWithoutSession(t *testing.T) {
	d := testDB(t)

	called := false
	handler := OptionalAuth(d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := UserFromContext(r.Context()); ok {
			t.Fatal("expected no user in context for an anonymous request")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected inner handler to run even without a session")
	}
}
