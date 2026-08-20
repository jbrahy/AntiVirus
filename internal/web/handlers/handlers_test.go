// internal/web/handlers/handlers_test.go
package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
	webdb "github.com/jbrahy/AntiVirus/internal/web/db"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = "root@tcp(127.0.0.1:3306)/avtool_web_test"
	}
	d, err := webdb.Open(dsn)
	if err != nil {
		t.Skipf("no reachable test MariaDB, skipping: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// uniqueEmail returns an email address that is unique to this test
// invocation, since the shared test database is not wiped between runs and
// users.email has a UNIQUE constraint.
func uniqueEmail(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating unique email suffix: %v", err)
	}
	return fmt.Sprintf("%s-%s@example.com", prefix, hex.EncodeToString(b))
}

func testTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.ParseGlob("../../../web/templates/*.html")
	if err != nil {
		t.Fatalf("parsing templates: %v", err)
	}
	return tmpl
}

func TestSignupCreatesUserAndSetsSessionCookie(t *testing.T) {
	d := testDB(t)
	tmpl := testTemplates(t)
	handler := SignupPage(d, tmpl)

	email := uniqueEmail(t, "newuser")
	form := url.Values{"email": {email}, "password": {"password123"}}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("Location = %q, want /dashboard", loc)
	}

	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "avtool_session" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a session cookie to be set after signup")
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	d := testDB(t)
	tmpl := testTemplates(t)

	// Seed a user directly via the signup handler first.
	email := uniqueEmail(t, "loginuser")
	signup := SignupPage(d, tmpl)
	form := url.Values{"email": {email}, "password": {"correctpassword"}}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	signup(httptest.NewRecorder(), req)

	login := LoginPage(d, tmpl)
	badForm := url.Values{"email": {email}, "password": {"wrongpassword"}}
	badReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(badForm.Encode()))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	login(rec, badReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (re-rendered form with error)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid") {
		t.Fatalf("body = %q, want it to mention an invalid-credentials error", rec.Body.String())
	}
}

func TestDashboardShowsNoSubscriptionForNewUser(t *testing.T) {
	d := testDB(t)
	tmpl := testTemplates(t)

	u, err := auth.CreateUser(d, uniqueEmail(t, "dash-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	handler := Dashboard(d, tmpl)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No active subscription") {
		t.Fatalf("body = %q, want it to mention no active subscription", rec.Body.String())
	}
}

func TestCheckoutRedirectSetsStripeCustomerIDAndRedirects(t *testing.T) {
	d := testDB(t)

	u, err := auth.CreateUser(d, uniqueEmail(t, "checkout-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// billing.CreateCheckoutSession makes a real call to Stripe's API, which
	// requires a real (test-mode) STRIPE_SECRET_KEY and network access. Skip
	// this test if one isn't configured for local/CI runs, the same way DB
	// tests skip without a reachable MariaDB - do not mock Stripe's API.
	stripeKey := os.Getenv("STRIPE_TEST_SECRET_KEY")
	if stripeKey == "" {
		t.Skip("STRIPE_TEST_SECRET_KEY not set, skipping test requiring real Stripe test-mode API access")
	}
	priceID := os.Getenv("STRIPE_TEST_PRICE_ID")
	if priceID == "" {
		t.Skip("STRIPE_TEST_PRICE_ID not set, skipping test requiring a real Stripe test-mode price")
	}

	handler := CheckoutRedirect(d, stripeKey, priceID, "https://example.com/success", "https://example.com/cancel")
	req := httptest.NewRequest(http.MethodGet, "/checkout", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "checkout.stripe.com") {
		t.Fatalf("Location = %q, want a stripe.com checkout URL", rec.Header().Get("Location"))
	}

	var storedCustomerID sql.NullString
	if err := d.QueryRow(`SELECT stripe_customer_id FROM users WHERE id = ?`, u.ID).Scan(&storedCustomerID); err != nil {
		t.Fatalf("querying stored customer id: %v", err)
	}
	if !storedCustomerID.Valid || storedCustomerID.String == "" {
		t.Fatal("expected stripe_customer_id to be persisted on the user row")
	}
}

// TestCheckoutRedirectReusesExistingStripeCustomerOnRepeatVisit is a
// regression test for a whole-branch review finding: a repeat visit to
// /checkout (back button, resubscribe, double-click) used to mint a SECOND
// Stripe Customer and overwrite users.stripe_customer_id, orphaning the
// first customer's webhook mapping. It must now reuse the customer ID
// persisted on the first visit.
func TestCheckoutRedirectReusesExistingStripeCustomerOnRepeatVisit(t *testing.T) {
	d := testDB(t)

	u, err := auth.CreateUser(d, uniqueEmail(t, "repeat-checkout-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	stripeKey := os.Getenv("STRIPE_TEST_SECRET_KEY")
	if stripeKey == "" {
		t.Skip("STRIPE_TEST_SECRET_KEY not set, skipping test requiring real Stripe test-mode API access")
	}
	priceID := os.Getenv("STRIPE_TEST_PRICE_ID")
	if priceID == "" {
		t.Skip("STRIPE_TEST_PRICE_ID not set, skipping test requiring a real Stripe test-mode price")
	}

	handler := CheckoutRedirect(d, stripeKey, priceID, "https://example.com/success", "https://example.com/cancel")

	req1 := httptest.NewRequest(http.MethodGet, "/checkout", nil)
	req1 = req1.WithContext(auth.ContextWithUser(req1.Context(), u))
	rec1 := httptest.NewRecorder()
	handler(rec1, req1)
	if rec1.Code != http.StatusFound {
		t.Fatalf("first checkout: status = %d, want 302", rec1.Code)
	}

	var firstCustomerID string
	if err := d.QueryRow(`SELECT stripe_customer_id FROM users WHERE id = ?`, u.ID).Scan(&firstCustomerID); err != nil {
		t.Fatalf("querying stored customer id after first checkout: %v", err)
	}
	if firstCustomerID == "" {
		t.Fatal("expected stripe_customer_id to be persisted after first checkout")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/checkout", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), u))
	rec2 := httptest.NewRecorder()
	handler(rec2, req2)
	if rec2.Code != http.StatusFound {
		t.Fatalf("second checkout: status = %d, want 302", rec2.Code)
	}

	var secondCustomerID string
	if err := d.QueryRow(`SELECT stripe_customer_id FROM users WHERE id = ?`, u.ID).Scan(&secondCustomerID); err != nil {
		t.Fatalf("querying stored customer id after second checkout: %v", err)
	}
	if secondCustomerID != firstCustomerID {
		t.Fatalf("second checkout: stripe_customer_id = %q, want it to still be %q (a repeat visit must reuse the existing customer, not mint a new one)", secondCustomerID, firstCustomerID)
	}
}

func TestLandingRendersNormallyForAnonymousVisitor(t *testing.T) {
	tmpl := testTemplates(t)

	handler := Landing(nil, tmpl)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an anonymous visitor", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "avtool") {
		t.Fatalf("body = %q, want it to mention avtool", rec.Body.String())
	}
}

// TestLandingRedirectsLoggedInUserToDashboard is a regression test for a
// whole-branch review finding: auth.OptionalAuth existed and was tested but
// was never wired to any route. Landing (behind auth.OptionalAuth in
// main.go) must behave differently for a caller with a valid session.
func TestLandingRedirectsLoggedInUserToDashboard(t *testing.T) {
	d := testDB(t)
	tmpl := testTemplates(t)

	u, err := auth.CreateUser(d, uniqueEmail(t, "landing-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	handler := Landing(d, tmpl)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 redirect for a logged-in visitor", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("Location = %q, want /dashboard", loc)
	}
}

// TestLogoutDeletesSessionAndClearsCookie is a regression test for a
// whole-branch review finding: there was no way to sign out — no /logout
// route, and nothing ever deleted a sessions row.
func TestLogoutDeletesSessionAndClearsCookie(t *testing.T) {
	d := testDB(t)

	u, err := auth.CreateUser(d, uniqueEmail(t, "logout-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token, err := auth.CreateSession(d, u.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	handler := LogoutHandler(d)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 redirect after logout", rec.Code)
	}

	var clearedCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			clearedCookie = c
		}
	}
	if clearedCookie == nil {
		t.Fatal("expected a Set-Cookie clearing the session cookie")
	}
	if clearedCookie.MaxAge >= 0 && !clearedCookie.Expires.Before(time.Now()) {
		t.Fatalf("cookie = %+v, want it cleared (negative MaxAge or an expired Expires)", clearedCookie)
	}

	if _, err := auth.ValidateSession(d, token); err != auth.ErrInvalidCredentials {
		t.Fatalf("ValidateSession after logout = %v, want ErrInvalidCredentials (session row should be gone)", err)
	}
}

// TestLogoutGracefulDegradationOnDeleteSessionError verifies that when
// DeleteSession fails (e.g., due to a DB connectivity issue), the logout
// handler still clears the cookie and redirects to /, rather than failing
// hard with a 500. The failure is logged server-side.
func TestLogoutGracefulDegradationOnDeleteSessionError(t *testing.T) {
	d := testDB(t)

	u, err := auth.CreateUser(d, uniqueEmail(t, "logout-error-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token, err := auth.CreateSession(d, u.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Create a closed DB connection to trigger a DeleteSession failure.
	closedDB := testDB(t)
	closedDB.Close()

	handler := LogoutHandler(closedDB)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler(rec, req)

	// Even though DeleteSession failed, the handler should still:
	// 1. Return a 302 redirect (not a 500)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 redirect (graceful degradation on DB error)", rec.Code)
	}

	// 2. Clear the session cookie
	var clearedCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			clearedCookie = c
		}
	}
	if clearedCookie == nil {
		t.Fatal("expected a Set-Cookie clearing the session cookie even on DB error")
	}
	if clearedCookie.MaxAge >= 0 && !clearedCookie.Expires.Before(time.Now()) {
		t.Fatalf("cookie = %+v, want it cleared (negative MaxAge or an expired Expires)", clearedCookie)
	}

	// 3. Redirect to /
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("Location = %q, want /", loc)
	}
}
