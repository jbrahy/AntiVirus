// internal/web/handlers/api_test.go
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
	"github.com/jbrahy/AntiVirus/internal/web/license"
)

func TestValidateLicenseAPIAcceptsValidKey(t *testing.T) {
	d := testDB(t)

	u, err := auth.CreateUser(d, uniqueEmail(t, "api-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	key, err := license.Generate(d, u.ID)
	if err != nil {
		t.Fatalf("license.Generate: %v", err)
	}

	// An active subscription is what a valid license implies in practice
	// (see webhook.go's upsertSubscription); insert one so the response's
	// tier field has something real to report.
	if _, err := d.Exec(`
		INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, tier, status, current_period_end)
		VALUES (?, ?, ?, 'standard', 'active', NOW())`,
		u.ID, "cus_api_test_"+u.Email, "sub_api_test_"+u.Email); err != nil {
		t.Fatalf("inserting subscription: %v", err)
	}

	handler := ValidateLicenseAPI(d)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/license/validate", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"valid":true`) {
		t.Fatalf("body = %q, want valid:true", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"tier":"standard"`) {
		t.Fatalf("body = %q, want tier:\"standard\"", rec.Body.String())
	}
}

func TestValidateLicenseAPIRejectsUnknownKey(t *testing.T) {
	d := testDB(t)

	handler := ValidateLicenseAPI(d)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/license/validate", nil)
	req.Header.Set("X-API-Key", "AVTOOL-0000-0000-0000-0000")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"valid":false`) {
		t.Fatalf("body = %q, want valid:false", rec.Body.String())
	}
}
