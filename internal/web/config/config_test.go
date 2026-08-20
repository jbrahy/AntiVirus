package config

import (
	"strings"
	"testing"
)

func setAllRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DB_DSN", "user:pass@tcp(127.0.0.1:3306)/avtool_web")
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_x")
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_x")
	t.Setenv("STRIPE_PRICE_ID", "price_x")
	t.Setenv("CHECKOUT_SUCCESS_URL", "https://example.com/success")
	t.Setenv("CHECKOUT_CANCEL_URL", "https://example.com/cancel")
	t.Setenv("SESSION_SECRET", "supersecret")
}

func TestLoadSucceedsWithAllRequiredVars(t *testing.T) {
	setAllRequiredEnv(t)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Port != "8100" {
		t.Errorf("Port = %q, want default 8100", c.Port)
	}
	if c.DBDSN != "user:pass@tcp(127.0.0.1:3306)/avtool_web" {
		t.Errorf("DBDSN = %q", c.DBDSN)
	}
}

func TestLoadUsesExplicitPort(t *testing.T) {
	setAllRequiredEnv(t)
	t.Setenv("PORT", "9000")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Port != "9000" {
		t.Errorf("Port = %q, want 9000", c.Port)
	}
}

func TestLoadErrorsOnMissingVars(t *testing.T) {
	setAllRequiredEnv(t)
	t.Setenv("DB_DSN", "")
	t.Setenv("STRIPE_SECRET_KEY", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing DB_DSN and STRIPE_SECRET_KEY")
	}
	if !strings.Contains(err.Error(), "DB_DSN") || !strings.Contains(err.Error(), "STRIPE_SECRET_KEY") {
		t.Fatalf("error = %q, want it to name both missing vars", err.Error())
	}
}
