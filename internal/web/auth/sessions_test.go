// internal/web/auth/sessions_test.go
package auth

import (
	"testing"
	"time"
)

func TestCreateAndValidateSession(t *testing.T) {
	d := testDB(t)

	u, err := CreateUser(d, uniqueEmail(t, "session-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	token, err := CreateSession(d, u.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty session token")
	}

	got, err := ValidateSession(d, token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("ValidateSession returned wrong user: %+v", got)
	}
}

func TestValidateSessionRejectsUnknownToken(t *testing.T) {
	d := testDB(t)

	if _, err := ValidateSession(d, "not-a-real-token"); err != ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestValidateSessionRejectsExpiredToken(t *testing.T) {
	d := testDB(t)

	u, err := CreateUser(d, uniqueEmail(t, "expired-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	token, err := CreateSession(d, u.ID, -time.Hour) // already expired
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if _, err := ValidateSession(d, token); err != ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials for an expired session", err)
	}
}
