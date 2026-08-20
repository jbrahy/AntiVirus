// internal/web/auth/users_test.go
package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

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

func TestCreateUserAndVerifyPassword(t *testing.T) {
	d := testDB(t)
	email := uniqueEmail(t, "alice")

	u, err := CreateUser(d, email, "correct horse battery staple")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Email != email {
		t.Fatalf("Email = %q", u.Email)
	}

	got, err := VerifyPassword(d, email, "correct horse battery staple")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("VerifyPassword returned different user: %+v vs %+v", got, u)
	}
}

func TestCreateUserRejectsDuplicateEmail(t *testing.T) {
	d := testDB(t)
	email := uniqueEmail(t, "bob")

	if _, err := CreateUser(d, email, "password1"); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	if _, err := CreateUser(d, email, "password2"); err == nil {
		t.Fatal("expected error creating a user with a duplicate email")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	d := testDB(t)
	email := uniqueEmail(t, "carol")

	if _, err := CreateUser(d, email, "rightpassword"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := VerifyPassword(d, email, "wrongpassword"); err != ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestVerifyPasswordRejectsUnknownEmailWithSameError(t *testing.T) {
	d := testDB(t)

	if _, err := VerifyPassword(d, "doesnotexist@example.com", "anything"); err != ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials (no user-enumeration)", err)
	}
}
