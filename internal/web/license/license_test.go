// internal/web/license/license_test.go
package license

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"testing"

	"database/sql"
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

var keyFormat = regexp.MustCompile(`^AVTOOL-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$`)

func TestGenerateProducesWellFormedUniqueKeys(t *testing.T) {
	d := testDB(t)
	u, err := auth.CreateUser(d, uniqueEmail(t, "license-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	k1, err := Generate(d, u.ID)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !keyFormat.MatchString(k1) {
		t.Fatalf("key %q does not match expected format", k1)
	}

	u2, err := auth.CreateUser(d, uniqueEmail(t, "license-user-2"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	k2, err := Generate(d, u2.ID)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if k1 == k2 {
		t.Fatal("expected two distinct generated keys")
	}
}

func TestValidateAcceptsGeneratedKey(t *testing.T) {
	d := testDB(t)
	u, err := auth.CreateUser(d, uniqueEmail(t, "validate-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	key, err := Generate(d, u.ID)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	userID, valid, err := Validate(d, key)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !valid {
		t.Fatal("expected freshly-generated key to be valid")
	}
	if userID != u.ID {
		t.Fatalf("userID = %d, want %d", userID, u.ID)
	}
}

func TestValidateRejectsUnknownKey(t *testing.T) {
	d := testDB(t)

	_, valid, err := Validate(d, "AVTOOL-0000-0000-0000-0000")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if valid {
		t.Fatal("expected an unknown key to be invalid")
	}
}

func TestValidateRejectsRevokedKey(t *testing.T) {
	d := testDB(t)
	u, err := auth.CreateUser(d, uniqueEmail(t, "revoke-user"), "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	key, err := Generate(d, u.ID)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := Revoke(d, key); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, valid, err := Validate(d, key)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if valid {
		t.Fatal("expected a revoked key to be invalid")
	}
}
