# avtool-web Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build avtool-web — a Go service providing account signup/login, Stripe subscription billing, and license key issuance/validation for paid avtool subscribers.

**Architecture:** A new, independent Go binary (`cmd/avtool-web`) in the existing AntiVirus repo, sharing the module but with zero import coupling to the CLI's `internal/` packages. MariaDB-backed (not the CLI's SQLite). Bottom-up: config → DB connection → auth (users, sessions, middleware) → license → billing (Stripe) → HTTP handlers → final wiring.

**Tech Stack:** Go, `github.com/go-chi/chi/v5` (router), `github.com/go-sql-driver/mysql` (MariaDB driver), `golang.org/x/crypto/bcrypt`, `github.com/stripe/stripe-go` (Stripe SDK — exact major version resolved at implementation time via `go get`, see Task 6's note), MariaDB.

**Spec:** `docs/superpowers/specs/2026-08-20-avtool-web-foundation-design.md`

## Global Constraints

- No import coupling between `internal/web/*` and the CLI's existing `internal/*` packages — these are independent programs sharing a repo.
- MariaDB, not SQLite, for this service's storage.
- Config via environment variables only: `DB_DSN`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_ID`, `CHECKOUT_SUCCESS_URL`, `CHECKOUT_CANCEL_URL`, `SESSION_SECRET`, `PORT` (default `8100` if unset).
- License keys: random opaque tokens via `crypto/rand`, format `AVTOOL-XXXX-XXXX-XXXX-XXXX`, never derived from user data, stored hashed (SHA-256 hex) at rest, compared with `crypto/subtle.ConstantTimeCompare`.
- CLI-facing API (`/api/v1/license/validate`) auth: `X-API-Key` header, constant-time comparison, JSON in/out, `401` + `{"success":false,"error":"..."}` on auth failure — never a 500 for an invalid/unknown key.
- Login/signup errors: generic "invalid credentials" regardless of whether the email exists (no user-enumeration).
- Database-dependent tests require a real MariaDB reachable via `TEST_DB_DSN` (default `root@tcp(127.0.0.1:3306)/avtool_web_test` if unset) and must `t.Skip` gracefully if unreachable — do not mock the database.
- Module path: `github.com/jbrahy/AntiVirus`. Binary: `avtool-web`, built from `./cmd/avtool-web`.

---

### Task 1: Project scaffolding — config, health-check server

**Files:**
- Create: `internal/web/config/config.go`
- Create: `internal/web/config/config_test.go`
- Create: `cmd/avtool-web/main.go`
- Create: `cmd/avtool-web/main_test.go`

**Interfaces:**
- Produces: `config.Config{DBDSN, StripeSecretKey, StripeWebhookSecret, StripePriceID, CheckoutSuccessURL, CheckoutCancelURL, SessionSecret, Port string}`, `config.Load() (*Config, error)` — errors listing every missing required env var if any of `DB_DSN`/`STRIPE_SECRET_KEY`/`STRIPE_WEBHOOK_SECRET`/`STRIPE_PRICE_ID`/`CHECKOUT_SUCCESS_URL`/`CHECKOUT_CANCEL_URL`/`SESSION_SECRET` is unset; `Port` defaults to `"8100"`.
- Produces: a `net/http` server in `main.go` with a `GET /healthz` route returning `200 ok`, wired through `github.com/go-chi/chi/v5`.

- [ ] **Step 1: Initialize dependencies**

```bash
go get github.com/go-chi/chi/v5@latest
```

- [ ] **Step 2: Write the failing config test**

```go
// internal/web/config/config_test.go
package config

import "testing"

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
```

Add `"strings"` to the test file's imports.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/web/config/... -v`
Expected: FAIL to compile — `Load`/`Config` undefined.

- [ ] **Step 4: Implement config.go**

```go
// internal/web/config/config.go
package config

import (
	"fmt"
	"os"
)

type Config struct {
	DBDSN               string
	StripeSecretKey     string
	StripeWebhookSecret string
	StripePriceID       string
	CheckoutSuccessURL  string
	CheckoutCancelURL   string
	SessionSecret       string
	Port                string
}

func Load() (*Config, error) {
	c := &Config{
		DBDSN:               os.Getenv("DB_DSN"),
		StripeSecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		StripeWebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
		StripePriceID:       os.Getenv("STRIPE_PRICE_ID"),
		CheckoutSuccessURL:  os.Getenv("CHECKOUT_SUCCESS_URL"),
		CheckoutCancelURL:   os.Getenv("CHECKOUT_CANCEL_URL"),
		SessionSecret:       os.Getenv("SESSION_SECRET"),
		Port:                os.Getenv("PORT"),
	}
	if c.Port == "" {
		c.Port = "8100"
	}

	var missing []string
	if c.DBDSN == "" {
		missing = append(missing, "DB_DSN")
	}
	if c.StripeSecretKey == "" {
		missing = append(missing, "STRIPE_SECRET_KEY")
	}
	if c.StripeWebhookSecret == "" {
		missing = append(missing, "STRIPE_WEBHOOK_SECRET")
	}
	if c.StripePriceID == "" {
		missing = append(missing, "STRIPE_PRICE_ID")
	}
	if c.CheckoutSuccessURL == "" {
		missing = append(missing, "CHECKOUT_SUCCESS_URL")
	}
	if c.CheckoutCancelURL == "" {
		missing = append(missing, "CHECKOUT_CANCEL_URL")
	}
	if c.SessionSecret == "" {
		missing = append(missing, "SESSION_SECRET")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}
	return c, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/web/config/... -v`
Expected: PASS

- [ ] **Step 6: Write the failing health-check test**

```go
// cmd/avtool-web/main_test.go
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthzReturnsOK(t *testing.T) {
	r := newRouter()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "ok")
	}
}
```

- [ ] **Step 7: Run test to verify it fails**

Run: `go test ./cmd/avtool-web/... -v`
Expected: FAIL to compile — `newRouter` undefined.

- [ ] **Step 8: Implement main.go**

```go
// cmd/avtool-web/main.go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jbrahy/AntiVirus/internal/web/config"
)

func newRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	return r
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	r := newRouter()
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("avtool-web listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("server: %v", err)
	}
}
```

- [ ] **Step 9: Run test to verify it passes**

Run: `go test ./cmd/avtool-web/... -v`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add go.mod go.sum internal/web/config cmd/avtool-web
git commit -m "feat: scaffold avtool-web config and health-check server"
```

---

### Task 2: internal/web/db — MariaDB connection

**Files:**
- Create: `internal/web/db/db.go`
- Create: `internal/web/db/db_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `db.Open(dsn string) (*sql.DB, error)` — opens and pings; returns a wrapped error on either failure, never a nil `*sql.DB` with a nil error.

- [ ] **Step 1: Add the MySQL driver**

```bash
go get github.com/go-sql-driver/mysql@latest
```

- [ ] **Step 2: Write the failing tests**

```go
// internal/web/db/db_test.go
package db

import (
	"os"
	"testing"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = "root@tcp(127.0.0.1:3306)/avtool_web_test"
	}
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("no reachable test MariaDB at %s, skipping: %v", dsn, err)
	}
	d.Close()
	return dsn
}

func TestOpenPingsSuccessfully(t *testing.T) {
	dsn := testDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()
}

func TestOpenFailsOnUnreachableHost(t *testing.T) {
	_, err := Open("root:wrong@tcp(127.0.0.1:1)/nonexistent")
	if err == nil {
		t.Fatal("expected error opening a DSN pointing at an unreachable host")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/web/db/... -v`
Expected: FAIL to compile — `Open` undefined.

- [ ] **Step 4: Implement db.go**

```go
// internal/web/db/db.go
package db

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

func Open(dsn string) (*sql.DB, error) {
	d, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	if err := d.Ping(); err != nil {
		d.Close()
		return nil, fmt.Errorf("connecting to db: %w", err)
	}
	return d, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/web/db/... -v`
Expected: PASS (or SKIP for `TestOpenPingsSuccessfully` if no local MariaDB is reachable — that's an acceptable outcome per this plan's Global Constraints; `TestOpenFailsOnUnreachableHost` must still PASS regardless).

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/web/db
git commit -m "feat: add MariaDB connection helper"
```

---

### Task 3: database/avtool-web schema + internal/web/auth users

**Files:**
- Create: `database/avtool-web/001_schema.sql`
- Create: `internal/web/auth/users.go`
- Create: `internal/web/auth/users_test.go`

**Interfaces:**
- Consumes: `db.Open` (Task 2) in tests only.
- Produces: `auth.User{ID uint64; Email, PasswordHash string; CreatedAt time.Time}`, `auth.CreateUser(db *sql.DB, email, password string) (*User, error)` (bcrypt-hashes the password, returns error if email already exists), `auth.VerifyPassword(db *sql.DB, email, password string) (*User, error)` (returns `(nil, ErrInvalidCredentials)` for both "no such user" and "wrong password" — never distinguishes them, per the no-user-enumeration constraint).

- [ ] **Step 1: Write the full schema file**

```sql
-- database/avtool-web/001_schema.sql
CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  stripe_customer_id VARCHAR(255) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sessions (
  token_hash CHAR(64) NOT NULL PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS subscriptions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  stripe_customer_id VARCHAR(255) NOT NULL,
  stripe_subscription_id VARCHAR(255) NOT NULL UNIQUE,
  tier VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  current_period_end DATETIME NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS licenses (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  key_hash CHAR(64) NOT NULL UNIQUE,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at DATETIME NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

This file is applied manually at deploy time (`mysql -u user -p database < database/avtool-web/001_schema.sql`), matching the deployment convention described in the spec. It is also applied by hand against the local test database before running this task's tests: `mysql -u root < database/avtool-web/001_schema.sql` after `CREATE DATABASE IF NOT EXISTS avtool_web_test;` (or point `TEST_DB_DSN` at wherever you've applied it). Document in your report whether you had a reachable test MariaDB and applied this schema, or whether DB-dependent tests were skipped.

- [ ] **Step 2: Write the failing tests**

```go
// internal/web/auth/users_test.go
package auth

import (
	"database/sql"
	"os"
	"path/filepath"
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
	// Best-effort cleanup between tests; schema must already be applied.
	d.Exec("DELETE FROM users")
	t.Cleanup(func() { d.Close() })
	return d
}

func TestCreateUserAndVerifyPassword(t *testing.T) {
	d := testDB(t)

	u, err := CreateUser(d, "alice@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("Email = %q", u.Email)
	}

	got, err := VerifyPassword(d, "alice@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("VerifyPassword returned different user: %+v vs %+v", got, u)
	}
}

func TestCreateUserRejectsDuplicateEmail(t *testing.T) {
	d := testDB(t)

	if _, err := CreateUser(d, "bob@example.com", "password1"); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	if _, err := CreateUser(d, "bob@example.com", "password2"); err == nil {
		t.Fatal("expected error creating a user with a duplicate email")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	d := testDB(t)

	if _, err := CreateUser(d, "carol@example.com", "rightpassword"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := VerifyPassword(d, "carol@example.com", "wrongpassword"); err != ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestVerifyPasswordRejectsUnknownEmailWithSameError(t *testing.T) {
	d := testDB(t)

	if _, err := VerifyPassword(d, "doesnotexist@example.com", "anything"); err != ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials (no user-enumeration)", err)
	}
}
```

Remove the unused `"path/filepath"` import if your editor flags it — it isn't needed here.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/web/auth/... -v`
Expected: FAIL to compile — `CreateUser`/`VerifyPassword`/`ErrInvalidCredentials` undefined.

- [ ] **Step 4: Implement users.go**

```go
// internal/web/auth/users.go
package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type User struct {
	ID           uint64
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

func CreateUser(db *sql.DB, email, password string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	res, err := db.Exec(`INSERT INTO users (email, password_hash) VALUES (?, ?)`, email, string(hash))
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("reading new user id: %w", err)
	}

	return &User{ID: uint64(id), Email: email, PasswordHash: string(hash)}, nil
}

func VerifyPassword(db *sql.DB, email, password string) (*User, error) {
	var u User
	err := db.QueryRow(`SELECT id, email, password_hash, created_at FROM users WHERE email = ?`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err == sql.ErrNoRows {
		// Run bcrypt anyway against a dummy hash so a missing-user lookup
		// takes roughly the same time as a wrong-password lookup.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$CwTycUXWue0Thq9StjUM0uJ8Q9uMv/aYSbSD9RvzMOULdG7lF.dPS"), []byte(password))
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}
	return &u, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/web/auth/... -v`
Expected: PASS (or SKIP if no local MariaDB is reachable, per this plan's Global Constraints — document which happened in your report).

- [ ] **Step 6: Commit**

```bash
git add database/avtool-web internal/web/auth
git commit -m "feat: add avtool-web schema and user signup/login"
```

---

### Task 4: internal/web/auth sessions + HTTP middleware

**Files:**
- Create: `internal/web/auth/sessions.go`
- Create: `internal/web/auth/sessions_test.go`
- Create: `internal/web/auth/middleware.go`
- Create: `internal/web/auth/middleware_test.go`

**Interfaces:**
- Consumes: `auth.User` (Task 3).
- Produces: `auth.CreateSession(db *sql.DB, userID uint64, ttl time.Duration) (token string, err error)` (returns the raw token; only its SHA-256 hash is stored), `auth.ValidateSession(db *sql.DB, token string) (*User, error)` (looks up by hash, checks expiry, joins to `users`; returns `ErrInvalidCredentials` for unknown/expired), `auth.SessionCookieName = "avtool_session"`.
- Produces: `auth.RequireAuth(db *sql.DB) func(http.Handler) http.Handler` (chi-compatible middleware; redirects to `/login` if no valid session cookie), `auth.OptionalAuth(db *sql.DB) func(http.Handler) http.Handler` (attaches the user to the request context if present and valid, otherwise passes through unauthenticated — never redirects), `auth.UserFromContext(ctx context.Context) (*User, bool)`.

- [ ] **Step 1: Write the failing session tests**

```go
// internal/web/auth/sessions_test.go
package auth

import (
	"testing"
	"time"
)

func TestCreateAndValidateSession(t *testing.T) {
	d := testDB(t)

	u, err := CreateUser(d, "session-user@example.com", "password123")
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

	u, err := CreateUser(d, "expired-user@example.com", "password123")
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/auth/... -run Session -v`
Expected: FAIL to compile — `CreateSession`/`ValidateSession` undefined.

- [ ] **Step 3: Implement sessions.go**

```go
// internal/web/auth/sessions.go
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

const SessionCookieName = "avtool_session"

func CreateSession(db *sql.DB, userID uint64, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating session token: %w", err)
	}
	token := hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	expiresAt := time.Now().UTC().Add(ttl)
	_, err := db.Exec(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		hashHex, userID, expiresAt.Format("2006-01-02 15:04:05"))
	if err != nil {
		return "", fmt.Errorf("storing session: %w", err)
	}
	return token, nil
}

func ValidateSession(db *sql.DB, token string) (*User, error) {
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	var u User
	var expiresAt time.Time
	err := db.QueryRow(`
		SELECT u.id, u.email, u.password_hash, u.created_at, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ?`, hashHex).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("looking up session: %w", err)
	}
	if time.Now().UTC().After(expiresAt) {
		return nil, ErrInvalidCredentials
	}
	return &u, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/web/auth/... -run Session -v`
Expected: PASS (or SKIP without a reachable test MariaDB)

- [ ] **Step 5: Write the failing middleware tests**

```go
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

	u, err := CreateUser(d, "middleware-user@example.com", "password123")
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
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/web/auth/... -run Auth -v`
Expected: FAIL to compile — `RequireAuth`/`OptionalAuth`/`UserFromContext` undefined.

- [ ] **Step 7: Implement middleware.go**

```go
// internal/web/auth/middleware.go
package auth

import (
	"context"
	"database/sql"
	"net/http"
)

type contextKey struct{}

func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(contextKey{}).(*User)
	return u, ok
}

func RequireAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			u, err := ValidateSession(db, cookie.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			ctx := context.WithValue(r.Context(), contextKey{}, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func OptionalAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			u, err := ValidateSession(db, cookie.Value)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), contextKey{}, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./internal/web/auth/... -v`
Expected: PASS (or SKIP without a reachable test MariaDB)

- [ ] **Step 9: Commit**

```bash
git add internal/web/auth
git commit -m "feat: add avtool-web session management and auth middleware"
```

---

### Task 5: internal/web/license — key generation, storage, validation

**Files:**
- Create: `internal/web/license/license.go`
- Create: `internal/web/license/license_test.go`

**Interfaces:**
- Consumes: nothing new (only `*sql.DB`).
- Produces: `license.Generate(db *sql.DB, userID uint64) (key string, err error)` — creates a random `AVTOOL-XXXX-XXXX-XXXX-XXXX` key, stores its SHA-256 hash, returns the raw key (shown to the user exactly once). `license.Validate(db *sql.DB, key string) (userID uint64, valid bool, err error)` — constant-time hash comparison, `valid=false` (not an error) for unknown/revoked keys. `license.Revoke(db *sql.DB, key string) error`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/web/license/license_test.go
package license

import (
	"os"
	"regexp"
	"testing"

	webdb "github.com/jbrahy/AntiVirus/internal/web/db"
	"github.com/jbrahy/AntiVirus/internal/web/auth"
	"database/sql"
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
	d.Exec("DELETE FROM licenses")
	d.Exec("DELETE FROM sessions")
	d.Exec("DELETE FROM users")
	t.Cleanup(func() { d.Close() })
	return d
}

var keyFormat = regexp.MustCompile(`^AVTOOL-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$`)

func TestGenerateProducesWellFormedUniqueKeys(t *testing.T) {
	d := testDB(t)
	u, err := auth.CreateUser(d, "license-user@example.com", "password123")
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

	u2, err := auth.CreateUser(d, "license-user-2@example.com", "password123")
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
	u, err := auth.CreateUser(d, "validate-user@example.com", "password123")
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
	u, err := auth.CreateUser(d, "revoke-user@example.com", "password123")
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/license/... -v`
Expected: FAIL to compile — package doesn't exist yet.

- [ ] **Step 3: Implement license.go**

```go
// internal/web/license/license.go
package license

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

func Generate(db *sql.DB, userID uint64) (string, error) {
	groups := make([]string, 4)
	for i := range groups {
		b := make([]byte, 2)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("generating license key: %w", err)
		}
		groups[i] = strings.ToUpper(hex.EncodeToString(b))
	}
	key := "AVTOOL-" + strings.Join(groups, "-")

	hash := sha256.Sum256([]byte(key))
	hashHex := hex.EncodeToString(hash[:])

	_, err := db.Exec(`INSERT INTO licenses (user_id, key_hash) VALUES (?, ?)`, userID, hashHex)
	if err != nil {
		return "", fmt.Errorf("storing license: %w", err)
	}
	return key, nil
}

func Validate(db *sql.DB, key string) (userID uint64, valid bool, err error) {
	hash := sha256.Sum256([]byte(key))
	hashHex := hex.EncodeToString(hash[:])

	var storedHash string
	var revokedAt sql.NullTime
	err = db.QueryRow(`SELECT user_id, key_hash, revoked_at FROM licenses WHERE key_hash = ?`, hashHex).
		Scan(&userID, &storedHash, &revokedAt)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("looking up license: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(hashHex)) != 1 {
		return 0, false, nil
	}
	if revokedAt.Valid {
		return 0, false, nil
	}
	return userID, true, nil
}

func Revoke(db *sql.DB, key string) error {
	hash := sha256.Sum256([]byte(key))
	hashHex := hex.EncodeToString(hash[:])

	_, err := db.Exec(`UPDATE licenses SET revoked_at = NOW() WHERE key_hash = ?`, hashHex)
	if err != nil {
		return fmt.Errorf("revoking license: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/web/license/... -v`
Expected: PASS (or SKIP without a reachable test MariaDB)

- [ ] **Step 5: Commit**

```bash
git add internal/web/license
git commit -m "feat: add avtool-web license key generation and validation"
```

---

### Task 6: internal/web/billing — Stripe checkout + webhook

**Files:**
- Create: `internal/web/billing/checkout.go`
- Create: `internal/web/billing/webhook.go`
- Create: `internal/web/billing/webhook_test.go`

**Interfaces:**
- Consumes: `*sql.DB` (Task 2), `license.Generate` (Task 5).
- Produces: `billing.CreateCheckoutSession(stripeSecretKey, priceID, successURL, cancelURL, customerEmail string) (checkoutURL, stripeCustomerID string, err error)` — creates a Stripe Customer first (so we get an ID synchronously, before the user ever reaches Stripe's page), then a Checkout Session for that customer. The caller (Task 9's `/checkout` handler) is responsible for persisting `stripeCustomerID` onto the local `users` row immediately — this is what lets the webhook handler below map an incoming `customer.subscription.*` event's `customer` id back to a local user, without needing to special-case `checkout.session.completed` separately.
- Produces: `billing.HandleWebhook(db *sql.DB, webhookSecret string) http.HandlerFunc` — verifies the Stripe signature, and on `customer.subscription.created`/`.updated` upserts a `subscriptions` row keyed off `users.stripe_customer_id` (generating a license via `license.Generate` the first time a subscription for that user becomes `active`), and on `customer.subscription.deleted` marks the row `status='canceled'`.

Note: the exact Stripe Go SDK major version is resolved at implementation time via `go get github.com/stripe/stripe-go/v82@latest` (or whatever major version `go get` resolves to when this task runs — Stripe's SDK versions its import path by major version, e.g. `.../v82`, `.../v83`; adjust every import path below to match whatever actually gets pulled in, they are not literal contracts). The webhook-verification and Checkout Session creation call shapes (`webhook.ConstructEvent`, `session.New`) have been stable across recent Stripe Go SDK majors — implement against whatever version resolves, keeping the same function signatures this task specifies.

- [ ] **Step 1: Add the Stripe SDK**

```bash
go get github.com/stripe/stripe-go/v82@latest
```

If this resolves to a different major version, note the actual version in your report and adjust the import paths in Steps 3-4 accordingly — the package's public API surface used here (`stripe.Key`, `checkout/session.New`, `webhook.ConstructEvent`) has been stable across recent majors.

- [ ] **Step 2: Write the failing webhook test**

Stripe's webhook signing makes a fully offline unit test require constructing a valid signature, which the SDK itself provides via `webhook.GenerateTestSignedPayload` (or equivalent — check the resolved SDK version's `github.com/stripe/stripe-go/vNN/webhook` package for the exact test-signing helper name and adjust this test to use it). Write the test against that helper:

```go
// internal/web/billing/webhook_test.go
package billing

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	webdb "github.com/jbrahy/AntiVirus/internal/web/db"
	"database/sql"
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
	d.Exec("DELETE FROM subscriptions")
	d.Exec("DELETE FROM licenses")
	d.Exec("DELETE FROM users")
	t.Cleanup(func() { d.Close() })
	return d
}

func TestHandleWebhookRejectsBadSignature(t *testing.T) {
	d := testDB(t)
	handler := HandleWebhook(d, "whsec_test_secret")

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewBufferString(`{"type":"customer.subscription.created"}`))
	req.Header.Set("Stripe-Signature", "t=1,v1=deadbeef")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a bad signature", rec.Code)
	}
}
```

Write additional test(s) covering a valid signed `customer.subscription.created`/`.updated` event driving a `subscriptions` row upsert, using whatever test-signature-generation helper the resolved Stripe SDK version provides — consult its package docs (`go doc github.com/stripe/stripe-go/vNN/webhook`) for the exact helper and payload shape, since this varies slightly by SDK version and can't be pinned exactly in this plan. Document what you found and used in your report. Since `upsertSubscription` looks up the user by `users.stripe_customer_id`, this test must first insert a `users` row with a known `stripe_customer_id` (e.g. `INSERT INTO users (email, password_hash, stripe_customer_id) VALUES (...)`) matching the `customer` id in the synthetic event payload — otherwise the lookup will correctly fail with "no such user," which is the right behavior for an event about an unknown customer, but not what this particular test is trying to exercise.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/web/billing/... -v`
Expected: FAIL to compile — package doesn't exist yet.

- [ ] **Step 4: Implement checkout.go**

```go
// internal/web/billing/checkout.go
package billing

import (
	"fmt"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/customer"
)

func CreateCheckoutSession(stripeSecretKey, priceID, successURL, cancelURL, customerEmail string) (checkoutURL, stripeCustomerID string, err error) {
	stripe.Key = stripeSecretKey

	cust, err := customer.New(&stripe.CustomerParams{Email: stripe.String(customerEmail)})
	if err != nil {
		return "", "", fmt.Errorf("creating stripe customer: %w", err)
	}

	params := &stripe.CheckoutSessionParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		SuccessURL: stripe.String(successURL),
		CancelURL:  stripe.String(cancelURL),
		Customer:   stripe.String(cust.ID),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
	}

	sess, err := session.New(params)
	if err != nil {
		return "", "", fmt.Errorf("creating checkout session: %w", err)
	}
	return sess.URL, cust.ID, nil
}
```

(Adjust field names above if the resolved SDK major version's `CheckoutSessionParams`/`CustomerParams` shape differs slightly — the customer-then-checkout-session flow itself, and the fields used here, have been stable, but confirm against `go doc` for the version that actually got pulled in.)

- [ ] **Step 5: Implement webhook.go**

```go
// internal/web/billing/webhook.go
package billing

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/license"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"
)

func HandleWebhook(db *sql.DB, webhookSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading request body", http.StatusBadRequest)
			return
		}

		event, err := webhook.ConstructEvent(payload, r.Header.Get("Stripe-Signature"), webhookSecret)
		if err != nil {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		switch event.Type {
		case "customer.subscription.created", "customer.subscription.updated":
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				http.Error(w, "parsing subscription payload", http.StatusBadRequest)
				return
			}
			if err := upsertSubscription(db, &sub); err != nil {
				http.Error(w, fmt.Sprintf("processing subscription: %v", err), http.StatusInternalServerError)
				return
			}
		case "customer.subscription.deleted":
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				http.Error(w, "parsing subscription payload", http.StatusBadRequest)
				return
			}
			if err := cancelSubscription(db, sub.ID); err != nil {
				http.Error(w, fmt.Sprintf("canceling subscription: %v", err), http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
	}
}

func upsertSubscription(db *sql.DB, sub *stripe.Subscription) error {
	// users.stripe_customer_id is populated synchronously by the /checkout
	// handler (Task 9) at the moment the Stripe Customer is created, before
	// the user ever reaches Stripe's page — so by the time this webhook
	// fires, the mapping already exists and this lookup is never racing
	// against it.
	var userID uint64
	err := db.QueryRow(`SELECT id FROM users WHERE stripe_customer_id = ?`, sub.Customer.ID).Scan(&userID)
	if err != nil {
		return fmt.Errorf("looking up user for stripe customer %s: %w", sub.Customer.ID, err)
	}

	_, err = db.Exec(`
		INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, tier, status, current_period_end)
		VALUES (?, ?, ?, ?, ?, FROM_UNIXTIME(?))
		ON DUPLICATE KEY UPDATE status = VALUES(status), current_period_end = VALUES(current_period_end)`,
		userID, sub.Customer.ID, sub.ID, "standard", string(sub.Status), sub.CurrentPeriodEnd)
	if err != nil {
		return fmt.Errorf("upserting subscription: %w", err)
	}
	return nil
}

func cancelSubscription(db *sql.DB, stripeSubscriptionID string) error {
	_, err := db.Exec(`UPDATE subscriptions SET status = 'canceled' WHERE stripe_subscription_id = ?`, stripeSubscriptionID)
	if err != nil {
		return fmt.Errorf("canceling subscription: %w", err)
	}
	return nil
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/web/billing/... -v`
Expected: PASS (or SKIP without a reachable test MariaDB) — including after resolving the schema gap above.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum database/avtool-web internal/web/billing
git commit -m "feat: add Stripe checkout session creation and webhook handling"
```

---

### Task 7: internal/web/handlers — signup and login

**Files:**
- Create: `internal/web/handlers/signup.go`
- Create: `internal/web/handlers/login.go`
- Create: `internal/web/handlers/handlers_test.go`
- Create: `web/templates/signup.html`
- Create: `web/templates/login.html`

**Interfaces:**
- Consumes: `auth.CreateUser`/`VerifyPassword`/`CreateSession` (Tasks 3-4).
- Produces: `handlers.SignupPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc` (GET renders the form, POST creates the user + a session, sets the `avtool_session` cookie, redirects to `/dashboard`), `handlers.LoginPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc` (same shape for login).

- [ ] **Step 1: Write minimal templates**

```html
<!-- web/templates/signup.html -->
<!doctype html>
<html>
<head><title>Sign up — avtool</title></head>
<body>
  <h1>Create your avtool account</h1>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form method="post" action="/signup">
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign up</button>
  </form>
</body>
</html>
```

```html
<!-- web/templates/login.html -->
<!doctype html>
<html>
<head><title>Log in — avtool</title></head>
<body>
  <h1>Log in to avtool</h1>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form method="post" action="/login">
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Log in</button>
  </form>
</body>
</html>
```

- [ ] **Step 2: Write the failing handler tests**

```go
// internal/web/handlers/handlers_test.go
package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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
	d.Exec("DELETE FROM sessions")
	d.Exec("DELETE FROM users")
	t.Cleanup(func() { d.Close() })
	return d
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

	form := url.Values{"email": {"newuser@example.com"}, "password": {"password123"}}
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
	signup := SignupPage(d, tmpl)
	form := url.Values{"email": {"loginuser@example.com"}, "password": {"correctpassword"}}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	signup(httptest.NewRecorder(), req)

	login := LoginPage(d, tmpl)
	badForm := url.Values{"email": {"loginuser@example.com"}, "password": {"wrongpassword"}}
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/web/handlers/... -v`
Expected: FAIL to compile — `SignupPage`/`LoginPage` undefined.

- [ ] **Step 4: Implement signup.go**

```go
// internal/web/handlers/signup.go
package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	"time"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
)

const sessionTTL = 30 * 24 * time.Hour

func SignupPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tmpl.ExecuteTemplate(w, "signup.html", nil)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		u, err := auth.CreateUser(db, email, password)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			tmpl.ExecuteTemplate(w, "signup.html", map[string]string{"Error": "Could not create account. That email may already be in use."})
			return
		}

		token, err := auth.CreateSession(db, u.ID, sessionTTL)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     auth.SessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(sessionTTL),
		})
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}
}
```

- [ ] **Step 5: Implement login.go**

```go
// internal/web/handlers/login.go
package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	"time"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
)

func LoginPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tmpl.ExecuteTemplate(w, "login.html", nil)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		u, err := auth.VerifyPassword(db, email, password)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid email or password."})
			return
		}

		token, err := auth.CreateSession(db, u.ID, sessionTTL)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     auth.SessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(sessionTTL),
		})
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/web/handlers/... -v`
Expected: PASS (or SKIP without a reachable test MariaDB)

- [ ] **Step 7: Commit**

```bash
git add internal/web/handlers web/templates
git commit -m "feat: add avtool-web signup and login handlers"
```

---

### Task 8: internal/web/handlers — landing page and dashboard

**Files:**
- Create: `internal/web/handlers/landing.go`
- Create: `internal/web/handlers/dashboard.go`
- Modify: `internal/web/handlers/handlers_test.go`
- Create: `web/templates/landing.html`
- Create: `web/templates/dashboard.html`

**Interfaces:**
- Consumes: `auth.UserFromContext` (Task 4), `license.Generate` (Task 5).
- Produces: `handlers.Landing(tmpl *template.Template) http.HandlerFunc` (static marketing copy, no auth required). `handlers.Dashboard(db *sql.DB, tmpl *template.Template) http.HandlerFunc` (must run behind `auth.RequireAuth`; shows subscription status — "no active subscription" if none — the user's license key if one exists, and a "no machines yet" placeholder line for the future fleet feature).

- [ ] **Step 1: Write the landing page copy — honest positioning, no overselling**

```html
<!-- web/templates/landing.html -->
<!doctype html>
<html>
<head><title>avtool</title></head>
<body>
  <h1>avtool</h1>
  <p>avtool scans your Mac for files matching known-malicious SHA256
  hashes, pulled from a public threat intelligence feed. It is a
  known-threat hash scanner — it does not use heuristics or behavioral
  detection, so it will not catch malware that isn't byte-identical to
  a sample already in its hash database. Pair it with, not instead of,
  your existing security tools.</p>
  <p><a href="https://github.com/jbrahy/AntiVirus">avtool is free and
  open source.</a> A paid subscription adds a premium curated threat
  feed, a multi-machine fleet dashboard, and priority support.</p>
  <p><a href="/signup">Sign up</a> | <a href="/login">Log in</a></p>
</body>
</html>
```

```html
<!-- web/templates/dashboard.html -->
<!doctype html>
<html>
<head><title>Dashboard — avtool</title></head>
<body>
  <h1>Your avtool account</h1>
  <p>Signed in as {{.Email}}</p>

  <h2>Subscription</h2>
  {{if .HasSubscription}}
    <p>Status: {{.SubscriptionStatus}}</p>
  {{else}}
    <p>No active subscription. <a href="/checkout">Subscribe</a></p>
  {{end}}

  <h2>License key</h2>
  {{if .LicenseKey}}
    <p><code>{{.LicenseKey}}</code></p>
  {{else}}
    <p>No license key yet — subscribe to get one.</p>
  {{end}}

  <h2>Machines</h2>
  <p>No machines yet. Fleet reporting is coming soon.</p>
</body>
</html>
```

- [ ] **Step 2: Write the failing dashboard test**

Add to `internal/web/handlers/handlers_test.go`:

```go
func TestDashboardShowsNoSubscriptionForNewUser(t *testing.T) {
	d := testDB(t)
	tmpl := testTemplates(t)

	u, err := auth.CreateUser(d, "dash-user@example.com", "password123")
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
```

Add `"github.com/jbrahy/AntiVirus/internal/web/auth"` to the test file's imports.

This test requires a new small exported helper, `auth.ContextWithUser(ctx, u) context.Context`, that Task 4 did not need (its own tests only ever went through the middleware, never constructed the context directly) — add it to `internal/web/auth/middleware.go` now:

```go
// add to internal/web/auth/middleware.go
func ContextWithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, contextKey{}, u)
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/web/handlers/... -run Dashboard -v`
Expected: FAIL to compile — `Dashboard`/`ContextWithUser` undefined.

- [ ] **Step 4: Implement landing.go**

```go
// internal/web/handlers/landing.go
package handlers

import (
	"html/template"
	"net/http"
)

func Landing(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl.ExecuteTemplate(w, "landing.html", nil)
	}
}
```

- [ ] **Step 5: Implement dashboard.go**

```go
// internal/web/handlers/dashboard.go
package handlers

import (
	"database/sql"
	"html/template"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
)

type dashboardData struct {
	Email              string
	HasSubscription    bool
	SubscriptionStatus string
	LicenseKey         string
}

func Dashboard(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.UserFromContext(r.Context())
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		data := dashboardData{Email: u.Email}

		var status string
		err := db.QueryRow(`SELECT status FROM subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 1`, u.ID).Scan(&status)
		if err == nil {
			data.HasSubscription = true
			data.SubscriptionStatus = status
		}

		// License keys are shown once at generation time in a real
		// checkout-completion flow; showing the most recent one here
		// keeps the dashboard useful even without that flow wired up yet.
		// This queries key_hash, not the raw key, since raw keys are
		// never stored — a real integration would surface the key at
		// generation time (e.g. via a one-time flash message) rather
		// than trying to redisplay it later. Documented here rather
		// than silently faked.

		w.WriteHeader(http.StatusOK)
		tmpl.ExecuteTemplate(w, "dashboard.html", data)
	}
}
```

**Known gap to flag, not silently fix:** because only `key_hash` is ever stored (never the raw key, per this plan's Global Constraints), the dashboard cannot redisplay a previously-generated license key after the user navigates away from the one-time reveal. This plan does not resolve that UX gap — a real implementation needs either a one-time flash-message reveal at generation time, or an explicit "regenerate license key" action the user can take (invalidating the old one). Leave `LicenseKey` empty in `dashboardData` for this task (do not query for it, since there is nothing valid to query), and say so plainly in your report rather than inventing a way to "look up" a value that is cryptographically not recoverable.

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/web/handlers/... -v`
Expected: PASS (or SKIP without a reachable test MariaDB)

- [ ] **Step 7: Commit**

```bash
git add internal/web/auth internal/web/handlers web/templates
git commit -m "feat: add avtool-web landing page and account dashboard"
```

---

### Task 9: License validation API, checkout initiation + final wiring

**Files:**
- Create: `internal/web/handlers/api.go`
- Create: `internal/web/handlers/api_test.go`
- Create: `internal/web/handlers/checkout.go`
- Modify: `internal/web/handlers/handlers_test.go`
- Modify: `cmd/avtool-web/main.go`
- Modify: `cmd/avtool-web/main_test.go`

**Interfaces:**
- Consumes: `license.Validate` (Task 5), `billing.CreateCheckoutSession` (Task 6), `handlers.Landing`/`SignupPage`/`LoginPage`/`Dashboard` (Tasks 7-8), `auth.RequireAuth`/`OptionalAuth`/`UserFromContext` (Task 4).
- Produces: `handlers.ValidateLicenseAPI(db *sql.DB) http.HandlerFunc` — `POST /api/v1/license/validate`, reads the license key from the `X-API-Key` header, returns `200 {"valid":true}` or `401 {"valid":false,"error":"invalid or unknown license key"}`.
- Produces: `handlers.CheckoutRedirect(db *sql.DB, stripeSecretKey, priceID, successURL, cancelURL string) http.HandlerFunc` — must run behind `auth.RequireAuth`. Calls `billing.CreateCheckoutSession` with the logged-in user's email, persists the returned Stripe customer id onto that user's row (`UPDATE users SET stripe_customer_id = ?`), then 302-redirects to the returned checkout URL. This is what the dashboard's "Subscribe" link (`/checkout`, written in Task 8) actually needs to work — Task 8 wrote the link but this task is what serves it.
- Produces: the final `newRouter` in `main.go` wiring every route together with parsed templates, including `GET /checkout` behind `RequireAuth`.

- [ ] **Step 1: Write the failing API test**

```go
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

	u, err := auth.CreateUser(d, "api-user@example.com", "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	key, err := license.Generate(d, u.ID)
	if err != nil {
		t.Fatalf("license.Generate: %v", err)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/handlers/... -run ValidateLicenseAPI -v`
Expected: FAIL to compile — `ValidateLicenseAPI` undefined.

- [ ] **Step 3: Implement api.go**

```go
// internal/web/handlers/api.go
package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/license"
)

func ValidateLicenseAPI(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": "missing X-API-Key header"})
			return
		}

		_, valid, err := license.Validate(db, key)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": "internal error"})
			return
		}
		if !valid {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": "invalid or unknown license key"})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"valid": true})
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/web/handlers/... -v`
Expected: PASS (or SKIP without a reachable test MariaDB)

- [ ] **Step 4b: Write the failing checkout-redirect test**

Add to `internal/web/handlers/handlers_test.go`:

```go
func TestCheckoutRedirectSetsStripeCustomerIDAndRedirects(t *testing.T) {
	d := testDB(t)

	u, err := auth.CreateUser(d, "checkout-user@example.com", "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// billing.CreateCheckoutSession makes a real call to Stripe's API, which
	// requires a real (test-mode) STRIPE_SECRET_KEY and network access. Skip
	// this test if one isn't configured for local/CI runs, the same way DB
	// tests skip without a reachable MariaDB — do not mock Stripe's API.
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
```

- [ ] **Step 4c: Run test to verify it fails**

Run: `go test ./internal/web/handlers/... -run CheckoutRedirect -v`
Expected: FAIL to compile — `CheckoutRedirect` undefined.

- [ ] **Step 4d: Implement checkout.go**

```go
// internal/web/handlers/checkout.go
package handlers

import (
	"database/sql"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
	"github.com/jbrahy/AntiVirus/internal/web/billing"
)

func CheckoutRedirect(db *sql.DB, stripeSecretKey, priceID, successURL, cancelURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.UserFromContext(r.Context())
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		checkoutURL, stripeCustomerID, err := billing.CreateCheckoutSession(stripeSecretKey, priceID, successURL, cancelURL, u.Email)
		if err != nil {
			http.Error(w, "could not start checkout", http.StatusInternalServerError)
			return
		}

		if _, err := db.Exec(`UPDATE users SET stripe_customer_id = ? WHERE id = ?`, stripeCustomerID, u.ID); err != nil {
			http.Error(w, "could not save checkout state", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, checkoutURL, http.StatusFound)
	}
}
```

- [ ] **Step 4e: Run test to verify it passes**

Run: `go test ./internal/web/handlers/... -run CheckoutRedirect -v`
Expected: PASS (or SKIP without `STRIPE_TEST_SECRET_KEY`/`STRIPE_TEST_PRICE_ID`/a reachable test MariaDB configured)

- [ ] **Step 5: Write the failing final-wiring test**

```go
// cmd/avtool-web/main_test.go — add this test, keep TestHealthzReturnsOK as-is
func TestLandingPageServesWithoutAuth(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = "root@tcp(127.0.0.1:3306)/avtool_web_test"
	}
	d, err := webdb.Open(dsn)
	if err != nil {
		t.Skipf("no reachable test MariaDB, skipping: %v", err)
	}
	defer d.Close()

	tmpl, err := template.ParseGlob("../../web/templates/*.html")
	if err != nil {
		t.Fatalf("parsing templates: %v", err)
	}

	cfg := &config.Config{StripeSecretKey: "sk_test_x", StripePriceID: "price_x", CheckoutSuccessURL: "https://example.com/success", CheckoutCancelURL: "https://example.com/cancel"}
	r := newRouter(d, tmpl, cfg)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "avtool") {
		t.Fatalf("body = %q, want it to mention avtool", rec.Body.String())
	}
}
```

Add `"database/sql"`, `"html/template"`, `"os"`, `"strings"`, `"github.com/jbrahy/AntiVirus/internal/web/config"`, and `webdb "github.com/jbrahy/AntiVirus/internal/web/db"` to the test file's imports.

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./cmd/avtool-web/... -v`
Expected: FAIL to compile — `newRouter`'s signature no longer matches (it currently takes no arguments; this test calls it with three).

- [ ] **Step 7: Rewrite main.go with full route wiring**

```go
// cmd/avtool-web/main.go
package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jbrahy/AntiVirus/internal/web/auth"
	"github.com/jbrahy/AntiVirus/internal/web/config"
	webdb "github.com/jbrahy/AntiVirus/internal/web/db"
	"github.com/jbrahy/AntiVirus/internal/web/handlers"
)

func newRouter(db *sql.DB, tmpl *template.Template, cfg *config.Config) *chi.Mux {
	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	r.Get("/", handlers.Landing(tmpl))
	r.Get("/signup", handlers.SignupPage(db, tmpl))
	r.Post("/signup", handlers.SignupPage(db, tmpl))
	r.Get("/login", handlers.LoginPage(db, tmpl))
	r.Post("/login", handlers.LoginPage(db, tmpl))

	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth(db))
		r.Get("/dashboard", handlers.Dashboard(db, tmpl))
		r.Get("/checkout", handlers.CheckoutRedirect(db, cfg.StripeSecretKey, cfg.StripePriceID, cfg.CheckoutSuccessURL, cfg.CheckoutCancelURL))
	})

	r.Post("/api/v1/license/validate", handlers.ValidateLicenseAPI(db))

	return r
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	db, err := webdb.Open(cfg.DBDSN)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	tmpl, err := template.ParseGlob("web/templates/*.html")
	if err != nil {
		log.Fatalf("templates: %v", err)
	}

	r := newRouter(db, tmpl, cfg)
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("avtool-web listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("server: %v", err)
	}
}
```

Update `TestHealthzReturnsOK` in `main_test.go` to match the new `newRouter(db, tmpl, cfg)` signature (build `testDB`/`testTemplates`/a minimal `cfg` the same way `TestLandingPageServesWithoutAuth` above does, or factor a tiny shared test helper — your call, keep it simple).

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./cmd/avtool-web/... -v`
Expected: PASS (or SKIP without a reachable test MariaDB)

- [ ] **Step 9: Run the full test suite and build the binary**

```bash
go build -o bin/avtool-web ./cmd/avtool-web
go vet ./...
go test ./...
```

Expected: build succeeds, `go vet` reports nothing, all tests PASS or SKIP (never FAIL). Confirm the existing CLI's tests (`cmd/avtool/...`, `internal/hashdb`, etc.) are completely unaffected — this task must not touch anything outside `internal/web`, `cmd/avtool-web`, `web/`, `database/avtool-web`.

- [ ] **Step 10: Commit**

```bash
git add internal/web cmd/avtool-web
git commit -m "feat: add license validation API and wire avtool-web's full route table"
```

---

## Deferred past this Foundation plan (per spec)

- Premium feed pipeline and CLI's `sync premium` command.
- Fleet check-in endpoint, CLI phone-home reporting, real fleet dashboard UI.
- CLI-side `avtool license activate/status` commands.
- Domain registration, DNS, systemd unit + Apache vhost + certbot setup on `pm-prod-development`, and final Stripe account configuration — these are deployment/ops steps blocked on the user's open-question answers (domain name, Stripe account choice), not code.
- Redisplaying a previously-generated license key on the dashboard (flagged explicitly in Task 8 as a real UX gap needing a one-time-reveal or regenerate-key flow, not resolved by this plan).
- License revocation UI/admin flow — `license.Revoke` (Task 5) exists and is tested, but no handler or dashboard action calls it yet in this Foundation.
