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
	Phone        string
	PasswordHash string
	CreatedAt    time.Time
}

// Consent records what a user agreed to at signup, alongside the request
// metadata that evidences it. Service and marketing are tracked separately
// because the carrier standard forbids bundling them into one opt-in.
type Consent struct {
	SMSService   bool
	SMSMarketing bool
	IP           string
	UserAgent    string
}

func CreateUser(db *sql.DB, email, password string) (*User, error) {
	return CreateUserWithConsent(db, email, "", password, Consent{})
}

// CreateUserWithConsent stores the account plus the phone number and SMS
// consent captured at signup. A consent timestamp is written only when that
// specific box was ticked, so an unticked box leaves NULL rather than a zero
// time that could later read as "consented at the epoch".
func CreateUserWithConsent(db *sql.DB, email, phone, password string, c Consent) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	var phoneArg any
	if phone != "" {
		phoneArg = phone
	}
	var serviceAt, marketingAt any
	now := time.Now().UTC()
	if c.SMSService {
		serviceAt = now
	}
	if c.SMSMarketing {
		marketingAt = now
	}
	var ipArg, uaArg any
	if c.IP != "" {
		ipArg = c.IP
	}
	if c.UserAgent != "" {
		uaArg = c.UserAgent
	}

	res, err := db.Exec(`INSERT INTO users
		(email, phone, password_hash,
		 sms_service_consent, sms_service_consent_at,
		 sms_marketing_consent, sms_marketing_consent_at,
		 consent_ip, consent_user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		email, phoneArg, string(hash),
		c.SMSService, serviceAt,
		c.SMSMarketing, marketingAt,
		ipArg, uaArg)
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("reading new user id: %w", err)
	}

	return &User{ID: uint64(id), Email: email, Phone: phone, PasswordHash: string(hash)}, nil
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
