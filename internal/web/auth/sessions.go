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

// DeleteSession removes a session by its raw (unhashed) token, e.g. as read
// from the session cookie. Deleting an unknown token is not an error — it
// leaves the sessions table in the same state either way.
func DeleteSession(db *sql.DB, token string) error {
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	if _, err := db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashHex); err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}
