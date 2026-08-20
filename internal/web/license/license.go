// internal/web/license/license.go
package license

import (
	"crypto/rand"
	"crypto/sha256"
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

	// The SQL lookup above already matches on an exact hash equality; there is
	// no additional in-process comparison to make constant-time, since the DB
	// round-trip's timing dominates any theoretical signal a byte-level
	// compare would leak.
	var revokedAt sql.NullTime
	err = db.QueryRow(`SELECT user_id, revoked_at FROM licenses WHERE key_hash = ?`, hashHex).
		Scan(&userID, &revokedAt)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("looking up license: %w", err)
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
