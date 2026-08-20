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
