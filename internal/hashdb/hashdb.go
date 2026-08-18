package hashdb

import (
	"database/sql"
	"fmt"
	"time"
)

type Entry struct {
	Hash    string
	Name    string
	Source  string // "manual" or "feed"
	AddedAt time.Time
}

func Upsert(db *sql.DB, entries []Entry) error {
	for _, e := range entries {
		if e.Source == "feed" {
			var existingSource string
			err := db.QueryRow(`SELECT source FROM hash_entries WHERE hash = ?`, e.Hash).Scan(&existingSource)
			if err == nil && existingSource == "manual" {
				continue
			}
			if err != nil && err != sql.ErrNoRows {
				return fmt.Errorf("checking existing entry for %s: %w", e.Hash, err)
			}
		}
		_, err := db.Exec(
			`INSERT INTO hash_entries (hash, name, source, added_at) VALUES (?, ?, ?, ?)
			 ON CONFLICT(hash) DO UPDATE SET name = excluded.name, source = excluded.source, added_at = excluded.added_at`,
			e.Hash, e.Name, e.Source, e.AddedAt.UTC().Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("upserting %s: %w", e.Hash, err)
		}
	}
	return nil
}

func Lookup(db *sql.DB, hash string) (*Entry, error) {
	var e Entry
	var addedAt string
	err := db.QueryRow(`SELECT hash, name, source, added_at FROM hash_entries WHERE hash = ?`, hash).
		Scan(&e.Hash, &e.Name, &e.Source, &addedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("looking up %s: %w", hash, err)
	}
	e.AddedAt, err = time.Parse(time.RFC3339, addedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing added_at for %s: %w", hash, err)
	}
	return &e, nil
}

func List(db *sql.DB) ([]Entry, error) {
	rows, err := db.Query(`SELECT hash, name, source, added_at FROM hash_entries ORDER BY added_at`)
	if err != nil {
		return nil, fmt.Errorf("listing entries: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var addedAt string
		if err := rows.Scan(&e.Hash, &e.Name, &e.Source, &addedAt); err != nil {
			return nil, fmt.Errorf("scanning entry: %w", err)
		}
		e.AddedAt, err = time.Parse(time.RFC3339, addedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing added_at: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func Remove(db *sql.DB, hash string) error {
	_, err := db.Exec(`DELETE FROM hash_entries WHERE hash = ?`, hash)
	if err != nil {
		return fmt.Errorf("removing %s: %w", hash, err)
	}
	return nil
}
