package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS hash_entries (
	hash TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	source TEXT NOT NULL CHECK (source IN ('manual','feed')),
	added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detections (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	path TEXT NOT NULL,
	hash TEXT NOT NULL,
	matched_name TEXT NOT NULL,
	detected_at TEXT NOT NULL,
	resolved INTEGER NOT NULL DEFAULT 0,
	resolution TEXT
);

CREATE TABLE IF NOT EXISTS quarantine_records (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	original_path TEXT NOT NULL,
	hash TEXT NOT NULL,
	quarantined_at TEXT NOT NULL,
	restored INTEGER NOT NULL DEFAULT 0
);
`

func Open(path string) (*sql.DB, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening db at %s: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	return db, nil
}
