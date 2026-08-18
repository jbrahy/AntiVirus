package quarantine

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Record struct {
	ID            int64
	OriginalPath  string
	Hash          string
	QuarantinedAt time.Time
	Restored      bool
}

// quarantineFileName builds the on-disk name for a quarantined file's body.
// It is prefixed with the quarantine_records id so that two different files
// sharing the same content/hash don't collide on the same body file.
func quarantineFileName(id int64, hash string) string {
	return fmt.Sprintf("%d-%s", id, hash)
}

func Quarantine(db *sql.DB, quarantineDir, path, hash string) (int64, error) {
	if err := os.MkdirAll(quarantineDir, 0o755); err != nil {
		return 0, fmt.Errorf("creating quarantine dir: %w", err)
	}

	res, err := db.Exec(
		`INSERT INTO quarantine_records (original_path, hash, quarantined_at, restored) VALUES (?, ?, ?, 0)`,
		path, hash, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return 0, fmt.Errorf("recording quarantine: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("getting quarantine record id: %w", err)
	}

	dest := filepath.Join(quarantineDir, quarantineFileName(id, hash))
	if err := moveFile(path, dest); err != nil {
		return 0, fmt.Errorf("moving %s to quarantine: %w", path, err)
	}
	if err := os.Chmod(dest, 0o600); err != nil {
		return 0, fmt.Errorf("stripping execute bit on %s: %w", dest, err)
	}

	return id, nil
}

func Restore(db *sql.DB, quarantineDir string, id int64) error {
	var originalPath, hash string
	var restored bool
	err := db.QueryRow(`SELECT original_path, hash, restored FROM quarantine_records WHERE id = ?`, id).
		Scan(&originalPath, &hash, &restored)
	if err == sql.ErrNoRows {
		return fmt.Errorf("no quarantine record with id %d", id)
	}
	if err != nil {
		return fmt.Errorf("looking up quarantine record %d: %w", id, err)
	}
	if restored {
		return fmt.Errorf("quarantine record %d already restored", id)
	}

	src := filepath.Join(quarantineDir, quarantineFileName(id, hash))
	if err := moveFile(src, originalPath); err != nil {
		return fmt.Errorf("restoring %s: %w", originalPath, err)
	}

	_, err = db.Exec(`UPDATE quarantine_records SET restored = 1 WHERE id = ?`, id)
	return err
}

func Purge(db *sql.DB, quarantineDir string, id int64) error {
	var hash string
	var restored bool
	err := db.QueryRow(`SELECT hash, restored FROM quarantine_records WHERE id = ?`, id).Scan(&hash, &restored)
	if err == sql.ErrNoRows {
		return fmt.Errorf("no quarantine record with id %d", id)
	}
	if err != nil {
		return fmt.Errorf("looking up quarantine record %d: %w", id, err)
	}
	if !restored {
		if err := os.Remove(filepath.Join(quarantineDir, quarantineFileName(id, hash))); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing quarantined file: %w", err)
		}
	}
	_, err = db.Exec(`DELETE FROM quarantine_records WHERE id = ?`, id)
	return err
}

func List(db *sql.DB) ([]Record, error) {
	rows, err := db.Query(`SELECT id, original_path, hash, quarantined_at, restored FROM quarantine_records ORDER BY quarantined_at`)
	if err != nil {
		return nil, fmt.Errorf("listing quarantine records: %w", err)
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		var r Record
		var quarantinedAt string
		var restored int
		if err := rows.Scan(&r.ID, &r.OriginalPath, &r.Hash, &quarantinedAt, &restored); err != nil {
			return nil, fmt.Errorf("scanning quarantine record: %w", err)
		}
		r.QuarantinedAt, err = time.Parse(time.RFC3339, quarantinedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing quarantined_at: %w", err)
		}
		r.Restored = restored != 0
		records = append(records, r)
	}
	return records, rows.Err()
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return os.Remove(src)
}
