package detections

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jbrahy/AntiVirus/internal/scanner"
)

type Detection struct {
	ID          int64
	Path        string
	Hash        string
	MatchedName string
	DetectedAt  time.Time
	Resolved    bool
	Resolution  string
}

func Enqueue(db *sql.DB, m scanner.Match) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO detections (path, hash, matched_name, detected_at, resolved) VALUES (?, ?, ?, ?, 0)`,
		m.Path, m.Hash, m.Entry.Name, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return 0, fmt.Errorf("enqueueing detection for %s: %w", m.Path, err)
	}
	return res.LastInsertId()
}

func ListPending(db *sql.DB) ([]Detection, error) {
	rows, err := db.Query(`SELECT id, path, hash, matched_name, detected_at, resolved, COALESCE(resolution, '') FROM detections WHERE resolved = 0 ORDER BY detected_at`)
	if err != nil {
		return nil, fmt.Errorf("listing pending detections: %w", err)
	}
	defer rows.Close()

	var out []Detection
	for rows.Next() {
		var d Detection
		var detectedAt string
		var resolved int
		if err := rows.Scan(&d.ID, &d.Path, &d.Hash, &d.MatchedName, &detectedAt, &resolved, &d.Resolution); err != nil {
			return nil, fmt.Errorf("scanning detection: %w", err)
		}
		d.DetectedAt, err = time.Parse(time.RFC3339, detectedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing detected_at: %w", err)
		}
		d.Resolved = resolved != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

func Resolve(db *sql.DB, id int64, resolution string) error {
	_, err := db.Exec(`UPDATE detections SET resolved = 1, resolution = ? WHERE id = ?`, resolution, id)
	if err != nil {
		return fmt.Errorf("resolving detection %d: %w", id, err)
	}
	return nil
}
