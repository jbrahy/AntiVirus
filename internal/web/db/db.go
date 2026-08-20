package db

import (
	"database/sql"
	"fmt"

	"github.com/go-sql-driver/mysql"
)

func Open(dsn string) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing dsn: %w", err)
	}
	// DATETIME/TIMESTAMP columns only scan into time.Time when parseTime is
	// enabled; otherwise the driver returns raw []byte.
	cfg.ParseTime = true

	d, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	if err := d.Ping(); err != nil {
		d.Close()
		return nil, fmt.Errorf("connecting to db: %w", err)
	}
	return d, nil
}
