package scanner

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jbrahy/AntiVirus/internal/hashdb"
)

const maxScanSize = 500 * 1024 * 1024 // 500MB

type Match struct {
	Path  string
	Hash  string
	Entry hashdb.Entry
}

func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ScanFile(db *sql.DB, path string) (*Match, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil
	}
	if info.Size() > maxScanSize {
		return nil, nil
	}

	hash, err := HashFile(path)
	if err != nil {
		return nil, err
	}

	entry, err := hashdb.Lookup(db, hash)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return &Match{Path: path, Hash: hash, Entry: *entry}, nil
}

func Scan(db *sql.DB, root string) ([]Match, error) {
	var matches []Match
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", path, err)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		m, err := ScanFile(db, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", path, err)
			return nil
		}
		if m != nil {
			matches = append(matches, *m)
		}
		return nil
	})
	return matches, err
}
