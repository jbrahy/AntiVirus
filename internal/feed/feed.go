package feed

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jbrahy/AntiVirus/internal/hashdb"
)

// DefaultURL is MalwareBazaar's recent-additions CSV feed (no API key required).
const DefaultURL = "https://bazaar.abuse.ch/export/csv/recent/"

const (
	colSHA256    = 1
	colSignature = 8
)

func Fetch(client *http.Client, url string) ([]hashdb.Entry, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching feed: unexpected status %s", resp.Status)
	}
	return Parse(resp.Body)
}

func Parse(r io.Reader) ([]hashdb.Entry, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.Comment = '#'

	now := time.Now().UTC()
	var entries []hashdb.Entry
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing feed row: %w", err)
		}
		if len(record) <= colSignature {
			continue
		}
		hash := strings.TrimSpace(record[colSHA256])
		if hash == "" {
			continue
		}
		name := strings.TrimSpace(record[colSignature])
		if name == "" {
			name = "unknown"
		}
		entries = append(entries, hashdb.Entry{
			Hash:    hash,
			Name:    name,
			Source:  "feed",
			AddedAt: now,
		})
	}
	return entries, nil
}
