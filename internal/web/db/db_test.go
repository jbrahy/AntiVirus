package db

import (
	"os"
	"testing"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = "root@tcp(127.0.0.1:3306)/avtool_web_test"
	}
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("no reachable test MariaDB at %s, skipping: %v", dsn, err)
	}
	d.Close()
	return dsn
}

func TestOpenPingsSuccessfully(t *testing.T) {
	dsn := testDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()
}

func TestOpenFailsOnUnreachableHost(t *testing.T) {
	_, err := Open("root:wrong@tcp(127.0.0.1:1)/nonexistent")
	if err == nil {
		t.Fatal("expected error opening a DSN pointing at an unreachable host")
	}
}
