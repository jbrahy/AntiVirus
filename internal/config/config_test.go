package config

import (
	"path/filepath"
	"testing"
)

func TestPathsUnderAppSupport(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	appDir, err := AppDir()
	if err != nil {
		t.Fatalf("AppDir: %v", err)
	}
	want := filepath.Join(tmp, "Library", "Application Support", "avtool")
	if appDir != want {
		t.Errorf("AppDir = %q, want %q", appDir, want)
	}

	dbPath, err := DBPath()
	if err != nil {
		t.Fatalf("DBPath: %v", err)
	}
	if dbPath != filepath.Join(want, "avtool.db") {
		t.Errorf("DBPath = %q", dbPath)
	}

	qDir, err := QuarantineDir()
	if err != nil {
		t.Fatalf("QuarantineDir: %v", err)
	}
	if qDir != filepath.Join(want, "quarantine") {
		t.Errorf("QuarantineDir = %q", qDir)
	}

	logPath, err := ReportLogPath()
	if err != nil {
		t.Fatalf("ReportLogPath: %v", err)
	}
	if logPath != filepath.Join(want, "detections.log") {
		t.Errorf("ReportLogPath = %q", logPath)
	}
}
