// internal/watcher/watcher_test.go
package watcher

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWatchDebouncesMultipleWrites(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "file.bin")

	var mu sync.Mutex
	var calls []string
	stop := make(chan struct{})

	done := make(chan error, 1)
	go func() {
		done <- Watch([]string{dir}, func(path string) {
			mu.Lock()
			calls = append(calls, path)
			mu.Unlock()
		}, stop)
	}()

	time.Sleep(50 * time.Millisecond) // let the watcher register

	for i := 0; i < 3; i++ {
		if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond) // let debounce settle
	close(stop)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after stop was closed")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("got %d onFile calls, want 1 (debounced): %v", len(calls), calls)
	}
	if calls[0] != target {
		t.Fatalf("call path = %q, want %q", calls[0], target)
	}
}
