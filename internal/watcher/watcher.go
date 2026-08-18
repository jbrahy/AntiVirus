// internal/watcher/watcher.go
package watcher

import (
	"fmt"
	"time"

	"github.com/fsnotify/fsnotify"
)

const debounce = 300 * time.Millisecond

func Watch(paths []string, onFile func(path string), stop <-chan struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}
	defer w.Close()

	for _, p := range paths {
		if err := w.Add(p); err != nil {
			fmt.Printf("watch error on %s (dropping this path): %v\n", p, err)
		}
	}

	pending := map[string]*time.Timer{}
	fire := make(chan string)

	for {
		select {
		case <-stop:
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			path := ev.Name
			if t, exists := pending[path]; exists {
				t.Stop()
			}
			pending[path] = time.AfterFunc(debounce, func() {
				fire <- path
			})
		case path := <-fire:
			delete(pending, path)
			onFile(path)
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			fmt.Printf("watcher error (continuing): %v\n", err)
		}
	}
}
