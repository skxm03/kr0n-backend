package watcher

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ReloadFunc is the callback signature invoked when a configuration file change is detected.
type ReloadFunc func(ctx context.Context, filePath string) error

// Watcher monitors the directory containing a target configuration file and triggers
// debounced reloads on writes, creates, or atomic renames.
type Watcher struct {
	targetPath string
	targetName string
	targetDir  string
	debounce   time.Duration
	onReload   ReloadFunc
	logger     *slog.Logger

	fsWatcher *fsnotify.Watcher
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewWatcher initializes a Watcher for targetPath.
func NewWatcher(targetPath string, debounce time.Duration, onReload ReloadFunc, logger *slog.Logger) (*Watcher, error) {
	if targetPath == "" {
		return nil, fmt.Errorf("target config file path cannot be empty")
	}
	if debounce <= 0 {
		debounce = 100 * time.Millisecond
	}
	if logger == nil {
		logger = slog.Default()
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, fmt.Errorf("resolve config path %q: %w", targetPath, err)
	}

	dir := filepath.Dir(absPath)
	name := filepath.Base(absPath)

	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("initialize fsnotify watcher: %w", err)
	}

	return &Watcher{
		targetPath: absPath,
		targetName: name,
		targetDir:  dir,
		debounce:   debounce,
		onReload:   onReload,
		logger:     logger,
		fsWatcher:  fsWatcher,
		stopCh:     make(chan struct{}),
	}, nil
}

// Start begins monitoring the configuration file's parent directory in a background goroutine.
func (w *Watcher) Start(ctx context.Context) error {
	// Ensure target directory exists
	if _, err := os.Stat(w.targetDir); err != nil {
		return fmt.Errorf("config directory %q does not exist: %w", w.targetDir, err)
	}

	if err := w.fsWatcher.Add(w.targetDir); err != nil {
		return fmt.Errorf("watch config directory %q: %w", w.targetDir, err)
	}

	w.wg.Add(1)
	go w.loop(ctx)

	return nil
}

func (w *Watcher) loop(ctx context.Context) {
	defer w.wg.Done()

	var timer *time.Timer
	var timerCh <-chan time.Time

	resetTimer := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.NewTimer(w.debounce)
		timerCh = timer.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}

			// Check if event pertains to our target configuration file
			eventBase := filepath.Base(event.Name)
			if eventBase != w.targetName {
				continue
			}

			// Focus on modification, creation, or write events
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
				resetTimer()
			}

		case <-timerCh:
			timerCh = nil
			w.triggerReload(ctx)

		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			w.logger.Error("config watcher error", "err", err)
		}
	}
}

func (w *Watcher) triggerReload(ctx context.Context) {
	w.logger.Info("configuration file change detected, reloading gateway...", "file", w.targetPath)
	if w.onReload != nil {
		if err := w.onReload(ctx, w.targetPath); err != nil {
			w.logger.Error("gateway configuration reload failed; existing configuration remains active", "err", err)
		} else {
			w.logger.Info("gateway configuration reloaded successfully", "file", w.targetPath)
		}
	}
}

// Stop closes the watcher and waits for background goroutines to terminate.
func (w *Watcher) Stop() {
	close(w.stopCh)
	_ = w.fsWatcher.Close()
	w.wg.Wait()
}
