package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatcher_DetectsDirectWrite(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "gateway.yaml")

	// Create initial file
	if err := os.WriteFile(configFile, []byte("initial"), 0644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	var reloadCount atomic.Int32
	reloadDone := make(chan struct{}, 10)

	onReload := func(ctx context.Context, filePath string) error {
		reloadCount.Add(1)
		reloadDone <- struct{}{}
		return nil
	}

	w, err := NewWatcher(configFile, 20*time.Millisecond, onReload, nil)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := w.Start(ctx); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer w.Stop()

	// Modify file
	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(configFile, []byte("modified"), 0644); err != nil {
		t.Fatalf("modify config: %v", err)
	}

	select {
	case <-reloadDone:
		// Reload detected!
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for reload event")
	}

	if reloadCount.Load() < 1 {
		t.Errorf("expected at least 1 reload, got %d", reloadCount.Load())
	}
}

func TestWatcher_DetectsAtomicRename(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "gateway.yaml")
	tmpFile := filepath.Join(tempDir, "gateway.yaml.tmp")

	if err := os.WriteFile(configFile, []byte("initial"), 0644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	var reloadCount atomic.Int32
	reloadDone := make(chan struct{}, 10)

	onReload := func(ctx context.Context, filePath string) error {
		reloadCount.Add(1)
		reloadDone <- struct{}{}
		return nil
	}

	w, err := NewWatcher(configFile, 20*time.Millisecond, onReload, nil)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := w.Start(ctx); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer w.Stop()

	// Atomic rename: write to .tmp and rename over gateway.yaml
	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(tmpFile, []byte("updated_content"), 0644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}
	if err := os.Rename(tmpFile, configFile); err != nil {
		t.Fatalf("rename tmp over config: %v", err)
	}

	select {
	case <-reloadDone:
		// Reload detected!
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for reload event via atomic rename")
	}

	if reloadCount.Load() < 1 {
		t.Errorf("expected at least 1 reload, got %d", reloadCount.Load())
	}
}

func TestWatcher_IgnoresUnrelatedFiles(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "gateway.yaml")
	unrelatedFile := filepath.Join(tempDir, "other.txt")

	if err := os.WriteFile(configFile, []byte("initial"), 0644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	var reloadCount atomic.Int32
	onReload := func(ctx context.Context, filePath string) error {
		reloadCount.Add(1)
		return nil
	}

	w, err := NewWatcher(configFile, 20*time.Millisecond, onReload, nil)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := w.Start(ctx); err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}
	defer w.Stop()

	// Write to unrelated file
	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(unrelatedFile, []byte("unrelated"), 0644); err != nil {
		t.Fatalf("write unrelated file: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if reloadCount.Load() != 0 {
		t.Errorf("expected 0 reloads for unrelated file, got %d", reloadCount.Load())
	}
}
