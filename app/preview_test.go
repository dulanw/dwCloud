package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceGeneratedFileReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "queue.json")
	tmp := dst + ".tmp"

	if err := os.WriteFile(dst, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := replaceGeneratedFile(tmp, dst); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("destination content = %q, want %q", data, "new")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("temp file still exists or stat failed: %v", err)
	}
}

func TestReplaceGeneratedFileReturnsRenameErrorWhenDestinationIsMissing(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "missing.jpg")
	tmp := dst + ".tmp"

	err := replaceGeneratedFile(tmp, dst)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), filepath.Base(tmp)) {
		t.Fatalf("error = %q, want it to reference missing temp file %q", err, filepath.Base(tmp))
	}
}

func TestEnqueueManyPersistsUniqueIDsOnce(t *testing.T) {
	dir := t.TempDir()
	service := &PreviewService{
		dir:       dir,
		queuePath: filepath.Join(dir, "queue.json"),
		queued:    make(map[string]struct{}),
		wake:      make(chan struct{}, 1),
	}

	added, err := service.enqueueMany([]string{" file-a ", "", "file-b", "file-a"})
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 {
		t.Fatalf("added = %d, want 2", added)
	}

	data, err := os.ReadFile(service.queuePath)
	if err != nil {
		t.Fatal(err)
	}
	var queue previewQueueFile
	if err := json.Unmarshal(data, &queue); err != nil {
		t.Fatal(err)
	}
	if len(queue.FileIDs) != 2 {
		t.Fatalf("queue IDs = %#v, want two unique IDs", queue.FileIDs)
	}

	added, err = service.enqueueMany([]string{"file-a", "file-b"})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Fatalf("second added = %d, want 0", added)
	}
}
