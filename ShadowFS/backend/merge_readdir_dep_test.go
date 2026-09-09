package backend

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMergeReaddirNamespaceDep reproduces the exp4 directory-enumeration
// producer creates a file inside its (unresolved) epoch, consumer enumerates
// the same directory from a second live epoch. MergeReaddirVersions must
// record the namespace read-from edge and return; in the failing run the
// consumer's Readdir hung forever and the whole daemon went silent.
func TestMergeReaddirNamespaceDep(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	dir := filepath.Join(orig, "exp4", "direnum-0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "preexisting.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := b.BeginEpoch("ep-P", "/cg-P", "s-P"); err != nil {
		t.Fatalf("begin P: %v", err)
	}
	if err := b.BeginEpoch("ep-C", "/cg-C", "s-C"); err != nil {
		t.Fatalf("begin C: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Producer: echo 'made' > dir/created.txt  (FUSE Create -> PrepareWrite)
		if _, err := b.PrepareWrite("ep-P", filepath.Join(dir, "created.txt")); err != nil {
			t.Errorf("producer PrepareWrite: %v", err)
			return
		}
		// Consumer: ls -1 dir  (FUSE Readdir -> MergeReaddirVersions)
		entries, err := b.MergeReaddirVersions("ep-C", dir)
		if err != nil {
			t.Errorf("consumer MergeReaddirVersions: %v", err)
			return
		}
		t.Logf("merged entries: %d", len(entries))
		for _, e := range entries {
			t.Logf("  %s", e.Name)
		}
		// The read-from edge must exist: rolling back P must cascade to C.
		set, err := b.RollbackWithAffected("ep-P")
		if err != nil {
			t.Errorf("rollback P: %v", err)
			return
		}
		t.Logf("affected: %v", set)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("HANG: readdir dependency sequence did not complete within 10s")
	}
}
