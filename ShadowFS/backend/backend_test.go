package backend

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const (
	agentA = "cgroup-agent-a"
	agentB = "cgroup-agent-b"
	agentC = "cgroup-agent-c"
)

// setup creates a temporary trackedDir and a stagingDir for tests.
// Returns the Backend, both paths, and a cleanup function.
func setup(t *testing.T) (*Backend, string, string, func()) {
	t.Helper()

	trackedDir, err := os.MkdirTemp("", "shadowfs_test_tracked_")
	if err != nil {
		t.Fatalf("MkdirTemp tracked: %v", err)
	}

	stagingDir, err := os.MkdirTemp("", "shadowfs_test_staging_")
	if err != nil {
		os.RemoveAll(trackedDir)
		t.Fatalf("MkdirTemp staging: %v", err)
	}

	b, err := NewBackend(stagingDir, trackedDir)
	if err != nil {
		os.RemoveAll(trackedDir)
		os.RemoveAll(stagingDir)
		t.Fatalf("NewBackend: %v", err)
	}

	cleanup := func() {
		b.Close()
		os.RemoveAll(trackedDir)
		os.RemoveAll(stagingDir)
	}

	return b, trackedDir, stagingDir, cleanup
}

// writeOverlay simulates a FUSE write: it calls PrepareWrite (which copies
// up if needed) and then writes the given content to the returned overlay
// path. The orig file is never touched.
func writeOverlay(t *testing.T, b *Backend, agent, origPath string, content []byte) {
	t.Helper()
	overlayPath, err := b.PrepareWrite(agent, origPath)
	if err != nil {
		t.Fatalf("PrepareWrite %q: %v", origPath, err)
	}
	if err := os.WriteFile(overlayPath, content, 0o644); err != nil {
		t.Fatalf("write overlay %q: %v", overlayPath, err)
	}
}

func TestNewBackend(t *testing.T) {
	_, _, stagingDir, cleanup := setup(t)
	defer cleanup()

	// Staging dir should contain only the overlay subdir.
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		t.Fatalf("ReadDir staging: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "overlay" && e.Name() != stateFileName {
			t.Errorf("unexpected entry in staging: %q", e.Name())
		}
	}
}

// --- Single-agent overlay semantics ---

func TestOverlayWriteRollbackDiscards(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "data.txt")
	orig := []byte("orig")
	if err := os.WriteFile(f, orig, 0o644); err != nil {
		t.Fatal(err)
	}

	writeOverlay(t, b, agentA, f, []byte("modified"))

	// Original must be untouched.
	got, _ := os.ReadFile(f)
	if string(got) != string(orig) {
		t.Errorf("orig changed: got %q, want %q", got, orig)
	}

	// Overlay copy must exist.
	overlayPath, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), f)
	if _, err := os.Stat(overlayPath); err != nil {
		t.Errorf("overlay copy missing: %v", err)
	}

	if err := b.Rollback(agentA); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	// Overlay should be gone, orig still untouched.
	if _, err := os.Stat(overlayPath); !os.IsNotExist(err) {
		t.Errorf("overlay should be removed after rollback")
	}
	got, _ = os.ReadFile(f)
	if string(got) != string(orig) {
		t.Errorf("orig changed after rollback: got %q", got)
	}
}

func TestOverlayWritePromoteOnCommit(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "data.txt")
	os.WriteFile(f, []byte("orig"), 0o644)

	writeOverlay(t, b, agentA, f, []byte("modified"))

	// Before commit, orig still original.
	got, _ := os.ReadFile(f)
	if string(got) != "orig" {
		t.Errorf("pre-commit orig = %q, want orig", got)
	}

	b.Commit(agentA)

	// Now orig should hold the modified content.
	got, _ = os.ReadFile(f)
	if string(got) != "modified" {
		t.Errorf("post-commit orig = %q, want modified", got)
	}

	// Agent gone after commit.
	if b.AgentLen(agentA) != 0 {
		t.Errorf("AgentLen = %d, want 0", b.AgentLen(agentA))
	}
}

func TestOverlayCreateAndCommit(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "new.txt")
	// File does NOT exist in orig yet.
	overlayPath, err := b.PrepareCreate(agentA, f)
	if err != nil {
		t.Fatalf("PrepareCreate: %v", err)
	}
	if err := os.WriteFile(overlayPath, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Error("orig should not exist before commit")
	}
	b.Commit(agentA)
	got, err := os.ReadFile(f)
	if err != nil || string(got) != "new" {
		t.Errorf("post-commit orig = %q err=%v", got, err)
	}
}

// --- Shared overlay (two agents touch same file) ---

func TestSharedOverlayTwoAgents(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "shared.txt")
	os.WriteFile(f, []byte("orig"), 0o644)

	writeOverlay(t, b, agentA, f, []byte("a-mod"))

	// B opens the same file; PrepareWrite returns the same overlay path.
	overlayPathA, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), f)
	overlayPathB, err := b.PrepareWrite(agentB, f)
	if err != nil {
		t.Fatalf("PrepareWrite B: %v", err)
	}
	if overlayPathA != overlayPathB {
		t.Errorf("overlay paths differ: %q vs %q", overlayPathA, overlayPathB)
	}
	// B reads what A wrote.
	got, _ := os.ReadFile(overlayPathB)
	if string(got) != "a-mod" {
		t.Errorf("B sees %q, want a-mod", got)
	}
	os.WriteFile(overlayPathB, []byte("b-mod"), 0o644)

	// B should depend on A.
	if !b.DependsOn(agentB, agentA) {
		t.Error("B should depend on A (shared file)")
	}

	// Rollback A cascades to B; overlay file gone, orig untouched.
	if err := b.Rollback(agentA); err != nil {
		t.Fatalf("Rollback A: %v", err)
	}
	if _, err := os.Stat(overlayPathA); !os.IsNotExist(err) {
		t.Errorf("overlay should be gone after cascading rollback")
	}
	if got, _ := os.ReadFile(f); string(got) != "orig" {
		t.Errorf("orig changed: %q", got)
	}
	if b.AgentLen(agentA) != 0 || b.AgentLen(agentB) != 0 {
		t.Errorf("both agents should be cleared")
	}
}

func TestPerFilePromoteWaitsForAllWriters(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "shared.txt")
	os.WriteFile(f, []byte("orig"), 0o644)

	writeOverlay(t, b, agentA, f, []byte("a-mod"))
	writeOverlay(t, b, agentB, f, []byte("b-mod"))

	// Commit B first; A still uncommitted -> no promote (B depends on A).
	b.Commit(agentB)
	if got, _ := os.ReadFile(f); string(got) != "orig" {
		t.Errorf("orig promoted prematurely: %q", got)
	}

	// Commit A -> both agents finalize, overlay promoted.
	b.Commit(agentA)
	if got, _ := os.ReadFile(f); string(got) != "b-mod" {
		t.Errorf("post-commit orig = %q, want b-mod", got)
	}
}

// --- Whiteout (unlink/rmdir) ---

func TestUnlinkWhiteout(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "doomed.txt")
	os.WriteFile(f, []byte("bye"), 0o644)

	if err := b.RecordUnlink(agentA, f); err != nil {
		t.Fatalf("RecordUnlink: %v", err)
	}
	// orig file still there (not promoted yet).
	if _, err := os.Stat(f); err != nil {
		t.Errorf("orig should still exist before promote: %v", err)
	}
	// Whiteout exists.
	if !hasWhiteout(b.StagingDir(), b.TrackedDir(), f) {
		t.Error("whiteout missing")
	}

	// Rollback: whiteout cleared, orig untouched.
	if err := b.Rollback(agentA); err != nil {
		t.Fatal(err)
	}
	if hasWhiteout(b.StagingDir(), b.TrackedDir(), f) {
		t.Error("whiteout should be cleared after rollback")
	}
	if _, err := os.Stat(f); err != nil {
		t.Errorf("orig should still exist after rollback: %v", err)
	}

	// Re-unlink and commit: orig actually deleted.
	if err := b.RecordUnlink(agentA, f); err != nil {
		t.Fatal(err)
	}
	b.Commit(agentA)
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Error("orig should be removed after commit")
	}
}

func TestMkdirRmdirOverlay(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	dir := filepath.Join(trackedDir, "newdir")
	if err := b.RecordMkdir(agentA, dir, 0o755); err != nil {
		t.Fatalf("RecordMkdir: %v", err)
	}
	// orig dir not yet created.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("orig dir should not exist before commit")
	}
	// overlay dir exists.
	op, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), dir)
	if st, err := os.Stat(op); err != nil || !st.IsDir() {
		t.Errorf("overlay dir missing: err=%v", err)
	}

	b.Commit(agentA)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Errorf("orig dir should exist after commit: %v", err)
	}
}

func TestRmdirRollback(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	dir := filepath.Join(trackedDir, "old")
	os.Mkdir(dir, 0o755)
	if err := b.RecordRmdir(agentA, dir); err != nil {
		t.Fatal(err)
	}
	// orig still there.
	if _, err := os.Stat(dir); err != nil {
		t.Error("orig should still exist before promote")
	}
	if !hasWhiteout(b.StagingDir(), b.TrackedDir(), dir) {
		t.Error("whiteout missing")
	}
	if err := b.Rollback(agentA); err != nil {
		t.Fatal(err)
	}
	if hasWhiteout(b.StagingDir(), b.TrackedDir(), dir) {
		t.Error("whiteout should be cleared after rollback")
	}
}

// --- Rename ---

func TestRecordRenameAndRollback(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	src := filepath.Join(trackedDir, "src.txt")
	dst := filepath.Join(trackedDir, "dst.txt")
	os.WriteFile(src, []byte("hello"), 0o644)

	if err := b.RecordRename(agentA, src, dst); err != nil {
		t.Fatalf("RecordRename: %v", err)
	}

	// Original src still exists; orig has no dst yet.
	if _, err := os.Stat(src); err != nil {
		t.Errorf("orig src should still exist: %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("orig dst should not exist before promote")
	}

	// Overlay should: have dst, have whiteout for src.
	dstOverlay, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), dst)
	if got, err := os.ReadFile(dstOverlay); err != nil || string(got) != "hello" {
		t.Errorf("overlay dst missing/wrong: %v %q", err, got)
	}
	if !hasWhiteout(b.StagingDir(), b.TrackedDir(), src) {
		t.Error("whiteout for src missing")
	}

	if err := b.Rollback(agentA); err != nil {
		t.Fatal(err)
	}
	if hasWhiteout(b.StagingDir(), b.TrackedDir(), src) {
		t.Error("whiteout should be cleared after rollback")
	}
	if _, err := os.Stat(src); err != nil {
		t.Errorf("src should still exist: %v", err)
	}
}

// --- Idempotency / dedup ---

func TestPrepareWriteDedup(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "a.txt")
	os.WriteFile(f, []byte("orig"), 0o644)

	if _, err := b.PrepareWrite(agentA, f); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PrepareWrite(agentA, f); err != nil {
		t.Fatal(err)
	}
	if b.AgentLen(agentA) != 1 {
		t.Errorf("AgentLen = %d, want 1 (dedup)", b.AgentLen(agentA))
	}
}

// --- Multi-agent rollback isolation / cascade ---

func TestMultiAgentIndependentRollback(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	dirA := filepath.Join(trackedDir, "dir_a")
	dirB := filepath.Join(trackedDir, "dir_b")
	if err := b.RecordMkdir(agentA, dirA, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordMkdir(agentB, dirB, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := b.Rollback(agentA); err != nil {
		t.Fatal(err)
	}
	if b.AgentLen(agentB) != 1 {
		t.Errorf("agentB len = %d, want 1", b.AgentLen(agentB))
	}
	opB, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), dirB)
	if _, err := os.Stat(opB); err != nil {
		t.Errorf("dirB overlay should still exist: %v", err)
	}
}

func TestContaminationDetection(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "shared.txt")
	os.WriteFile(f, []byte("orig"), 0o644)
	writeOverlay(t, b, agentA, f, []byte("a"))
	writeOverlay(t, b, agentB, f, []byte("b"))

	if !b.DependsOn(agentB, agentA) {
		t.Error("B should depend on A")
	}
	if b.DependsOn(agentA, agentB) {
		t.Error("A should not depend on B")
	}
}

func TestRollbackDownstreamDoesNotAffectUpstream(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "shared.txt")
	os.WriteFile(f, []byte("orig"), 0o644)
	writeOverlay(t, b, agentA, f, []byte("a"))
	writeOverlay(t, b, agentB, f, []byte("b"))

	if err := b.Rollback(agentB); err != nil {
		t.Fatal(err)
	}
	if b.AgentLen(agentB) != 0 {
		t.Error("agentB should be cleared")
	}
	if b.AgentLen(agentA) != 1 {
		t.Errorf("agentA should still have 1 entry, got %d", b.AgentLen(agentA))
	}
	// Overlay file kept (other writer A still references it). Content
	// reflects the last write ("b") since the overlay is shared and
	// per-write history is not preserved — but A's UndoLog entry stays
	// alive so a future Commit will still promote the overlay onto orig.
	op, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), f)
	if _, err := os.Stat(op); err != nil {
		t.Errorf("overlay should still exist after downstream rollback: %v", err)
	}
}

// --- Parent-Child path dependencies ---

func TestParentChildDependency(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	dir := filepath.Join(trackedDir, "parent")
	if err := b.RecordMkdir(agentA, dir, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "child.txt")
	writeOverlay(t, b, agentB, child, []byte("c"))

	if !b.DependsOn(agentB, agentA) {
		t.Error("B should depend on A (child depends on parent)")
	}
	if b.DependsOn(agentA, agentB) {
		t.Error("A should not depend on B")
	}
}

func TestSiblingDirectoriesNoDependency(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	a := filepath.Join(trackedDir, "a")
	bb := filepath.Join(trackedDir, "b")
	b.RecordMkdir(agentA, a, 0o755)
	b.RecordMkdir(agentB, bb, 0o755)

	if b.DependsOn(agentB, agentA) || b.DependsOn(agentA, agentB) {
		t.Error("siblings should be independent")
	}
}

func TestSimilarPrefixNoDependency(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	a := filepath.Join(trackedDir, "foobar")
	bb := filepath.Join(trackedDir, "foo")
	b.RecordMkdir(agentA, a, 0o755)
	b.RecordMkdir(agentB, bb, 0o755)

	if b.DependsOn(agentB, agentA) || b.DependsOn(agentA, agentB) {
		t.Error("similar-prefix dirs should not depend on each other")
	}
}

// --- Commit semantics ---

func TestCommitDoesNotAffectOtherAgent(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	fA := filepath.Join(trackedDir, "a.txt")
	fB := filepath.Join(trackedDir, "b.txt")
	writeOverlay(t, b, agentA, fA, []byte("a"))
	writeOverlay(t, b, agentB, fB, []byte("b"))

	b.Commit(agentA)
	if b.AgentLen(agentA) != 0 {
		t.Errorf("agentA len after commit = %d", b.AgentLen(agentA))
	}
	if b.AgentLen(agentB) != 1 {
		t.Errorf("agentB len = %d, want 1", b.AgentLen(agentB))
	}
	if got, _ := os.ReadFile(fA); string(got) != "a" {
		t.Errorf("fA orig = %q, want a", got)
	}
}

func TestCommitPendingCascadeRollback(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "shared.txt")
	os.WriteFile(f, []byte("orig"), 0o644)
	writeOverlay(t, b, agentA, f, []byte("a"))
	writeOverlay(t, b, agentB, f, []byte("b"))

	b.Commit(agentB)
	if b.AgentLen(agentB) == 0 {
		t.Error("agentB should remain pending while A uncommitted")
	}
	if !b.DependsOn(agentB, agentA) {
		t.Error("dependency should still hold")
	}

	if err := b.Rollback(agentA); err != nil {
		t.Fatal(err)
	}
	// Overlay gone, orig untouched.
	op, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), f)
	if _, err := os.Stat(op); !os.IsNotExist(err) {
		t.Error("overlay should be gone")
	}
	if got, _ := os.ReadFile(f); string(got) != "orig" {
		t.Errorf("orig = %q, want orig", got)
	}
}

func TestCommitFinalizesImmediatelyWithoutDeps(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "f.txt")
	writeOverlay(t, b, agentA, f, []byte("a"))
	b.Commit(agentA)
	if b.AgentLen(agentA) != 0 {
		t.Errorf("AgentLen after commit = %d", b.AgentLen(agentA))
	}
}

// --- Read dependency ---

func TestRecordReadOpenAddsDependency(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "f.txt")
	writeOverlay(t, b, agentA, f, []byte("a"))
	b.RecordReadOpen(agentB, f)

	if !b.DependsOn(agentB, agentA) {
		t.Error("B should depend on A after read")
	}
	if b.AgentLen(agentB) != 0 {
		t.Errorf("agentB len = %d, want 0", b.AgentLen(agentB))
	}
}

func TestRecordReadOpenNoWriterNoDependency(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "clean.txt")
	os.WriteFile(f, []byte("clean"), 0o644)
	b.RecordReadOpen(agentB, f)

	if b.DependsOn(agentB, agentA) {
		t.Error("B should not depend on A (clean file)")
	}
	if b.AgentLen(agentB) != 0 {
		t.Errorf("agentB len = %d, want 0", b.AgentLen(agentB))
	}
}

// --- isAncestor ---

func TestIsAncestor(t *testing.T) {
	tests := []struct {
		dir, child string
		want       bool
	}{
		{"/a", "/a/b", true},
		{"/a", "/a/b/c", true},
		{"/a/b", "/a/b/c", true},
		{"/a", "/a", false},
		{"/a/b", "/a", false},
		{"/foo", "/foobar", false},
		{"/foo", "/foo/bar", true},
		{"/", "/a", true},
		{"", "/a", false},
	}
	for _, tc := range tests {
		got := isAncestor(tc.dir, tc.child)
		if got != tc.want {
			t.Errorf("isAncestor(%q, %q) = %v, want %v", tc.dir, tc.child, got, tc.want)
		}
	}
}

// --- Empty rollback ---

func TestRollbackEmptyLog(t *testing.T) {
	b, _, _, cleanup := setup(t)
	defer cleanup()
	if err := b.Rollback(agentA); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRollbackWriteRestoresWhiteout verifies the fix for a subtle bug:
// Agent A deletes a file (whiteout created), then Agent B creates a new
// file with the same name (whiteout removed by PrepareWrite). If only B
// is rolled back, the whiteout from A must be restored so that A's delete
// intent survives.
func TestRollbackWriteRestoresWhiteout(t *testing.T) {
	b, trackedDir, stagingDir, cleanup := setup(t)
	defer cleanup()

	// 1. Create an original file.
	orig := filepath.Join(trackedDir, "victim.txt")
	if err := os.WriteFile(orig, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Agent A deletes the file.
	if err := b.RecordUnlink(agentA, orig); err != nil {
		t.Fatalf("RecordUnlink: %v", err)
	}

	// Verify: whiteout exists, file is hidden in merged view.
	wp, _ := whiteoutPathFor(stagingDir, trackedDir, orig)
	if _, err := os.Lstat(wp); err != nil {
		t.Fatalf("expected whiteout at %q, got err=%v", wp, err)
	}
	entries, _ := MergeReaddir(trackedDir, stagingDir)
	for _, e := range entries {
		if e.Name == "victim.txt" {
			t.Fatal("victim.txt should be hidden by whiteout after unlink")
		}
	}

	// 3. Agent B creates a new file with the same name.
	overlayPath, err := b.PrepareWrite(agentB, orig)
	if err != nil {
		t.Fatalf("PrepareWrite: %v", err)
	}
	if err := os.WriteFile(overlayPath, []byte("new content"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Verify: whiteout is gone, file is visible again.
	if _, err := os.Lstat(wp); !os.IsNotExist(err) {
		t.Fatalf("expected whiteout removed after PrepareWrite, err=%v", err)
	}

	// 4. Rollback only Agent B (upstream A is NOT rolled back).
	if err := b.Rollback(agentB); err != nil {
		t.Fatalf("Rollback B: %v", err)
	}

	// 5. Verify: the whiteout has been restored, file is hidden again.
	if _, err := os.Lstat(wp); err != nil {
		t.Fatalf("expected whiteout restored after rollback of B, got err=%v", err)
	}
	entries, _ = MergeReaddir(trackedDir, stagingDir)
	for _, e := range entries {
		if e.Name == "victim.txt" {
			t.Fatal("victim.txt should be hidden by restored whiteout after B's rollback")
		}
	}
}

// --- FD tracking: cascade close on rollback ---

// TestCascadeRollbackClosesOpenFDs verifies that when agent A triggers a
// cascade rollback that also rolls back agent B (because B depends on A),
// any tracked fds held by both A and B are force-closed so their
// processes get EBADF instead of silently reading stale overlay data.
func TestCascadeRollbackClosesOpenFDs(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "shared.txt")
	os.WriteFile(f, []byte("orig"), 0o644)

	// Agent A opens (PrepareWrite) the file.
	overlayPath, err := b.PrepareWrite(agentA, f)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate opening the overlay file (like the FUSE layer does).
	fdA, err := syscall.Open(overlayPath, syscall.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open overlay for A: %v", err)
	}
	tfdA := NewTrackedFD(fdA)
	b.RegisterFD(agentA, tfdA)

	// Agent B opens the same file (B depends on A via shared write).
	_, err = b.PrepareWrite(agentB, f)
	if err != nil {
		t.Fatal(err)
	}
	fdB, err := syscall.Open(overlayPath, syscall.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open overlay for B: %v", err)
	}
	tfdB := NewTrackedFD(fdB)
	b.RegisterFD(agentB, tfdB)

	// Verify B depends on A.
	if !b.DependsOn(agentB, agentA) {
		t.Fatal("B should depend on A")
	}

	// Both fds should be valid before rollback.
	if tfdA.IsClosed() || tfdB.IsClosed() {
		t.Fatal("fds should not be closed before rollback")
	}

	// Rollback A (upstream) -> cascades to B (downstream).
	if err := b.Rollback(agentA); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// Both tracked fds should now be closed.
	if !tfdA.IsClosed() {
		t.Error("agent A's fd should be closed after cascade rollback")
	}
	if !tfdB.IsClosed() {
		t.Error("agent B's fd should be closed after cascade rollback")
	}

	// Verify the fd is actually invalid (read returns EBADF).
	buf := make([]byte, 10)
	_, readErr := syscall.Read(fdA, buf)
	if readErr == nil {
		t.Error("read on closed fd should fail")
	}
}

// TestTrackedFDDoubleClose verifies that TrackedFD.Close is idempotent.
func TestTrackedFDDoubleClose(t *testing.T) {
	f, err := os.CreateTemp("", "trackedfd_test_")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	defer os.Remove(name)

	fd := int(f.Fd())
	// Duplicate the fd so we control it independently.
	dupFD, err := syscall.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	f.Close() // close the Go-managed fd

	tfd := NewTrackedFD(dupFD)
	if tfd.IsClosed() {
		t.Error("should not be closed initially")
	}
	if err := tfd.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if !tfd.IsClosed() {
		t.Error("should be closed after Close()")
	}
	// Second close should be a no-op.
	if err := tfd.Close(); err != nil {
		t.Errorf("second close should be no-op, got: %v", err)
	}
}

// TestUnregisterFDBeforeRollback verifies that if the FUSE Release
// handler unregisters an fd before rollback fires, the rollback doesn't
// try to close it again (no double-close on the raw fd).
func TestUnregisterFDBeforeRollback(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "test.txt")
	os.WriteFile(f, []byte("orig"), 0o644)

	overlayPath, err := b.PrepareWrite(agentA, f)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(overlayPath, syscall.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	tfd := NewTrackedFD(fd)
	b.RegisterFD(agentA, tfd)

	// Simulate FUSE Release: unregister + close via TrackedFD.
	b.UnregisterFD(agentA, tfd)
	_ = tfd.Close()

	// Now rollback should not panic or double-close.
	if err := b.Rollback(agentA); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// TrackedFD should be closed exactly once.
	if !tfd.IsClosed() {
		t.Error("tfd should be closed")
	}
}

// --- hasWriteEntry: Unlink→Write dedup fix ---

// TestHasWriteEntryAfterUnlink verifies that after an agent unlinks a file
// and then writes to the same path, hasWriteEntry returns false so that a
// fresh OverlayWriteEntry is created. The old WriteEntry was invalidated by
// the Unlink and must not suppress the new write.
func TestHasWriteEntryAfterUnlink(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "reuse.txt")
	if err := os.WriteFile(f, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Agent A writes the file → UndoLog: [WriteEntry(reuse.txt)]
	writeOverlay(t, b, agentA, f, []byte("v1"))
	if b.AgentLen(agentA) != 1 {
		t.Fatalf("AgentLen = %d, want 1", b.AgentLen(agentA))
	}

	// 2. Agent A deletes the file → UndoLog: [WriteEntry, UnlinkEntry]
	if err := b.RecordUnlink(agentA, f); err != nil {
		t.Fatalf("RecordUnlink: %v", err)
	}
	if b.AgentLen(agentA) != 2 {
		t.Fatalf("AgentLen = %d, want 2", b.AgentLen(agentA))
	}

	// 3. Agent A writes again → must create a NEW WriteEntry (not dedup).
	//    The old WriteEntry + UnlinkEntry are cleaned up, leaving only
	//    the fresh WriteEntry.
	writeOverlay(t, b, agentA, f, []byte("v2"))
	if b.AgentLen(agentA) != 1 {
		t.Fatalf("AgentLen = %d, want 1 (old entries cleaned, new WriteEntry)", b.AgentLen(agentA))
	}

	// 4. A second write on the same path should still dedup.
	writeOverlay(t, b, agentA, f, []byte("v3"))
	if b.AgentLen(agentA) != 1 {
		t.Fatalf("AgentLen = %d, want 1 (dedup on second write)", b.AgentLen(agentA))
	}

	// 5. Commit should promote correctly.
	b.Commit(agentA)
	got, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("read orig after commit: %v", err)
	}
	if string(got) != "v3" {
		t.Errorf("orig = %q, want v3", got)
	}
}

// TestHasWriteEntryAfterRmdir verifies the same dedup invalidation for
// directories: after mkdir → rmdir → mkdir on the same path, a fresh
// OverlayMkdirEntry must be created.
func TestHasWriteEntryAfterRmdir(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	dir := filepath.Join(trackedDir, "mydir")

	// 1. Agent A creates dir.
	if err := b.RecordMkdir(agentA, dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if b.AgentLen(agentA) != 1 {
		t.Fatalf("AgentLen = %d, want 1", b.AgentLen(agentA))
	}

	// 2. Agent A removes dir.
	if err := b.RecordRmdir(agentA, dir); err != nil {
		t.Fatal(err)
	}
	if b.AgentLen(agentA) != 2 {
		t.Fatalf("AgentLen = %d, want 2", b.AgentLen(agentA))
	}

	// 3. Agent A re-creates dir → must NOT dedup; old entries cleaned.
	if err := b.RecordMkdir(agentA, dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if b.AgentLen(agentA) != 1 {
		t.Fatalf("AgentLen = %d, want 1 (old entries cleaned, new MkdirEntry)", b.AgentLen(agentA))
	}
}

// --- Read-only agent: promotion and finalization ---

// TestReadOnlyAgentDoesNotBlockPromote verifies that a pure-read agent
// (created via RecordReadOpen, no UndoLog entries, no dirty files) does
// NOT prevent an upstream writer from being promoted when committed.
//
// Scenario:
//   Agent A writes f.txt     → A is a writer
//   Agent B reads f.txt      → B depends on A (read dependency)
//   commit(B)                → B.Committed=true (but B has no writes)
//   commit(A)                → should promote f.txt even though B has
//                              no explicit write-level commit
func TestReadOnlyAgentDoesNotBlockPromote(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "data.txt")
	if err := os.WriteFile(f, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Agent A writes the file.
	writeOverlay(t, b, agentA, f, []byte("modified"))

	// Agent B only reads it (establishes dependency).
	b.RecordReadOpen(agentB, f)
	if !b.DependsOn(agentB, agentA) {
		t.Fatal("B should depend on A after read")
	}
	if b.AgentLen(agentB) != 0 {
		t.Fatalf("read-only agentB should have 0 undo entries, got %d", b.AgentLen(agentB))
	}

	// Commit B first (read-only, no writes to promote).
	b.Commit(agentB)

	// Commit A → should promote f.txt despite B being a "reader" upstream
	// of nothing (B is a downstream of A, not upstream).
	b.Commit(agentA)

	got, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("read orig: %v", err)
	}
	if string(got) != "modified" {
		t.Errorf("orig = %q, want modified", got)
	}
}

// TestReadOnlyAgentDoesNotBlockUpstreamFinalize verifies the core fix:
// when a writer W has a read-only dependent R (R depends on W because it
// read a file W wrote), committing W should finalize W even though R is
// not committed. R is read-only and cannot affect promotion.
//
// Scenario:
//   Agent A writes f.txt      → A is a writer
//   Agent B reads f.txt       → B depends on A
//   commit(A)                 → A should promote + finalize immediately
//                                (B is read-only, should not block)
func TestReadOnlyAgentDoesNotBlockUpstreamFinalize(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "f.txt")
	if err := os.WriteFile(f, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Agent A writes.
	writeOverlay(t, b, agentA, f, []byte("new"))

	// Agent B only reads → B depends on A.
	b.RecordReadOpen(agentB, f)
	if !b.DependsOn(agentB, agentA) {
		t.Fatal("B should depend on A")
	}

	// Commit A WITHOUT committing B.
	b.Commit(agentA)

	// A should be finalized (removed) despite B not being committed.
	// Before the fix, A would remain because B is an uncommitted
	// dependent... wait, B depends on A, not A depends on B. So B is
	// in A's dependents, not in A's dependsOn. Let me re-check.
	//
	// Actually the dependency is: B depends on A (B read A's dirty file).
	// So dependsOn[B] = {A}, dependents[A] = {B}.
	// When tryFinalize(A): checks dependsOn[A] = {} (empty) → no upstream.
	// So A can finalize regardless of B's state. This was already correct.
	//
	// The REAL scenario is: A writes, C writes (C depends on A),
	// B reads (B depends on A and C). Commit C and A. Does B block?
	// Let me test this more precisely.
	if b.AgentLen(agentA) != 0 {
		t.Errorf("agentA should be finalized, but AgentLen = %d", b.AgentLen(agentA))
	}

	// orig should be promoted.
	got, _ := os.ReadFile(f)
	if string(got) != "new" {
		t.Errorf("orig = %q, want new", got)
	}
}

// TestReadOnlyUpstreamDoesNotBlockWriterPromote is the precise test for
// the read-only agent blocking fix. It creates a scenario where a writer
// has a read-only upstream dependency that would previously block promote.
//
// Scenario:
//   Agent A writes shared.txt
//   Agent B reads shared.txt  → B depends on A
//   Agent C writes shared.txt → C depends on A AND B
//     (C depends on B because B read a file that C is also writing,
//      via the isAncestor/exact-path dependency in RecordReadOpen)
//
// Wait — actually C depends on B only if B also wrote the file. Let me
// reconsider the dependency model.
//
// In the current model:
//   - RecordReadOpen(B, f): B depends on all current writers of f (i.e., A)
//   - PrepareWrite(C, f): C depends on all current writers of f (i.e., A)
//     C does NOT depend on B because B is not a writer.
//
// So the only way B blocks is if C somehow depends on B. This can't happen
// through write dependencies alone. The read-only blocking was in tryFinalize
// for the agent itself (B has Committed=false and tryFinalize requires it).
//
// The real fix scenario:
//   Agent A writes f.txt → fileDirty[f] = {A}
//   Agent B reads f.txt  → B depends on A
//   commit(B)            → B.Committed=true, tryFinalize(B):
//     dependsOn[B] = {A}, A not committed → B stays
//   commit(A)            → A.Committed=true, tryPromoteAll:
//     tryPromotePath(f): writers={A}, A committed ✓
//       upstreams of A: none ✓ → promote!
//     tryFinalize(A): UndoLog empty ✓, dependsOn[A] empty ✓ → finalize A
//     tryFinalize(B): UndoLog empty ✓, Committed=true ✓,
//       dependsOn[B]={A}, A was finalized (removed) → not in agents → skip
//       → finalize B
//
// This actually works correctly WITHOUT the fix because B IS committed.
// The issue is when B is NOT committed:
//   Agent A writes f.txt
//   Agent B reads f.txt  → B depends on A
//   commit(A) only       → promote f.txt, tryFinalize(A):
//     UndoLog empty ✓, dependsOn[A] empty ✓ → finalize A
//     tryFinalize(B): B.Committed=false → before fix: return false
//     After fix: B is read-only (no undo, no dirty) → allowed
func TestReadOnlyUpstreamDoesNotBlockWriterPromote(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "f.txt")
	if err := os.WriteFile(f, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Agent A writes.
	writeOverlay(t, b, agentA, f, []byte("new"))

	// Agent B only reads (never committed).
	b.RecordReadOpen(agentB, f)

	// Commit ONLY A. B is never committed.
	b.Commit(agentA)

	// A should be finalized and f.txt promoted.
	got, _ := os.ReadFile(f)
	if string(got) != "new" {
		t.Errorf("orig = %q, want new", got)
	}
	if b.AgentLen(agentA) != 0 {
		t.Errorf("agentA should be finalized, AgentLen = %d", b.AgentLen(agentA))
	}

	// B should also be auto-finalized (read-only, no undo, no dirty).
	b.mu.Lock()
	_, bExists := b.agents[agentB]
	b.mu.Unlock()
	if bExists {
		t.Error("read-only agentB should be auto-finalized after upstream A is finalized")
	}
}

// --- Rename HadWhiteout: rollback restores destination whiteout ---

// TestRenameRollbackRestoresDstWhiteout verifies that when a rename targets
// a path that had a whiteout (created by another agent's unlink), rolling
// back the rename restores the whiteout so the original delete intent is
// preserved.
func TestRenameRollbackRestoresDstWhiteout(t *testing.T) {
	b, trackedDir, stagingDir, cleanup := setup(t)
	defer cleanup()

	src := filepath.Join(trackedDir, "src.txt")
	dst := filepath.Join(trackedDir, "dst.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("doomed"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Agent A deletes dst (creates whiteout).
	if err := b.RecordUnlink(agentA, dst); err != nil {
		t.Fatalf("RecordUnlink: %v", err)
	}

	// Verify dst is hidden.
	wp, _ := whiteoutPathFor(stagingDir, trackedDir, dst)
	if _, err := os.Lstat(wp); err != nil {
		t.Fatalf("expected whiteout at %q", wp)
	}

	// Agent B renames src -> dst (clears dst whiteout).
	if err := b.RecordRename(agentB, src, dst); err != nil {
		t.Fatalf("RecordRename: %v", err)
	}

	// dst whiteout should be gone (cleared by rename).
	if _, err := os.Lstat(wp); !os.IsNotExist(err) {
		t.Error("dst whiteout should be cleared by rename")
	}

	// Rollback B only (A is NOT rolled back).
	// Note: B depends on A (B wrote to dst which A also dirtied), so
	// rolling back A would cascade to B. But rolling back B alone is fine.
	if err := b.Rollback(agentB); err != nil {
		t.Fatalf("Rollback B: %v", err)
	}

	// After rolling back B, A's whiteout for dst must be restored.
	if _, err := os.Lstat(wp); err != nil {
		t.Fatalf("expected dst whiteout restored after B rollback, got err=%v", err)
	}
}

// --- RecordUnlink cleans up overlay orphan ---

// TestRecordUnlinkCleansUpOverlay verifies that when an agent unlinks a
// file that has an existing overlay copy (from a prior write), the overlay
// file is cleaned up to prevent orphans.
func TestRecordUnlinkCleansUpOverlay(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "data.txt")
	if err := os.WriteFile(f, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Agent A writes the file (creates overlay copy).
	writeOverlay(t, b, agentA, f, []byte("modified"))

	overlayPath, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), f)
	if _, err := os.Stat(overlayPath); err != nil {
		t.Fatalf("overlay should exist after write: %v", err)
	}

	// Agent A unlinks the file. The overlay copy should be cleaned up.
	if err := b.RecordUnlink(agentA, f); err != nil {
		t.Fatalf("RecordUnlink: %v", err)
	}

	// Overlay file should be removed (not just hidden by whiteout).
	if _, err := os.Stat(overlayPath); !os.IsNotExist(err) {
		t.Error("overlay file should be cleaned up after unlink")
	}

	// Whiteout should exist (file is hidden).
	if !hasWhiteout(b.StagingDir(), b.TrackedDir(), f) {
		t.Error("whiteout should exist after unlink")
	}
}

// --- Rename stale UndoLog cleanup ---

// TestRenameStaleUndoLogCleanup verifies that RecordRename cleans up stale
// UndoLog entries for both oldPath and newPath. Without this, a prior
// write→unlink→rename-to-same-path sequence leaves conflicting entries
// that cause incorrect behaviour during promote.
func TestRenameStaleUndoLogCleanup(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	src := filepath.Join(trackedDir, "src.txt")
	dst := filepath.Join(trackedDir, "dst.txt")
	if err := os.WriteFile(src, []byte("src-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("dst-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Agent writes dst → UndoLog: [Write(dst)]
	writeOverlay(t, b, agentA, dst, []byte("written"))
	if b.AgentLen(agentA) != 1 {
		t.Fatalf("AgentLen = %d, want 1", b.AgentLen(agentA))
	}

	// 2. Agent deletes dst → UndoLog: [Write(dst), Unlink(dst)]
	if err := b.RecordUnlink(agentA, dst); err != nil {
		t.Fatalf("RecordUnlink: %v", err)
	}
	if b.AgentLen(agentA) != 2 {
		t.Fatalf("AgentLen = %d, want 2", b.AgentLen(agentA))
	}

	// 3. Agent renames src → dst → stale entries for dst must be cleaned.
	//    UndoLog should contain only: [Write(dst) from rename, Unlink(src)]
	if err := b.RecordRename(agentA, src, dst); err != nil {
		t.Fatalf("RecordRename: %v", err)
	}
	if b.AgentLen(agentA) != 2 {
		t.Fatalf("AgentLen = %d, want 2 (stale entries cleaned, rename adds 2)", b.AgentLen(agentA))
	}

	// 4. Commit and verify correct promotion: dst in orig should have
	//    src's content (from the rename), and src should be gone.
	b.Commit(agentA)
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != "src-data" {
		t.Errorf("dst = %q, want src-data", got)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("src should be removed after promote")
	}
}

// --- RollbackLastEntry cleans dirty tracking ---

// TestRollbackLastEntryCleansDirtyTracking verifies that RollbackLastEntry
// not only undoes the overlay artefact but also cleans the DirtyFiles and
// fileDirty tracking so the path is no longer considered dirty.
func TestRollbackLastEntryCleansDirtyTracking(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "data.txt")
	if err := os.WriteFile(f, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Agent writes the file.
	writeOverlay(t, b, agentA, f, []byte("modified"))
	if b.AgentLen(agentA) != 1 {
		t.Fatalf("AgentLen = %d, want 1", b.AgentLen(agentA))
	}

	// Verify dirty tracking is set.
	b.mu.Lock()
	agent := b.agents[agentA]
	_, dirtySet := agent.DirtyFiles[f]
	_, fileDirtySet := b.fileDirty[f]
	b.mu.Unlock()
	if !dirtySet {
		t.Error("agent DirtyFiles should contain f before rollback")
	}
	if !fileDirtySet {
		t.Error("fileDirty should contain f before rollback")
	}

	// Rollback the last entry.
	b.RollbackLastEntry(agentA)

	// Verify dirty tracking is cleaned.
	b.mu.Lock()
	agent = b.agents[agentA]
	_, dirtySet = agent.DirtyFiles[f]
	_, fileDirtySet = b.fileDirty[f]
	b.mu.Unlock()
	if dirtySet {
		t.Error("agent DirtyFiles should NOT contain f after rollbackLastEntry")
	}
	if fileDirtySet {
		t.Error("fileDirty should NOT contain f after rollbackLastEntry")
	}
	if b.AgentLen(agentA) != 0 {
		t.Errorf("AgentLen = %d, want 0", b.AgentLen(agentA))
	}
}

// --- MkdirEntry Rollback handles non-empty overlay dir ---

// TestMkdirRollbackRemovesOverlayChildren verifies that rolling back a
// mkdir properly removes the overlay directory even if it contains
// residual children (e.g. from dependent agents that were cascade-rolled
// back but left files behind).
func TestMkdirRollbackRemovesOverlayChildren(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	dir := filepath.Join(trackedDir, "parent")
	if err := b.RecordMkdir(agentA, dir, 0o755); err != nil {
		t.Fatalf("RecordMkdir: %v", err)
	}

	// Simulate an overlay child being left behind (e.g. from a dependent
	// agent whose cascade rollback ran but didn't fully clean up).
	op, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), dir)
	childDir := filepath.Join(op, "leftover")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(childDir, "stale.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Rollback should succeed (RemoveAll) even with residual children.
	if err := b.Rollback(agentA); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// Overlay dir should be completely gone.
	if _, err := os.Stat(op); !os.IsNotExist(err) {
		t.Error("overlay dir should be removed after rollback")
	}
}
