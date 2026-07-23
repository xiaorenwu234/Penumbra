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

// TestRenameRollbackRemovesDstOverlayAndInvalidates verifies that rolling back
// a rename removes the destination's overlay copy (so the merged view no longer
// shows the renamed file) and that the registered invalidate callback is
// notified of both endpoints so the FUSE layer can drop stale kernel dentries.
func TestRenameRollbackRemovesDstOverlayAndInvalidates(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	var invalidated []string
	b.SetInvalidateCallback(func(paths []string) {
		invalidated = append(invalidated, paths...)
	})

	src := filepath.Join(trackedDir, "src.txt")
	dst := filepath.Join(trackedDir, "dst.txt")
	os.WriteFile(src, []byte("hello"), 0o644)

	if err := b.RecordRename(agentA, src, dst); err != nil {
		t.Fatalf("RecordRename: %v", err)
	}
	dstOverlay, _ := overlayPathFor(b.StagingDir(), b.TrackedDir(), dst)
	if _, err := os.Stat(dstOverlay); err != nil {
		t.Fatalf("dst overlay should exist after rename: %v", err)
	}

	if err := b.Rollback(agentA); err != nil {
		t.Fatal(err)
	}

	// The destination overlay copy must be gone; otherwise the merged view
	// would keep showing the renamed file after a rollback.
	if _, err := os.Stat(dstOverlay); !os.IsNotExist(err) {
		t.Errorf("dst overlay should be removed after rollback, got err=%v", err)
	}

	// The invalidate callback must have been told about both endpoints.
	sawSrc, sawDst := false, false
	for _, p := range invalidated {
		if p == src {
			sawSrc = true
		}
		if p == dst {
			sawDst = true
		}
	}
	if !sawSrc || !sawDst {
		t.Errorf("invalidate callback missing endpoints: sawSrc=%v sawDst=%v (got %v)", sawSrc, sawDst, invalidated)
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

// --- Release gating (CanRelease) ---

// TestCanReleaseGatedByUpstreamCommit verifies that a committed downstream
// agent is only releasable once its upstream dependency is also committed —
// the same gate ShadowFS uses to promote file changes. This mirrors the
// property ShadowProc relies on to hold external (IPC/network) operations
// until no upstream rollback can still cascade into the cgroup.
func TestCanReleaseGatedByUpstreamCommit(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	// A writes f; B reads f (so B depends on A) and writes its own file g
	// to give B active state that must survive until A commits.
	f := filepath.Join(trackedDir, "f.txt")
	writeOverlay(t, b, agentA, f, []byte("a"))
	b.RecordReadOpen(agentB, f)
	writeOverlay(t, b, agentB, filepath.Join(trackedDir, "g.txt"), []byte("b"))

	if !b.DependsOn(agentB, agentA) {
		t.Fatal("precondition: B should depend on A")
	}

	// Untracked cgroup: FAIL CLOSED. Since the release gate is now strictly
	// "agent reached Finalized", an unknown cgroup is NOT releasable (it must
	// be registered + finalized via Commit, not assumed safe).
	if b.CanRelease("cgroup-unknown") {
		t.Error("untracked cgroup must NOT be releasable (fail closed)")
	}

	// Nothing committed yet: neither is releasable.
	if b.CanRelease(agentA) {
		t.Error("A should not be releasable before commit")
	}
	if b.CanRelease(agentB) {
		t.Error("B should not be releasable before commit")
	}

	// Commit B only: its upstream A is still uncommitted → B must NOT be
	// releasable (an A rollback would still cascade into B).
	b.Commit(agentB)
	if b.CanRelease(agentB) {
		t.Error("B must not be releasable while upstream A is uncommitted")
	}

	// Commit A: now B's only upstream is committed → B becomes releasable.
	b.Commit(agentA)
	if !b.CanRelease(agentB) {
		t.Error("B should be releasable once upstream A is committed")
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
//
//	Agent A writes f.txt     → A is a writer
//	Agent B reads f.txt      → B depends on A (read dependency)
//	commit(B)                → B.Committed=true (but B has no writes)
//	commit(A)                → should promote f.txt even though B has
//	                           no explicit write-level commit
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
//
//	Agent A writes f.txt      → A is a writer
//	Agent B reads f.txt       → B depends on A
//	commit(A)                 → A should promote + finalize immediately
//	                             (B is read-only, should not block)
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
//
//	Agent A writes shared.txt
//	Agent B reads shared.txt  → B depends on A
//	Agent C writes shared.txt → C depends on A AND B
//	  (C depends on B because B read a file that C is also writing,
//	   via the isAncestor/exact-path dependency in RecordReadOpen)
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
//
//	Agent A writes f.txt → fileDirty[f] = {A}
//	Agent B reads f.txt  → B depends on A
//	commit(B)            → B.Committed=true, tryFinalize(B):
//	  dependsOn[B] = {A}, A not committed → B stays
//	commit(A)            → A.Committed=true, tryPromoteAll:
//	  tryPromotePath(f): writers={A}, A committed ✓
//	    upstreams of A: none ✓ → promote!
//	  tryFinalize(A): UndoLog empty ✓, dependsOn[A] empty ✓ → finalize A
//	  tryFinalize(B): UndoLog empty ✓, Committed=true ✓,
//	    dependsOn[B]={A}, A was finalized (removed) → not in agents → skip
//	    → finalize B
//
// This actually works correctly WITHOUT the fix because B IS committed.
// The issue is when B is NOT committed:
//
//	Agent A writes f.txt
//	Agent B reads f.txt  → B depends on A
//	commit(A) only       → promote f.txt, tryFinalize(A):
//	  UndoLog empty ✓, dependsOn[A] empty ✓ → finalize A
//	  tryFinalize(B): B.Committed=false → before fix: return false
//	  After fix: B is read-only (no undo, no dirty) → allowed
// TestReadOnlyDownstreamDoesNotBlockWriterFinalize: an uncommitted read-only
// agent B (which merely read A's file, so B depends on A) does NOT block A's
// promotion/finalization -- B is downstream, not upstream. Under the strong
// semantics B is NOT auto-finalized: it has no filesystem writes but may still
// have process/network/output effects, so it stays Speculative until its own
// policy is approved (committed).
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

	// A should be finalized and f.txt promoted (B, being downstream, does
	// not block it).
	got, _ := os.ReadFile(f)
	if string(got) != "new" {
		t.Errorf("orig = %q, want new", got)
	}
	if b.AgentLen(agentA) != 0 {
		t.Errorf("agentA should be finalized, AgentLen = %d", b.AgentLen(agentA))
	}
	if !b.CanRelease(agentA) {
		t.Error("agentA should be releasable after finalize")
	}

	// B must NOT be auto-finalized: an epoch is only authorized by an explicit
	// commit (policy approval), even with zero filesystem writes. It stays
	// Speculative and is NOT releasable.
	b.mu.Lock()
	bAgent, bExists := b.agents[agentB]
	var bState AgentLifecycle = -1
	if bExists {
		bState = bAgent.State
	}
	b.mu.Unlock()
	if !bExists || bState != Speculative {
		t.Errorf("read-only agentB must stay Speculative until committed (exists=%v state=%v)", bExists, bState)
	}
	if b.CanRelease(agentB) {
		t.Error("uncommitted read-only agentB must NOT be releasable")
	}

	// Once B's policy is approved, it finalizes (upstream A already finalized).
	if _, err := b.Commit(agentB); err != nil {
		t.Fatalf("Commit B: %v", err)
	}
	if !b.CanRelease(agentB) {
		t.Error("agentB should finalize+release once committed and upstream is finalized")
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

// --- P0 lifecycle: finalize / retention / ack_release ---

// TestLifecycleFinalizeThenAck verifies the retention contract: a committed
// agent with no un-finalized upstream reaches Finalized and is RELEASABLE, but
// its record is RETAINED until AckRelease is called (so the orchestrator can
// release external effects first). AckRelease then drops it and is idempotent.
func TestLifecycleFinalizeThenAck(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "f.txt")
	writeOverlay(t, b, agentA, f, []byte("a"))

	res, err := b.Commit(agentA)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if res.State != Finalized || !res.CanRelease {
		t.Fatalf("want Finalized+releasable, got state=%v canRelease=%v", res.State, res.CanRelease)
	}
	if !b.CanRelease(agentA) {
		t.Error("agentA should be releasable after finalize")
	}
	// Retained (not deleted) until ack.
	b.mu.Lock()
	_, exists := b.agents[agentA]
	b.mu.Unlock()
	if !exists {
		t.Error("finalized agent must be retained until AckRelease")
	}
	// The file must have been promoted to the real filesystem.
	if got, _ := os.ReadFile(f); string(got) != "a" {
		t.Errorf("promoted file = %q, want \"a\"", got)
	}

	if err := b.AckRelease(agentA); err != nil {
		t.Fatalf("AckRelease: %v", err)
	}
	b.mu.Lock()
	_, exists = b.agents[agentA]
	b.mu.Unlock()
	if exists {
		t.Error("agent must be dropped after AckRelease")
	}
	// Idempotent.
	if err := b.AckRelease(agentA); err != nil {
		t.Errorf("AckRelease should be idempotent, got %v", err)
	}
}

// TestCommitRegistersNoFileOpAgent verifies that committing a cgroup ShadowFS
// never saw (no file operations) REGISTERS it and drives it straight to
// Finalized, so release gating never has to treat "absent" as "safe".
func TestCommitRegistersNoFileOpAgent(t *testing.T) {
	b, _, _, cleanup := setup(t)
	defer cleanup()

	// Never touched by any Record*; fail-closed before commit.
	if b.CanRelease("cgroup-noop") {
		t.Fatal("unknown cgroup must not be releasable before commit")
	}
	res, err := b.Commit("cgroup-noop")
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if res.State != Finalized || !res.CanRelease {
		t.Fatalf("no-file-op agent should finalize immediately, got state=%v", res.State)
	}
	if !b.CanRelease("cgroup-noop") {
		t.Error("no-file-op agent should be releasable after commit")
	}
}

// TestPromotionFailureKeepsFenced is the core P0 guarantee: when a promotion
// fails (here: the destination directory is read-only), NOTHING is released
// and NO recovery state is discarded — CanRelease stays false, the undo entry
// and dirty tracking are preserved. After the fault is cleared, RetryFinalize
// drives the agent to Finalized. Skipped as root (root ignores dir perms).
func TestPromotionFailureKeepsFenced(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions; cannot inject rename EACCES")
	}
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	sub := filepath.Join(trackedDir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "f.txt")
	writeOverlay(t, b, agentA, f, []byte("payload"))

	// Inject the fault: make the promote destination directory read-only so
	// the overlay->orig rename fails with EACCES.
	if err := os.Chmod(sub, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(sub, 0o755) // ensure cleanup can remove it

	res, err := b.Commit(agentA)
	if err != nil {
		t.Fatalf("Commit (infra) error: %v", err)
	}
	// Promotion failed => NOT finalized, NOT releasable.
	if res.CanRelease || b.CanRelease(agentA) {
		t.Fatal("agent must NOT be releasable when a promotion failed")
	}
	if res.State == Finalized {
		t.Fatalf("state must not be Finalized after a promotion failure, got %v", res.State)
	}
	// Recovery state preserved: the undo entry and dirty tracking survive so
	// the promotion can be retried.
	if b.AgentLen(agentA) == 0 {
		t.Error("undo entry must be preserved after a failed promotion")
	}
	b.mu.Lock()
	_, stillDirty := b.fileDirty[f]
	ferr := ""
	if a := b.agents[agentA]; a != nil {
		ferr = a.FinalizeErr
	}
	b.mu.Unlock()
	if !stillDirty {
		t.Error("fileDirty tracking must be preserved after a failed promotion")
	}
	if ferr == "" {
		t.Error("FinalizeErr should record why promotion failed")
	}

	// Clear the fault and retry: now it must finalize and become releasable.
	if err := os.Chmod(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err = b.RetryFinalize(agentA)
	if err != nil {
		t.Fatalf("RetryFinalize: %v", err)
	}
	if res.State != Finalized || !res.CanRelease || !b.CanRelease(agentA) {
		t.Fatalf("after clearing the fault, retry must finalize: state=%v canRelease=%v", res.State, res.CanRelease)
	}
	if got, _ := os.ReadFile(f); string(got) != "payload" {
		t.Errorf("promoted file = %q, want \"payload\"", got)
	}
}

// roDirInject creates trackedDir/<name> (0755) and returns it plus a function
// that makes it read-only (so an overlay->orig rename into it fails EACCES).
// Tests using it must t.Skip when running as root (root bypasses perms).
func roDir(t *testing.T, trackedDir, name string) (string, func(), func()) {
	t.Helper()
	dir := filepath.Join(trackedDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fail := func() {
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
	}
	heal := func() { _ = os.Chmod(dir, 0o755) }
	return dir, fail, heal
}

// TestMultiFilePartialPromoteFailureKeepsFenced: one agent writes two files;
// promoting the second fails (read-only dir). The agent must NOT finalize or
// release, the failed path's recovery state is preserved, yet the successful
// path was promoted. After the fault clears, retry finalizes.
func TestMultiFilePartialPromoteFailureKeepsFenced(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	good := filepath.Join(trackedDir, "good.txt")
	writeOverlay(t, b, agentA, good, []byte("good"))
	badDir, fail, heal := roDir(t, trackedDir, "bad")
	defer heal()
	bad := filepath.Join(badDir, "bad.txt")
	writeOverlay(t, b, agentA, bad, []byte("bad"))

	fail()
	res, err := b.Commit(agentA)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if res.CanRelease || b.CanRelease(agentA) {
		t.Fatal("agent must NOT release while one file's promotion failed")
	}
	if res.State == Finalized {
		t.Fatalf("must not be Finalized, got %v", res.State)
	}
	if b.AgentLen(agentA) == 0 {
		t.Error("failed path's undo entry must be preserved")
	}
	// The good file must already be on disk (partial promotion is allowed;
	// only external-effect RELEASE is gated).
	if got, _ := os.ReadFile(good); string(got) != "good" {
		t.Errorf("good file should be promoted, got %q", got)
	}

	heal()
	res, err = b.RetryFinalize(agentA)
	if err != nil {
		t.Fatalf("RetryFinalize: %v", err)
	}
	if res.State != Finalized || !b.CanRelease(agentA) {
		t.Fatalf("retry should finalize, state=%v", res.State)
	}
	if got, _ := os.ReadFile(bad); string(got) != "bad" {
		t.Errorf("bad file should be promoted after retry, got %q", got)
	}
}

// TestUpstreamPromoteFailureBlocksDownstream: B depends on A. A's promotion
// fails; B's own promotion succeeds and B is approved — but B must NOT be
// releasable because its upstream A is not Finalized. Clearing A's fault and
// retrying finalizes both.
func TestUpstreamPromoteFailureBlocksDownstream(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	aDir, fail, heal := roDir(t, trackedDir, "a")
	defer heal()
	fa := filepath.Join(aDir, "fa.txt")
	writeOverlay(t, b, agentA, fa, []byte("a"))

	// B reads A's file (B depends on A) and writes its own file in a writable dir.
	b.RecordReadOpen(agentB, fa)
	gb := filepath.Join(trackedDir, "gb.txt")
	writeOverlay(t, b, agentB, gb, []byte("b"))
	if !b.DependsOn(agentB, agentA) {
		t.Fatal("precondition: B must depend on A")
	}

	fail()
	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if _, err := b.Commit(agentB); err != nil {
		t.Fatalf("Commit B: %v", err)
	}
	if b.CanRelease(agentB) {
		t.Fatal("downstream B must NOT release while upstream A's promotion failed")
	}
	if b.CanRelease(agentA) {
		t.Fatal("A must NOT release with a failed promotion")
	}

	heal()
	if _, err := b.RetryFinalize(agentA); err != nil {
		t.Fatalf("RetryFinalize A: %v", err)
	}
	if !b.CanRelease(agentA) {
		t.Error("A should finalize after fault cleared")
	}
	if !b.CanRelease(agentB) {
		t.Error("B should finalize once upstream A finalized")
	}
}

// TestCycleFinalizesTogether: A <-> B mutual dependency. Once both commit and
// both promotions succeed, the whole SCC finalizes and both become releasable.
func TestCycleFinalizesTogether(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	fa := filepath.Join(trackedDir, "fa.txt")
	fb := filepath.Join(trackedDir, "fb.txt")
	writeOverlay(t, b, agentA, fa, []byte("a"))
	writeOverlay(t, b, agentB, fb, []byte("b"))
	// Build the cycle: B reads fa (B->A), A reads fb (A->B).
	b.RecordReadOpen(agentB, fa)
	b.RecordReadOpen(agentA, fb)
	if !b.DependsOn(agentB, agentA) || !b.DependsOn(agentA, agentB) {
		t.Fatal("precondition: A and B must form a dependency cycle")
	}

	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	// Before B commits, A cannot finalize (its SCC partner B is unapproved).
	if b.CanRelease(agentA) {
		t.Fatal("A must not release before its cycle partner B is approved")
	}
	if _, err := b.Commit(agentB); err != nil {
		t.Fatalf("Commit B: %v", err)
	}
	if !b.CanRelease(agentA) || !b.CanRelease(agentB) {
		t.Fatal("the whole cycle should finalize once both are approved+promoted")
	}
	if got, _ := os.ReadFile(fa); string(got) != "a" {
		t.Errorf("fa not promoted: %q", got)
	}
	if got, _ := os.ReadFile(fb); string(got) != "b" {
		t.Errorf("fb not promoted: %q", got)
	}
}

// TestCycleMemberPromoteFailureFencesAll: in an A <-> B cycle, if ONE member's
// promotion fails the ENTIRE SCC stays fenced (no member releases), even the
// member whose own promotion succeeded. Clearing the fault + retry finalizes
// the whole cycle.
func TestCycleMemberPromoteFailureFencesAll(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	aDir, fail, heal := roDir(t, trackedDir, "a")
	defer heal()
	fa := filepath.Join(aDir, "fa.txt")       // A's promote will fail
	fb := filepath.Join(trackedDir, "fb.txt") // B's promote will succeed
	writeOverlay(t, b, agentA, fa, []byte("a"))
	writeOverlay(t, b, agentB, fb, []byte("b"))
	b.RecordReadOpen(agentB, fa)
	b.RecordReadOpen(agentA, fb)

	fail()
	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if _, err := b.Commit(agentB); err != nil {
		t.Fatalf("Commit B: %v", err)
	}
	// A's promotion failed => the whole SCC must be fenced.
	if b.CanRelease(agentA) || b.CanRelease(agentB) {
		t.Fatal("no cycle member may release when one member's promotion failed")
	}

	heal()
	if _, err := b.RetryFinalize(agentA); err != nil {
		t.Fatalf("RetryFinalize: %v", err)
	}
	if !b.CanRelease(agentA) || !b.CanRelease(agentB) {
		t.Fatal("the whole cycle should finalize after the fault clears")
	}
}

// --- Advanced FS features: hard links / special files / xattr ---

// TestHardLinkPromotesRealLink: a hard link recorded speculatively becomes a
// real hard link (same inode, nlink>=2) on the orig FS after commit.
func TestHardLinkPromotesRealLink(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	target := filepath.Join(trackedDir, "t.txt")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(trackedDir, "l.txt")
	if err := b.RecordLink(agentA, target, link); err != nil {
		t.Fatalf("RecordLink: %v", err)
	}
	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	var st1, st2 syscall.Stat_t
	if err := syscall.Stat(target, &st1); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(link, &st2); err != nil {
		t.Fatalf("orig hard link not promoted: %v", err)
	}
	if st1.Ino != st2.Ino {
		t.Errorf("hard link inode mismatch: target=%d link=%d", st1.Ino, st2.Ino)
	}
	if st1.Nlink < 2 {
		t.Errorf("target nlink=%d, want >=2", st1.Nlink)
	}
	if got, _ := os.ReadFile(link); string(got) != "data" {
		t.Errorf("link content=%q", got)
	}
}

// TestHardLinkRollback: rolling back discards the overlay link and never
// creates the orig link.
func TestHardLinkRollback(t *testing.T) {
	b, trackedDir, stagingDir, cleanup := setup(t)
	defer cleanup()

	target := filepath.Join(trackedDir, "t.txt")
	os.WriteFile(target, []byte("data"), 0o644)
	link := filepath.Join(trackedDir, "l.txt")
	if err := b.RecordLink(agentA, target, link); err != nil {
		t.Fatalf("RecordLink: %v", err)
	}
	if err := b.Rollback(agentA); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Error("orig link must not exist after rollback")
	}
	if _, err := os.Lstat(filepath.Join(stagingDir, "l.txt")); !os.IsNotExist(err) {
		t.Error("overlay link must be removed on rollback")
	}
}

// TestMknodFifoCommitAndRollback: a FIFO special file is created in the
// overlay, removed on rollback, and promoted to a real FIFO on commit.
func TestMknodFifoCommitAndRollback(t *testing.T) {
	b, trackedDir, stagingDir, cleanup := setup(t)
	defer cleanup()

	fifo := filepath.Join(trackedDir, "p.fifo")
	overlay := filepath.Join(stagingDir, "p.fifo")

	if err := b.RecordMknod(agentA, fifo, syscall.S_IFIFO|0o644, 0); err != nil {
		t.Fatalf("RecordMknod: %v", err)
	}
	if _, err := os.Lstat(overlay); err != nil {
		t.Fatalf("overlay fifo should exist: %v", err)
	}
	if err := b.Rollback(agentA); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, err := os.Lstat(overlay); !os.IsNotExist(err) {
		t.Error("overlay fifo should be gone after rollback")
	}
	if _, err := os.Lstat(fifo); !os.IsNotExist(err) {
		t.Error("orig fifo must not exist after rollback")
	}

	// Commit path.
	if err := b.RecordMknod(agentA, fifo, syscall.S_IFIFO|0o644, 0); err != nil {
		t.Fatalf("RecordMknod (2): %v", err)
	}
	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(fifo, &st); err != nil {
		t.Fatalf("orig fifo not promoted: %v", err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		t.Errorf("promoted node is not a FIFO: mode=%#o", st.Mode)
	}
}

// TestSetxattrRollbackAndCommit: a speculative xattr change lands on the
// overlay copy; rollback leaves the orig's xattrs untouched, and commit
// carries the new xattr onto orig while preserving pre-existing ones (ACLs
// are xattrs, so this exercises the same path).
func TestSetxattrRollbackAndCommit(t *testing.T) {
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	f := filepath.Join(trackedDir, "f.txt")
	os.WriteFile(f, []byte("x"), 0o644)
	if err := syscall.Setxattr(f, "user.orig", []byte("O"), 0); err != nil {
		t.Skipf("xattr unsupported on this filesystem: %v", err)
	}

	op, err := b.RecordXattrWrite(agentA, f)
	if err != nil {
		t.Fatalf("RecordXattrWrite: %v", err)
	}
	if err := syscall.Setxattr(op, "user.agent", []byte("A"), 0); err != nil {
		t.Fatalf("Setxattr overlay: %v", err)
	}
	if err := b.Rollback(agentA); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := syscall.Getxattr(f, "user.agent", buf); err == nil {
		t.Error("orig must NOT carry the agent xattr after rollback")
	}

	op, err = b.RecordXattrWrite(agentA, f)
	if err != nil {
		t.Fatalf("RecordXattrWrite (2): %v", err)
	}
	if err := syscall.Setxattr(op, "user.agent", []byte("A"), 0); err != nil {
		t.Fatalf("Setxattr overlay (2): %v", err)
	}
	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	n, gerr := syscall.Getxattr(f, "user.agent", buf)
	if gerr != nil {
		t.Fatalf("orig missing agent xattr after commit: %v", gerr)
	}
	if string(buf[:n]) != "A" {
		t.Errorf("agent xattr=%q, want A", buf[:n])
	}
	n2, gerr2 := syscall.Getxattr(f, "user.orig", buf)
	if gerr2 != nil || string(buf[:n2]) != "O" {
		t.Errorf("pre-existing xattr not preserved after commit: err=%v val=%q", gerr2, buf[:n2])
	}
}

// --- Strong-semantics invariants: no auto-authorize / deferred promotion /
//     rollback refused after promotion starts ---

// TestRollbackRefusedAfterPromotionStarted: once an agent has entered
// Finalizing (a promotion has started, so some writes may already be
// published), a rollback must be REFUSED -- the undo log can no longer restore
// the torn workspace. Uses a read-only destination dir to wedge the agent in
// Finalizing. Skipped as root (root bypasses dir perms).
func TestRollbackRefusedAfterPromotionStarted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	sub, fail, heal := roDir(t, trackedDir, "sub")
	defer heal()
	f := filepath.Join(sub, "f.txt")
	writeOverlay(t, b, agentA, f, []byte("v"))

	fail()
	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Promotion started but failed => agent is Finalizing.
	b.mu.Lock()
	st := b.agents[agentA].State
	b.mu.Unlock()
	if st != Finalizing {
		t.Fatalf("expected Finalizing after a failed promotion, got %v", st)
	}
	// Rollback must be refused (cannot undo already-started promotion).
	if _, err := b.RollbackWithAffected(agentA); err == nil {
		t.Fatal("rollback of a Finalizing agent must be refused")
	}
	// The agent and its recovery state must still be intact for retry.
	if b.AgentLen(agentA) == 0 {
		t.Error("undo log must be preserved after a refused rollback")
	}
	// Clearing the fault + retry still finalizes it.
	heal()
	if _, err := b.RetryFinalize(agentA); err != nil {
		t.Fatalf("RetryFinalize: %v", err)
	}
	if !b.CanRelease(agentA) {
		t.Error("agent should finalize after fault cleared")
	}
}

// TestPromotionDeferredUntilUpstreamFinalized: a downstream agent's files must
// NOT be published to the real workspace while its upstream is merely approved
// (not yet Finalized). A writes fa into a read-only dir (so A is stuck in
// Finalizing, approved-but-not-finalized); B writes fb (writable) and depends
// on A (reads fa). Committing both must leave fb UN-promoted until A finalizes.
// Skipped as root.
func TestPromotionDeferredUntilUpstreamFinalized(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	aDir, fail, heal := roDir(t, trackedDir, "a")
	defer heal()
	fa := filepath.Join(aDir, "fa.txt")
	writeOverlay(t, b, agentA, fa, []byte("a"))

	fb := filepath.Join(trackedDir, "fb.txt")
	writeOverlay(t, b, agentB, fb, []byte("b"))
	b.RecordReadOpen(agentB, fa) // B depends on A (distinct paths, not co-writers)
	if !b.DependsOn(agentB, agentA) {
		t.Fatal("precondition: B must depend on A")
	}

	fail()
	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if _, err := b.Commit(agentB); err != nil {
		t.Fatalf("Commit B: %v", err)
	}
	// A is approved but NOT Finalized (its promotion is failing), so B's fb
	// must NOT have been published yet -- promotion is deferred.
	if _, err := os.Lstat(fb); !os.IsNotExist(err) {
		t.Error("downstream fb must NOT be promoted while upstream A is un-finalized")
	}
	if b.CanRelease(agentB) {
		t.Error("downstream B must not be releasable before upstream A finalizes")
	}

	// Once A's fault clears and A finalizes, B's fb may finally publish.
	heal()
	if _, err := b.RetryFinalize(agentA); err != nil {
		t.Fatalf("RetryFinalize A: %v", err)
	}
	if !b.CanRelease(agentA) {
		t.Fatal("A should finalize after fault cleared")
	}
	if got, _ := os.ReadFile(fb); string(got) != "b" {
		t.Errorf("fb should be promoted once upstream finalized, got %q", got)
	}
	if !b.CanRelease(agentB) {
		t.Error("B should finalize once upstream A is finalized")
	}
}

// TestRollbackInternalAuthoritativeGuard exercises the guard where it is
// AUTHORITATIVE -- inside rollbackInternal, the executor shared by live apply
// and WAL replay. A Finalizing agent (promotion started) must be refused
// in-place, so a durable rollback record that raced a commit becomes a safe
// no-op on replay rather than corrupting published state. Skipped as root.
func TestRollbackInternalAuthoritativeGuard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	sub, fail, heal := roDir(t, trackedDir, "sub")
	defer heal()
	f := filepath.Join(sub, "f.txt")
	writeOverlay(t, b, agentA, f, []byte("v"))

	fail()
	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	b.mu.Lock()
	if st := b.agents[agentA].State; st != Finalizing {
		b.mu.Unlock()
		t.Fatalf("expected Finalizing, got %v", st)
	}
	// Invoke the authoritative executor exactly as replayWAL would.
	err := b.rollbackInternal(agentA)
	b.mu.Unlock()
	if err == nil {
		t.Fatal("rollbackInternal must refuse a Finalizing agent (authoritative guard)")
	}
	if b.AgentLen(agentA) == 0 {
		t.Error("recovery state must be preserved after the refused rollback")
	}
	heal()
	if _, err := b.RetryFinalize(agentA); err != nil {
		t.Fatalf("RetryFinalize: %v", err)
	}
	if !b.CanRelease(agentA) {
		t.Error("agent should finalize after fault cleared")
	}
}

// TestRollbackEpochRefusedWhenFinalizing verifies the control-plane fix:
// RollbackEpoch now returns an error when the epoch's promotion has already
// started (State >= Finalizing), so the socket layer reports status=error and
// the orchestrator (which rolls ShadowFS back FIRST) will NOT roll back the
// process/network version. The epoch's undo state must be preserved. Skipped
// as root.
func TestRollbackEpochRefusedWhenFinalizing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	b, trackedDir, _, cleanup := setup(t)
	defer cleanup()

	sub, fail, heal := roDir(t, trackedDir, "sub")
	defer heal()
	f := filepath.Join(sub, "f.txt")

	b.BeginEpoch(agentA)
	writeOverlay(t, b, agentA, f, []byte("v"))

	fail()
	if _, err := b.Commit(agentA); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	b.mu.Lock()
	st := b.agents[agentA].State
	open := b.agents[agentA].EpochOpen
	b.mu.Unlock()
	if st != Finalizing {
		t.Fatalf("expected Finalizing after a failed promotion, got %v", st)
	}
	if !open {
		t.Fatal("epoch should still be open (commit does not clear the epoch marker)")
	}

	// RollbackEpoch must be REFUSED with an error (not a silent ok).
	if err := b.RollbackEpoch(agentA); err == nil {
		t.Fatal("RollbackEpoch must return an error once the epoch's promotion has started")
	}
	// The epoch's recovery state must be intact (nothing undone), so a later
	// retry can still finalize.
	if b.AgentLen(agentA) == 0 {
		t.Error("epoch undo entries must be preserved after a refused rollback_epoch")
	}

	heal()
	if _, err := b.RetryFinalize(agentA); err != nil {
		t.Fatalf("RetryFinalize: %v", err)
	}
	if !b.CanRelease(agentA) {
		t.Error("agent should finalize after fault cleared")
	}
}
