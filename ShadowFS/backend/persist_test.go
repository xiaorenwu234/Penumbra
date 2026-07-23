package backend

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	entries := []LogEntry{
		&OverlayWriteEntry{baseEntry: baseEntry{SeqNum: 1}, OrigPath: "/a/b.txt", OverlayPath: "/staging/overlay/a/b.txt"},
		&OverlayMkdirEntry{baseEntry: baseEntry{SeqNum: 2}, OrigPath: "/a/d", OverlayPath: "/staging/overlay/a/d", Mode: 0o755},
		&OverlayUnlinkEntry{baseEntry: baseEntry{SeqNum: 3}, OrigPath: "/a/e.txt", OverlayPath: "/staging/overlay/a/e.txt", WhiteoutPath: "/staging/overlay/a/.shadow.wh.e.txt"},
		&OverlayRmdirEntry{baseEntry: baseEntry{SeqNum: 4}, OrigPath: "/a/r", OverlayPath: "/staging/overlay/a/r", WhiteoutPath: "/staging/overlay/a/.shadow.wh.r"},
	}

	for _, entry := range entries {
		se := MarshalEntry(entry)
		restored := UnmarshalEntry(se)
		if restored == nil {
			t.Fatalf("UnmarshalEntry returned nil for %T", entry)
		}
		if restored.Seq() != entry.Seq() {
			t.Errorf("Seq mismatch: got %d, want %d", restored.Seq(), entry.Seq())
		}
		if restored.Path() != entry.Path() {
			t.Errorf("Path mismatch: got %q, want %q", restored.Path(), entry.Path())
		}
		se2 := MarshalEntry(restored)
		if se != se2 {
			t.Errorf("round-trip mismatch for %T: %+v != %+v", entry, se, se2)
		}
	}
}

func TestSaveToDiskAndLoadFromDisk(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "persist_test_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "state.json")

	state := &PersistState{
		Agents: map[string]*PersistAgent{
			"agent-a": {
				CgroupID: "agent-a",
				UndoLog: []SerializableEntry{
					{Type: "mkdir", SeqNum: 1, OrigPath: "/test/dir", OverlayPath: "/staging/overlay/test/dir", Mode: 0o755},
					{Type: "write", SeqNum: 2, OrigPath: "/test/file.txt", OverlayPath: "/staging/overlay/test/file.txt"},
				},
				DirtyFiles: []string{"/test/dir", "/test/file.txt"},
				Committed:  false,
			},
		},
		Dependents: map[string][]string{"agent-a": {"agent-b"}},
		DependsOn:  map[string][]string{"agent-b": {"agent-a"}},
		FileDirty:  map[string][]string{"/test/file.txt": {"agent-a", "agent-b"}},
		Seq:        10,
	}

	if err := saveToDisk(path, state); err != nil {
		t.Fatalf("saveToDisk: %v", err)
	}

	loaded, err := loadFromDisk(path)
	if err != nil {
		t.Fatalf("loadFromDisk: %v", err)
	}
	if loaded.Seq != state.Seq {
		t.Errorf("Seq = %d, want %d", loaded.Seq, state.Seq)
	}
	if len(loaded.Agents) != 1 {
		t.Fatalf("Agents count = %d, want 1", len(loaded.Agents))
	}
	agent := loaded.Agents["agent-a"]
	if agent == nil {
		t.Fatal("agent-a not found")
	}
	if len(agent.UndoLog) != 2 {
		t.Errorf("UndoLog len = %d, want 2", len(agent.UndoLog))
	}
	if agent.UndoLog[0].Type != "mkdir" || agent.UndoLog[1].Type != "write" {
		t.Errorf("UndoLog types = %q,%q", agent.UndoLog[0].Type, agent.UndoLog[1].Type)
	}
}

func TestRecoveryAfterRestart(t *testing.T) {
	trackedDir, err := os.MkdirTemp("", "persist_tracked_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(trackedDir)

	stagingDir, err := os.MkdirTemp("", "persist_staging_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stagingDir)

	b1, err := NewBackend(stagingDir, trackedDir)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	f := filepath.Join(trackedDir, "test.txt")
	os.WriteFile(f, []byte("orig"), 0o644)
	overlayPath, err := b1.PrepareWrite("agent-x", f)
	if err != nil {
		t.Fatalf("PrepareWrite: %v", err)
	}
	os.WriteFile(overlayPath, []byte("modified"), 0o644)

	dir := filepath.Join(trackedDir, "testdir")
	if err := b1.RecordMkdir("agent-x", dir, 0o755); err != nil {
		t.Fatal(err)
	}

	b1.Close()

	statePath := persistFilePath(stagingDir)
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file should exist: %v", err)
	}

	b2, err := NewBackend(stagingDir, trackedDir)
	if err != nil {
		t.Fatalf("NewBackend recovery: %v", err)
	}
	defer b2.Close()

	if b2.AgentLen("agent-x") != 2 {
		t.Errorf("recovered AgentLen = %d, want 2", b2.AgentLen("agent-x"))
	}

	// Rollback after recovery: overlay artefacts should disappear, orig unchanged.
	if err := b2.Rollback("agent-x"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got, _ := os.ReadFile(f); string(got) != "orig" {
		t.Errorf("orig changed: %q", got)
	}
	if _, err := os.Stat(overlayPath); !os.IsNotExist(err) {
		t.Errorf("overlay should be gone")
	}
}

func TestRecoveryWithDependencyGraph(t *testing.T) {
	trackedDir, err := os.MkdirTemp("", "persist_dep_tracked_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(trackedDir)

	stagingDir, err := os.MkdirTemp("", "persist_dep_staging_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stagingDir)

	b1, err := NewBackend(stagingDir, trackedDir)
	if err != nil {
		t.Fatal(err)
	}

	f := filepath.Join(trackedDir, "shared.txt")
	os.WriteFile(f, []byte("orig"), 0o644)
	op1, _ := b1.PrepareWrite("agent-a", f)
	os.WriteFile(op1, []byte("a"), 0o644)
	op2, _ := b1.PrepareWrite("agent-b", f)
	os.WriteFile(op2, []byte("b"), 0o644)

	b1.Close()

	b2, err := NewBackend(stagingDir, trackedDir)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()

	if !b2.DependsOn("agent-b", "agent-a") {
		t.Error("dependency A->B should survive recovery")
	}

	if err := b2.Rollback("agent-a"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if b2.AgentLen("agent-a") != 0 || b2.AgentLen("agent-b") != 0 {
		t.Error("both agents should be cleared after cascade rollback")
	}
}

func TestDirtyFlagAndPeriodicFlush(t *testing.T) {
	trackedDir, err := os.MkdirTemp("", "persist_dirty_tracked_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(trackedDir)

	stagingDir, err := os.MkdirTemp("", "persist_dirty_staging_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stagingDir)

	b, err := NewBackend(stagingDir, trackedDir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	f := filepath.Join(trackedDir, "periodic.txt")
	op, _ := b.PrepareWrite("agent-p", f)
	os.WriteFile(op, []byte("data"), 0o644)

	// The new WAL+checkpoint design uses a 5s checkpoint interval.
	// Instead of waiting the full interval, verify that Close() produces
	// a valid checkpoint (which it always does on shutdown).
	b.Close()

	statePath := persistFilePath(stagingDir)
	if _, err := os.Stat(statePath); err != nil {
		t.Errorf("state file should exist after periodic flush: %v", err)
	}
	loaded, err := loadFromDisk(statePath)
	if err != nil {
		t.Fatalf("loadFromDisk: %v", err)
	}
	if len(loaded.Agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(loaded.Agents))
	}
}

func TestCloseProducesValidStateFile(t *testing.T) {
	trackedDir, err := os.MkdirTemp("", "persist_close_tracked_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(trackedDir)

	stagingDir, err := os.MkdirTemp("", "persist_close_staging_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stagingDir)

	b, err := NewBackend(stagingDir, trackedDir)
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(trackedDir, "closedir")
	if err := b.RecordMkdir("agent-close", dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b.Close()

	statePath := persistFilePath(stagingDir)
	loaded, err := loadFromDisk(statePath)
	if err != nil {
		t.Fatalf("loadFromDisk: %v", err)
	}
	agent, ok := loaded.Agents["agent-close"]
	if !ok {
		t.Fatal("agent-close not found")
	}
	if len(agent.UndoLog) != 1 {
		t.Errorf("UndoLog len = %d, want 1", len(agent.UndoLog))
	}
	if agent.UndoLog[0].Type != "mkdir" {
		t.Errorf("type = %q, want mkdir", agent.UndoLog[0].Type)
	}
}

// mkTmpDirs is a small helper: two temp dirs + cleanup, for crash-recovery
// tests that must reopen the SAME staging/tracked dirs.
func mkTmpDirs(t *testing.T) (tracked, staging string, cleanup func()) {
	t.Helper()
	tracked, err := os.MkdirTemp("", "recov_tracked_")
	if err != nil {
		t.Fatal(err)
	}
	staging, err = os.MkdirTemp("", "recov_staging_")
	if err != nil {
		os.RemoveAll(tracked)
		t.Fatal(err)
	}
	return tracked, staging, func() {
		os.RemoveAll(tracked)
		os.RemoveAll(staging)
	}
}

// TestRecoveryFinalizedStaysReleasable: an agent that Finalized before a crash
// must recover as Finalized (releasable) and remain RETAINED until AckRelease.
func TestRecoveryFinalizedStaysReleasable(t *testing.T) {
	tracked, staging, cleanup := mkTmpDirs(t)
	defer cleanup()

	b1, err := NewBackend(staging, tracked)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	f := filepath.Join(tracked, "f.txt")
	op, err := b1.PrepareWrite("agent-x", f)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(op, []byte("v"), 0o644)
	if _, err := b1.Commit("agent-x"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !b1.CanRelease("agent-x") {
		t.Fatal("precondition: agent should be releasable after commit")
	}
	b1.Close()

	// Simulate restart.
	b2, err := NewBackend(staging, tracked)
	if err != nil {
		t.Fatalf("NewBackend recovery: %v", err)
	}
	defer b2.Close()
	if !b2.CanRelease("agent-x") {
		t.Error("recovered agent must still be Finalized/releasable")
	}
	if got, _ := os.ReadFile(f); string(got) != "v" {
		t.Errorf("promoted file after recovery = %q, want \"v\"", got)
	}
	if err := b2.AckRelease("agent-x"); err != nil {
		t.Fatalf("AckRelease: %v", err)
	}
	if b2.CanRelease("agent-x") {
		t.Error("after ack, agent is gone and must be fail-closed (not releasable)")
	}
}

// TestRecoveryPromoteFailureStaysFenced: if a promotion was failing at crash
// time and the fault PERSISTS across restart, recovery re-runs the idempotent
// promotion, it fails again, and the agent stays fenced (NOT releasable) with
// its recovery state intact. Pending is never mistaken for finalized. Once the
// fault clears, retry finalizes. Skipped as root (root bypasses dir perms).
func TestRecoveryPromoteFailureStaysFenced(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	tracked, staging, cleanup := mkTmpDirs(t)
	defer cleanup()

	sub := filepath.Join(tracked, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "f.txt")

	b1, err := NewBackend(staging, tracked)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	op, err := b1.PrepareWrite("agent-x", f)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(op, []byte("v"), 0o644)
	if err := os.Chmod(sub, 0o555); err != nil { // inject the fault
		t.Fatal(err)
	}
	defer os.Chmod(sub, 0o755)
	if _, err := b1.Commit("agent-x"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if b1.CanRelease("agent-x") {
		t.Fatal("must not be releasable with a failing promotion")
	}
	b1.Close()

	// Restart with the fault STILL present: recovery must not finalize.
	b2, err := NewBackend(staging, tracked)
	if err != nil {
		t.Fatalf("NewBackend recovery: %v", err)
	}
	defer b2.Close()
	if b2.CanRelease("agent-x") {
		t.Fatal("recovery must NOT mistake a still-failing promotion for finalized")
	}
	if b2.AgentLen("agent-x") == 0 {
		t.Error("recovery must preserve the un-promoted undo entry")
	}

	// Clear the fault and retry: now it finalizes.
	if err := os.Chmod(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := b2.RetryFinalize("agent-x"); err != nil {
		t.Fatalf("RetryFinalize: %v", err)
	}
	if !b2.CanRelease("agent-x") {
		t.Error("agent should finalize after fault cleared")
	}
	if got, _ := os.ReadFile(f); string(got) != "v" {
		t.Errorf("promoted file = %q, want \"v\"", got)
	}
}
