package backend

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// reopen opens a second backend over the same staging/orig pair.
func reopen(t *testing.T, staging, orig string) *Backend {
	t.Helper()
	b, err := NewBackend(staging, orig)
	if err != nil {
		t.Fatalf("reopen NewBackend: %v", err)
	}
	t.Cleanup(b.Close)
	return b
}

// --- serialization round trip ---

func TestVersionMarshalRoundTrip(t *testing.T) {
	v := &FileVersion{
		ID: 7, Owner: "ep-1", LogicalPath: "/o/f", StagePath: "/s/e/f",
		Parent: 3, Seq: 42, Operation: OpWhiteout, State: VSpeculative,
		Mode: 0o755, Rdev: 9, RenameFrom: "/o/old", LinkTarget: "/o/t",
		Dir: true,
	}
	p := marshalVersion(v)
	got := unmarshalVersion(&p)
	if *got != *v {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, v)
	}
}

// --- checkpoint (graceful close) recovery ---

func TestCheckpointRecovery(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	os.MkdirAll(orig, 0o755)
	f := filepath.Join(orig, "f.txt")
	os.WriteFile(f, []byte("base"), 0o644)

	b1, err := NewBackend(staging, orig)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := b1.PrepareWrite("A", f)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(sp, []byte("fa"), 0o644)
	// B reads A's version (edge) and writes g.
	g := filepath.Join(orig, "g.txt")
	if r := b1.Resolve("B", f); r.Producer != "A" {
		t.Fatal("setup: B must read A's version")
	}
	spg, err := b1.PrepareWrite("B", g)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(spg, []byte("gb"), 0o644)
	b1.Close() // graceful: final checkpoint captures the full version graph

	b2 := reopen(t, staging, orig)
	if _, owner := b2.HeadVersion(f); owner != "A" {
		t.Fatalf("recovered head owner of f = %q, want A", owner)
	}
	if _, owner := b2.HeadVersion(g); owner != "B" {
		t.Fatalf("recovered head owner of g = %q, want B", owner)
	}
	if !b2.DependsOn("B", "A") {
		t.Fatal("read-from edge must survive recovery")
	}
	// Cascade semantics intact after recovery.
	set, err := b2.RollbackWithAffected("A")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range set.Epochs {
		got[e] = true
	}
	if !got["A"] || !got["B"] {
		t.Fatalf("post-recovery cascade = %v, want {A,B}", set.Epochs)
	}
	if vid, _ := b2.HeadVersion(g); vid != 0 {
		t.Fatal("g must be rolled back after recovery cascade")
	}
}

// --- WAL replay (crash) recovery ---

func TestWALReplayRecovery(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	os.MkdirAll(orig, 0o755)
	f := filepath.Join(orig, "f.txt")
	os.WriteFile(f, []byte("base"), 0o644)

	b1, err := NewBackend(staging, orig)
	if err != nil {
		t.Fatal(err)
	}
	if err := b1.BeginEpoch("ep-x", "/cg/x", "sess-1"); err != nil {
		t.Fatal(err)
	}
	sp, err := b1.PrepareWrite("ep-x", f)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(sp, []byte("fx"), 0o644)
	if r := b1.Resolve("ep-y", f); r.Producer != "ep-x" {
		t.Fatal("setup: ep-y must read ep-x's version")
	}
	crash(t, b1) // WAL durable, checkpoint suppressed

	b2 := reopen(t, staging, orig)
	// Version chain, head, epoch registration and read edge all rebuilt
	// from the WAL alone.
	if _, owner := b2.HeadVersion(f); owner != "ep-x" {
		t.Fatalf("replayed head owner = %q, want ep-x", owner)
	}
	if id, ok := b2.ActiveEpochForCgroup("/cg/x"); !ok || id != "ep-x" {
		t.Fatalf("active epoch binding lost: %q %v", id, ok)
	}
	if !b2.DependsOn("ep-y", "ep-x") {
		t.Fatal("read_dep record must rebuild the edge")
	}
	res := b2.Resolve("reader", f)
	if !res.Exists || res.Producer != "ep-x" {
		t.Fatalf("replayed resolve = %+v", res)
	}
	if data, err := os.ReadFile(res.PhysicalPath); err != nil || string(data) != "fx" {
		t.Fatalf("replayed stage content = %q (%v), want fx", data, err)
	}
}

// A commit WAL record replayed after a crash re-authorizes the epoch and the
// recovery pass drives it to Finalized (promotion is idempotent).
func TestWALReplayCommitFinalizes(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	os.MkdirAll(orig, 0o755)
	f := filepath.Join(orig, "f.txt")
	os.WriteFile(f, []byte("base"), 0o644)

	b1, err := NewBackend(staging, orig)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := b1.PrepareWrite("A", f)
	os.WriteFile(sp, []byte("fa"), 0o644)
	if res, err := b1.Commit("A"); err != nil || res.State != Finalized {
		t.Fatalf("commit: %v %v", res, err)
	}
	crash(t, b1)

	b2 := reopen(t, staging, orig)
	if st, rel, ferr := b2.GetLifecycle("A"); st != "finalized" || !rel {
		t.Fatalf("recovered lifecycle = %s/%v (%s), want finalized", st, rel, ferr)
	}
	if data, _ := os.ReadFile(f); string(data) != "fa" {
		t.Fatalf("backing = %q, want fa", data)
	}
}

// --- fail-closed format gates ---

func TestLegacyV1StateRefused(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	os.MkdirAll(orig, 0o755)
	os.MkdirAll(staging, 0o755)
	// v1 kept its state file at the STAGING ROOT.
	legacy := filepath.Join(staging, ".shadow_state.json")
	os.WriteFile(legacy, []byte(`{"agents":{},"seq":3}`), 0o644)

	if _, err := NewBackend(staging, orig); err == nil {
		t.Fatal("legacy v1 state must abort startup (fail closed)")
	}
}

func TestUnsupportedCheckpointVersionRefused(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	os.MkdirAll(orig, 0o755)
	os.MkdirAll(metadataDir(staging), 0o755)
	// A v2-located checkpoint with the wrong format version.
	bad, _ := json.Marshal(map[string]any{"format_version": 1})
	os.WriteFile(persistFilePath(staging), bad, 0o644)

	if _, err := NewBackend(staging, orig); err == nil {
		t.Fatal("unsupported checkpoint format must abort startup (fail closed)")
	}
}

func TestUnsupportedWALFormatRefused(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	os.MkdirAll(orig, 0o755)
	os.MkdirAll(metadataDir(staging), 0o755)
	// A legacy-style WAL record (no "v" field -> format 0).
	os.WriteFile(walFilePath(staging),
		[]byte(`{"cgroup_id":"x","seq":1,"control_op":"commit"}`+"\n"), 0o644)

	if _, err := NewBackend(staging, orig); err == nil {
		t.Fatal("unsupported WAL format must abort startup (fail closed)")
	}
}
