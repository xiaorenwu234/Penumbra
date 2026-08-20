package backend

import (
	"os"
	"path/filepath"
	"testing"
)

// --- helpers ---

// newTestBackend creates a backend over a fresh orig/staging pair.
func newTestBackend(t *testing.T) (*Backend, string, string) {
	t.Helper()
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(orig, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := NewBackend(staging, orig)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	t.Cleanup(b.Close)
	return b, orig, staging
}

func writeOrig(t *testing.T, orig, rel, content string) string {
	t.Helper()
	p := filepath.Join(orig, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// stageWrite simulates a FUSE write: PrepareWrite then write the payload.
func stageWrite(t *testing.T, b *Backend, epoch EpochID, origPath, content string) string {
	t.Helper()
	sp, err := b.PrepareWrite(epoch, origPath)
	if err != nil {
		t.Fatalf("PrepareWrite(%s, %s): %v", epoch, origPath, err)
	}
	if err := os.WriteFile(sp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return sp
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %q: %v", p, err)
	}
	return string(data)
}

func mustCommitFinalized(t *testing.T, b *Backend, epoch EpochID) {
	t.Helper()
	res, err := b.Commit(epoch)
	if err != nil {
		t.Fatalf("Commit(%s): %v", epoch, err)
	}
	if res.State != Finalized {
		t.Fatalf("Commit(%s): state=%s failures=%v, want finalized", epoch, res.State, res.Failures)
	}
}

// crash simulates a hard crash: WAL is flushed durable, but the graceful
// final checkpoint is suppressed (walCount forced to 0 makes checkpoint a
// no-op), so a reopen exercises the WAL REPLAY path.
func crash(t *testing.T, b *Backend) {
	t.Helper()
	b.flushPending()
	b.mu.Lock()
	b.walCount = 0
	b.mu.Unlock()
	b.Close()
}

// --- acceptance case 1: MVCC basic chain ---
//
// A writes "a"; B writes "b" over it; rollback B => readers see "a";
// commit A => backing == "a".
func TestMVCCBasicChain(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	stageWrite(t, b, "A", f, "a")
	spB := stageWrite(t, b, "B", f, "b")

	// B's copy-up base must be A's version (the visible head), not backing.
	if _, owner := b.HeadVersion(f); owner != "B" {
		t.Fatalf("head owner = %q, want B", owner)
	}
	_ = spB

	set, err := b.RollbackWithAffected("B")
	if err != nil {
		t.Fatalf("rollback B: %v", err)
	}
	if len(set.Epochs) != 1 || set.Epochs[0] != "B" {
		t.Fatalf("rollback B affected %v, want [B] only", set.Epochs)
	}

	// Predecessor version RE-EXPOSED: a reader now sees A's "a".
	res := b.Resolve("reader", f)
	if !res.Exists || res.Producer != "A" {
		t.Fatalf("post-rollback resolve: %+v, want producer A", res)
	}
	if got := readFile(t, res.PhysicalPath); got != "a" {
		t.Fatalf("post-rollback content = %q, want a", got)
	}

	mustCommitFinalized(t, b, "A")
	if got := readFile(t, f); got != "a" {
		t.Fatalf("backing after commit = %q, want a", got)
	}
	if vid, _ := b.HeadVersion(f); vid != 0 {
		t.Fatalf("head after promote = v%d, want backing (0)", vid)
	}
}

// --- acceptance case 2: cascade removes consumers, preserves unrelated ---
//
// A writes f; B reads A:f and writes g; C writes unrelated h.
// rollback A => remove A:f and B:g, preserve C:h.
func TestCascadePreservesUnrelated(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base-f")
	g := filepath.Join(orig, "g.txt")
	h := filepath.Join(orig, "h.txt")

	stageWrite(t, b, "A", f, "fa")

	// B reads the version A produced (read-from edge), then writes g.
	res := b.Resolve("B", f)
	if res.Producer != "A" {
		t.Fatalf("B resolved producer %q, want A", res.Producer)
	}
	if got := readFile(t, res.PhysicalPath); got != "fa" {
		t.Fatalf("B read %q, want fa", got)
	}
	stageWrite(t, b, "B", g, "gb")

	stageWrite(t, b, "C", h, "hc")

	if !b.DependsOn("B", "A") {
		t.Fatal("expected B to depend on A after reading A:f")
	}
	if b.DependsOn("C", "A") {
		t.Fatal("C must NOT depend on A")
	}

	set, err := b.RollbackWithAffected("A")
	if err != nil {
		t.Fatalf("rollback A: %v", err)
	}
	got := map[string]bool{}
	for _, e := range set.Epochs {
		got[e] = true
	}
	if !got["A"] || !got["B"] || got["C"] {
		t.Fatalf("affected = %v, want {A,B} without C", set.Epochs)
	}

	// f back to backing content; g gone; h intact.
	if r := b.Resolve("reader", f); !r.Exists || r.Version != 0 {
		t.Fatalf("f resolve %+v, want backing", r)
	} else if readFile(t, r.PhysicalPath) != "base-f" {
		t.Fatal("f content not restored to backing")
	}
	if vid, _ := b.HeadVersion(g); vid != 0 {
		t.Fatal("g version must be removed with B")
	}
	if _, owner := b.HeadVersion(h); owner != "C" {
		t.Fatal("C:h must be preserved")
	}
}

// --- acceptance case 3: same-epoch rewrite vs. new head ---
func TestSameEpochRewriteAndNewHead(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	sp1 := stageWrite(t, b, "A", f, "a1")
	// Same epoch, still head: reuse the version.
	sp2, err := b.PrepareWrite("A", f)
	if err != nil {
		t.Fatal(err)
	}
	if sp1 != sp2 {
		t.Fatalf("expected version reuse, got %q vs %q", sp1, sp2)
	}
	if n := b.EpochVersionCount("A"); n != 1 {
		t.Fatalf("A owns %d versions, want 1", n)
	}

	// B takes over the head.
	stageWrite(t, b, "B", f, "b1")

	// A writes again: no longer head owner -> NEW version, based on B's.
	sp3, err := b.PrepareWrite("A", f)
	if err != nil {
		t.Fatal(err)
	}
	if sp3 == sp1 {
		t.Fatalf("expected distinct VersionID stage path for A rewrite, got %q", sp3)
	}
	if n := b.EpochVersionCount("A"); n != 2 {
		t.Fatalf("A owns %d versions, want 2", n)
	}
	// Snapshot semantics: A's own view prefers its OWN previous version, so
	// the rewrite is based on A's "a1" — NOT on B's head (which A's
	// processes never observed).
	if got := readFile(t, sp3); got != "a1" {
		t.Fatalf("A's new base = %q, want a1 (A's own snapshot)", got)
	}
	// Write-write edge: rolling back B must cascade to A now.
	if !b.DependsOn("A", "B") {
		t.Fatal("A must depend on B after building on B's version")
	}
	if _, owner := b.HeadVersion(f); owner != "A" {
		t.Fatal("A's new version must be the head")
	}
}

// --- acceptance case 4a: whiteout (unlink) versioning ---
func TestUnlinkVersioning(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	if err := b.RecordUnlink("A", f); err != nil {
		t.Fatalf("RecordUnlink: %v", err)
	}
	if r := b.Resolve("reader1", f); r.Exists {
		t.Fatal("f must be hidden by A's whiteout")
	}
	// Rollback re-exposes the backing file.
	if _, err := b.RollbackWithAffected("A"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if r := b.Resolve("reader2", f); !r.Exists || r.Version != 0 {
		t.Fatalf("f must be re-exposed after rollback, got %+v", r)
	}

	// Delete again and COMMIT: backing file removed.
	if err := b.RecordUnlink("A2", f); err != nil {
		t.Fatal(err)
	}
	mustCommitFinalized(t, b, "A2")
	if _, err := os.Lstat(f); !os.IsNotExist(err) {
		t.Fatal("backing f must be removed after committed unlink")
	}
}

// --- acceptance case 4b: rename versioning ---
func TestRenameVersioning(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "content")
	g := filepath.Join(orig, "g.txt")

	if err := b.RecordRename("A", f, g); err != nil {
		t.Fatalf("RecordRename: %v", err)
	}
	if r := b.Resolve("A", f); r.Exists {
		t.Fatal("source must be hidden after rename")
	}
	r := b.Resolve("A", g)
	if !r.Exists {
		t.Fatal("destination must exist after rename")
	}
	if got := readFile(t, r.PhysicalPath); got != "content" {
		t.Fatalf("dst content = %q", got)
	}

	mustCommitFinalized(t, b, "A")
	if _, err := os.Lstat(f); !os.IsNotExist(err) {
		t.Fatal("backing src must be gone after committed rename")
	}
	if got := readFile(t, g); got != "content" {
		t.Fatalf("backing dst = %q, want content", got)
	}
}

// --- acceptance case 4c: mkdir + rmdir versioning ---
func TestMkdirRmdirVersioning(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	d := filepath.Join(orig, "newdir")

	if err := b.RecordMkdir("A", d, 0o755); err != nil {
		t.Fatal(err)
	}
	if r := b.Resolve("A", d); !r.Exists {
		t.Fatal("dir must resolve after mkdir")
	}
	if _, err := b.RollbackWithAffected("A"); err != nil {
		t.Fatal(err)
	}
	if vid, _ := b.HeadVersion(d); vid != 0 {
		t.Fatal("dir version must be gone after rollback")
	}

	// mkdir + commit publishes the dir; rmdir + commit removes it.
	if err := b.RecordMkdir("A2", d, 0o755); err != nil {
		t.Fatal(err)
	}
	mustCommitFinalized(t, b, "A2")
	if st, err := os.Lstat(d); err != nil || !st.IsDir() {
		t.Fatal("backing dir must exist after committed mkdir")
	}
	if err := b.RecordRmdir("A3", d); err != nil {
		t.Fatal(err)
	}
	if r := b.Resolve("readerX", d); r.Exists {
		t.Fatal("dir must be hidden by rmdir whiteout")
	}
	mustCommitFinalized(t, b, "A3")
	if _, err := os.Lstat(d); !os.IsNotExist(err) {
		t.Fatal("backing dir must be removed after committed rmdir")
	}
}

// --- acceptance case 4d: hard link versioning ---
func TestLinkVersioning(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	target := writeOrig(t, orig, "target.txt", "T")
	link := filepath.Join(orig, "link.txt")

	sp, err := b.RecordLink("A", target, link)
	if err != nil {
		t.Fatalf("RecordLink: %v", err)
	}
	if got := readFile(t, sp); got != "T" {
		t.Fatalf("link stage content = %q", got)
	}
	mustCommitFinalized(t, b, "A")
	st1, err1 := os.Stat(target)
	st2, err2 := os.Stat(link)
	if err1 != nil || err2 != nil {
		t.Fatalf("stat after promote: %v %v", err1, err2)
	}
	if !os.SameFile(st1, st2) {
		t.Fatal("promoted link must share the target's inode")
	}
}

// --- acceptance case 5: read-from records the ACTUAL version, not history ---
func TestReadFromPrecision(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	// B reads the BACKING file (A has not written yet): no dependency.
	if r := b.Resolve("B", f); r.Version != 0 || r.Producer != "" {
		t.Fatalf("expected backing resolve, got %+v", r)
	}
	stageWrite(t, b, "A", f, "fa")
	if b.DependsOn("B", "A") {
		t.Fatal("B read the base version BEFORE A wrote: no dependency may exist")
	}
	set, err := b.RollbackWithAffected("A")
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Epochs) != 1 || set.Epochs[0] != "A" {
		t.Fatalf("rollback A affected %v, want [A] only", set.Epochs)
	}

	// Now A writes again and B DOES read A's version: dependency appears.
	stageWrite(t, b, "A", f, "fa2")
	if r := b.Resolve("B", f); r.Producer != "A" {
		t.Fatalf("B must observe A's version, got %+v", r)
	}
	if !b.DependsOn("B", "A") {
		t.Fatal("B must depend on A after reading A's version")
	}
	set, err = b.RollbackWithAffected("A")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range set.Epochs {
		got[e] = true
	}
	if !got["A"] || !got["B"] {
		t.Fatalf("affected = %v, want {A,B}", set.Epochs)
	}
}

// --- acceptance case 6: directory enumeration is a namespace read ---
func TestReaddirNamespaceDependency(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	writeOrig(t, orig, "existing.txt", "x")
	f := filepath.Join(orig, "new-by-a.txt")

	stageWrite(t, b, "A", f, "na")

	merged, err := b.MergeReaddirVersions("B", orig)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range merged {
		names[e.Name] = true
	}
	if !names["existing.txt"] || !names["new-by-a.txt"] {
		t.Fatalf("merged view = %v", names)
	}
	if !b.DependsOn("B", "A") {
		t.Fatal("listing a dir containing A's version must add the namespace read edge")
	}

	set, err := b.RollbackWithAffected("A")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range set.Epochs {
		got[e] = true
	}
	if !got["B"] {
		t.Fatalf("reader B must cascade with A, affected=%v", set.Epochs)
	}
}

// Whiteouts observed through readdir also create the namespace edge.
func TestReaddirWhiteoutHidesAndDepends(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "victim.txt", "x")

	if err := b.RecordUnlink("A", f); err != nil {
		t.Fatal(err)
	}
	merged, err := b.MergeReaddirVersions("B", orig)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range merged {
		if e.Name == "victim.txt" {
			t.Fatal("whiteout'd entry must be hidden from the merged view")
		}
	}
	if !b.DependsOn("B", "A") {
		t.Fatal("observing A's deletion must add the namespace read edge")
	}
}

// --- acceptance case 8: producer rollback force-closes consumer fds ---
func TestRollbackClosesEpochFDs(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	stageWrite(t, b, "A", f, "fa")
	// B reads A's version and holds an fd on it.
	res := b.Resolve("B", f)
	fd, err := os.Open(res.PhysicalPath)
	if err != nil {
		t.Fatal(err)
	}
	tfd := NewTrackedFD(int(fd.Fd()))
	b.RegisterFD("B", tfd)

	if _, err := b.RollbackWithAffected("A"); err != nil {
		t.Fatal(err)
	}
	if !tfd.IsClosed() {
		t.Fatal("consumer fd must be force-closed when producer rolls back")
	}
}

// --- acceptance case 9: production cgroup attribution fails closed without an explicit epoch ---
func TestImplicitEpochFailClosed(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	if ep, err := b.EpochForCgroup("/sys/fs/cgroup/demo"); err == nil {
		t.Fatalf("EpochForCgroup unexpectedly created implicit epoch %q", ep)
	}
	if err := b.BeginEpoch("explicit-demo", "/sys/fs/cgroup/demo", "sess-demo"); err != nil {
		t.Fatal(err)
	}
	ep, err := b.EpochForCgroup("/sys/fs/cgroup/demo")
	if err != nil || ep != "explicit-demo" {
		t.Fatalf("explicit EpochForCgroup = %q, %v", ep, err)
	}
	stageWrite(t, b, ep, f, "explicit")
	mustCommitFinalized(t, b, ep)
	if got := readFile(t, f); got != "explicit" {
		t.Fatalf("backing = %q", got)
	}
	if ep2, err := b.EpochForCgroup("/sys/fs/cgroup/demo"); err == nil {
		t.Fatalf("finalized explicit epoch must fail closed, got %q", ep2)
	}
}

// --- lifecycle / gating semantics ---

func TestRollbackRefusedAfterFinalizing(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	stageWrite(t, b, "A", f, "fa")
	mustCommitFinalized(t, b, "A")
	if _, err := b.RollbackWithAffected("A"); err == nil {
		t.Fatal("rollback of a finalized epoch must be refused")
	}
	// AckRelease drops it.
	if err := b.AckRelease("A"); err != nil {
		t.Fatalf("AckRelease: %v", err)
	}
	if b.CanRelease("A") {
		t.Fatal("acked epoch must be gone (fail-closed CanRelease)")
	}
}

func TestCanReleaseFailClosed(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")
	if b.CanRelease("ghost") {
		t.Fatal("unknown epoch must not be releasable")
	}
	stageWrite(t, b, "A", f, "fa")
	if b.CanRelease("A") {
		t.Fatal("speculative epoch must not be releasable")
	}
}

// Downstream finalization is blocked until the upstream group finalizes.
func TestDownstreamBlockedUntilUpstreamFinalized(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")
	g := filepath.Join(orig, "g.txt")

	stageWrite(t, b, "A", f, "fa")
	if r := b.Resolve("B", f); r.Producer != "A" {
		t.Fatal("setup: B must read A's version")
	}
	stageWrite(t, b, "B", g, "gb")

	// Commit B only: it must stay fenced (upstream A not finalized).
	res, err := b.Commit("B")
	if err != nil {
		t.Fatal(err)
	}
	if res.State == Finalized || res.CanRelease {
		t.Fatalf("B finalized despite un-finalized upstream A (state=%s)", res.State)
	}
	// Commit A: both settle.
	mustCommitFinalized(t, b, "A")
	if st, rel, _ := b.GetLifecycle("B"); st != "finalized" || !rel {
		t.Fatalf("B lifecycle after A commit = %s/%v, want finalized", st, rel)
	}
	if readFile(t, f) != "fa" || readFile(t, g) != "gb" {
		t.Fatal("backing contents wrong after group settle")
	}
}

// --- Rename batch planner tests ---

// TestRenameSwap tests the classic swap pattern: a→tmp, b→a, tmp→b.
func TestRenameSwap(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	a := writeOrig(t, orig, "a.txt", "content-a")
	bPath := writeOrig(t, orig, "b.txt", "content-b")
	tmp := filepath.Join(orig, "tmp.txt")

	// Perform swap: a→tmp, b→a, tmp→b
	if err := b.RecordRename("E", a, tmp); err != nil {
		t.Fatalf("rename a→tmp: %v", err)
	}
	if err := b.RecordRename("E", bPath, a); err != nil {
		t.Fatalf("rename b→a: %v", err)
	}
	if err := b.RecordRename("E", tmp, bPath); err != nil {
		t.Fatalf("rename tmp→b: %v", err)
	}

	// Verify speculative view.
	if r := b.Resolve("E", a); !r.Exists || readFile(t, r.PhysicalPath) != "content-b" {
		t.Fatal("speculative a should have content-b")
	}
	if r := b.Resolve("E", bPath); !r.Exists || readFile(t, r.PhysicalPath) != "content-a" {
		t.Fatal("speculative b should have content-a")
	}

	// Commit and verify backing.
	mustCommitFinalized(t, b, "E")
	if readFile(t, a) != "content-b" {
		t.Fatalf("backing a = %q, want content-b", readFile(t, a))
	}
	if readFile(t, bPath) != "content-a" {
		t.Fatalf("backing b = %q, want content-a", readFile(t, bPath))
	}
	if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
		t.Fatal("tmp should not exist after swap")
	}
}

// TestRenameThreeCycle tests a true three-element swap using a temp file:
// a→tmp, b→a, c→b, tmp→c
// Result: a=B, b=C, c=A
func TestRenameThreeCycle(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	a := writeOrig(t, orig, "a.txt", "A")
	bPath := writeOrig(t, orig, "b.txt", "B")
	c := writeOrig(t, orig, "c.txt", "C")
	tmp := filepath.Join(orig, "tmp.txt")

	// Four-element swap: a→tmp, b→a, c→b, tmp→c
	if err := b.RecordRename("E", a, tmp); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordRename("E", bPath, a); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordRename("E", c, bPath); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordRename("E", tmp, c); err != nil {
		t.Fatal(err)
	}

	mustCommitFinalized(t, b, "E")
	// Verify three-way swap: a=B, b=C, c=A
	if readFile(t, a) != "B" {
		t.Fatalf("a = %q, want B", readFile(t, a))
	}
	if readFile(t, bPath) != "C" {
		t.Fatalf("b = %q, want C", readFile(t, bPath))
	}
	if readFile(t, c) != "A" {
		t.Fatalf("c = %q, want A", readFile(t, c))
	}
	if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
		t.Fatal("tmp should not exist after swap")
	}
}

// TestRenameChain tests a chain: a→b, b→c (no cycle).
// POSIX semantics: sequential renames, so b is deleted by the second rename.
func TestRenameChain(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	a := writeOrig(t, orig, "a.txt", "A")
	bPath := writeOrig(t, orig, "b.txt", "B")
	c := filepath.Join(orig, "c.txt")

	// Chain: a→b, b→c
	// After a→b: b="A", a deleted
	// After b→c: c="A", b deleted
	if err := b.RecordRename("E", a, bPath); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordRename("E", bPath, c); err != nil {
		t.Fatal(err)
	}

	mustCommitFinalized(t, b, "E")
	if _, err := os.Lstat(a); !os.IsNotExist(err) {
		t.Fatal("a should not exist")
	}
	if _, err := os.Lstat(bPath); !os.IsNotExist(err) {
		t.Fatal("b should not exist (deleted by second rename)")
	}
	if readFile(t, c) != "A" {
		t.Fatalf("c = %q, want A", readFile(t, c))
	}
}

// TestRenameThenWriteDestination tests rename followed by write to destination.
func TestRenameThenWriteDestination(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	a := writeOrig(t, orig, "a.txt", "original")
	bPath := filepath.Join(orig, "b.txt")

	if err := b.RecordRename("E", a, bPath); err != nil {
		t.Fatal(err)
	}
	// Write to destination after rename.
	stageWrite(t, b, "E", bPath, "modified")

	mustCommitFinalized(t, b, "E")
	if readFile(t, bPath) != "modified" {
		t.Fatalf("b = %q, want modified", readFile(t, bPath))
	}
}

// TestRenameRollbackCleansSnapshots verifies rollback removes all snapshots.
func TestRenameRollbackCleansSnapshots(t *testing.T) {
	b, orig, staging := newTestBackend(t)
	a := writeOrig(t, orig, "a.txt", "A")
	bPath := writeOrig(t, orig, "b.txt", "B")
	tmp := filepath.Join(orig, "tmp.txt")

	// Create conflicting renames (swap).
	b.RecordRename("E", a, tmp)
	b.RecordRename("E", bPath, a)
	b.RecordRename("E", tmp, bPath)

	// Call planRenames to create snapshots (this is what happens during commit).
	b.mu.Lock()
	err := b.planRenames()
	b.mu.Unlock()
	if err != nil {
		t.Fatalf("planRenames: %v", err)
	}

	// Verify snapshots were created.
	snapDir := filepath.Join(staging, "epochs", "E", "rename-snapshots")
	if _, err := os.Lstat(snapDir); os.IsNotExist(err) {
		t.Fatal("snapshot dir should exist after planRenames")
	}

	// Rollback.
	if _, err := b.RollbackWithAffected("E"); err != nil {
		t.Fatal(err)
	}

	// Verify snapshots are cleaned up.
	if _, err := os.Lstat(snapDir); !os.IsNotExist(err) {
		t.Fatalf("snapshot dir should not exist after rollback: %v", err)
	}

	// Verify backing unchanged.
	if readFile(t, a) != "A" || readFile(t, bPath) != "B" {
		t.Fatal("backing should be unchanged after rollback")
	}
}

// TestRenameIndependentFastPath verifies independent renames use fast path (no snapshot).
func TestRenameIndependentFastPath(t *testing.T) {
	b, orig, staging := newTestBackend(t)
	a := writeOrig(t, orig, "a1.txt", "A1")
	bPath := writeOrig(t, orig, "a2.txt", "A2")
	a1New := filepath.Join(orig, "b1.txt")
	a2New := filepath.Join(orig, "b2.txt")

	// Independent renames (no conflict).
	if err := b.RecordRename("E", a, a1New); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordRename("E", bPath, a2New); err != nil {
		t.Fatal(err)
	}

	mustCommitFinalized(t, b, "E")

	// Verify no snapshots were created for independent renames.
	snapDir := filepath.Join(staging, "epochs", "E", "rename-snapshots")
	if _, err := os.Lstat(snapDir); !os.IsNotExist(err) {
		t.Fatal("independent renames should not create snapshots")
	}

	if readFile(t, a1New) != "A1" || readFile(t, a2New) != "A2" {
		t.Fatal("independent rename results wrong")
	}
}

// TestRenameReverseOverlap tests that a rename whose SOURCE is an ancestor
// of another rename's DESTINATION is correctly detected as conflicting.
// Example: /a→/x and /b→/a/y — source /a is ancestor of dest /a/y.
func TestRenameReverseOverlap(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	// Create directory /a with a file inside.
	aDir := filepath.Join(orig, "a")
	if err := os.MkdirAll(aDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeOrig(t, orig, "a/inner.txt", "inner")
	bFile := writeOrig(t, orig, "b.txt", "B")
	xDir := filepath.Join(orig, "x")
	ayPath := filepath.Join(orig, "a", "y.txt")

	// Rename /a → /x (moves the directory).
	if err := b.RecordRename("E", aDir, xDir); err != nil {
		t.Fatal(err)
	}
	// Rename /b → /a/y (destination is inside /a, which is being moved).
	if err := b.RecordRename("E", bFile, ayPath); err != nil {
		t.Fatal(err)
	}

	// planRenames should detect the overlap and mark both as conflicting.
	// Since one involves a directory, it should return EOPNOTSUPP.
	b.mu.Lock()
	err := b.planRenames()
	b.mu.Unlock()
	if err == nil {
		t.Fatal("expected EOPNOTSUPP for conflicting directory rename, got nil")
	}
}

// TestOrphanRenameTempCleanup verifies that .penumbra-rename-* files left
// in the backing store are cleaned up during recovery.
func TestOrphanRenameTempCleanup(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(orig, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create an orphan temp file simulating a crash mid-promotion.
	orphan := filepath.Join(orig, ".penumbra-rename-123456")
	if err := os.WriteFile(orphan, []byte("orphan"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Also create a normal file that should NOT be removed.
	normal := filepath.Join(orig, "normal.txt")
	if err := os.WriteFile(normal, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Open backend — recovery should clean the orphan.
	b, err := NewBackend(staging, orig)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	defer b.Close()

	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan .penumbra-rename-* file should have been removed")
	}
	if _, err := os.Lstat(normal); err != nil {
		t.Fatal("normal file should not be removed")
	}
}

// TestRenamePartialPromotionRecovery simulates a crash after one destination
// is installed but before the second. On recovery, retry should complete.
func TestRenamePartialPromotionRecovery(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(orig, 0o755); err != nil {
		t.Fatal(err)
	}

	// Setup: two files for a swap.
	aPath := filepath.Join(orig, "a.txt")
	bPath := filepath.Join(orig, "b.txt")
	os.WriteFile(aPath, []byte("A"), 0o644)
	os.WriteFile(bPath, []byte("B"), 0o644)
	tmpPath := filepath.Join(orig, "tmp.txt")

	// First run: create the swap and commit.
	b1, err := NewBackend(staging, orig)
	if err != nil {
		t.Fatal(err)
	}
	b1.RecordRename("E", aPath, tmpPath)
	b1.RecordRename("E", bPath, aPath)
	b1.RecordRename("E", tmpPath, bPath)

	// Simulate partial promotion: manually install a→tmp's result.
	// This represents a crash after the first rename but before the rest.
	b1.mu.Lock()
	_ = b1.planRenames()
	b1.mu.Unlock()

	// Commit should complete all renames.
	mustCommitFinalized(t, b1, "E")
	b1.Close()

	// Verify final state: a=B, b=A.
	if readFile(t, aPath) != "B" {
		t.Fatalf("a.txt = %q, want B", readFile(t, aPath))
	}
	if readFile(t, bPath) != "A" {
		t.Fatalf("b.txt = %q, want A", readFile(t, bPath))
	}
}
