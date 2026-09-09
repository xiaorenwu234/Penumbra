package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The whole existing suite is single-threaded, so nothing in it exercises the
// lock protocol documented at the top of the group-commit section: every
// mutating op holds opRW.RLock() for its full duration, and checkpoint (plus
// Authorize) take opRW.Lock(). The scalability experiment is the first thing
// to drive several agents at one backend at once, and it wedges the daemon:
// the last line in the log is rollbackInternal's "cascading to" message and
// nothing is ever printed again, by any goroutine, until the process is
// killed. These tests reproduce that concurrency; run them with a short
// -timeout so a wedge produces a full goroutine dump instead of a hang.

// concurrentAgents drives N agents through begin -> write -> read-shared ->
// rollback (or commit), the shape of the experiment's rollback phase.
func concurrentAgents(t *testing.T, b *Backend, orig string, agents, rounds int, commit bool) {
	t.Helper()
	shared := writeOrig(t, orig, "shared.dat", "seed")
	for a := 0; a < agents; a++ {
		writeOrig(t, orig, fmt.Sprintf("ind_%d.dat", a), "base")
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for a := 0; a < agents; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			<-start
			for r := 0; r < rounds; r++ {
				ep := EpochID(fmt.Sprintf("ep-a%d-r%d", a, r))
				cg := fmt.Sprintf("/cg-%d-%d", a, r)
				if err := b.BeginEpoch(ep, cg, cg); err != nil {
					t.Errorf("agent%d round%d BeginEpoch: %v", a, r, err)
					return
				}
				own := filepath.Join(orig, fmt.Sprintf("ind_%d.dat", a))
				if _, err := b.PrepareWrite(ep, own); err != nil {
					t.Errorf("agent%d round%d PrepareWrite: %v", a, r, err)
					return
				}
				// Resolve is what records a read-from edge on the observed
				// version, so the rollback has a graph to walk.
				if res := b.Resolve(ep, shared); res.Err != nil {
					t.Errorf("agent%d round%d Resolve: %v", a, r, res.Err)
					return
				}
				if commit {
					if _, err := b.Commit(ep); err != nil {
						t.Errorf("agent%d round%d Commit: %v", a, r, err)
						return
					}
					continue
				}
				if _, err := b.RollbackWithAffected(ep); err != nil {
					t.Errorf("agent%d round%d Rollback: %v", a, r, err)
					return
				}
			}
		}(a)
	}
	close(start)
	wg.Wait()
}

func TestConcurrentRollbacksDoNotWedge(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	concurrentAgents(t, b, orig, 4, 40, false)
}

func TestConcurrentCommitsDoNotWedge(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	concurrentAgents(t, b, orig, 4, 40, true)
}

// TestConcurrentRollbackAgainstCommit mixes both, which is what the insertion
// phase does: one agent publishes while the others are still being undone, so
// Authorize's opRW.Lock() contends with Rollback's opRW.RLock() every round.
func TestConcurrentRollbackAgainstCommit(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	concurrentAgents(t, b, orig, 4, 40, false)

	shared := writeOrig(t, orig, "mix.dat", "seed")
	start := make(chan struct{})
	var wg sync.WaitGroup
	for a := 0; a < 4; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			<-start
			for r := 0; r < 40; r++ {
				ep := EpochID(fmt.Sprintf("ep-m%d-r%d", a, r))
				cg := fmt.Sprintf("/cg-m%d-%d", a, r)
				if err := b.BeginEpoch(ep, cg, cg); err != nil {
					t.Errorf("agent%d round%d BeginEpoch: %v", a, r, err)
					return
				}
				if res := b.Resolve(ep, shared); res.Err != nil {
					t.Errorf("agent%d round%d Resolve: %v", a, r, res.Err)
					return
				}
				if a%2 == 0 {
					if _, err := b.Commit(ep); err != nil {
						t.Errorf("agent%d round%d Commit: %v", a, r, err)
						return
					}
					continue
				}
				if _, err := b.RollbackWithAffected(ep); err != nil {
					t.Errorf("agent%d round%d Rollback: %v", a, r, err)
					return
				}
			}
		}(a)
	}
	close(start)
	wg.Wait()
}

// TestGroupFinalizeAgainstRollback drives the path the orchestrator actually
// uses to publish -- Authorize, PrepareResolution, BeginFinalize,
// AckReleaseGroup -- concurrently with other agents undoing their epochs.
// Authorize takes opRW.Lock() and AckReleaseGroup allocates one seq per member
// plus one for the group delete, so this is the mix that puts the write lock,
// the multi-seq apply order, and cascading rollback in the same window.
// TOCTOU refusals from BeginFinalize are expected under concurrency and are
// not failures; a wedge is.
func TestGroupFinalizeAgainstRollback(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	shared := writeOrig(t, orig, "shared.dat", "seed")
	const agents = 6
	for a := 0; a < agents; a++ {
		writeOrig(t, orig, fmt.Sprintf("ind_%d.dat", a), "base")
	}

	// The daemon checkpoints on a 5s ticker; force it far more often so the
	// writer-preference window is hit rather than waited for.
	stop := make(chan struct{})
	var ck sync.WaitGroup
	ck.Add(1)
	go func() {
		defer ck.Done()
		for {
			select {
			case <-stop:
				return
			default:
				b.checkpoint()
			}
		}
	}()

	start := make(chan struct{})
	var wg sync.WaitGroup
	for a := 0; a < agents; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			<-start
			for r := 0; r < 60; r++ {
				ep := EpochID(fmt.Sprintf("ep-g%d-r%d", a, r))
				cg := fmt.Sprintf("/cg-g%d-%d", a, r)
				if err := b.BeginEpoch(ep, cg, cg); err != nil {
					t.Errorf("agent%d round%d BeginEpoch: %v", a, r, err)
					return
				}
				own := filepath.Join(orig, fmt.Sprintf("ind_%d.dat", a))
				if _, err := b.PrepareWrite(ep, own); err != nil {
					t.Errorf("agent%d round%d PrepareWrite: %v", a, r, err)
					return
				}
				if res := b.Resolve(ep, shared); res.Err != nil {
					t.Errorf("agent%d round%d Resolve: %v", a, r, res.Err)
					return
				}
				if a%2 == 1 {
					if _, err := b.RollbackWithAffected(ep); err != nil {
						t.Errorf("agent%d round%d Rollback: %v", a, r, err)
						return
					}
					continue
				}
				if _, err := b.Authorize(ep, "test-policy"); err != nil {
					t.Logf("agent%d round%d Authorize: %v", a, r, err)
					continue
				}
				pr, err := b.PrepareResolution(ep)
				if err != nil {
					t.Logf("agent%d round%d PrepareResolution: %v", a, r, err)
					continue
				}
				if _, err := b.BeginFinalize(pr.GroupID, pr.GraphGeneration); err != nil {
					t.Logf("agent%d round%d BeginFinalize: %v", a, r, err)
					if cerr := b.CancelGroup(pr.GroupID); cerr != nil {
						t.Logf("agent%d round%d CancelGroup: %v", a, r, cerr)
					}
					continue
				}
				if err := b.AckReleaseGroup(pr.GroupID); err != nil {
					t.Logf("agent%d round%d AckReleaseGroup: %v", a, r, err)
				}
			}
		}(a)
	}
	close(start)
	wg.Wait()
	close(stop)
	ck.Wait()
}

// TestCheckpointAgainstConcurrentRollback forces the periodic snapshot to run
// while rollbacks are in flight. checkpoint() takes opRW.Lock(), and Go's
// RWMutex blocks new readers once a writer is waiting, so one checkpoint that
// cannot drain is enough to freeze every later operation.
func TestCheckpointAgainstConcurrentRollback(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	for a := 0; a < 4; a++ {
		writeOrig(t, orig, fmt.Sprintf("ind_%d.dat", a), "base")
	}
	writeOrig(t, orig, "shared.dat", "seed")

	stop := make(chan struct{})
	var ck sync.WaitGroup
	ck.Add(1)
	go func() {
		defer ck.Done()
		for {
			select {
			case <-stop:
				return
			default:
				b.checkpoint()
			}
		}
	}()

	concurrentAgents(t, b, orig, 4, 40, false)
	close(stop)
	ck.Wait()

	if _, err := os.Stat(orig); err != nil {
		t.Fatalf("orig vanished: %v", err)
	}
}

// --- the wedge these tests were written for, and the fix ---
//
// None of the concurrency tests above reproduce it, and that is itself the
// lesson: the lock protocol between backend operations is sound. What wedged
// the daemon was a call OUT of the backend, into the kernel, made while
// holding the backend's central mutex. The RQ3 log stopped immediately after
// rollbackInternal's "cascading to" line and nothing was ever printed again,
// by any goroutine, until the process was killed -- no panic, no error, every
// OS thread in S state. A SIGQUIT dump named it exactly:
//
//	goroutine 11 [syscall]:
//	  unix.Writev(0x9, ...)                        <- the /dev/fuse notify
//	  fuse.(*protocolServer).EntryNotify(...)
//	  main.main.func1(...)                         <- the invalidate callback
//	  backend.(*Backend).rollbackInternal(...)     <- WITH b.mu HELD
//	  backend.(*Backend).RollbackWithAffected(...)
//
// with a dozen goroutines parked behind it on sync.Mutex.Lock, among them the
// WAL worker and the five-second checkpoint. That is why the log went silent
// rather than merely slow.
//
// Invalidating a kernel dentry means writing a notify message to /dev/fuse,
// and the kernel can stall that write indefinitely: it needs the dcache locks
// for the entry, which a process already blocked in a FUSE request that this
// same daemon has not answered may be holding. Doing it under b.mu turned an
// ordinary stall into a total freeze.

// TestRollbackInvalidatesWithNoLockHeld checks the invariant directly. The
// callback probes both locks with TryLock rather than Lock: if the rollback
// still held either, a Lock would make the test itself the deadlock, and a
// test that hangs tells us nothing until the timeout fires.
func TestRollbackInvalidatesWithNoLockHeld(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")
	stageWrite(t, b, "A", f, "a")

	var called, muFree, opRWFree bool
	var paths []string
	b.SetInvalidateCallback(func(p []string) {
		called = true
		paths = p
		muFree = b.mu.TryLock()
		if muFree {
			b.mu.Unlock()
		}
		opRWFree = b.opRW.TryLock()
		if opRWFree {
			b.opRW.Unlock()
		}
	})

	set, err := b.RollbackWithAffected("A")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if len(set.Epochs) != 1 || set.Epochs[0] != "A" {
		t.Fatalf("affected = %v, want [A]", set.Epochs)
	}
	if !called {
		t.Fatal("the invalidate callback never ran, so the lock assertions " +
			"below would pass vacuously")
	}
	if len(paths) != 1 || paths[0] != f {
		t.Errorf("callback got paths %v, want [%s]", paths, f)
	}
	if !muFree {
		t.Error("b.mu was still held while the invalidation callback ran -- a " +
			"stalled notify would freeze every operation in the daemon")
	}
	if !opRWFree {
		t.Error("b.opRW was still held while the invalidation callback ran -- a " +
			"stalled notify would freeze the checkpoint")
	}
}

// TestABlockedInvalidationDoesNotFreezeTheBackend is the wedge itself, reduced
// to a test. The callback stands in for a /dev/fuse notify write the kernel
// never completes; while it is parked, the rest of the backend must still
// work. Before the fix this hung until the test binary timed out.
func TestABlockedInvalidationDoesNotFreezeTheBackend(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")
	stageWrite(t, b, "A", f, "a")

	entered := make(chan struct{})
	release := make(chan struct{})
	b.SetInvalidateCallback(func([]string) {
		close(entered)
		<-release // the kernel, not answering the notify write
	})

	rolledBack := make(chan error, 1)
	go func() {
		_, err := b.RollbackWithAffected("A")
		rolledBack <- err
	}()

	select {
	case <-entered:
	case err := <-rolledBack:
		t.Fatalf("rollback finished without ever entering the callback: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("rollback never reached the invalidation callback")
	}

	// The callback is parked now, exactly as a stalled notify parks. An
	// unrelated epoch must still be openable -- this is the property lost.
	begun := make(chan error, 1)
	go func() { begun <- b.BeginEpoch("B", "/cg/b", "sess-b") }()
	select {
	case err := <-begun:
		if err != nil {
			t.Fatalf("BeginEpoch while an invalidation is blocked: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("BeginEpoch stalled behind a blocked invalidation: the backend " +
			"locks are still held across the notify")
	}

	// So must the WAL worker's drain, which needs the very mutex the notify
	// used to sit under. Its loss is what silenced the log.
	flushed := make(chan struct{})
	go func() {
		b.flushPending()
		close(flushed)
	}()
	select {
	case <-flushed:
	case <-time.After(10 * time.Second):
		t.Fatal("flushPending stalled behind a blocked invalidation")
	}

	close(release)
	select {
	case err := <-rolledBack:
		if err != nil {
			t.Fatalf("rollback: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("rollback did not finish after the notify was released")
	}

	// And the rollback really did take effect, not merely return.
	if vid, owner := b.HeadVersion(f); vid != 0 || owner != "" {
		t.Errorf("head after rollback = v%d/%q, want the backing version", vid, owner)
	}
}

// TestReplayRollbackDoesNotInvalidate covers the other caller of
// rollbackInternal. WAL replay runs inside NewBackend, before any FUSE mount
// exists, so there is no kernel dentry cache to invalidate and no /dev/fuse to
// block on -- but the paths must still come back as a value rather than being
// delivered from under the lock.
func TestReplayRollbackDoesNotInvalidate(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")
	stageWrite(t, b, "A", f, "a")

	var called bool
	b.SetInvalidateCallback(func([]string) { called = true })

	b.mu.Lock()
	paths, err := b.rollbackInternal("A")
	b.mu.Unlock()
	if err != nil {
		t.Fatalf("rollbackInternal: %v", err)
	}
	if called {
		t.Error("rollbackInternal delivered the invalidation itself; only " +
			"notifyInvalidated may, and only with no lock held")
	}
	if len(paths) != 1 || paths[0] != f {
		t.Errorf("rollbackInternal returned %v, want [%s]", paths, f)
	}

	b.notifyInvalidated(paths)
	if !called {
		t.Error("notifyInvalidated did not deliver the paths")
	}

	// An empty list must not wake the kernel at all: most rollbacks touch
	// nothing that was ever looked up through the mount.
	called = false
	b.notifyInvalidated(nil)
	if called {
		t.Error("notifyInvalidated called the callback with no paths")
	}
}

// TestRollbackSurvivesAnEdgeToAMissingEpoch pins the nil guard in
// rollbackInternal's version-collection loop. reachableFrom walks graph edges,
// and affectedSetLocked already guards the same lookup with `ep != nil` -- the
// author knew an edge can outlive the epoch it names. The collection loop did
// not guard it. There is no recover() anywhere in this daemon, so the resulting
// nil dereference would not degrade one rollback; it would take the process
// down in the middle of a cascade, with the graph half-pruned.
func TestRollbackSurvivesAnEdgeToAMissingEpoch(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")
	stageWrite(t, b, "A", f, "a")
	aVid, _ := b.HeadVersion(f)
	stageWrite(t, b, "B", f, "b")

	// Drop B's record but leave the edge that names it, which is the
	// inconsistency the guard exists for.
	b.mu.Lock()
	delete(b.epochs, "B")
	b.mu.Unlock()

	set, err := b.RollbackWithAffected("A")
	if err != nil {
		t.Fatalf("rollback A with a dangling edge: %v", err)
	}
	if len(set.Epochs) == 0 {
		t.Fatal("affected set is empty; the cascade did not run")
	}

	// What the guard promises is that the cascade RUNS TO COMPLETION, and that
	// A's own versions are undone. It does not promise the graph comes out
	// consistent: B's version has no epoch record left to attribute it to, so
	// nothing can collect it, and it stays as the head. That residue is the
	// inconsistency this test manufactured by hand, not something the rollback
	// introduced -- asserting the head fell all the way back to the backing
	// version would be asserting a repair the guard never claimed to do.
	if _, owner := b.HeadVersion(f); owner == "A" {
		t.Errorf("A still owns the head after A was rolled back")
	}
	b.mu.Lock()
	_, aAlive := b.versionByID[aVid]
	_, aRecorded := b.epochs["A"]
	b.mu.Unlock()
	if aAlive {
		t.Errorf("A's version v%d survived the rollback of A", aVid)
	}
	if aRecorded {
		t.Error("A's epoch record survived the rollback of A")
	}
}

// TestFinalizeSurvivesConcurrentBeginEpoch is the publication starvation bug
// reduced to a test. The scaling run measured it directly: finalize=51 calls to
// publish 3 nodes, finalize=101 for 5 nodes, and one SCC that took 2844 attempts
// over 121s, hit the 120s drain timeout and never published at all, while the
// contended/16 cell completed 0 of 80 invocations with 16 epochs stranded in
// authorized_pending. Before the fix this test fails on the first assertion.
func TestFinalizeSurvivesConcurrentBeginEpoch(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	if err := b.BeginEpoch("A", "/cg-a", "s-a"); err != nil {
		t.Fatal(err)
	}
	stageWrite(t, b, "A", f, "a")
	if _, err := b.Authorize("A", "policy-hash"); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	prep, err := b.PrepareResolution("A")
	if err != nil {
		t.Fatalf("PrepareResolution: %v", err)
	}

	// 64 unrelated agents start up while A waits to publish. Every one of them
	// bumps the whole-graph generation counter, so under the old comparison each
	// one turned A's pending finalization into a TOCTOU rejection and the
	// orchestrator retried into a graph that kept moving. None of them can touch
	// A's member set: BeginEpoch inserts an isolated node, with no edges.
	for i := 0; i < 64; i++ {
		ep := EpochID(fmt.Sprintf("noise-%d", i))
		if err := b.BeginEpoch(ep, "/cg-"+string(ep), string(ep)); err != nil {
			t.Fatalf("BeginEpoch %s: %v", ep, err)
		}
	}
	// Guard the premise: if the counter had not actually moved, this test would
	// pass without exercising a stale generation at all.
	if st := b.GraphStatsSnapshot(); st.GraphGeneration <= prep.GraphGeneration {
		t.Fatalf("graph_generation did not advance (%d -> %d); the test no longer "+
			"presents a stale generation", prep.GraphGeneration, st.GraphGeneration)
	}

	// The TOCTOU gate must not feed scc_computations. Probed directly instead of
	// as a delta across BeginFinalize, because a SUCCESSFUL finalize legitimately
	// runs instrumented finalize-readiness sweeps (tryFinalizeSCCs) and that
	// counter is documented to include them: measuring the whole call would assert
	// against intended pre-existing behaviour, not against this fix.
	b.mu.Lock()
	gateBefore := b.graphCtr.sccComputations
	if !b.groupStillAtomicLocked(b.activeGroups[prep.GroupID]) {
		b.mu.Unlock()
		t.Fatal("setup: the prepared group is not atomic before BeginFinalize")
	}
	gateSweeps := b.graphCtr.sccComputations - gateBefore
	b.mu.Unlock()
	if gateSweeps != 0 {
		t.Errorf("the TOCTOU gate counted %d SCC sweep(s): scc_computations covers "+
			"group resolution and finalize-readiness sweeps, and a retry storm must "+
			"not be able to inflate it", gateSweeps)
	}

	res, err := b.BeginFinalize(prep.GroupID, prep.GraphGeneration)
	if err != nil {
		t.Fatalf("BeginFinalize refused after 64 unrelated BeginEpoch calls: %v", err)
	}
	if res.Status != "finalized" {
		t.Fatalf("status = %q, want finalized", res.Status)
	}
	if st := b.GraphStatsSnapshot(); st.FinalizeRejectedTOCTOU != 0 {
		t.Errorf("finalize_rejected_toctou = %d, want 0: unrelated graph activity "+
			"is not a TOCTOU", st.FinalizeRejectedTOCTOU)
	}
}

// TestFinalizeRejectsWhenTheSCCGrowsBeneathIt is the other half, and the reason
// the fix is a narrowing rather than a removal: revalidation must still refuse a
// group whose cycle is no longer the cycle it was prepared for. Publishing {B C}
// after the SCC has grown to {B C D} would publish part of a dependency cycle
// while the rest of it is still speculative, which is precisely what atomic
// SCC publication exists to prevent.
func TestFinalizeRejectsWhenTheSCCGrowsBeneathIt(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	g := writeOrig(t, orig, "g.txt", "base-g")
	h := writeOrig(t, orig, "h.txt", "base-h")
	ip := writeOrig(t, orig, "i.txt", "base-i")

	for _, ep := range []EpochID{"B", "C"} {
		if err := b.BeginEpoch(ep, "/cg-"+string(ep), "s-"+string(ep)); err != nil {
			t.Fatal(err)
		}
	}
	stageWrite(t, b, "B", g, "b")
	b.Resolve("C", g) // C reads B's g -> dependsOn[C] holds B
	stageWrite(t, b, "C", h, "c")
	b.Resolve("B", h) // B reads C's h -> dependsOn[B] holds C, closing {B C}
	for _, ep := range []EpochID{"B", "C"} {
		if _, err := b.Authorize(ep, "policy-hash"); err != nil {
			t.Fatalf("Authorize %s: %v", ep, err)
		}
	}
	prep, err := b.PrepareResolution("B")
	if err != nil {
		t.Fatalf("PrepareResolution: %v", err)
	}
	if len(prep.Members) != 2 {
		t.Fatalf("prepared members = %v, want the 2-cycle {B C}", prep.Members)
	}

	// A third epoch closes a cycle through the prepared group. This is reachable
	// in production, not only in a test: needsReadDepLocked gates on the
	// PRODUCER's state and never on the reader's, so an epoch that is already
	// AuthorizedPending and waiting to publish can still record a new read-from
	// edge. D is deliberately left unauthorized -- it is not in the prepared
	// member set, so nothing checks its state.
	if err := b.BeginEpoch("D", "/cg-d", "s-d"); err != nil {
		t.Fatal(err)
	}
	stageWrite(t, b, "D", ip, "d")
	b.Resolve("C", ip) // C reads D's i -> dependsOn[C] holds D
	b.Resolve("D", h)  // D reads C's h -> dependsOn[D] holds C, closing C<->D

	// A refused finalize is the path that repeats in production -- every rejected
	// attempt costs one revalidation -- so it must not feed scc_computations
	// either. The delta across the whole call is exact here, unlike on the success
	// path, because a refusal returns before tryFinalizeSCCs runs any of the
	// instrumented finalize-readiness sweeps.
	sweepsBefore := b.GraphStatsSnapshot().SCCComputations

	if _, err := b.BeginFinalize(prep.GroupID, prep.GraphGeneration); err == nil {
		t.Fatal("BeginFinalize published a group whose SCC had grown from {B C} to {B C D}")
	}
	if st := b.GraphStatsSnapshot(); st.FinalizeRejectedTOCTOU != 1 {
		t.Errorf("finalize_rejected_toctou = %d, want 1", st.FinalizeRejectedTOCTOU)
	}
	if d := b.GraphStatsSnapshot().SCCComputations - sweepsBefore; d != 0 {
		t.Errorf("the refused finalize counted %d SCC sweep(s): a retry storm must "+
			"not be able to inflate the reported cost of SCC detection", d)
	}

	// Refused, not half-applied: the group has to survive intact so the
	// orchestrator can re-prepare against the wider component.
	b.mu.Lock()
	for _, ep := range []EpochID{"B", "C"} {
		if e := b.epochs[ep]; e == nil {
			t.Errorf("epoch %s vanished after a refused finalize", ep)
		} else if e.State != AuthorizedPending {
			t.Errorf("epoch %s state = %s, want it left at AuthorizedPending", ep, e.State)
		}
	}
	b.mu.Unlock()
}
