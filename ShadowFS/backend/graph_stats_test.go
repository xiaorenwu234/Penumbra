package backend

import "testing"

// graph_stats is the observation surface the RQ3 scalability experiments
// measure through, so its numbers must be exact rather than indicative: a
// wrong edge count or a counter that also fires on introspection would make
// every scaling curve in the paper unverifiable.

// --- shape + counters on a two-node read-from chain ---

func TestGraphStatsChainShape(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	if err := b.BeginEpoch("A", "/cg-a", "s-a"); err != nil {
		t.Fatal(err)
	}
	if err := b.BeginEpoch("B", "/cg-b", "s-b"); err != nil {
		t.Fatal(err)
	}
	// A produces a version of f; B observes it -> read-from edge A -> B.
	stageWrite(t, b, "A", f, "a")
	if res := b.Resolve("B", f); res.Producer != "A" {
		t.Fatalf("Resolve(B) producer = %q, want A", res.Producer)
	}

	st := b.GraphStatsSnapshot()
	if st.Epochs != 2 {
		t.Fatalf("epochs = %d, want 2", st.Epochs)
	}
	if st.Edges != 1 {
		t.Fatalf("edges = %d, want 1 (B depends on A)", st.Edges)
	}
	if st.Versions != 1 {
		t.Fatalf("versions = %d, want 1", st.Versions)
	}
	// A single read-from edge is acyclic: two singleton components.
	if st.CyclicSCCCount != 0 || st.MaxSCCSize != 1 || st.SCCCount != 2 {
		t.Fatalf("scc shape = {count:%d cyclic:%d max:%d}, want {2 0 1}",
			st.SCCCount, st.CyclicSCCCount, st.MaxSCCSize)
	}
	if st.EdgeInsertions != 1 {
		t.Fatalf("edge_insertions = %d, want 1", st.EdgeInsertions)
	}
	// Introspection must NOT be counted as dependency work: taking a second
	// snapshot may not move the SCC counters' *call* count for graph walk
	// bookkeeping, and must never invent edges.
	before := b.GraphStatsSnapshot()
	after := b.GraphStatsSnapshot()
	if before.Edges != after.Edges || before.Epochs != after.Epochs {
		t.Fatalf("snapshot not idempotent: %+v vs %+v", before, after)
	}
	if after.EdgeInsertions != before.EdgeInsertions {
		t.Fatalf("snapshot inflated edge_insertions: %d -> %d",
			before.EdgeInsertions, after.EdgeInsertions)
	}
	if after.AffectedQueries != before.AffectedQueries ||
		after.Rollbacks != before.Rollbacks ||
		after.PrepareCalls != before.PrepareCalls ||
		after.FinalizeCalls != before.FinalizeCalls {
		t.Fatalf("snapshot inflated work counters: %+v -> %+v", before, after)
	}
}

// --- edge insertion is deduplicated (one edge per producer/consumer pair) ---

func TestGraphStatsEdgeInsertionDedup(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	mustBegin := func(ep EpochID, cg string) {
		t.Helper()
		if err := b.BeginEpoch(ep, cg, "s-"+string(ep)); err != nil {
			t.Fatal(err)
		}
	}
	mustBegin("A", "/cg-a")
	mustBegin("B", "/cg-b")
	stageWrite(t, b, "A", f, "a")

	// Three reads of the SAME version by the same consumer = ONE edge.
	for i := 0; i < 3; i++ {
		if res := b.Resolve("B", f); res.Producer != "A" {
			t.Fatalf("Resolve(B) #%d producer = %q, want A", i, res.Producer)
		}
	}
	st := b.GraphStatsSnapshot()
	if st.Edges != 1 || st.EdgeInsertions != 1 {
		t.Fatalf("edges=%d insertions=%d, want 1/1 (read-from is deduplicated)",
			st.Edges, st.EdgeInsertions)
	}
	// A second consumer of the same version IS a new edge.
	mustBegin("C", "/cg-c")
	if res := b.Resolve("C", f); res.Producer != "A" {
		t.Fatalf("Resolve(C) producer = %q, want A", res.Producer)
	}
	st = b.GraphStatsSnapshot()
	if st.Edges != 2 || st.EdgeInsertions != 2 {
		t.Fatalf("edges=%d insertions=%d, want 2/2", st.Edges, st.EdgeInsertions)
	}
}

// --- cycle detection: an SCC shows up as one multi-member component ---

func TestGraphStatsDetectsSCC(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base-f")
	g := writeOrig(t, orig, "g.txt", "base-g")

	for _, ep := range []EpochID{"A", "B"} {
		if err := b.BeginEpoch(ep, "/cg-"+string(ep), "s-"+string(ep)); err != nil {
			t.Fatal(err)
		}
	}
	stageWrite(t, b, "A", f, "a") // A produces f
	b.Resolve("B", f)             // B reads A's f  -> edge A -> B
	stageWrite(t, b, "B", g, "b") // B produces g
	b.Resolve("A", g)             // A reads B's g  -> edge B -> A  (cycle)

	st := b.GraphStatsSnapshot()
	if st.Edges != 2 {
		t.Fatalf("edges = %d, want 2 (the cycle)", st.Edges)
	}
	if st.CyclicSCCCount != 1 || st.MaxSCCSize != 2 {
		t.Fatalf("scc = {cyclic:%d max:%d}, want {1 2}",
			st.CyclicSCCCount, st.MaxSCCSize)
	}
	if st.SCCCount != 1 {
		t.Fatalf("scc_count = %d, want 1 (A and B are one component)", st.SCCCount)
	}
	if st.SCCComputations == 0 {
		t.Fatal("scc_computations = 0, want the snapshot's Tarjan sweep counted")
	}
}

// --- cascade walk + rollback counters ---

func TestGraphStatsRollbackCounters(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")
	g := writeOrig(t, orig, "g.txt", "base")

	for _, ep := range []EpochID{"A", "B", "C"} {
		if err := b.BeginEpoch(ep, "/cg-"+string(ep), "s-"+string(ep)); err != nil {
			t.Fatal(err)
		}
	}
	// Chain A -> B -> C.
	stageWrite(t, b, "A", f, "a")
	b.Resolve("B", f)
	stageWrite(t, b, "B", g, "b")
	b.Resolve("C", g)

	// Dry-run cascade query: counted, and the walked set size accumulates.
	if set := b.GetAffected("A"); len(set.Epochs) != 3 {
		t.Fatalf("GetAffected(A) = %v, want all three epochs", set.Epochs)
	}
	st := b.GraphStatsSnapshot()
	if st.AffectedQueries != 1 || st.AffectedNodes != 3 {
		t.Fatalf("affected = {queries:%d nodes:%d}, want {1 3}",
			st.AffectedQueries, st.AffectedNodes)
	}
	if st.Rollbacks != 0 {
		t.Fatalf("rollbacks = %d before any rollback, want 0", st.Rollbacks)
	}

	// Real cascade: rolling back A must take B and C with it.
	set, err := b.RollbackWithAffected("A")
	if err != nil {
		t.Fatalf("rollback A: %v", err)
	}
	if len(set.Epochs) != 3 {
		t.Fatalf("cascade affected %v, want 3 epochs", set.Epochs)
	}
	st = b.GraphStatsSnapshot()
	if st.Rollbacks != 1 || st.RollbackNodes != 3 {
		t.Fatalf("rollback = {calls:%d nodes:%d}, want {1 3}",
			st.Rollbacks, st.RollbackNodes)
	}
	if st.Epochs != 0 || st.Edges != 0 {
		t.Fatalf("post-cascade shape = {epochs:%d edges:%d}, want {0 0}",
			st.Epochs, st.Edges)
	}
}

// --- group resolution counters incl. the TOCTOU revalidation rate ---

func TestGraphStatsFinalizeCounters(t *testing.T) {
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
	st := b.GraphStatsSnapshot()
	if st.PrepareCalls != 1 {
		t.Fatalf("prepare_calls = %d, want 1", st.PrepareCalls)
	}

	// A stale graph generation ON ITS OWN must no longer be refused, and that is
	// the fix rather than a relaxation. The whole-graph counter was bumped by
	// beginEpochInternal as well as by real topology changes, so with N agents
	// running every BeginEpoch -- an isolated node, no edges, unable to move any
	// existing SCC -- invalidated every in-flight finalization and the optimistic
	// retry starved: 48 refused attempts per published group was the routine
	// case, and one SCC burned 2844 attempts over 121s without ever publishing.
	// The generation is still carried, for the diagnostic message.
	res, err := b.BeginFinalize(prep.GroupID, prep.GraphGeneration-1)
	if err != nil {
		t.Fatalf("BeginFinalize refused on a stale generation alone: %v", err)
	}
	if res.Status != "finalized" {
		t.Fatalf("BeginFinalize status = %q, want finalized", res.Status)
	}
	st = b.GraphStatsSnapshot()
	if st.FinalizeRejectedTOCTOU != 0 {
		t.Fatalf("finalize_rejected_toctou = %d, want 0: a generation mismatch "+
			"with the member set intact is not a TOCTOU", st.FinalizeRejectedTOCTOU)
	}
	if st.FinalizeCalls != 1 || st.FinalizedNodes != 1 {
		t.Fatalf("finalize = {calls:%d nodes:%d}, want {1 1}",
			st.FinalizeCalls, st.FinalizedNodes)
	}

	// What DOES invalidate a prepared group is its member set moving. Build a
	// real two-member cycle, prepare it, then break one of its edges the way
	// cleanupEpochs does when a rollback prunes the graph: the prepared set
	// {B C} stops being a single component, and publishing it would publish half
	// a cycle -- which is what the revalidation counter exists to report.
	g := writeOrig(t, orig, "g.txt", "base-g")
	h := writeOrig(t, orig, "h.txt", "base-h")
	for _, ep := range []EpochID{"B", "C"} {
		if err := b.BeginEpoch(ep, "/cg-"+string(ep), "s-"+string(ep)); err != nil {
			t.Fatal(err)
		}
	}
	stageWrite(t, b, "B", g, "b")
	b.Resolve("C", g) // C reads B's g -> edge B -> C
	stageWrite(t, b, "C", h, "c")
	b.Resolve("B", h) // B reads C's h -> edge C -> B  (cycle)
	for _, ep := range []EpochID{"B", "C"} {
		if _, err := b.Authorize(ep, "policy-hash"); err != nil {
			t.Fatalf("Authorize %s: %v", ep, err)
		}
	}
	prep2, err := b.PrepareResolution("B")
	if err != nil {
		t.Fatalf("PrepareResolution(B): %v", err)
	}
	if len(prep2.Members) != 2 {
		t.Fatalf("prepared members = %v, want the 2-cycle {B C}", prep2.Members)
	}

	b.mu.Lock()
	delete(b.dependsOn["B"], "C")
	delete(b.dependents["C"], "B")
	b.mu.Unlock()

	if _, err := b.BeginFinalize(prep2.GroupID, prep2.GraphGeneration); err == nil {
		t.Fatal("BeginFinalize accepted a group whose SCC had split beneath it")
	}
	st = b.GraphStatsSnapshot()
	if st.FinalizeCalls != 2 || st.FinalizedNodes != 1 {
		t.Fatalf("finalize = {calls:%d nodes:%d}, want {2 1} (the rejected attempt counts)",
			st.FinalizeCalls, st.FinalizedNodes)
	}
	if st.FinalizeRejectedTOCTOU != 1 {
		t.Fatalf("finalize_rejected_toctou = %d, want 1", st.FinalizeRejectedTOCTOU)
	}
}

// --- the shape fields describe the LIVE frontier, not the history ---

func TestGraphStatsShapeFollowsTheLiveFrontier(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	for _, ep := range []EpochID{"A", "B"} {
		if err := b.BeginEpoch(ep, "/cg-"+string(ep), "s-"+string(ep)); err != nil {
			t.Fatal(err)
		}
	}
	stageWrite(t, b, "A", f, "a")
	b.Resolve("B", f) // edge A -> B

	if st := b.GraphStatsSnapshot(); st.Epochs != 2 || st.Edges != 1 {
		t.Fatalf("pre-commit shape = {epochs:%d edges:%d}, want {2 1}",
			st.Epochs, st.Edges)
	}

	// Publishing A drops its edges: a finalized version can no longer cascade a
	// rollback, so the edge is dead weight in every later cascade walk.
	if _, err := b.Authorize("A", "policy-hash"); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	prep, err := b.PrepareResolution("A")
	if err != nil {
		t.Fatalf("PrepareResolution: %v", err)
	}
	if _, err := b.BeginFinalize(prep.GroupID, prep.GraphGeneration); err != nil {
		t.Fatalf("BeginFinalize: %v", err)
	}
	st := b.GraphStatsSnapshot()
	if st.Edges != 0 {
		t.Fatalf("edges after finalize = %d, want 0 (finalized edges are dropped)",
			st.Edges)
	}
	if st.Epochs != 2 {
		t.Fatalf("epochs after finalize = %d, want 2 (nodes survive until ack)",
			st.Epochs)
	}

	// The node itself leaves only when its terminal record is acked.
	if err := b.AckRelease("A"); err != nil {
		t.Fatalf("AckRelease: %v", err)
	}
	if st := b.GraphStatsSnapshot(); st.Epochs != 1 {
		t.Fatalf("epochs after ack = %d, want 1", st.Epochs)
	}
}

// --- reset delimits a measurement window without touching the live graph ---

func TestGraphStatsReset(t *testing.T) {
	b, orig, _ := newTestBackend(t)
	f := writeOrig(t, orig, "f.txt", "base")

	if err := b.BeginEpoch("A", "/cg-a", "s-a"); err != nil {
		t.Fatal(err)
	}
	if err := b.BeginEpoch("B", "/cg-b", "s-b"); err != nil {
		t.Fatal(err)
	}
	stageWrite(t, b, "A", f, "a")
	b.Resolve("B", f)
	b.GetAffected("A")

	// The snapshot returned by ResetGraphStats is the state BEFORE the reset.
	prev := b.ResetGraphStats()
	if prev.EdgeInsertions != 1 || prev.AffectedQueries != 1 {
		t.Fatalf("pre-reset snapshot = {edges:%d affected:%d}, want {1 1}",
			prev.EdgeInsertions, prev.AffectedQueries)
	}
	after := b.GraphStatsSnapshot()
	if after.EdgeInsertions != 0 || after.AffectedQueries != 0 ||
		after.AffectedNodes != 0 || after.SCCComputations != 0 ||
		after.PrepareCalls != 0 || after.FinalizeCalls != 0 ||
		after.Rollbacks != 0 {
		t.Fatalf("counters not zeroed by reset: %+v", after)
	}
	// The live graph is NOT measurement state: it survives the reset intact.
	if after.Epochs != 2 || after.Edges != 1 || after.Versions != 1 {
		t.Fatalf("reset damaged the graph: %+v", after)
	}
	// The generation fence is a correctness value, not a counter: never reset.
	if after.GraphGeneration == 0 {
		t.Fatal("graph_generation was zeroed by reset (would break TOCTOU fencing)")
	}
	// Work after the reset accumulates from zero.
	if set := b.GetAffected("A"); len(set.Epochs) != 2 {
		t.Fatalf("GetAffected(A) = %v, want 2 epochs", set.Epochs)
	}
	after2 := b.GraphStatsSnapshot()
	if after2.AffectedQueries != 1 || after2.AffectedNodes != 2 {
		t.Fatalf("post-reset affected = {queries:%d nodes:%d}, want {1 2}",
			after2.AffectedQueries, after2.AffectedNodes)
	}
}
