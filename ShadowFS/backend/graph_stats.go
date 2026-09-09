package backend

import (
	"runtime"
)

// Dependency-graph scalability instrumentation.
//
// The causal DAG is a first-class part of the design (version-level
// dependency, exact read provenance, SCC-atomic publication, cascading
// rollback), so its COST has to be measurable from outside the daemon: an
// experiment samples `graph_stats` before and after a measured phase and
// attributes the delta to the invocations it issued. That is what the
// counters below are for.
//
// Design rules:
//
//   - Every counter is guarded by Backend.mu and is only touched on paths
//     that already hold it, so instrumentation introduces no new lock order.
//   - The hottest instrumented path is addDependency (called for every read
//     that observes a foreign version). It pays one time.Since plus two
//     increments; the log.Printf it already executes for each NEW edge costs
//     far more, so the instrumentation is not the bottleneck it measures.
//   - Counters are cumulative and monotonic. They are measurement state, not
//     recovery state: they are deliberately NOT written to the checkpoint/WAL,
//     and a restarted daemon starts from zero. ResetGraphStats zeroes them so
//     each measured phase gets a clean delta.
//   - GraphStatsSnapshot calls runtime.ReadMemStats, which stops the world for
//     a few hundred microseconds. Experiments must therefore sample it
//     OUTSIDE their timed intervals (before/after a phase), never inside.

// graphCounters accumulates dependency-graph work. Guarded by Backend.mu.
type graphCounters struct {
	// Edge insertion (addDependency).
	edgeInsertions uint64 // calls that created a NEW edge
	edgeInsertNs   uint64 // cumulative time inside addDependency

	// SCC detection (computeSCCs — Tarjan over the whole graph).
	sccComputations uint64
	sccComputeNs    uint64

	// Cascade-set queries (GetAffected dry-run).
	affectedQueries uint64
	affectedQueryNs uint64
	affectedNodes   uint64 // cumulative size of the returned sets

	// Group resolution (PrepareResolution — includes its SCC computation).
	prepareCalls uint64
	prepareNs    uint64

	// Group finalization (BeginFinalize).
	finalizeCalls          uint64
	finalizeNs             uint64
	finalizedNodes         uint64 // members of groups that reached "finalized"
	finalizeRejectedTOCTOU uint64 // refused: graph_generation moved (revalidation)

	// Cascading rollback (RollbackWithAffected — includes WAL + staging cleanup).
	rollbacks     uint64
	rollbackNs    uint64
	rollbackNodes uint64 // cumulative size of the rolled-back sets
}

// GraphStats is a read-only snapshot of the dependency graph and of the
// cumulative work the daemon has done maintaining it. Serialized verbatim to
// the control socket (`graph_stats`) and to experiment result files.
//
// READING THE SHAPE FIELDS: the graph holds LIVE (unfinalized) epochs.
// finalizeEpoch drops every edge touching the epoch it finalizes -- a published
// version can no longer cascade a rollback, so keeping the edge would only make
// the cascade walks longer -- and ackReleaseInternal then drops the node itself.
// Epochs and Edges therefore describe the speculative frontier, not the history:
// a workload that opens N epochs, wires a topology and commits everything reads
// back Epochs=0, Edges=0. An experiment that wants "the graph at size N" must
// sample BETWEEN wiring the topology and committing it.
type GraphStats struct {
	// ── Instantaneous graph shape ──
	Epochs          int   `json:"epochs"`           // tracked graph nodes
	Edges           int   `json:"edges"`            // dependency edges (dependsOn)
	Versions        int   `json:"versions"`         // live speculative versions
	Objects         int   `json:"objects"`          // tracked logical paths
	GraphGeneration int64 `json:"graph_generation"` // TOCTOU fence counter
	SCCCount        int   `json:"scc_count"`        // components (incl. singletons)
	CyclicSCCCount  int   `json:"cyclic_scc_count"` // components with >1 member
	MaxSCCSize      int   `json:"max_scc_size"`
	ActiveGroups    int   `json:"active_groups"` // prepared-but-unreleased groups

	// ── Daemon memory (Go runtime, whole process) ──
	HeapAllocBytes uint64 `json:"heap_alloc_bytes"`
	HeapInuseBytes uint64 `json:"heap_inuse_bytes"`
	SysBytes       uint64 `json:"sys_bytes"`
	Goroutines     int    `json:"goroutines"`

	// ── Cumulative work counters (zeroed by ResetGraphStats) ──
	EdgeInsertions         uint64 `json:"edge_insertions"`
	EdgeInsertNs           uint64 `json:"edge_insert_ns"`
	SCCComputations        uint64 `json:"scc_computations"`
	SCCComputeNs           uint64 `json:"scc_compute_ns"`
	AffectedQueries        uint64 `json:"affected_queries"`
	AffectedQueryNs        uint64 `json:"affected_query_ns"`
	AffectedNodes          uint64 `json:"affected_nodes_total"`
	PrepareCalls           uint64 `json:"prepare_calls"`
	PrepareNs              uint64 `json:"prepare_ns"`
	FinalizeCalls          uint64 `json:"finalize_calls"`
	FinalizeNs             uint64 `json:"finalize_ns"`
	FinalizedNodes         uint64 `json:"finalized_nodes_total"`
	FinalizeRejectedTOCTOU uint64 `json:"finalize_rejected_toctou"`
	Rollbacks              uint64 `json:"rollbacks"`
	RollbackNs             uint64 `json:"rollback_ns"`
	RollbackNodes          uint64 `json:"rollback_nodes_total"`
}

// GraphStatsSnapshot returns the current graph shape plus cumulative counters.
// Safe to call at any time; briefly stops the world for the memory read.
func (b *Backend) GraphStatsSnapshot() GraphStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.graphStatsLocked()
}

// ResetGraphStats zeroes the cumulative counters and returns the snapshot
// taken immediately BEFORE the reset, so a caller can both report the
// previous phase and start the next one from a clean delta in a single RPC.
// The instantaneous shape (epochs/edges/versions) is never reset — it is a
// property of the live graph, not of a measurement window.
func (b *Backend) ResetGraphStats() GraphStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	prev := b.graphStatsLocked()
	b.graphCtr = graphCounters{}
	return prev
}

// graphStatsLocked builds the snapshot. Must be called with b.mu held.
//
// It uses computeSCCsLocked (NOT computeSCCs) so that introspection never
// inflates the SCC counters it is reporting.
func (b *Backend) graphStatsLocked() GraphStats {
	edges := 0
	for _, set := range b.dependsOn {
		edges += len(set)
	}
	maxSCC, cyclic, sccCount := 0, 0, 0
	for _, comp := range b.computeSCCsLocked() {
		sccCount++
		if len(comp) > maxSCC {
			maxSCC = len(comp)
		}
		if len(comp) > 1 {
			cyclic++
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	c := b.graphCtr
	return GraphStats{
		Epochs:          len(b.epochs),
		Edges:           edges,
		Versions:        len(b.versionByID),
		Objects:         len(b.versionsByObject),
		GraphGeneration: b.graphGen,
		SCCCount:        sccCount,
		CyclicSCCCount:  cyclic,
		MaxSCCSize:      maxSCC,
		ActiveGroups:    len(b.activeGroups),

		HeapAllocBytes: ms.HeapAlloc,
		HeapInuseBytes: ms.HeapInuse,
		SysBytes:       ms.Sys,
		Goroutines:     runtime.NumGoroutine(),

		EdgeInsertions:         c.edgeInsertions,
		EdgeInsertNs:           c.edgeInsertNs,
		SCCComputations:        c.sccComputations,
		SCCComputeNs:           c.sccComputeNs,
		AffectedQueries:        c.affectedQueries,
		AffectedQueryNs:        c.affectedQueryNs,
		AffectedNodes:          c.affectedNodes,
		PrepareCalls:           c.prepareCalls,
		PrepareNs:              c.prepareNs,
		FinalizeCalls:          c.finalizeCalls,
		FinalizeNs:             c.finalizeNs,
		FinalizedNodes:         c.finalizedNodes,
		FinalizeRejectedTOCTOU: c.finalizeRejectedTOCTOU,
		Rollbacks:              c.rollbacks,
		RollbackNs:             c.rollbackNs,
		RollbackNodes:          c.rollbackNodes,
	}
}
