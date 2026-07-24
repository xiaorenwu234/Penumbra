package backend

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// AgentLifecycle is the explicit finalization state of an agent's session.
// It replaces the old single `Committed bool` so callers can distinguish
// "policy approved but not yet safe to release" from "file state durably
// promoted and safe to release". External side effects (fs promotion,
// ShadowProc release, network un-fencing, stdout/tool output) may ONLY be
// released once the agent reaches Finalized.
type AgentLifecycle int32

const (
	// Speculative: running/observed, policy not yet approved. Nothing may
	// escape the sandbox.
	Speculative AgentLifecycle = iota
	// AuthorizedPending: policy approved, but promotions and/or upstream
	// dependencies are not all finalized yet. STILL fully fenced.
	AuthorizedPending
	// Finalizing: promotion has started for this agent. Only completion or
	// retry is allowed from here; a normal rollback must NOT run.
	Finalizing
	// Finalized: every promotion succeeded and every upstream is Finalized.
	// This is the ONLY state in which CanRelease returns true. The agent is
	// retained (not deleted) until the orchestrator calls AckRelease.
	Finalized
)

func (s AgentLifecycle) String() string {
	switch s {
	case Speculative:
		return "speculative"
	case AuthorizedPending:
		return "authorized_pending"
	case Finalizing:
		return "finalizing"
	case Finalized:
		return "finalized"
	default:
		return "unknown"
	}
}

// AgentState holds the undo log and dirty file set for a single agent.
type AgentState struct {
	CgroupID   string
	UndoLog    []LogEntry
	DirtyFiles map[string]struct{} // logical orig paths touched by this agent
	// State is the explicit lifecycle position (see AgentLifecycle). It
	// supersedes the old `Committed bool`: `approved()` (>= AuthorizedPending)
	// is the predicate the promotion/finalization logic uses where it used to
	// read `Committed`. An upstream rollback still cascades and undoes this
	// agent's changes UNLESS it has reached Finalizing/Finalized (durable).
	State AgentLifecycle
	// FinalizeErr records the most recent promotion failure (path/op/error)
	// so retry_finalize / get_lifecycle can report why an agent is stuck in
	// Finalizing instead of Finalized. Cleared on a fully successful finalize.
	FinalizeErr string
	// EpochOpen indicates a speculative epoch is currently active for this
	// agent (see BeginEpoch/CommitEpoch/RollbackEpoch). While open, every
	// undo entry whose Seq() > EpochStartSeq belongs to the epoch and can be
	// undone in isolation by RollbackEpoch, WITHOUT touching pre-epoch state
	// or cascading to other agents.
	EpochOpen bool
	// EpochStartSeq is the control-op seq allocated by BeginEpoch. Undo
	// entries recorded after the epoch began carry a strictly greater seq,
	// which is how RollbackEpoch distinguishes epoch work from prior state.
	EpochStartSeq int64
}

// approved reports whether the agent's policy has been approved, i.e. it has
// reached AuthorizedPending or beyond. This is the exact predicate the old
// code expressed as `agent.Committed`, so promotion/finalization/release logic
// reads it in place of the removed bool.
func (a *AgentState) approved() bool { return a.State >= AuthorizedPending }

// WAL tuning parameters.
const (
	checkpointInterval     = 5 * time.Second // full snapshot interval
	checkpointWALThreshold = 1000            // force checkpoint when WAL exceeds this
)

// walPending is one submission unit handed off to the WAL worker. A single
// submission may carry multiple records that should be fsync'd atomically
// (e.g. a rename produces two undo entries). The worker writes accumulated
// pending units in a single appendWAL+fsync and acks every waiter with the
// shared error result.
type walPending struct {
	recs []WALRecord
	done chan error
}

// Backend tracks overlay operations per-agent and supports rollback with
// contamination detection via a directed dependency graph. See the package
// comment in operations.go for high-level semantics.
//
// Concurrency model (group-commit WAL):
//
//   - opRW: every mutating operation acquires opRW.RLock() for its full
//     duration. Checkpoint takes opRW.Lock() to wait until all in-flight
//     operations have completed AND all their WAL records have been
//     fsync'd, guaranteeing snapshot consistency.
//   - mu: protects in-memory state (agents, fileDirty, dependency graph,
//     seq counter, walCount, walPending, applyCond state). Held briefly
//     during compute and apply phases.
//   - WAL fsync runs in a dedicated walWorker goroutine. Multiple callers
//     submit records concurrently and each waits on its own done channel.
//     The worker coalesces all submissions accumulated between fsyncs into
//     a single appendWAL+fsync, achieving group commit.
//   - applyCond enforces seq-order on the post-fsync apply phase so that
//     dependency-graph edges and overlay mutations observe the same
//     ordering as the WAL on disk.
type Backend struct {
	stagingDir string
	trackedDir string
	agents     map[string]*AgentState
	dependents map[string]map[string]struct{}
	dependsOn  map[string]map[string]struct{}
	fileDirty  map[string]map[string]struct{} // orig path -> set of agents that have dirtied it
	// publishDirs accumulates the orig parent directories of paths promoted
	// during the current settle. They are fsync'd as ONE group barrier before
	// any agent in the group is marked Finalized, so the whole commit group's
	// externally-visible publish is crash-atomic (all-or-nothing after
	// recovery). Protected by mu.
	publishDirs map[string]struct{}
	seq         int64
	mu          sync.Mutex
	persistPath string
	walPath     string

	// opRW gates concurrent mutating operations against checkpoint. All
	// Record*/Rollback*/Commit operations hold RLock for their full
	// duration; checkpoint takes the writer lock so it observes a
	// quiescent state before snapshotting+truncating the WAL.
	opRW sync.RWMutex

	walCount int64 // total WAL records since last checkpoint (protected by mu)

	// WAL worker channels.
	walPending []*walPending // protected by mu
	walNotify  chan struct{} // 1-buffered wakeup for walWorker
	walStop    chan struct{}
	walDone    chan struct{} // closed when walWorker exits

	// Seq-ordered apply coordination.
	nextApply  int64          // next seq allowed to enter the apply phase (protected by mu)
	applyCond  *sync.Cond     // signalled when nextApply advances
	abortedSeq map[int64]bool // seqs that failed before apply (must be skipped) (protected by mu)

	// Signalling
	chkptTrigger chan struct{} // poked when WAL exceeds checkpointWALThreshold
	stopCh       chan struct{}
	chkptDone    chan struct{} // closed when checkpointLoop exits
	closeOnce    sync.Once

	// Open FD tracking: cgroupID → list of tracked fds.
	// When a cascade rollback cleans up an agent, all its tracked fds are
	// force-closed so the agent's process gets EBADF on the next I/O
	// instead of silently reading stale overlay data.
	openFDs   map[string][]*TrackedFD
	openFDsMu sync.Mutex

	// invalidateFn, when set, is invoked after a rollback with the list of
	// tracked (orig) file paths whose overlay state was removed. Rollback
	// mutates overlay files out-of-band (via the control socket, not through
	// the FUSE data path), so the kernel's dentry cache keeps serving stale
	// positive entries for paths whose overlay copy was just deleted (e.g. the
	// destination of a rolled-back rename). The FUSE layer registers this to
	// drop those cache entries. Set once at startup; read without locking.
	invalidateFn func(paths []string)
}

// SetInvalidateCallback registers a function invoked after a rollback with the
// tracked file paths whose overlay state was removed, so the FUSE layer can
// invalidate stale kernel dentry cache entries. Must be set before serving.
func (b *Backend) SetInvalidateCallback(fn func(paths []string)) {
	b.invalidateFn = fn
}

// NewBackend creates a Backend. stagingDir is the overlay root (write side)
// and also holds the persisted state file. trackedDir is the original
// filesystem root being shadowed.
func NewBackend(stagingDir, trackedDir string) (*Backend, error) {
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return nil, fmt.Errorf("create staging dir %q: %w", stagingDir, err)
	}
	b := &Backend{
		stagingDir:   stagingDir,
		trackedDir:   trackedDir,
		agents:       make(map[string]*AgentState),
		dependents:   make(map[string]map[string]struct{}),
		dependsOn:    make(map[string]map[string]struct{}),
		fileDirty:    make(map[string]map[string]struct{}),
		publishDirs:  make(map[string]struct{}),
		persistPath:  persistFilePath(stagingDir),
		walPath:      walFilePath(stagingDir),
		walNotify:    make(chan struct{}, 1),
		walStop:      make(chan struct{}),
		walDone:      make(chan struct{}),
		abortedSeq:   make(map[int64]bool),
		openFDs:      make(map[string][]*TrackedFD),
		chkptTrigger: make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
		chkptDone:    make(chan struct{}),
	}
	b.applyCond = sync.NewCond(&b.mu)

	// --- Crash recovery ---
	if _, err := os.Stat(b.persistPath); err == nil {
		state, loadErr := loadFromDisk(b.persistPath)
		if loadErr != nil {
			log.Printf("[backend] WARNING: failed to load persisted state: %v (starting fresh)", loadErr)
		} else {
			b.loadState(state)
		}
	}
	// Replay WAL records written after last checkpoint.
	if records, err := loadWAL(b.walPath); err != nil {
		log.Printf("[backend] WARNING: failed to load WAL: %v", err)
	} else if len(records) > 0 {
		b.replayWAL(records)
	}
	// NOTE: agents are NOT auto-authorized on recovery. An epoch is authorized
	// only if a durable "commit" (authorize) WAL record was replayed above,
	// which sets AuthorizedPending via commitInternal. A read-only epoch that
	// was never committed stays Speculative: it may still have process /
	// network / output effects that policy must approve before it finalizes
	// (see the invariant enforced in tryPromoteAll / tryFinalizeSCCs).
	// Re-derive Finalized states after recovery. Every Promote() is
	// idempotent, so this is safe to run and reconstructs the durable
	// finalized set from the authorized agents. Crucially, an agent is only
	// (re-)marked Finalized if its promotions ACTUALLY succeed now, so a
	// crash mid-promotion recovers as AuthorizedPending/Finalizing (fenced,
	// retryable) — pending is never mistaken for finalized.
	_ = b.tryPromoteAll()
	b.nextApply = b.seq + 1

	go b.walWorker()
	go b.checkpointLoop()
	return b, nil
}

// replayWAL applies WAL records to rebuild in-memory state after a crash.
// Must be called before the backend is shared (no locking needed).
//
// Records with SeqNum <= snapshotSeq (the seq captured by the most recent
// checkpoint already loaded into memory) are skipped: they have been
// folded into the snapshot. Control records (commit/rollback) are
// dispatched to the corresponding *Internal helper so the in-memory
// state matches what the original caller observed before the crash.
//
// For mutation records the on-disk overlay state is also REDONE via
// redoEntry. This is required because of the strict write-ahead order:
// the WAL record is durable BEFORE the overlay-side mutation is applied,
// so a crash after WAL fsync but before mutation completion can leave
// the disk inconsistent. redoEntry uses idempotent primitives so it is
// safe to re-run even when the mutation already finished.
func (b *Backend) replayWAL(records []WALRecord) {
	snapshotSeq := b.seq
	applied := 0
	for _, rec := range records {
		recSeq := rec.SeqNum
		if recSeq == 0 {
			recSeq = rec.Entry.SeqNum
		}
		if recSeq != 0 && recSeq <= snapshotSeq {
			continue // already in snapshot
		}
		if rec.ControlOp != "" {
			switch rec.ControlOp {
			case "commit":
				b.commitInternal(rec.CgroupID)
			case "rollback":
				_ = b.rollbackInternal(rec.CgroupID)
			case "rollback_last":
				b.rollbackLastInternal(rec.CgroupID)
			case "begin_epoch":
				b.beginEpochInternal(rec.CgroupID, recSeq)
			case "commit_epoch":
				b.commitEpochInternal(rec.CgroupID)
			case "rollback_epoch":
				_ = b.rollbackEpochInternal(rec.CgroupID)
			case "read_dep":
				b.replayReadDep(rec.CgroupID, rec.Entry.OrigPath)
			case "release_ack":
				// The orchestrator acked release of a finalized agent before
				// the crash. Drop its terminal record (idempotent; only acts
				// if the agent is currently Finalized).
				b.ackReleaseInternal(rec.CgroupID)
			default:
				log.Printf("[backend] WAL: unknown control op %q", rec.ControlOp)
			}
			if recSeq > b.seq {
				b.seq = recSeq
			}
			applied++
			continue
		}
		agent := b.ensureAgent(rec.CgroupID)
		entry := UnmarshalEntry(rec.Entry)
		if entry == nil {
			continue
		}
		agent.UndoLog = append(agent.UndoLog, entry)
		if rec.Entry.SeqNum > b.seq {
			b.seq = rec.Entry.SeqNum
		}
		// Rebuild dirty tracking AND dependency graph via markDirty.
		b.markDirty(rec.CgroupID, entry.Path())
		// REDO the overlay-side mutation idempotently. This recovers the
		// disk state for crashes that occurred between WAL fsync and
		// mutation completion.
		b.redoEntry(rec.Entry)
		applied++
	}
	log.Printf("[backend] WAL replayed: %d/%d records (filtered by snapshot seq=%d)", applied, len(records), snapshotSeq)
}

// replayReadDep rebuilds the dependency edges for a read_dep WAL record.
// Must be called before the backend is shared (no locking needed).
func (b *Backend) replayReadDep(cgroupID, origPath string) {
	if writers, ok := b.fileDirty[origPath]; ok {
		for prev := range writers {
			if prev != cgroupID {
				b.addDependency(prev, cgroupID)
			}
		}
	}
	for dirtyPath, dirtyWriters := range b.fileDirty {
		if dirtyPath == origPath {
			continue
		}
		if isAncestor(dirtyPath, origPath) || isAncestor(origPath, dirtyPath) {
			for prev := range dirtyWriters {
				if prev != cgroupID {
					b.addDependency(prev, cgroupID)
				}
			}
		}
	}
	b.ensureAgent(cgroupID)
}

// --- Group-commit WAL (write-ahead with batched fsync) ---
//
// Every mutating Record* / Rollback* / Commit method follows this protocol:
//
//  1. opRW.RLock() for the full operation (gates against checkpoint).
//  2. mu.Lock(); allocate seq, compute paths, build the WAL record(s);
//     mu.Unlock().
//  3. submitWAL(rec) hands the record(s) to walWorker and returns a
//     waiter channel. Block on the waiter — when it fires, the record
//     is fsync'd to disk. Multiple callers submitting concurrently are
//     coalesced by the worker into a single fsync (group commit).
//  4. applyTurnWait(seq) blocks under mu until our seq is the next one
//     allowed to apply. Then idempotently apply the overlay mutation
//     and update in-memory state (UndoLog, dirty maps, dependency
//     graph). Finally call applyTurnDone(seq) and release mu.
//  5. opRW.RUnlock().
//
// Crash semantics:
//
//   - Crash before step 3 returns ⇒ WAL has no record AND in-memory /
//     overlay update never happened. Recovery: nothing to do.
//   - Crash after step 3 returns but before step 4 completes ⇒ WAL has
//     the record but in-memory / overlay may be partial. replayWAL
//     rebuilds in-memory state and idempotently re-applies the overlay
//     mutation via redoEntry.
//   - Crash after step 4 ⇒ WAL has the record and disk reflects the
//     mutation. replayWAL's redo is idempotent so it is a no-op.
//
// Checkpoint correctness: opRW writer-lock waits until every in-flight
// op has reached opRW.RUnlock() — at that point all WAL records have
// been fsync'd AND all in-memory updates have been applied. The
// snapshot is therefore consistent with the on-disk WAL.

// submitWAL hands one or more records to walWorker for batched fsync and
// returns a channel that fires (with the shared fsync result) once the
// records are durable. May be called concurrently from any number of
// goroutines without holding mu.
func (b *Backend) submitWAL(recs ...WALRecord) <-chan error {
	p := &walPending{recs: append([]WALRecord(nil), recs...), done: make(chan error, 1)}
	b.mu.Lock()
	b.walPending = append(b.walPending, p)
	b.mu.Unlock()
	select {
	case b.walNotify <- struct{}{}:
	default:
	}
	return p.done
}

// walWorker is the single goroutine responsible for performing fsync on
// behalf of all submitWAL callers. It runs flushPending whenever poked,
// coalescing every submission accumulated since the previous fsync into
// one appendWAL call.
func (b *Backend) walWorker() {
	defer close(b.walDone)
	for {
		select {
		case <-b.walStop:
			b.flushPending()
			return
		case <-b.walNotify:
			b.flushPending()
		}
	}
}

// flushPending drains b.walPending, fsyncs every record in one call, and
// acks every waiter. Safe to call from the worker or from checkpoint.
func (b *Backend) flushPending() {
	b.mu.Lock()
	batch := b.walPending
	b.walPending = nil
	b.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	var allRecs []WALRecord
	for _, p := range batch {
		allRecs = append(allRecs, p.recs...)
	}
	err := appendWAL(b.walPath, allRecs)
	if err == nil {
		b.mu.Lock()
		b.walCount += int64(len(allRecs))
		over := b.walCount >= checkpointWALThreshold
		b.mu.Unlock()
		if over {
			select {
			case b.chkptTrigger <- struct{}{}:
			default:
			}
		}
	} else {
		err = fmt.Errorf("WAL append: %w", err)
	}
	for _, p := range batch {
		p.done <- err
	}
}

// applyTurnWait blocks until seq is the next seq allowed to apply. Caller
// must hold b.mu; on return b.mu is still held and the caller may run its
// apply step. After the apply step, the caller MUST call applyTurnDone.
func (b *Backend) applyTurnWait(seq int64) {
	for b.nextApply != seq {
		b.applyCond.Wait()
	}
}

// applyTurnDone advances nextApply past seq (skipping any seqs marked as
// aborted). Caller must hold b.mu.
func (b *Backend) applyTurnDone(seq int64) {
	b.nextApply = seq + 1
	for b.abortedSeq[b.nextApply] {
		delete(b.abortedSeq, b.nextApply)
		b.nextApply++
	}
	b.applyCond.Broadcast()
}

// applyTurnAbort marks seq as aborted (won't be applied) so subsequent
// seqs aren't blocked waiting for it. Used when WAL fsync fails and the
// caller cannot apply.
func (b *Backend) applyTurnAbort(seq int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nextApply == seq {
		b.applyTurnDone(seq)
		return
	}
	b.abortedSeq[seq] = true
}

// redoEntry idempotently re-applies the overlay-side effect of a WAL
// mutation record. Called from replayWAL so that crashes between WAL
// fsync and mutation completion are recovered. Every step uses
// idempotent primitives: MkdirAll, copy-up only when overlay missing,
// whiteout creation via O_CREATE, etc.
func (b *Backend) redoEntry(s SerializableEntry) {
	switch s.Type {
	case "mkdir":
		if s.OverlayPath == "" {
			return
		}
		if err := ensureOverlayParent(s.OverlayPath); err != nil {
			log.Printf("[backend] redo mkdir parent %q: %v", s.OverlayPath, err)
			return
		}
		mode := os.FileMode(s.Mode)
		if mode == 0 {
			mode = 0o755
		}
		if err := os.Mkdir(s.OverlayPath, mode); err != nil && !os.IsExist(err) {
			log.Printf("[backend] redo mkdir %q: %v", s.OverlayPath, err)
		}
		if s.HadWhiteout && s.WhiteoutPath != "" {
			if err := os.Remove(s.WhiteoutPath); err != nil && !os.IsNotExist(err) {
				log.Printf("[backend] redo mkdir whiteout-remove %q: %v", s.WhiteoutPath, err)
			}
		}
	case "write":
		if s.OverlayPath == "" {
			return
		}
		if err := ensureOverlayParent(s.OverlayPath); err != nil {
			log.Printf("[backend] redo write parent %q: %v", s.OverlayPath, err)
			return
		}
		needCopyUp := false
		if st, err := os.Lstat(s.OverlayPath); os.IsNotExist(err) {
			needCopyUp = true
		} else if err == nil && s.OrigSize > 0 && st.Size() < s.OrigSize {
			// Overlay exists but is smaller than the orig at copy-up time:
			// this indicates a partial write (crash between io.Copy and
			// fsync in copyUpFile). Remove and re-copy.
			log.Printf("[backend] redo write: partial overlay %q (size=%d, want=%d), re-copy",
				s.OverlayPath, st.Size(), s.OrigSize)
			os.Remove(s.OverlayPath)
			needCopyUp = true
		}
		if needCopyUp {
			if _, oerr := os.Lstat(s.OrigPath); oerr == nil {
				if cerr := copyUpFile(s.OrigPath, s.OverlayPath); cerr != nil {
					log.Printf("[backend] redo copy-up %q: %v", s.OrigPath, cerr)
				}
			}
			// If orig is also missing this is a fresh create: leave the
			// overlay empty for the FUSE caller to populate on the next
			// open. The undo log entry alone is sufficient.
		}
		if s.HadWhiteout && s.WhiteoutPath != "" {
			if err := os.Remove(s.WhiteoutPath); err != nil && !os.IsNotExist(err) {
				log.Printf("[backend] redo write whiteout-remove %q: %v", s.WhiteoutPath, err)
			}
		}
	case "unlink", "rmdir":
		if s.WhiteoutPath == "" {
			return
		}
		if err := os.MkdirAll(filepath.Dir(s.WhiteoutPath), 0o755); err != nil {
			log.Printf("[backend] redo whiteout parent %q: %v", s.WhiteoutPath, err)
			return
		}
		f, err := os.OpenFile(s.WhiteoutPath, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Printf("[backend] redo whiteout %q: %v", s.WhiteoutPath, err)
			return
		}
		f.Close()
	case "link":
		// Recreate the overlay hard link to the target's overlay copy so a
		// crash between WAL fsync and the os.Link is recovered. Idempotent:
		// EEXIST is fine; a missing target overlay is skipped (the target's
		// own redo will materialise it, and promote links on the orig side).
		if s.OverlayPath == "" || s.TargetPath == "" {
			return
		}
		if err := ensureOverlayParent(s.OverlayPath); err != nil {
			log.Printf("[backend] redo link parent %q: %v", s.OverlayPath, err)
			return
		}
		tgtOverlay, oerr := overlayPathFor(b.stagingDir, b.trackedDir, s.TargetPath)
		if oerr == nil {
			if _, st := os.Lstat(tgtOverlay); st == nil {
				if err := os.Link(tgtOverlay, s.OverlayPath); err != nil && !os.IsExist(err) {
					log.Printf("[backend] redo link %q -> %q: %v", tgtOverlay, s.OverlayPath, err)
				}
			}
		}
		if s.HadWhiteout && s.WhiteoutPath != "" {
			if err := os.Remove(s.WhiteoutPath); err != nil && !os.IsNotExist(err) {
				log.Printf("[backend] redo link whiteout-remove %q: %v", s.WhiteoutPath, err)
			}
		}
	case "mknod":
		if s.OverlayPath == "" {
			return
		}
		if err := ensureOverlayParent(s.OverlayPath); err != nil {
			log.Printf("[backend] redo mknod parent %q: %v", s.OverlayPath, err)
			return
		}
		if err := syscall.Mknod(s.OverlayPath, s.Mode, int(s.Rdev)); err != nil && !errors.Is(err, syscall.EEXIST) {
			log.Printf("[backend] redo mknod %q: %v", s.OverlayPath, err)
		}
		if s.HadWhiteout && s.WhiteoutPath != "" {
			if err := os.Remove(s.WhiteoutPath); err != nil && !os.IsNotExist(err) {
				log.Printf("[backend] redo mknod whiteout-remove %q: %v", s.WhiteoutPath, err)
			}
		}
	}
}

// --- Checkpoint loop ---

func (b *Backend) checkpointLoop() {
	defer close(b.chkptDone)
	ticker := time.NewTicker(checkpointInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.stopCh:
			b.checkpoint()
			return
		case <-ticker.C:
			b.checkpoint()
		case <-b.chkptTrigger:
			b.checkpoint()
		}
	}
}

// checkpoint writes a full state snapshot and truncates the WAL.
//
// Synchronisation: opRW.Lock() waits until every in-flight Record* /
// Rollback* / Commit op has reached opRW.RUnlock(). At that point the
// in-memory state and the on-disk WAL are consistent (every applied
// in-memory change has its corresponding WAL record fsync'd; every
// fsync'd WAL record has had its apply step run). flushPending() before
// taking the writer lock makes sure pending waiters are unblocked so
// they can complete and release their RLock.
func (b *Backend) checkpoint() {
	// Drain any pending submissions so currently-waiting RLock holders
	// can finish their apply step and release the RLock.
	b.flushPending()

	// Wait for all in-flight ops to release their RLock. After Lock
	// succeeds, no new ops can start until we Unlock.
	b.opRW.Lock()
	defer b.opRW.Unlock()

	// Belt-and-suspenders: any submission that snuck in just before the
	// last RLock holder released gets fsync'd here.
	b.flushPending()

	b.mu.Lock()
	if b.walCount == 0 {
		b.mu.Unlock()
		return
	}
	state := b.snapshot()
	b.walCount = 0
	b.mu.Unlock()

	if err := saveToDisk(b.persistPath, state); err != nil {
		log.Printf("[backend] checkpoint save failed: %v", err)
		b.mu.Lock()
		b.walCount = 1 // ensure retry
		b.mu.Unlock()
		return
	}
	if err := truncateWAL(b.walPath); err != nil {
		log.Printf("[backend] checkpoint truncate WAL failed: %v", err)
	}
	log.Printf("[backend] checkpoint complete (snapshot seq=%d)", state.Seq)
}

// Close stops the checkpoint loop and the WAL worker, and performs a
// final flush.
func (b *Backend) Close() {
	b.closeOnce.Do(func() {
		close(b.stopCh)
		<-b.chkptDone
		close(b.walStop)
		<-b.walDone
	})
}

// TrackedDir returns the original (read) filesystem root.
func (b *Backend) TrackedDir() string { return b.trackedDir }

// OverlayDir returns the overlay (write) filesystem root, which is the
// staging directory itself.
func (b *Backend) OverlayDir() string { return b.stagingDir }

// StagingDir returns the staging directory passed to NewBackend.
func (b *Backend) StagingDir() string { return b.stagingDir }

// --- FD tracking ---

// TrackedFD wraps a raw file descriptor with a safe double-close guard.
// Both the FUSE Release handler and the cascade rollback path may try to
// close the fd; the atomic flag ensures exactly one syscall.Close runs.
type TrackedFD struct {
	fd     int
	closed atomic.Bool
}

// NewTrackedFD wraps a raw fd obtained from syscall.Open.
func NewTrackedFD(fd int) *TrackedFD {
	return &TrackedFD{fd: fd}
}

// FD returns the raw file descriptor.
func (t *TrackedFD) FD() int { return t.fd }

// Close closes the fd exactly once. Subsequent calls are no-ops.
// Returns EBADF-style nil if already closed.
func (t *TrackedFD) Close() error {
	if t.closed.Swap(true) {
		return nil // already closed
	}
	return syscall.Close(t.fd)
}

// IsClosed reports whether Close has already been called.
func (t *TrackedFD) IsClosed() bool {
	return t.closed.Load()
}

// RegisterFD associates a tracked fd with an agent. The fd will be
// force-closed if the agent is cleaned up by a cascade rollback.
func (b *Backend) RegisterFD(cgroupID string, tfd *TrackedFD) {
	b.openFDsMu.Lock()
	b.openFDs[cgroupID] = append(b.openFDs[cgroupID], tfd)
	b.openFDsMu.Unlock()
}

// UnregisterFD removes a tracked fd from an agent. Called when the FUSE
// Release handler fires (i.e. the kernel closed the fd). Safe to call
// even if the fd was already removed by CloseAgentFDs.
func (b *Backend) UnregisterFD(cgroupID string, tfd *TrackedFD) {
	b.openFDsMu.Lock()
	fds := b.openFDs[cgroupID]
	for i, f := range fds {
		if f == tfd {
			b.openFDs[cgroupID] = append(fds[:i], fds[i+1:]...)
			break
		}
	}
	if len(b.openFDs[cgroupID]) == 0 {
		delete(b.openFDs, cgroupID)
	}
	b.openFDsMu.Unlock()
}

// CloseAgentFDs force-closes every tracked fd belonging to the given
// agent. Called during cascade rollback so the agent's process receives
// EBADF on its next I/O rather than silently accessing stale overlay
// data through a dangling fd.
func (b *Backend) CloseAgentFDs(cgroupID string) {
	b.openFDsMu.Lock()
	fds := b.openFDs[cgroupID]
	delete(b.openFDs, cgroupID)
	b.openFDsMu.Unlock()
	for _, tfd := range fds {
		if err := tfd.Close(); err != nil {
			log.Printf("[backend] CloseAgentFDs: agent=%q fd=%d: %v", cgroupID, tfd.FD(), err)
		}
	}
	if len(fds) > 0 {
		log.Printf("[backend] CloseAgentFDs: agent=%q closed %d fd(s)", cgroupID, len(fds))
	}
}

// flushAgentFDs fsyncs every tracked fd of the agent so that any data the
// kernel has written back through the FUSE data path -- including dirty pages
// of a writable MAP_SHARED mmap that the process has already msync'd/flushed --
// is durable on the overlay copy BEFORE promotion renames it onto orig. Called
// at commit time, when ShadowProc has frozen the agent. Best-effort: an fsync
// error on an already-closed or read-only fd is ignored. NOTE: this cannot
// force writeback of a still-live mapping whose dirty pages a FROZEN process
// has not yet flushed -- see the mmap scope note in Open().
func (b *Backend) flushAgentFDs(cgroupID string) {
	b.openFDsMu.Lock()
	fds := make([]*TrackedFD, len(b.openFDs[cgroupID]))
	copy(fds, b.openFDs[cgroupID])
	b.openFDsMu.Unlock()
	for _, tfd := range fds {
		if tfd.IsClosed() {
			continue
		}
		if err := syscall.Fsync(tfd.FD()); err != nil {
			log.Printf("[backend] flushAgentFDs: agent=%q fd=%d: %v", cgroupID, tfd.FD(), err)
		}
	}
}

// --- Dependency graph ---

func (b *Backend) addDependency(on, dependent string) {
	if on == dependent {
		return
	}
	set, ok := b.dependents[on]
	if !ok {
		set = make(map[string]struct{})
		b.dependents[on] = set
	}
	if _, exists := set[dependent]; !exists {
		set[dependent] = struct{}{}
		log.Printf("[backend] addDependency: %q depends on %q", dependent, on)
	}
	rev, ok := b.dependsOn[dependent]
	if !ok {
		rev = make(map[string]struct{})
		b.dependsOn[dependent] = rev
	}
	rev[on] = struct{}{}
}

func (b *Backend) reachableFrom(start string) map[string]struct{} {
	visited := make(map[string]struct{})
	var dfs func(string)
	dfs = func(id string) {
		if _, seen := visited[id]; seen {
			return
		}
		visited[id] = struct{}{}
		for next := range b.dependents[id] {
			dfs(next)
		}
	}
	dfs(start)
	return visited
}

// --- Agent / dirty management ---

func (b *Backend) ensureAgent(cgroupID string) *AgentState {
	agent, ok := b.agents[cgroupID]
	if !ok {
		agent = &AgentState{CgroupID: cgroupID, DirtyFiles: make(map[string]struct{})}
		b.agents[cgroupID] = agent
	}
	return agent
}

// markDirty marks origPath as dirtied by cgroupID and adds dependency edges
// from every prior writer (exact path or parent-child) to cgroupID.
func (b *Backend) markDirty(cgroupID, origPath string) {
	agent := b.ensureAgent(cgroupID)
	agent.DirtyFiles[origPath] = struct{}{}

	writers, ok := b.fileDirty[origPath]
	if !ok {
		writers = make(map[string]struct{})
		b.fileDirty[origPath] = writers
	}
	for prev := range writers {
		if prev != cgroupID {
			b.addDependency(prev, cgroupID)
		}
	}
	writers[cgroupID] = struct{}{}

	// Parent-child path dependencies.
	otherPaths := make([]string, 0, len(b.fileDirty))
	for p := range b.fileDirty {
		if p != origPath {
			otherPaths = append(otherPaths, p)
		}
	}
	for _, dirty := range otherPaths {
		dirtyWriters := b.fileDirty[dirty]
		if isAncestor(dirty, origPath) {
			for prev := range dirtyWriters {
				if prev != cgroupID {
					b.addDependency(prev, cgroupID)
				}
			}
		} else if isAncestor(origPath, dirty) {
			for other := range dirtyWriters {
				if other != cgroupID {
					b.addDependency(cgroupID, other)
				}
			}
		}
	}
}

// hasAncestorWhiteoutOverlay checks whether any ancestor directory of the
// given absolute overlay path has a whiteout marker. This is used during
// the apply phase of PrepareWrite / RecordMkdir to detect the case where
// another agent deleted a parent directory while we waited for WAL fsync.
//
// The walk is bounded by stagingRoot so we never read ".shadow.wh.*" files
// that happen to live OUTSIDE the staging tree (e.g. in /tmp or /). This
// preserves correctness when stagingDir is itself a subdirectory of a
// directory the user does not control, and avoids unnecessary stats.
func hasAncestorWhiteoutOverlay(stagingRoot, overlayAbsPath string) bool {
	cleanRoot := filepath.Clean(stagingRoot)
	dir := filepath.Dir(overlayAbsPath)
	for {
		// Stop once we reach the staging root: ancestors above it are
		// outside the overlay and cannot legitimately carry whiteouts.
		if dir == cleanRoot {
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		// The whiteout for directory `dir` lives in its PARENT, named
		// `.shadow.wh.<basename(dir)>` — mirroring whiteoutPathFor /
		// whiteoutPath. Previously this looked inside `dir` itself,
		// which never matched and silently disabled the apply-phase
		// race check entirely.
		wp := filepath.Join(parent, whiteoutPrefix+filepath.Base(dir))
		if _, err := os.Lstat(wp); err == nil {
			return true
		}
		dir = parent
	}
}

// isAncestor reports whether dir is a strict ancestor directory of child.
func isAncestor(dir, child string) bool {
	if dir == "" {
		return false
	}
	dir = filepath.Clean(dir)
	child = filepath.Clean(child)
	if len(child) <= len(dir) {
		return false
	}
	if child[:len(dir)] != dir {
		return false
	}
	if dir == string(os.PathSeparator) {
		return true
	}
	return child[len(dir)] == os.PathSeparator
}

// restoreWhiteout recreates a whiteout marker file. Best-effort: errors are
// logged but not returned (used during rollback cleanup paths).
func restoreWhiteout(whiteoutPath string) {
	if err := os.MkdirAll(filepath.Dir(whiteoutPath), 0o755); err != nil {
		log.Printf("[backend] restoreWhiteout: mkdir %q: %v", whiteoutPath, err)
		return
	}
	f, err := os.OpenFile(whiteoutPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("[backend] restoreWhiteout: create %q: %v", whiteoutPath, err)
		return
	}
	f.Close()
	log.Printf("[backend] restoreWhiteout: restored %q", whiteoutPath)
}

func (b *Backend) nextSeq() int64 { b.seq++; return b.seq }

// hasWriteEntry reports whether the given agent already has an active
// OverlayWriteEntry or OverlayMkdirEntry for origPath that has NOT been
// superseded by a later Unlink/Rmdir on the same path. Used to dedupe
// repeated open(W) calls.
func (b *Backend) hasWriteEntry(cgroupID, origPath string) bool {
	agent, ok := b.agents[cgroupID]
	if !ok {
		return false
	}
	// Iterate from the most recent entry backwards so that an
	// Unlink/Rmdir that follows a Write correctly invalidates the
	// dedup: the agent deleted and then re-wrote the path, so a
	// fresh WriteEntry is needed.
	for i := len(agent.UndoLog) - 1; i >= 0; i-- {
		entry := agent.UndoLog[i]
		if entry.Path() != origPath {
			continue
		}
		switch entry.(type) {
		case *OverlayWriteEntry, *OverlayMkdirEntry:
			return true
		case *OverlayUnlinkEntry, *OverlayRmdirEntry:
			return false
		}
	}
	return false
}

// --- Record methods ---

// PrepareWrite ensures an overlay copy of origPath exists (copy-up if the
// orig file exists and the overlay does not), records an OverlayWriteEntry
// for the agent if it has not already done so, and returns the overlay
// path the caller should open for writing.
//
// Strict write-ahead protocol: the WAL record is appended+fsynced BEFORE
// any overlay mutation (copy-up, whiteout removal). On crash between WAL
// fsync and mutation, replayWAL's redoEntry idempotently restores the
// overlay state.
func (b *Backend) PrepareWrite(cgroupID, origPath string) (string, error) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	overlayPath, err := overlayPathFor(b.stagingDir, b.trackedDir, origPath)
	if err != nil {
		return "", err
	}
	whPath, _ := whiteoutPathFor(b.stagingDir, b.trackedDir, origPath)

	// Reject writes targeting a symlink. copyUpFile preserves symlinks
	// verbatim, and every subsequent mutation primitive used by Open(W)
	// / Setattr (syscall.Open without O_NOFOLLOW, os.Truncate, os.Chmod,
	// os.Chown, os.Chtimes) follows symlinks. If orig is a symlink, the
	// resulting fd / metadata change would be applied to the symlink
	// target — potentially a file inside orig — directly breaking the
	// "orig is immutable" invariant. The check is done before allocating
	// a seq / writing WAL so a refused op leaves no trace.
	if st, lerr := os.Lstat(origPath); lerr == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", syscall.EOPNOTSUPP
	}

	// --- compute (under mu) ---
	b.mu.Lock()
	if b.hasWriteEntry(cgroupID, origPath) {
		// Already recorded for this agent; a duplicate WAL marker would
		// just be filtered by replayWAL. Skip WAL+apply, only refresh
		// dirty graph.
		b.markDirty(cgroupID, origPath)
		b.mu.Unlock()
		log.Printf("[backend] PrepareWrite: agent=%q path=%q already recorded, skip", cgroupID, origPath)
		return overlayPath, nil
	}
	hadWh := false
	if whPath != "" {
		if _, statErr := os.Lstat(whPath); statErr == nil {
			hadWh = true
		}
	}
	// Record orig file size so redoEntry can detect partial copy-up after
	// a crash between io.Copy and fsync in copyUpFile.
	var origSize int64
	if origInfo, statErr := os.Lstat(origPath); statErr == nil && !origInfo.IsDir() {
		origSize = origInfo.Size()
	}
	seqNum := b.nextSeq()
	rec := WALRecord{
		CgroupID:          cgroupID,
		SeqNum:            seqNum,
		Entry:             SerializableEntry{Type: "write", SeqNum: seqNum, OrigPath: origPath, OverlayPath: overlayPath, HadWhiteout: hadWh, WhiteoutPath: whPath, OrigSize: origSize},
		DirtyOverlayPaths: []string{overlayPath},
	}
	b.mu.Unlock()

	// --- WAL fsync (group-commit) ---
	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return "", err
	}

	// --- apply (in seq order, under mu) ---
	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	if err := ensureOverlayParent(overlayPath); err != nil {
		return "", err
	}
	// Check ancestor whiteouts at apply time: if a parent directory was
	// deleted (whiteout created) by another agent while we waited for
	// WAL fsync, abort this write to maintain view consistency.
	if hasAncestorWhiteoutOverlay(b.stagingDir, overlayPath) {
		return "", fmt.Errorf("ancestor directory of %q has been deleted", origPath)
	}
	if _, statErr := os.Lstat(overlayPath); os.IsNotExist(statErr) {
		if _, oerr := os.Lstat(origPath); oerr == nil {
			if err := copyUpFile(origPath, overlayPath); err != nil {
				return "", fmt.Errorf("copy-up %q: %w", origPath, err)
			}
		}
	}
	// Re-check whiteout state at apply time to close the TOCTOU window
	// between compute (hadWh snapshot) and apply. Another agent may have
	// created or removed a whiteout while we waited for WAL fsync.
	if whPath != "" {
		if _, statErr := os.Lstat(whPath); statErr == nil {
			// Whiteout exists now — remove it and record hadWh=true so
			// rollback can restore it.
			hadWh = true
			if _, err := removeWhiteout(b.stagingDir, b.trackedDir, origPath); err != nil {
				return "", err
			}
		}
		// If whiteout is absent at apply time but was present at compute
		// time, another agent already removed it. Keep hadWh as-is from
		// compute so our rollback still restores it (the other agent's
		// rollback is responsible for its own whiteout lifecycle).
	}

	agent := b.ensureAgent(cgroupID)
	b.markDirty(cgroupID, origPath)

	// If there are old UndoLog entries for this path (e.g. the agent
	// previously unlinked and now re-writes), remove them. Keeping
	// stale Unlink/Rmdir entries would cause promote to execute both
	// the unlink's "remove orig" and the write's "rename overlay→orig",
	// leaving orig deleted.
	cleanedStale := false
	if len(agent.UndoLog) > 0 {
		kept := agent.UndoLog[:0]
		for _, e := range agent.UndoLog {
			if e.Path() == origPath {
				cleanedStale = true
				continue
			}
			kept = append(kept, e)
		}
		agent.UndoLog = kept
	}
	// When we cleaned stale Unlink/Rmdir entries, the new write fully
	// supersedes the old delete-then-write sequence. Set hadWh=false so
	// that rolling back the new write does NOT restore a whiteout that
	// belonged to the superseded sequence.
	if cleanedStale {
		hadWh = false
	}

	log.Printf("[backend] PrepareWrite: agent=%q path=%q overlay=%q hadWhiteout=%v", cgroupID, origPath, overlayPath, hadWh)
	agent.UndoLog = append(agent.UndoLog, &OverlayWriteEntry{
		baseEntry:    baseEntry{SeqNum: seqNum},
		OrigPath:     origPath,
		OverlayPath:  overlayPath,
		HadWhiteout:  hadWh,
		WhiteoutPath: whPath,
		OrigSize:     origSize,
	})
	return overlayPath, nil
}

// PrepareCreate prepares the overlay for a brand new file at origPath.
// Behaves like PrepareWrite but does not require the orig file to exist.
// Any existing whiteout for the path is removed.
func (b *Backend) PrepareCreate(cgroupID, origPath string) (string, error) {
	return b.PrepareWrite(cgroupID, origPath)
}

// RecordMkdir records an overlay mkdir. The overlay directory is created
// here (so subsequent FUSE lookups see it). Any whiteout is cleared.
func (b *Backend) RecordMkdir(cgroupID, origPath string, mode uint32) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	overlayPath, err := overlayPathFor(b.stagingDir, b.trackedDir, origPath)
	if err != nil {
		return err
	}
	whPath, _ := whiteoutPathFor(b.stagingDir, b.trackedDir, origPath)

	b.mu.Lock()
	// Dedup check FIRST — before allocating a seq, writing WAL, or
	// mutating the overlay. If the agent already has an active
	// MkdirEntry for this path (not superseded by a Rmdir), skip
	// everything. Previously the dedup was checked after os.Mkdir and
	// WAL write, causing WAL/UndoLog divergence on crash.
	if b.hasWriteEntry(cgroupID, origPath) {
		b.markDirty(cgroupID, origPath)
		b.mu.Unlock()
		log.Printf("[backend] RecordMkdir: agent=%q path=%q already recorded, skip", cgroupID, origPath)
		return nil
	}
	hadWh := false
	if whPath != "" {
		if _, statErr := os.Lstat(whPath); statErr == nil {
			hadWh = true
		}
	}
	seqNum := b.nextSeq()
	rec := WALRecord{
		CgroupID: cgroupID,
		SeqNum:   seqNum,
		Entry:    SerializableEntry{Type: "mkdir", SeqNum: seqNum, OrigPath: origPath, OverlayPath: overlayPath, Mode: mode, HadWhiteout: hadWh, WhiteoutPath: whPath},
	}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return err
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	if err := ensureOverlayParent(overlayPath); err != nil {
		return err
	}
	// Check ancestor whiteouts at apply time: if a parent directory was
	// deleted while we waited for WAL fsync, abort this mkdir.
	if hasAncestorWhiteoutOverlay(b.stagingDir, overlayPath) {
		return fmt.Errorf("ancestor directory of %q has been deleted", origPath)
	}
	// Re-check whiteout state at apply time to close the TOCTOU window
	// between compute (hadWh snapshot) and apply.
	if whPath != "" {
		if _, statErr := os.Lstat(whPath); statErr == nil {
			hadWh = true
			if _, err := removeWhiteout(b.stagingDir, b.trackedDir, origPath); err != nil {
				return err
			}
		}
	}
	if err := os.Mkdir(overlayPath, os.FileMode(mode)); err != nil && !os.IsExist(err) {
		return fmt.Errorf("overlay mkdir %q: %w", overlayPath, err)
	}

	agent := b.ensureAgent(cgroupID)
	b.markDirty(cgroupID, origPath)

	// Clean up stale entries for the same path (e.g. mkdir → rmdir →
	// mkdir). See PrepareWrite for the same logic.
	if len(agent.UndoLog) > 0 {
		kept := agent.UndoLog[:0]
		for _, e := range agent.UndoLog {
			if e.Path() == origPath {
				continue
			}
			kept = append(kept, e)
		}
		agent.UndoLog = kept
	}

	log.Printf("[backend] RecordMkdir: agent=%q path=%q mode=%#o hadWhiteout=%v", cgroupID, origPath, mode, hadWh)
	agent.UndoLog = append(agent.UndoLog, &OverlayMkdirEntry{
		baseEntry:    baseEntry{SeqNum: seqNum},
		OrigPath:     origPath,
		OverlayPath:  overlayPath,
		Mode:         mode,
		HadWhiteout:  hadWh,
		WhiteoutPath: whPath,
	})
	return nil
}

// RecordUnlink records a file unlink. A whiteout marker is written so the
// file disappears from the merged view; the orig file is not touched.
func (b *Backend) RecordUnlink(cgroupID, origPath string) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	overlayPath, err := overlayPathFor(b.stagingDir, b.trackedDir, origPath)
	if err != nil {
		return err
	}
	whiteoutPath, err := whiteoutPathFor(b.stagingDir, b.trackedDir, origPath)
	if err != nil {
		return err
	}

	b.mu.Lock()
	seqNum := b.nextSeq()
	rec := WALRecord{
		CgroupID:          cgroupID,
		SeqNum:            seqNum,
		Entry:             SerializableEntry{Type: "unlink", SeqNum: seqNum, OrigPath: origPath, OverlayPath: overlayPath, WhiteoutPath: whiteoutPath},
		DirtyOverlayPaths: []string{whiteoutPath},
	}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return err
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	// Close the TOCTOU window with another agent's rmdir on a parent: if
	// any ancestor was whiteout'd while we waited for WAL fsync, abort
	// instead of materialising a whiteout inside an already-deleted dir.
	if hasAncestorWhiteoutOverlay(b.stagingDir, overlayPath) {
		return fmt.Errorf("ancestor directory of %q has been deleted", origPath)
	}

	if err := writeWhiteout(b.stagingDir, b.trackedDir, origPath); err != nil {
		return err
	}
	// Clean up any existing overlay copy so it doesn't become an orphan
	// file. The whiteout already hides the path in the merged view, but
	// leaving the overlay copy wastes disk space and could cause confusion
	// if the whiteout is later removed (e.g. by a partial rollback).
	if _, statErr := os.Lstat(overlayPath); statErr == nil {
		os.Remove(overlayPath) // best-effort; ignore errors
	}

	agent := b.ensureAgent(cgroupID)
	b.markDirty(cgroupID, origPath)
	log.Printf("[backend] RecordUnlink: agent=%q path=%q", cgroupID, origPath)
	agent.UndoLog = append(agent.UndoLog, &OverlayUnlinkEntry{
		baseEntry:    baseEntry{SeqNum: seqNum},
		OrigPath:     origPath,
		OverlayPath:  overlayPath,
		WhiteoutPath: whiteoutPath,
	})
	return nil
}

// RecordRmdir records a directory removal. Like Unlink but for a dir tree.
func (b *Backend) RecordRmdir(cgroupID, origPath string) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	overlayPath, err := overlayPathFor(b.stagingDir, b.trackedDir, origPath)
	if err != nil {
		return err
	}
	whiteoutPath, err := whiteoutPathFor(b.stagingDir, b.trackedDir, origPath)
	if err != nil {
		return err
	}

	b.mu.Lock()
	seqNum := b.nextSeq()
	rec := WALRecord{
		CgroupID:          cgroupID,
		SeqNum:            seqNum,
		Entry:             SerializableEntry{Type: "rmdir", SeqNum: seqNum, OrigPath: origPath, OverlayPath: overlayPath, WhiteoutPath: whiteoutPath},
		DirtyOverlayPaths: []string{whiteoutPath},
	}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return err
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	// Apply-time ancestor whiteout check: same TOCTOU window as RecordUnlink.
	if hasAncestorWhiteoutOverlay(b.stagingDir, overlayPath) {
		return fmt.Errorf("ancestor directory of %q has been deleted", origPath)
	}

	if err := writeWhiteout(b.stagingDir, b.trackedDir, origPath); err != nil {
		return err
	}
	// Do NOT os.RemoveAll the overlay directory here. Other agents may
	// have written files into this overlay directory; removing it would
	// silently destroy their data. The whiteout already hides the entire
	// directory from the merged view. On rollback the whiteout is removed
	// (revealing any surviving overlay children); on promote the
	// OverlayRmdirEntry.Promote() removes the orig directory tree.

	agent := b.ensureAgent(cgroupID)
	b.markDirty(cgroupID, origPath)
	log.Printf("[backend] RecordRmdir: agent=%q path=%q", cgroupID, origPath)
	agent.UndoLog = append(agent.UndoLog, &OverlayRmdirEntry{
		baseEntry:    baseEntry{SeqNum: seqNum},
		OrigPath:     origPath,
		OverlayPath:  overlayPath,
		WhiteoutPath: whiteoutPath,
	})
	return nil
}

// RecordRename records a file or directory rename. It is implemented as a
// pair of overlay actions (write at newPath + unlink at oldPath) so both
// edges of the dependency graph are tracked uniformly. The caller should
// invoke this BEFORE relying on the new path: by the time the call
// returns, the overlay has been mutated to reflect the rename.
func (b *Backend) RecordRename(cgroupID, oldPath, newPath string) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	// Cycle detection: prevent rename("dir", "dir/subdir/...") which
	// would create a directory cycle and confuse rollback ordering.
	cleanOld := filepath.Clean(oldPath)
	cleanNew := filepath.Clean(newPath)
	// rename(x, x) is a POSIX no-op. Without this short-circuit the
	// apply phase below would `os.RemoveAll(dstOverlay)` (which is the
	// same path as srcOverlay) and then fail to rename the now-deleted
	// source onto itself, leaving the overlay in an inconsistent state.
	if cleanOld == cleanNew {
		return nil
	}
	if strings.HasPrefix(cleanNew, cleanOld+string(os.PathSeparator)) {
		return fmt.Errorf("rename %q into its own subdirectory %q is not allowed", oldPath, newPath)
	}

	srcOverlay, err := overlayPathFor(b.stagingDir, b.trackedDir, oldPath)
	if err != nil {
		return err
	}
	dstOverlay, err := overlayPathFor(b.stagingDir, b.trackedDir, newPath)
	if err != nil {
		return err
	}
	srcWhiteout, err := whiteoutPathFor(b.stagingDir, b.trackedDir, oldPath)
	if err != nil {
		return err
	}
	dstWhiteout, err := whiteoutPathFor(b.stagingDir, b.trackedDir, newPath)
	if err != nil {
		return err
	}

	b.mu.Lock()
	// Check if the destination has a whiteout BEFORE we remove it in the
	// apply phase, so rollback can restore it.
	dstHadWh := false
	if dstWhiteout != "" {
		if _, statErr := os.Lstat(dstWhiteout); statErr == nil {
			dstHadWh = true
		}
	}
	// Record orig file size for redo partial-write detection.
	var origSize int64
	if origInfo, statErr := os.Lstat(oldPath); statErr == nil && !origInfo.IsDir() {
		origSize = origInfo.Size()
	}
	seq1 := b.nextSeq()
	seq2 := b.nextSeq()
	recs := []WALRecord{
		{
			CgroupID:          cgroupID,
			SeqNum:            seq1,
			Entry:             SerializableEntry{Type: "write", SeqNum: seq1, OrigPath: newPath, OverlayPath: dstOverlay, HadWhiteout: dstHadWh, WhiteoutPath: dstWhiteout, OrigSize: origSize},
			DirtyOverlayPaths: []string{dstOverlay},
		},
		{
			CgroupID:          cgroupID,
			SeqNum:            seq2,
			Entry:             SerializableEntry{Type: "unlink", SeqNum: seq2, OrigPath: oldPath, OverlayPath: srcOverlay, WhiteoutPath: srcWhiteout},
			DirtyOverlayPaths: []string{srcWhiteout},
		},
	}
	b.mu.Unlock()

	// Both records go in one fsync; share the same waiter.
	if err := <-b.submitWAL(recs...); err != nil {
		b.applyTurnAbort(seq1)
		b.applyTurnAbort(seq2)
		return err
	}

	b.mu.Lock()
	b.applyTurnWait(seq1)
	// We will advance both seqs ourselves under mu (seq1 then seq2).
	defer func() {
		b.applyTurnDone(seq1)
		b.applyTurnDone(seq2)
		b.mu.Unlock()
	}()

	// Apply-time ancestor whiteout check on BOTH endpoints. If a parent
	// of the source has been deleted, copy-up would materialise files in
	// an already-deleted directory; if a parent of the destination has
	// been deleted, we'd rename into an invisible location.
	if hasAncestorWhiteoutOverlay(b.stagingDir, srcOverlay) {
		return fmt.Errorf("ancestor directory of %q has been deleted", oldPath)
	}
	if hasAncestorWhiteoutOverlay(b.stagingDir, dstOverlay) {
		return fmt.Errorf("ancestor directory of %q has been deleted", newPath)
	}

	if _, statErr := os.Lstat(srcOverlay); os.IsNotExist(statErr) {
		if origInfo, oerr := os.Lstat(oldPath); oerr == nil {
			if origInfo.IsDir() {
				if err := copyUpDir(oldPath, srcOverlay); err != nil {
					return fmt.Errorf("rename copy-up dir %q: %w", oldPath, err)
				}
			} else {
				if err := copyUpFile(oldPath, srcOverlay); err != nil {
					return fmt.Errorf("rename copy-up %q: %w", oldPath, err)
				}
			}
		}
	}
	if err := ensureOverlayParent(dstOverlay); err != nil {
		return err
	}
	if _, err := os.Lstat(dstOverlay); err == nil {
		if err := os.RemoveAll(dstOverlay); err != nil {
			return fmt.Errorf("rename clear dst overlay: %w", err)
		}
	}
	if _, err := removeWhiteout(b.stagingDir, b.trackedDir, newPath); err != nil {
		return err
	}
	if err := os.Rename(srcOverlay, dstOverlay); err != nil {
		return fmt.Errorf("rename overlay %q -> %q: %w", srcOverlay, dstOverlay, err)
	}
	if err := writeWhiteout(b.stagingDir, b.trackedDir, oldPath); err != nil {
		return err
	}

	agent := b.ensureAgent(cgroupID)
	b.markDirty(cgroupID, oldPath)
	b.markDirty(cgroupID, newPath)

	// Clean stale entries for both oldPath and newPath. Without this,
	// prior writes/unlinks on these paths would remain in the UndoLog
	// and cause conflicting operations during promote.
	if len(agent.UndoLog) > 0 {
		kept := agent.UndoLog[:0]
		for _, e := range agent.UndoLog {
			if e.Path() == oldPath || e.Path() == newPath {
				continue
			}
			kept = append(kept, e)
		}
		agent.UndoLog = kept
	}

	log.Printf("[backend] RecordRename: agent=%q %q -> %q", cgroupID, oldPath, newPath)
	agent.UndoLog = append(agent.UndoLog,
		&OverlayWriteEntry{
			baseEntry:    baseEntry{SeqNum: seq1},
			OrigPath:     newPath,
			OverlayPath:  dstOverlay,
			HadWhiteout:  dstHadWh,
			WhiteoutPath: dstWhiteout,
			OrigSize:     origSize,
		},
		&OverlayUnlinkEntry{
			baseEntry:    baseEntry{SeqNum: seq2},
			OrigPath:     oldPath,
			OverlayPath:  srcOverlay,
			WhiteoutPath: srcWhiteout,
		},
	)
	return nil
}

// RecordLink creates a hard link at linkOrig pointing to targetOrig, tracked
// for rollback/promote. The target is copied up so the overlay holds a shared
// inode; on promote a real hard link is created on the orig FS. Hard links to
// directories are rejected (EPERM), matching link(2).
func (b *Backend) RecordLink(cgroupID, targetOrig, linkOrig string) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	if st, lerr := os.Lstat(targetOrig); lerr == nil && st.IsDir() {
		return syscall.EPERM
	}

	linkOverlay, err := overlayPathFor(b.stagingDir, b.trackedDir, linkOrig)
	if err != nil {
		return err
	}
	targetOverlay, err := overlayPathFor(b.stagingDir, b.trackedDir, targetOrig)
	if err != nil {
		return err
	}
	linkWhiteout, _ := whiteoutPathFor(b.stagingDir, b.trackedDir, linkOrig)

	b.mu.Lock()
	hadWh := false
	if linkWhiteout != "" {
		if _, statErr := os.Lstat(linkWhiteout); statErr == nil {
			hadWh = true
		}
	}
	seqNum := b.nextSeq()
	rec := WALRecord{
		CgroupID:          cgroupID,
		SeqNum:            seqNum,
		Entry:             SerializableEntry{Type: "link", SeqNum: seqNum, OrigPath: linkOrig, OverlayPath: linkOverlay, TargetPath: targetOrig, HadWhiteout: hadWh, WhiteoutPath: linkWhiteout},
		DirtyOverlayPaths: []string{linkOverlay},
	}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return err
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	if hasAncestorWhiteoutOverlay(b.stagingDir, linkOverlay) {
		return fmt.Errorf("ancestor directory of %q has been deleted", linkOrig)
	}
	// Ensure the target has an overlay copy so both names share one inode.
	if _, statErr := os.Lstat(targetOverlay); os.IsNotExist(statErr) {
		if _, oerr := os.Lstat(targetOrig); oerr == nil {
			if err := copyUpFile(targetOrig, targetOverlay); err != nil {
				return fmt.Errorf("link copy-up target %q: %w", targetOrig, err)
			}
		} else {
			return syscall.ENOENT
		}
	}
	if err := ensureOverlayParent(linkOverlay); err != nil {
		return err
	}
	if _, err := os.Lstat(linkOverlay); err == nil {
		if err := os.RemoveAll(linkOverlay); err != nil {
			return fmt.Errorf("link clear dst overlay: %w", err)
		}
	}
	if linkWhiteout != "" {
		if _, statErr := os.Lstat(linkWhiteout); statErr == nil {
			hadWh = true
			if _, err := removeWhiteout(b.stagingDir, b.trackedDir, linkOrig); err != nil {
				return err
			}
		}
	}
	if err := os.Link(targetOverlay, linkOverlay); err != nil {
		return fmt.Errorf("link overlay %q -> %q: %w", targetOverlay, linkOverlay, err)
	}

	agent := b.ensureAgent(cgroupID)
	b.markDirty(cgroupID, linkOrig)
	// The link's content derives from the target: if the target's writer(s)
	// roll back, this link must too. Add that dependency WITHOUT registering
	// this agent as a writer of the target (it did not modify the target).
	if tw, ok := b.fileDirty[targetOrig]; ok {
		for prev := range tw {
			if prev != cgroupID {
				b.addDependency(prev, cgroupID)
			}
		}
	}
	if len(agent.UndoLog) > 0 {
		kept := agent.UndoLog[:0]
		for _, e := range agent.UndoLog {
			if e.Path() == linkOrig {
				continue
			}
			kept = append(kept, e)
		}
		agent.UndoLog = kept
	}
	log.Printf("[backend] RecordLink: agent=%q %q -> %q", cgroupID, linkOrig, targetOrig)
	agent.UndoLog = append(agent.UndoLog, &OverlayLinkEntry{
		baseEntry:     baseEntry{SeqNum: seqNum},
		OrigPath:      linkOrig,
		TargetOrig:    targetOrig,
		OverlayPath:   linkOverlay,
		OverlayTarget: targetOverlay,
		HadWhiteout:   hadWh,
		WhiteoutPath:  linkWhiteout,
	})
	return nil
}

// RecordMknod creates a special file (FIFO / socket / char / block device, or
// a plain node) at origPath in the overlay, tracked for rollback/promote.
// `mode` includes the S_IFMT type bits; `rdev` is the device number.
func (b *Backend) RecordMknod(cgroupID, origPath string, mode uint32, rdev uint64) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	overlayPath, err := overlayPathFor(b.stagingDir, b.trackedDir, origPath)
	if err != nil {
		return err
	}
	whPath, _ := whiteoutPathFor(b.stagingDir, b.trackedDir, origPath)

	b.mu.Lock()
	hadWh := false
	if whPath != "" {
		if _, statErr := os.Lstat(whPath); statErr == nil {
			hadWh = true
		}
	}
	seqNum := b.nextSeq()
	rec := WALRecord{
		CgroupID:          cgroupID,
		SeqNum:            seqNum,
		Entry:             SerializableEntry{Type: "mknod", SeqNum: seqNum, OrigPath: origPath, OverlayPath: overlayPath, Mode: mode, Rdev: rdev, HadWhiteout: hadWh, WhiteoutPath: whPath},
		DirtyOverlayPaths: []string{overlayPath},
	}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return err
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	if hasAncestorWhiteoutOverlay(b.stagingDir, overlayPath) {
		return fmt.Errorf("ancestor directory of %q has been deleted", origPath)
	}
	if err := ensureOverlayParent(overlayPath); err != nil {
		return err
	}
	if _, err := os.Lstat(overlayPath); err == nil {
		if err := os.RemoveAll(overlayPath); err != nil {
			return fmt.Errorf("mknod clear overlay: %w", err)
		}
	}
	if whPath != "" {
		if _, statErr := os.Lstat(whPath); statErr == nil {
			hadWh = true
			if _, err := removeWhiteout(b.stagingDir, b.trackedDir, origPath); err != nil {
				return err
			}
		}
	}
	if err := syscall.Mknod(overlayPath, mode, int(rdev)); err != nil {
		return fmt.Errorf("mknod overlay %q: %w", overlayPath, err)
	}

	agent := b.ensureAgent(cgroupID)
	b.markDirty(cgroupID, origPath)
	if len(agent.UndoLog) > 0 {
		kept := agent.UndoLog[:0]
		for _, e := range agent.UndoLog {
			if e.Path() == origPath {
				continue
			}
			kept = append(kept, e)
		}
		agent.UndoLog = kept
	}
	log.Printf("[backend] RecordMknod: agent=%q path=%q mode=%#o rdev=%d", cgroupID, origPath, mode, rdev)
	agent.UndoLog = append(agent.UndoLog, &OverlayMknodEntry{
		baseEntry:    baseEntry{SeqNum: seqNum},
		OrigPath:     origPath,
		OverlayPath:  overlayPath,
		Mode:         mode,
		Rdev:         rdev,
		HadWhiteout:  hadWh,
		WhiteoutPath: whPath,
	})
	return nil
}

// RecordXattrWrite ensures origPath is copied up and tracked as a write, so a
// subsequent syscall.Setxattr / Removexattr applied to the returned overlay
// copy is captured for rollback (discard overlay) and promote (rename carries
// the modified attributes). ACLs are stored as xattrs, so this covers them.
func (b *Backend) RecordXattrWrite(cgroupID, origPath string) (string, error) {
	return b.PrepareWrite(cgroupID, origPath)
}

// HasActiveState reports whether the agent has any undo log entries or dirty
// files. Purely-read agents with no active state do not need read dependency
// tracking (they have nothing to roll back).
func (b *Backend) HasActiveState(cgroupID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	agent, ok := b.agents[cgroupID]
	if !ok {
		return false
	}
	return len(agent.UndoLog) > 0 || len(agent.DirtyFiles) > 0
}

// RecordReadOpen records that an agent opened the path for reading. It
// adds dependency edges so a later cascaded rollback affects this agent
// too, but it does NOT add an undo log entry or mark the file dirty.
// A WAL record is written so that the dependency survives a crash.
func (b *Backend) RecordReadOpen(cgroupID, origPath string) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	seqNum := b.nextSeq()
	rec := WALRecord{
		CgroupID:  cgroupID,
		SeqNum:    seqNum,
		ControlOp: "read_dep",
		Entry:     SerializableEntry{OrigPath: origPath},
	}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] RecordReadOpen WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	if writers, ok := b.fileDirty[origPath]; ok {
		for prev := range writers {
			if prev != cgroupID {
				b.addDependency(prev, cgroupID)
			}
		}
	}
	for dirtyPath, dirtyWriters := range b.fileDirty {
		if dirtyPath == origPath {
			continue
		}
		if isAncestor(dirtyPath, origPath) || isAncestor(origPath, dirtyPath) {
			for prev := range dirtyWriters {
				if prev != cgroupID {
					b.addDependency(prev, cgroupID)
				}
			}
		}
	}
	b.ensureAgent(cgroupID)
}

// --- Rollback ---

// RollbackLastEntry undoes the most recent log entry of the given agent.
// Used to recover from a FUSE op that prepared overlay state but failed
// downstream.
func (b *Backend) RollbackLastEntry(cgroupID string) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	agent, ok := b.agents[cgroupID]
	if !ok || len(agent.UndoLog) == 0 {
		b.mu.Unlock()
		return
	}
	seqNum := b.nextSeq()
	rec := WALRecord{CgroupID: cgroupID, SeqNum: seqNum, ControlOp: "rollback_last"}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] RollbackLastEntry WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	b.rollbackLastInternal(cgroupID)
}

// rollbackBlockedBy returns the first agent id in `ids` whose promotion has
// STARTED (State >= Finalizing) and is therefore no longer safely rollable:
// some of its writes may already be published to the real workspace with their
// undo-log entries removed, so undoing would leave a torn, unrecoverable
// state. Returns "" if none. Must be called with b.mu held.
//
// This is the AUTHORITATIVE rollback gate. It lives inside the *Internal
// executors (rollbackInternal / rollbackEpochInternal / rollbackLastInternal)
// so that BOTH live apply AND WAL replay enforce the identical rule. In
// particular it closes the race where a lower-seq commit is ordered before a
// rollback: the commit applies first and moves an agent into Finalizing, and
// the later rollback record — already durable — is then refused / no-op'd here
// rather than corrupting the published state.
func (b *Backend) rollbackBlockedBy(ids map[string]struct{}) string {
	for id := range ids {
		if a := b.agents[id]; a != nil && a.State >= Finalizing {
			return id
		}
	}
	return ""
}

// rollbackLastInternal performs the in-memory + disk effects of
// RollbackLastEntry without touching the WAL. Must be called with b.mu
// held. Used both by RollbackLastEntry and by replayWAL.
func (b *Backend) rollbackLastInternal(cgroupID string) {
	agent, ok := b.agents[cgroupID]
	if !ok || len(agent.UndoLog) == 0 {
		return
	}
	// Authoritative guard: once promotion has started this agent cannot be
	// rolled back. Safe no-op (this executor is void and shared with replay).
	if agent.State >= Finalizing {
		log.Printf("[backend] RollbackLastEntry refused: agent=%q is %s (promotion started)", cgroupID, agent.State)
		return
	}
	last := agent.UndoLog[len(agent.UndoLog)-1]
	agent.UndoLog = agent.UndoLog[:len(agent.UndoLog)-1]
	if err := last.Rollback(); err != nil {
		log.Printf("[backend] RollbackLastEntry: %v", err)
	}

	// Clean dirty tracking if no remaining entries reference this path.
	// Without this the path stays marked dirty, blocking promote/finalize.
	path := last.Path()
	stillReferenced := false
	for _, e := range agent.UndoLog {
		if e.Path() == path {
			stillReferenced = true
			break
		}
	}
	if !stillReferenced {
		delete(agent.DirtyFiles, path)
		if writers, ok := b.fileDirty[path]; ok {
			delete(writers, cgroupID)
			if len(writers) == 0 {
				delete(b.fileDirty, path)
			}
		}
	}
}

// --- Speculative epoch (per-agent, epoch-scoped rollback) ---
//
// A speculative epoch segments a single agent's undo log by seq so a batch
// of file changes can be committed or rolled back in isolation, mirroring
// the ShadowProc process layer's begin_speculative / reject_pid / commit_pid.
// This lets the orchestrator roll back a long-lived bash session's file
// changes AND its process state for one tool invocation together, while the
// session (agent) keeps living for the next epoch.

// BeginEpoch opens a speculative epoch for the agent. Undo entries recorded
// after this call carry a strictly greater seq than the marker allocated
// here, which is how CommitEpoch / RollbackEpoch tell epoch work apart from
// pre-epoch state. Follows the standard write-ahead protocol.
func (b *Backend) BeginEpoch(cgroupID string) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	seqNum := b.nextSeq()
	rec := WALRecord{CgroupID: cgroupID, SeqNum: seqNum, ControlOp: "begin_epoch"}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] BeginEpoch WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	b.beginEpochInternal(cgroupID, seqNum)
}

// beginEpochInternal performs the in-memory effect of BeginEpoch without
// touching the WAL. Must be called with b.mu held. Used both by BeginEpoch
// and by replayWAL.
func (b *Backend) beginEpochInternal(cgroupID string, startSeq int64) {
	agent := b.ensureAgent(cgroupID)
	agent.EpochOpen = true
	agent.EpochStartSeq = startSeq
	log.Printf("[backend] BeginEpoch: agent=%q startSeq=%d", cgroupID, startSeq)
}

// CommitEpoch accepts the current epoch's changes: the epoch's undo entries
// stay in the agent's undo log as ordinary (still-uncommitted, still-in-
// overlay) state and will be promoted when the whole agent is committed.
// Only the epoch marker is cleared. No-op if no epoch is open.
func (b *Backend) CommitEpoch(cgroupID string) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	agent, ok := b.agents[cgroupID]
	if !ok || !agent.EpochOpen {
		b.mu.Unlock()
		log.Printf("[backend] CommitEpoch: agent %q has no open epoch, no-op", cgroupID)
		return
	}
	seqNum := b.nextSeq()
	rec := WALRecord{CgroupID: cgroupID, SeqNum: seqNum, ControlOp: "commit_epoch"}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] CommitEpoch WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	b.commitEpochInternal(cgroupID)
}

// commitEpochInternal performs the in-memory effect of CommitEpoch without
// touching the WAL. Must be called with b.mu held. Used both by CommitEpoch
// and by replayWAL.
func (b *Backend) commitEpochInternal(cgroupID string) {
	agent, ok := b.agents[cgroupID]
	if !ok {
		return
	}
	agent.EpochOpen = false
	log.Printf("[backend] CommitEpoch: agent=%q epoch accepted", cgroupID)
}

// RollbackEpoch undoes every undo-log entry the agent recorded during the
// current epoch (Seq > EpochStartSeq), in reverse seq order, then clears the
// epoch marker. Pre-epoch state is left intact. Unlike the whole-agent
// Rollback, this is SINGLE-AGENT scoped: it does NOT cascade to dependent
// agents (an epoch is a private speculative batch of one session).
//
// Returns nil on success (including the no-open-epoch no-op). Returns an error
// if the epoch's promotion has already started (State >= Finalizing): the
// published file state can no longer be undone, so the caller (orchestrator)
// MUST NOT roll back the corresponding process/network state either.
func (b *Backend) RollbackEpoch(cgroupID string) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	agent, ok := b.agents[cgroupID]
	if !ok || !agent.EpochOpen {
		b.mu.Unlock()
		log.Printf("[backend] RollbackEpoch: agent %q has no open epoch, no-op", cgroupID)
		return nil
	}
	// Fast-path pre-check: refuse an obviously-blocked rollback before writing
	// a WAL record. The authoritative gate is in rollbackEpochInternal, which
	// also catches the race where a lower-seq commit finalizes after this
	// check but before apply.
	if agent.State >= Finalizing {
		st := agent.State
		b.mu.Unlock()
		return fmt.Errorf("rollback_epoch refused: agent %q is %s (promotion started; published state cannot be undone)", cgroupID, st)
	}
	seqNum := b.nextSeq()
	rec := WALRecord{CgroupID: cgroupID, SeqNum: seqNum, ControlOp: "rollback_epoch"}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] RollbackEpoch WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return err
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	return b.rollbackEpochInternal(cgroupID)
}

// rollbackEpochInternal performs the in-memory + disk effects of
// RollbackEpoch without touching the WAL. Must be called with b.mu held.
// Used both by RollbackEpoch and by replayWAL. Returns an error (without
// mutating anything) when the authoritative guard refuses the rollback; on
// replay the caller ignores the return so the durable record is a safe no-op.
func (b *Backend) rollbackEpochInternal(cgroupID string) error {
	agent, ok := b.agents[cgroupID]
	if !ok {
		return nil
	}
	// Authoritative guard: once promotion has started this agent cannot be
	// rolled back. Refuse in-place (shared by live apply and WAL replay).
	if agent.State >= Finalizing {
		log.Printf("[backend] RollbackEpoch refused: agent=%q is %s (promotion started)", cgroupID, agent.State)
		return fmt.Errorf("rollback_epoch refused: agent %q is %s (promotion started; published state cannot be undone)", cgroupID, agent.State)
	}
	mark := agent.EpochStartSeq
	// Partition the undo log: keep pre-epoch entries, collect epoch entries
	// (Seq > mark) to undo.
	var epochEntries []LogEntry
	var kept []LogEntry
	for _, e := range agent.UndoLog {
		if e.Seq() > mark {
			epochEntries = append(epochEntries, e)
		} else {
			kept = append(kept, e)
		}
	}
	agent.UndoLog = kept

	// Undo in reverse seq order (most recent first), reusing each entry's
	// own Rollback primitive.
	sort.Slice(epochEntries, func(i, j int) bool { return epochEntries[i].Seq() > epochEntries[j].Seq() })
	var invalidatePaths []string
	seen := make(map[string]struct{})
	for _, e := range epochEntries {
		if err := e.Rollback(); err != nil {
			log.Printf("[backend] RollbackEpoch: agent=%q seq=%d: %v", cgroupID, e.Seq(), err)
		}
		if p := e.Path(); p != "" {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				invalidatePaths = append(invalidatePaths, p)
			}
		}
	}

	// Recompute dirty tracking: a path stays dirty only if a kept (pre-epoch)
	// entry still references it.
	for p := range seen {
		stillReferenced := false
		for _, k := range agent.UndoLog {
			if k.Path() == p {
				stillReferenced = true
				break
			}
		}
		if !stillReferenced {
			delete(agent.DirtyFiles, p)
			if writers, ok := b.fileDirty[p]; ok {
				delete(writers, cgroupID)
				if len(writers) == 0 {
					delete(b.fileDirty, p)
				}
			}
		}
	}

	agent.EpochOpen = false
	if b.invalidateFn != nil && len(invalidatePaths) > 0 {
		b.invalidateFn(invalidatePaths)
	}
	log.Printf("[backend] RollbackEpoch: agent=%q undid %d epoch entry(ies)", cgroupID, len(epochEntries))
	return nil
}

// Rollback discards all overlay artefacts produced by the named agent and
// every agent that transitively depends on it.
func (b *Backend) Rollback(cgroupID string) error {
	_, err := b.RollbackWithAffected(cgroupID)
	return err
}

// RollbackWithAffected performs a cascading rollback and returns the list of
// all affected cgroup IDs (including the target itself). This is used by the
// orchestrator to coordinate with ShadowProc.
func (b *Backend) RollbackWithAffected(cgroupID string) ([]string, error) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	if _, ok := b.agents[cgroupID]; !ok {
		b.mu.Unlock()
		log.Printf("[backend] Rollback: agent %q not found, no-op", cgroupID)
		return nil, nil
	}
	// Fast-path pre-check (before allocating a seq / writing WAL): refuse an
	// obviously-blocked rollback early. This is only an optimization -- the
	// AUTHORITATIVE gate is inside rollbackInternal, which also catches the
	// race where a lower-seq commit moves an agent to Finalizing after this
	// check but before apply.
	if blk := b.rollbackBlockedBy(b.reachableFrom(cgroupID)); blk != "" {
		st := b.agents[blk].State
		b.mu.Unlock()
		return nil, fmt.Errorf("rollback refused: agent %q is %s (promotion started; published state cannot be undone)", blk, st)
	}
	seqNum := b.nextSeq()
	rec := WALRecord{CgroupID: cgroupID, SeqNum: seqNum, ControlOp: "rollback"}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] Rollback WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return nil, err
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	// Compute affected set before rollback executes cleanup
	affected := b.reachableFrom(cgroupID)
	affectedList := make([]string, 0, len(affected))
	for id := range affected {
		affectedList = append(affectedList, id)
	}

	err := b.rollbackInternal(cgroupID)
	return affectedList, err
}

// GetAffected returns the list of cgroup IDs that would be affected by a
// rollback of the given agent, without actually performing the rollback.
func (b *Backend) GetAffected(cgroupID string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.agents[cgroupID]; !ok {
		return nil
	}
	affected := b.reachableFrom(cgroupID)
	result := make([]string, 0, len(affected))
	for id := range affected {
		result = append(result, id)
	}
	return result
}

// ListAgents returns the cgroup IDs of all currently tracked agents.
func (b *Backend) ListAgents() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([]string, 0, len(b.agents))
	for id := range b.agents {
		result = append(result, id)
	}
	return result
}

// rollbackInternal performs the cascading rollback (in-memory cleanup +
// overlay deletions) without touching the WAL. Must be called with b.mu
// held. Used both by Rollback and by replayWAL.
func (b *Backend) rollbackInternal(cgroupID string) error {
	if _, ok := b.agents[cgroupID]; !ok {
		return nil
	}
	affected := b.reachableFrom(cgroupID)
	// Authoritative guard (shared by live apply AND WAL replay): refuse if the
	// target or ANY agent this rollback would cascade into has entered
	// Finalizing/Finalized. On the live path this returns an error; on replay
	// the return is ignored, so a durable rollback record that raced a
	// lower-seq commit becomes a safe no-op instead of corrupting the
	// already-published state.
	if blk := b.rollbackBlockedBy(affected); blk != "" {
		log.Printf("[backend] Rollback refused: agent=%q is %s (promotion started; published state cannot be undone)", blk, b.agents[blk].State)
		return fmt.Errorf("rollback refused: agent %q is %s (promotion started; published state cannot be undone)", blk, b.agents[blk].State)
	}
	memberList := make([]string, 0, len(affected))
	for id := range affected {
		memberList = append(memberList, id)
	}
	log.Printf("[backend] Rollback: agent=%q cascading to %v", cgroupID, memberList)

	var allEntries []LogEntry
	dirtyPaths := make(map[string]struct{})
	for id := range affected {
		agent := b.agents[id]
		allEntries = append(allEntries, agent.UndoLog...)
		for p := range agent.DirtyFiles {
			dirtyPaths[p] = struct{}{}
		}
	}
	sort.Slice(allEntries, func(i, j int) bool { return allEntries[i].Seq() > allEntries[j].Seq() })

	// Collect the tracked paths touched by this rollback so the FUSE layer
	// can invalidate the kernel dentry cache for them once the overlay files
	// have been removed below (see Backend.invalidateFn).
	var invalidatePaths []string
	if b.invalidateFn != nil {
		seen := make(map[string]struct{})
		add := func(p string) {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				invalidatePaths = append(invalidatePaths, p)
			}
		}
		for _, entry := range allEntries {
			add(entry.Path())
		}
		for p := range dirtyPaths {
			add(p)
		}
	}

	pathFullyAffected := func(path string) bool {
		writers, ok := b.fileDirty[path]
		if !ok {
			return true
		}
		for w := range writers {
			if _, in := affected[w]; !in {
				return false
			}
		}
		return true
	}

	// Force-close every tracked fd belonging to an affected agent BEFORE
	// executing rollback entries or deleting overlay files. This ensures
	// the agent's process receives EBADF on its next I/O instead of
	// silently reading stale data from a dangling fd to an overlay file
	// that is about to be rolled back or deleted.
	for id := range affected {
		b.CloseAgentFDs(id)
	}

	var errs []error
	for _, entry := range allEntries {
		if !pathFullyAffected(entry.Path()) {
			switch v := entry.(type) {
			case *OverlayWriteEntry:
				if v.HadWhiteout && v.WhiteoutPath != "" {
					restoreWhiteout(v.WhiteoutPath)
				}
			case *OverlayMkdirEntry:
				if v.HadWhiteout && v.WhiteoutPath != "" {
					restoreWhiteout(v.WhiteoutPath)
				}
			}
			continue
		}
		if err := entry.Rollback(); err != nil {
			errs = append(errs, err)
		}
	}
	for path := range dirtyPaths {
		if !pathFullyAffected(path) {
			continue
		}
		_ = removeOverlayState(b.stagingDir, b.trackedDir, path, true)
	}

	b.cleanupAgents(affected)
	if b.invalidateFn != nil && len(invalidatePaths) > 0 {
		b.invalidateFn(invalidatePaths)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (b *Backend) cleanupAgents(affected map[string]struct{}) {
	for id := range affected {
		delete(b.agents, id)
	}
	for path, writers := range b.fileDirty {
		for id := range affected {
			delete(writers, id)
		}
		if len(writers) == 0 {
			delete(b.fileDirty, path)
		}
	}
	for id := range affected {
		delete(b.dependents, id)
	}
	for src, dsts := range b.dependents {
		for id := range affected {
			delete(dsts, id)
		}
		if len(dsts) == 0 {
			delete(b.dependents, src)
		}
	}
	for id := range affected {
		delete(b.dependsOn, id)
	}
	for src, dsts := range b.dependsOn {
		for id := range affected {
			delete(dsts, id)
		}
		if len(dsts) == 0 {
			delete(b.dependsOn, src)
		}
	}
}

// --- Commit ---

// Commit marks the agent's session as committed. The agent is retained
// while it has uncommitted upstream dependencies; per-file promotion runs
// for every dirty path whose writers are all committed and whose writers
// have all-finalized upstreams.
// PromoteFailure records why a single path's promotion failed, so the caller
// (and get_lifecycle) can see exactly what is keeping an agent fenced.
type PromoteFailure struct {
	Path string `json:"path"`
	Op   string `json:"op"`
	Err  string `json:"err"`
}

// CommitResult is returned by Commit / RetryFinalize. It reports the agent's
// resulting lifecycle state, whether it is now safe to release, which agents
// became Finalized as a side effect, and any promotion failures that must be
// retried before release. A non-nil error is reserved for infrastructure
// failures (WAL); promotion failures are surfaced via Failures + a non-
// Finalized State so the orchestrator keeps the workload fenced and retries.
type CommitResult struct {
	State      AgentLifecycle   `json:"state"`
	CanRelease bool             `json:"can_release"`
	Finalized  []string         `json:"finalized,omitempty"`
	Failures   []PromoteFailure `json:"failures,omitempty"`
}

// Commit AUTHORIZES the agent's session (policy approved) and then attempts to
// drive it to Finalized. Authorization alone does NOT permit release: the
// agent only becomes releasable once every dirty path has been durably
// promoted and every upstream dependency is Finalized. Promotion failures do
// not abort the commit; they leave the agent in AuthorizedPending/Finalizing
// (CanRelease=false) so the caller can retry via RetryFinalize.
//
// An unknown cgroup is REGISTERED here (a no-file-op agent) and immediately
// driven to Finalized, so the release path never has to treat "not tracked"
// as "safe" (fail-closed).
func (b *Backend) Commit(cgroupID string) (CommitResult, error) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	agent := b.agents[cgroupID]
	if agent != nil && agent.State >= Finalized {
		// Idempotent: already finalized.
		res := b.lifecycleResultLocked(cgroupID)
		b.mu.Unlock()
		return res, nil
	}
	seqNum := b.nextSeq()
	rec := WALRecord{CgroupID: cgroupID, SeqNum: seqNum, ControlOp: "commit"}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] Commit WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return CommitResult{}, fmt.Errorf("commit WAL: %w", err)
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	b.commitInternal(cgroupID)
	return b.lifecycleResultLocked(cgroupID), nil
}

// commitInternal AUTHORIZES the agent (Speculative -> AuthorizedPending),
// registering it first if it never touched the shadowed filesystem, then runs
// the promotion/finalization pass. Must be called with b.mu held. Used both by
// Commit and by replayWAL; idempotent and re-runnable.
func (b *Backend) commitInternal(cgroupID string) {
	agent, ok := b.agents[cgroupID]
	if !ok {
		// Register a no-file-op agent so release gating never has to treat an
		// unknown cgroup as safe. With no undo entries it finalizes at once.
		agent = b.ensureAgent(cgroupID)
	}
	if agent.State < AuthorizedPending {
		agent.State = AuthorizedPending
		log.Printf("[backend] Commit: agent=%q authorized (pending finalization)", cgroupID)
	}
	// Flush the agent's writable overlay fds (incl. written-back mmap pages)
	// so promotion renames a fully up-to-date overlay copy.
	b.flushAgentFDs(cgroupID)
	_ = b.tryPromoteAll()
}

// RetryFinalize re-runs the promotion/finalization pass for a stuck agent
// (one left in AuthorizedPending/Finalizing by an earlier promotion failure,
// e.g. a transient I/O error). It is safe to call repeatedly: every Promote()
// is idempotent, so already-promoted entries are no-ops. Returns the agent's
// resulting lifecycle. A no-op WAL "commit" record is NOT re-appended; the
// original authorization record already drives re-promotion on replay.
func (b *Backend) RetryFinalize(cgroupID string) (CommitResult, error) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	agent, ok := b.agents[cgroupID]
	if !ok {
		return CommitResult{}, fmt.Errorf("retry_finalize: agent %q not found", cgroupID)
	}
	if agent.State < AuthorizedPending {
		return CommitResult{}, fmt.Errorf("retry_finalize: agent %q not authorized (state=%s)", cgroupID, agent.State)
	}
	b.flushAgentFDs(cgroupID)
	_ = b.tryPromoteAll()
	return b.lifecycleResultLocked(cgroupID), nil
}

// lifecycleResultLocked builds a CommitResult snapshot for cgroupID. Must be
// called with b.mu held.
func (b *Backend) lifecycleResultLocked(cgroupID string) CommitResult {
	res := CommitResult{}
	agent, ok := b.agents[cgroupID]
	if !ok {
		// Absent after finalize+ack is the only benign "gone" case, but a
		// bare absence is NOT releasable here: callers use canReleaseLocked.
		res.State = Speculative
		res.CanRelease = false
		return res
	}
	res.State = agent.State
	res.CanRelease = agent.State == Finalized
	if agent.FinalizeErr != "" {
		res.Failures = append(res.Failures, PromoteFailure{
			Path: "", Op: "promote", Err: agent.FinalizeErr,
		})
	}
	return res
}

// GetLifecycle reports an agent's current lifecycle state and any pending
// promotion failure, without mutating anything. An unknown cgroup reports
// state "unknown" and CanRelease=false (fail-closed).
func (b *Backend) GetLifecycle(cgroupID string) (state string, canRelease bool, finalizeErr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	agent, ok := b.agents[cgroupID]
	if !ok {
		return "unknown", false, ""
	}
	return agent.State.String(), agent.State == Finalized, agent.FinalizeErr
}

// AckRelease is called by the orchestrator AFTER it has successfully released
// a Finalized agent's external effects (processes resumed, network un-fenced,
// stdout/tool output flushed). Only then is the terminal record cleaned up.
// Refuses to drop an agent that has not reached Finalized (fail-closed), so a
// premature ack can never discard state that is still needed for rollback.
func (b *Backend) AckRelease(cgroupID string) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	agent, ok := b.agents[cgroupID]
	if !ok {
		b.mu.Unlock()
		return nil // already cleaned up: idempotent
	}
	if agent.State != Finalized {
		state := agent.State
		b.mu.Unlock()
		return fmt.Errorf("ack_release: agent %q is %s, not finalized", cgroupID, state)
	}
	seqNum := b.nextSeq()
	rec := WALRecord{CgroupID: cgroupID, SeqNum: seqNum, ControlOp: "release_ack"}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return fmt.Errorf("ack_release WAL: %w", err)
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	b.ackReleaseInternal(cgroupID)
	return nil
}

// ackReleaseInternal drops a Finalized agent's terminal record. Must be called
// with b.mu held. Used by AckRelease and by replayWAL. Idempotent.
func (b *Backend) ackReleaseInternal(cgroupID string) {
	agent, ok := b.agents[cgroupID]
	if !ok {
		return
	}
	if agent.State != Finalized {
		// Only a finalized agent may be acked. On replay this guards against
		// a stale release_ack for an agent that (post-checkpoint) is not yet
		// finalized: leave it in place to be re-finalized.
		return
	}
	delete(b.agents, cgroupID)
	log.Printf("[backend] release_ack: dropped finalized agent=%q", cgroupID)
}

// publishBarrier fsyncs every orig parent directory accumulated by promotions
// since the last barrier, then clears the set. This is the crash-atomic
// group-publish durability point: it runs BEFORE any agent in the group is
// marked Finalized, so a commit group's renames are all durable together
// before its external effects can be released. Must be called with b.mu held.
func (b *Backend) publishBarrier() {
	for dir := range b.publishDirs {
		if err := fsyncDir(dir); err != nil && !os.IsNotExist(err) {
			log.Printf("[backend] publishBarrier fsync %q: %v", dir, err)
		}
		delete(b.publishDirs, dir)
	}
}

// tryPromoteAll iterates over every dirty path and promotes those whose
// writers are all authorized (with all-finalized upstreams). Promotion of
// one path may finalize an agent which in turn unblocks downstream agents,
// so the loop runs until no progress is made. Returns the joined error of any
// promotion failures encountered this pass (nil if all promotions succeeded);
// failed agents are left non-Finalized with FinalizeErr set for retry.
func (b *Backend) tryPromoteAll() error {
	for {
		var errs []error
		paths := make([]string, 0, len(b.fileDirty))
		for p := range b.fileDirty {
			paths = append(paths, p)
		}
		// Promote deeper paths first. After a path is promoted,
		// removeOverlayState() does RemoveAll on its overlay copy; if a
		// parent directory promoted first, that RemoveAll would wipe out
		// any descendant overlay files whose entries have not yet run,
		// causing OverlayWriteEntry.Promote to find the overlay missing
		// and silently no-op — losing the agent's data. Iterating from
		// the deepest path upwards guarantees descendants are renamed to
		// orig BEFORE any ancestor's cleanup runs.
		sort.Slice(paths, func(i, j int) bool {
			di := strings.Count(paths[i], string(os.PathSeparator))
			dj := strings.Count(paths[j], string(os.PathSeparator))
			if di != dj {
				return di > dj
			}
			return paths[i] > paths[j]
		})
		// SCC membership for this pass. Under the strong-semantics model,
		// promoting a member's files requires every upstream OUTSIDE its SCC to
		// be Finalized (the incoming group must finalize before we publish
		// downstream work); intra-SCC upstreams are resolved by the atomic SCC
		// finalize below. Crucially, NO agent is auto-authorized here: an epoch
		// must be explicitly committed (policy-approved) to advance, even if it
		// made no filesystem writes -- a pure-read epoch may still have
		// process / network / output effects that policy must gate.
		sccOf := b.sccMembership()
		progress := false
		for _, p := range paths {
			ran, err := b.tryPromotePath(p, sccOf)
			if ran {
				progress = true
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		// Finalize whole strongly-connected components at once so dependency
		// cycles (A -> B -> A) resolve together, and never before every
		// member's promotion has succeeded.
		if b.tryFinalizeSCCs() {
			progress = true
		}
		if !progress {
			// No forward progress this pass: return any promotion errors so
			// the caller keeps the workload fenced and schedules a retry.
			// errors.Join(nil...) is nil, so a clean settle returns nil.
			return errors.Join(errs...)
		}
	}
}

// tryPromotePath attempts to promote every entry that targets path. It
// requires that every writer of path is authorized AND that none of those
// writers has an un-finalized upstream dependency.
//
// All-or-nothing per path: if ANY entry's Promote() fails, NOTHING is torn
// down — the UndoLog entries, DirtyFiles, fileDirty tracking and overlay
// recovery data are ALL preserved, the involved writers are left in
// Finalizing with FinalizeErr set, and (false, err) is returned. Because
// every Promote() is idempotent, a later RetryFinalize re-runs the whole set
// and only tears down once they all succeed. Returns (true, nil) when the
// path was fully promoted, (false, nil) when it is not yet eligible.
func (b *Backend) tryPromotePath(path string, sccOf map[string]int) (bool, error) {
	writers, ok := b.fileDirty[path]
	if !ok || len(writers) == 0 {
		return false, nil
	}
	for w := range writers {
		agent, ok := b.agents[w]
		if !ok || !agent.approved() {
			return false, nil
		}
		for up := range b.dependsOn[w] {
			upAgent, ok := b.agents[up]
			if !ok {
				continue // upstream gone => finalized and acked
			}
			if upAgent.State == Finalized {
				continue
			}
			// Co-writers of THIS path share a single overlay copy and are
			// promoted together as a unit (one rename), so their mutual
			// dependency does not block the path's promotion: they all move to
			// Finalizing together here, and the rollback guard then protects
			// the torn window.
			if _, coWriter := writers[up]; coWriter {
				continue
			}
			// Strong semantics: an un-finalized upstream OUTSIDE this writer's
			// SCC blocks promotion. Its group must Finalize first, otherwise a
			// later reject of that upstream could cascade into files we have
			// already published to the real workspace -- which the undo log can
			// no longer restore. Intra-SCC upstreams do NOT block: the whole
			// cycle promotes and finalizes together (see tryFinalizeSCCs).
			if sccOf[up] == sccOf[w] {
				continue
			}
			return false, nil
		}
	}

	type writerEntry struct {
		writer string
		entry  LogEntry
		idx    int
	}
	var matched []writerEntry
	for w := range writers {
		agent := b.agents[w]
		for i, entry := range agent.UndoLog {
			if entry.Path() == path {
				matched = append(matched, writerEntry{writer: w, entry: entry, idx: i})
			}
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].entry.Seq() < matched[j].entry.Seq() })

	// Promotion has started for this path: move its (authorized) writers to
	// Finalizing so a normal rollback is refused from here on.
	for w := range writers {
		if a := b.agents[w]; a != nil && a.State == AuthorizedPending {
			a.State = Finalizing
		}
	}

	// Each Promote() implementation is idempotent against a missing
	// OverlayPath (returns nil), so an ancestor rmdir that already wiped a
	// descendant overlay is a no-op rather than an error.
	var promoteErr error
	for _, m := range matched {
		if err := m.entry.Promote(); err != nil {
			log.Printf("[backend] Promote: path=%q seq=%d failed: %v", path, m.entry.Seq(), err)
			promoteErr = err
			break
		}
	}
	if promoteErr != nil {
		// FAIL CLOSED: preserve ALL recovery state (UndoLog, DirtyFiles,
		// fileDirty, overlay copies) so the exact same promotion can be
		// retried. Record why on every writer of this path so get_lifecycle
		// can surface it. Do NOT removeOverlayState and do NOT drop entries.
		msg := fmt.Sprintf("promote %q: %v", path, promoteErr)
		for w := range writers {
			if a := b.agents[w]; a != nil {
				a.FinalizeErr = msg
			}
		}
		return false, fmt.Errorf("%s", msg)
	}

	// All entries for this path promoted: now it is safe to tear down.
	type rem struct {
		writer string
		idx    int
	}
	rems := make([]rem, 0, len(matched))
	for _, m := range matched {
		rems = append(rems, rem{writer: m.writer, idx: m.idx})
	}
	sort.Slice(rems, func(i, j int) bool { return rems[i].idx > rems[j].idx })
	for _, r := range rems {
		agent := b.agents[r.writer]
		if r.idx < len(agent.UndoLog) {
			agent.UndoLog = append(agent.UndoLog[:r.idx], agent.UndoLog[r.idx+1:]...)
		}
	}
	for w := range writers {
		if a := b.agents[w]; a != nil {
			delete(a.DirtyFiles, path)
			a.FinalizeErr = "" // this path is clean now
		}
	}
	delete(b.fileDirty, path)

	// Do NOT remove whiteout during promote: another agent may still have
	// an active UnlinkEntry for this path whose whiteout this is. The
	// UnlinkEntry.Promote() will clean up its own whiteout when it runs.
	_ = removeOverlayState(b.stagingDir, b.trackedDir, path, false)
	// Record this path's orig parent dir for the group publish barrier.
	b.publishDirs[filepath.Dir(path)] = struct{}{}
	log.Printf("[backend] Promote: path=%q promoted (%d entries)", path, len(matched))
	return true, nil
}

// tryFinalize transitions a SINGLE agent to Finalized when it is authorized,
// has no remaining undo entries, and all its upstream dependencies are
// finalized (a pure-read upstream does not block). Retained for the trivial
// acyclic case and direct callers; the promotion loop uses tryFinalizeSCCs so
// dependency CYCLES finalize as a unit. Returns true if it finalized.
func (b *Backend) tryFinalize(cgroupID string) bool {
	agent, ok := b.agents[cgroupID]
	if !ok || !agent.approved() {
		return false
	}
	if agent.State == Finalized {
		return false // already finalized
	}
	if len(agent.UndoLog) > 0 {
		return false
	}
	for up := range b.dependsOn[cgroupID] {
		upAgent, ok := b.agents[up]
		if ok && upAgent.State != Finalized {
			// Strong semantics: every incoming (upstream) group must be
			// Finalized before this agent can finalize.
			return false
		}
	}
	b.finalizeAgent(cgroupID)
	return true
}

// finalizeAgent performs the state mutation of finalizing one agent: drop its
// dependency edges (a finalized agent's changes are durable and can no longer
// cascade a rollback, so it must neither block nor be reached by the graph),
// then set State=Finalized. The agent record itself is RETAINED until
// AckRelease. Must be called with b.mu held; callers own the readiness checks.
func (b *Backend) finalizeAgent(cgroupID string) {
	agent, ok := b.agents[cgroupID]
	if !ok {
		return
	}
	log.Printf("[backend] finalize: agent=%q", cgroupID)
	for src := range b.dependsOn[cgroupID] {
		if dsts, ok := b.dependents[src]; ok {
			delete(dsts, cgroupID)
			if len(dsts) == 0 {
				delete(b.dependents, src)
			}
		}
	}
	delete(b.dependsOn, cgroupID)
	for s := range b.dependents[cgroupID] {
		if preds, ok := b.dependsOn[s]; ok {
			delete(preds, cgroupID)
			if len(preds) == 0 {
				delete(b.dependsOn, s)
			}
		}
	}
	delete(b.dependents, cgroupID)
	agent.State = Finalized
	agent.FinalizeErr = ""
}

// computeSCCs returns the strongly-connected components of the current
// dependency graph (edges: dependent -> upstream, from b.dependsOn) using
// Tarjan's algorithm. Every tracked agent appears in exactly one component;
// an acyclic agent is a singleton. SCCs are the unit of finalization so a
// dependency cycle (A -> B -> A) is finalized all-at-once or not at all. Must
// be called with b.mu held.
func (b *Backend) computeSCCs() [][]string {
	const unvisited = -1
	index := make(map[string]int, len(b.agents))
	lowlink := make(map[string]int, len(b.agents))
	onStack := make(map[string]bool, len(b.agents))
	var stack []string
	var sccs [][]string
	next := 0

	// Iterative Tarjan to avoid deep recursion on long dependency chains.
	type frame struct {
		node string
		succ []string
		i    int
	}
	successors := func(id string) []string {
		out := make([]string, 0, len(b.dependsOn[id]))
		for up := range b.dependsOn[id] {
			if _, ok := b.agents[up]; ok {
				out = append(out, up)
			}
		}
		return out
	}

	for id := range b.agents {
		if _, seen := index[id]; seen {
			continue
		}
		var callStack []*frame
		callStack = append(callStack, &frame{node: id, succ: successors(id)})
		index[id] = next
		lowlink[id] = next
		next++
		stack = append(stack, id)
		onStack[id] = true

		for len(callStack) > 0 {
			fr := callStack[len(callStack)-1]
			if fr.i < len(fr.succ) {
				w := fr.succ[fr.i]
				fr.i++
				if _, seen := index[w]; !seen {
					index[w] = next
					lowlink[w] = next
					next++
					stack = append(stack, w)
					onStack[w] = true
					callStack = append(callStack, &frame{node: w, succ: successors(w)})
				} else if onStack[w] {
					if index[w] < lowlink[fr.node] {
						lowlink[fr.node] = index[w]
					}
				}
				continue
			}
			// Done exploring fr.node; if it's a root, pop an SCC.
			if lowlink[fr.node] == index[fr.node] {
				var comp []string
				for {
					n := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[n] = false
					comp = append(comp, n)
					if n == fr.node {
						break
					}
				}
				sccs = append(sccs, comp)
			}
			callStack = callStack[:len(callStack)-1]
			if len(callStack) > 0 {
				parent := callStack[len(callStack)-1].node
				if lowlink[fr.node] < lowlink[parent] {
					lowlink[parent] = lowlink[fr.node]
				}
			}
		}
	}
	return sccs
}

// sccMembership maps each tracked agent to an integer identifying its
// strongly-connected component in the current dependency graph. Two agents
// share an id iff they are mutually reachable (a dependency cycle). Used by
// tryPromotePath to allow intra-SCC promotion while still requiring every
// upstream OUTSIDE the SCC to be Finalized. Must be called with b.mu held.
func (b *Backend) sccMembership() map[string]int {
	m := make(map[string]int, len(b.agents))
	for i, comp := range b.computeSCCs() {
		for _, id := range comp {
			m[id] = i
		}
	}
	return m
}

// tryFinalizeSCCs finalizes every strongly-connected component that is READY,
// treating each SCC as an atomic unit. An SCC becomes Finalized iff:
//
//	(1) every member's policy is approved, AND
//	(2) every member has no remaining undo entries (all its file promotions
//	    have succeeded — a failed/pending promotion leaves undo entries), AND
//	(3) every upstream OUTSIDE the SCC is already Finalized (a pure-read
//	    upstream with no undo/dirty state does not block).
//
// If any member fails (2), the WHOLE SCC stays fenced — this is what prevents a
// cycle A -> B -> A from being released early or waiting forever. Returns true
// if any SCC finalized. Must be called with b.mu held.
func (b *Backend) tryFinalizeSCCs() bool {
	progress := false
	for _, scc := range b.computeSCCs() {
		if b.finalizeSCCIfReady(scc) {
			progress = true
		}
	}
	return progress
}

func (b *Backend) finalizeSCCIfReady(scc []string) bool {
	inSCC := make(map[string]bool, len(scc))
	for _, id := range scc {
		inSCC[id] = true
	}
	// (1)+(2): every member approved, none already finalized, and no member
	// has pending/failed promotions (undo must be empty).
	anyPending := false
	for _, id := range scc {
		a := b.agents[id]
		if a == nil {
			return false
		}
		if a.State == Finalized {
			return false // component already finalized; nothing to do
		}
		if !a.approved() {
			return false
		}
		if len(a.UndoLog) > 0 {
			anyPending = true
		}
	}
	if anyPending {
		return false // a member's promotion is not done: keep the whole SCC fenced
	}
	// (3): every external upstream must be Finalized (pure-read exempt).
	for _, id := range scc {
		for up := range b.dependsOn[id] {
			if inSCC[up] {
				continue // intra-SCC edge: satisfied by finalizing together
			}
			upA, ok := b.agents[up]
			if !ok {
				continue // gone => finalized and acked
			}
			if upA.State != Finalized {
				// Strong semantics: the incoming group must be Finalized
				// before this group may finalize (and release its effects).
				return false
			}
		}
	}
	// Ready: finalize the whole component atomically. Publish barrier FIRST:
	// fsync every orig parent directory touched by promotions in this settle
	// so the group's on-disk state is durable as a unit before ANY member
	// becomes releasable.
	b.publishBarrier()
	if len(scc) > 1 {
		log.Printf("[backend] finalize SCC (cycle) as a unit: %v", scc)
	}
	for _, id := range scc {
		b.finalizeAgent(id)
	}
	return true
}

// --- Release gating ---

// CanRelease reports whether the external side effects of the given cgroup
// (its processes are held frozen by ShadowProc, its network fenced, its
// stdout/tool output buffered) are safe to externalize.
//
// It is TRUE only when the agent has reached the Finalized lifecycle state:
// every dirty path has been durably promoted to the real filesystem and every
// upstream dependency is itself Finalized, so no rollback can ever cascade
// into this cgroup. Any other state (Speculative, AuthorizedPending,
// Finalizing) is NOT releasable.
//
// FAIL CLOSED: an unknown / untracked cgroup is NOT releasable. Callers that
// legitimately have no filesystem footprint must be registered and driven to
// Finalized via Commit (which registers no-file-op agents), rather than
// relying on "absent means safe".
func (b *Backend) CanRelease(cgroupID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.canReleaseLocked(cgroupID)
}

// canReleaseLocked implements CanRelease. Must be called with b.mu held.
func (b *Backend) canReleaseLocked(cgroupID string) bool {
	agent, ok := b.agents[cgroupID]
	if !ok {
		return false // fail closed: unknown cgroup is never releasable
	}
	return agent.State == Finalized
}

// --- Inspection ---

// Len returns the total number of log entries across all agents.
func (b *Backend) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	total := 0
	for _, a := range b.agents {
		total += len(a.UndoLog)
	}
	return total
}

// AgentLen returns the number of log entries for a specific agent.
func (b *Backend) AgentLen(cgroupID string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	a, ok := b.agents[cgroupID]
	if !ok {
		return 0
	}
	return len(a.UndoLog)
}

// DependsOn reports whether rolling back `on` would cascade to `dependent`.
func (b *Backend) DependsOn(dependent, on string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.reachableFrom(on)[dependent]
	return ok
}

// --- Helpers ---

// copyUpDir recursively copies the directory tree rooted at src into dst.
// Symlinks are recreated; regular files are copied; directories preserve
// their mode.
func copyUpDir(src, dst string) error {
	stat, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return fmt.Errorf("copyUpDir: %q is not a directory", src)
	}
	if err := os.MkdirAll(dst, stat.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		info, err := e.Info()
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := copyUpDir(s, d); err != nil {
				return err
			}
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(s)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, d); err != nil {
				return err
			}
		default:
			if err := copyUpFileOrEmpty(s, d); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyUpFileOrEmpty(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	stat, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, stat.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return fmt.Errorf("fsync overlay %q: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return err
	}
	// Preserve ownership (best-effort: EPERM is non-fatal for non-root).
	if lstat, err := os.Lstat(src); err == nil {
		if sys, ok := lstat.Sys().(*syscall.Stat_t); ok {
			if err := syscall.Lchown(dst, int(sys.Uid), int(sys.Gid)); err != nil && err != syscall.EPERM {
				return fmt.Errorf("lchown overlay %q: %w", dst, err)
			}
		}
	}
	return nil
}
