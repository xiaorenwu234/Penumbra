package backend

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// AgentLifecycle is the explicit finalization state of an epoch. External
// side effects (fs promotion, ShadowProc release, network un-fencing,
// stdout/tool output) may ONLY be released once the epoch reaches Finalized.
type AgentLifecycle int32

const (
	// Speculative: running/observed, policy not yet approved. Nothing may
	// escape the sandbox.
	Speculative AgentLifecycle = iota
	// AuthorizedPending: policy approved, but promotions and/or upstream
	// dependencies are not all finalized yet. STILL fully fenced.
	AuthorizedPending
	// Finalizing: promotion has started for this epoch. Only completion or
	// retry is allowed from here; a normal rollback must NOT run.
	Finalizing
	// Finalized: every promotion succeeded and every upstream is Finalized.
	// This is the ONLY state in which CanRelease returns true. The epoch is
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

// WAL tuning parameters.
const (
	checkpointInterval     = 5 * time.Second // full snapshot interval
	checkpointWALThreshold = 1000            // force checkpoint when WAL exceeds this
)

// debugLog controls per-object debug logging. When false (default), only
// epoch-level summary statistics are logged. Set via SetDebugLog.
var debugLog atomic.Bool

// EpochStats accumulates per-epoch operation counters for summary logging.
type EpochStats struct {
	Versions    int64 // total versions created
	Creates     int64 // file creates (OpWrite without RenameFrom)
	Renames     int64 // rename operations
	Whiteouts   int64 // unlink/rmdir operations
	Mkdirs      int64 // directory creates
	WALFlushes  int64 // WAL flush calls
	FileFsyncs  int64 // file fsync calls
	DirFsyncs   int64 // directory fsync calls
	PromoteTime time.Duration
}

// walPending is one submission unit handed off to the WAL worker. A single
// submission may carry multiple records that should be fsync'd atomically
// (e.g. a rename produces two version records). The worker writes accumulated
// pending units in a single appendWAL+fsync and acks every waiter with the
// shared error result.
type walPending struct {
	recs []WALRecord
	done chan error
}

// finalizeGroup tracks a group of epochs (an SCC) between BeginFinalize and
// AckReleaseGroup, so the orchestrator can drive the whole group atomically.
type finalizeGroup struct {
	id          int
	members     []EpochID
	graphGen    int64
	state       string // "pending", "finalized", "failed"
	finalizeErr string
}

// Backend tracks per-epoch MVCC file versions and supports rollback with
// contamination detection via a directed dependency graph whose nodes are
// EPOCHS (not cgroups). See version.go for the data model.
//
// Concurrency model (group-commit WAL, unchanged from the pre-MVCC design):
//
//   - opRW: every mutating operation acquires opRW.RLock() for its full
//     duration. Checkpoint takes opRW.Lock() to wait until all in-flight
//     operations have completed AND all their WAL records have been
//     fsync'd, guaranteeing snapshot consistency.
//   - mu: protects in-memory state (epochs, version graph, dependency
//     graph, seq counter, walCount, walPending, applyCond state).
//   - WAL fsync runs in a dedicated walWorker goroutine (group commit).
//   - applyCond enforces seq-order on the post-fsync apply phase so that
//     the version graph observes the same ordering as the WAL on disk.
type Backend struct {
	stagingDir string
	trackedDir string

	// MVCC state (protected by mu).
	epochs              map[EpochID]*EpochState
	activeEpochByCgroup map[string]EpochID
	versionsByObject    map[ObjectID][]VersionID // seq-ascending version chain
	versionByID         map[VersionID]*FileVersion
	visibleHead         map[ObjectID]VersionID
	dependents          map[EpochID]map[EpochID]struct{}
	dependsOn           map[EpochID]map[EpochID]struct{}
	nextVersion         uint64 // next VersionID to allocate
	implicitCtr         int64  // uniquifier for successor implicit epochs

	// publishDirs accumulates the orig parent directories of objects promoted
	// during the current settle. They are fsync'd as ONE group barrier before
	// any epoch in the group is marked Finalized, so the whole commit group's
	// externally-visible publish is crash-atomic. Protected by mu.
	publishDirs map[string]struct{}
	seq         int64
	mu          sync.Mutex
	persistPath string
	walPath     string

	// opRW gates concurrent mutating operations against checkpoint.
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
	abortedSeq map[int64]bool // seqs that failed before apply (protected by mu)

	// Signalling
	chkptTrigger chan struct{} // poked when WAL exceeds checkpointWALThreshold
	stopCh       chan struct{}
	chkptDone    chan struct{} // closed when checkpointLoop exits
	closeOnce    sync.Once

	// Open FD tracking: epochID → list of tracked fds. When a cascade
	// rollback cleans up an epoch, all its tracked fds are force-closed so
	// the process gets EBADF on the next I/O instead of silently reading a
	// stale (now rolled-back) version.
	openFDs   map[EpochID][]*TrackedFD
	openFDsMu sync.Mutex

	// invalidateFn, when set, is invoked after a rollback with the list of
	// tracked (orig) logical paths whose speculative versions were removed,
	// so the FUSE layer can drop stale kernel dentry cache entries. Set once
	// at startup; read without locking.
	invalidateFn func(paths []string)

	// mountDir is the FUSE mountpoint (set once at startup via SetMountDir).
	// Commit-time mmap quiescence matches an epoch's /proc/<pid>/maps entries
	// (which show the mount path) to its stage copies. Empty disables it.
	mountDir string

	// Group-level finalization state (Phase 3).
	// graphGen increments on every dependency-graph mutation (epoch add,
	// edge add, epoch cleanup, ack-release) so prepare_resolution ->
	// begin_finalize can detect TOCTOU changes.
	graphGen     int64
	activeGroups map[int]*finalizeGroup
	nextGroupID  int

	// Epoch-local WAL buffer for batched persistence (Optimization 1).
	// Records are buffered per-epoch and flushed with a single fsync when
	// FlushEpochWAL is called (before results are released to the agent).
	epochWALBuf   map[EpochID][]WALRecord
	epochWALMu    sync.Mutex
	walFileExists bool // tracks if WAL file has been created
	walDirSynced  bool // tracks if WAL parent dir has been fsync'd (Fix 3)

	// Per-epoch statistics for summary logging (Optimization 5).
	epochStats   map[EpochID]*EpochStats
	epochStatsMu sync.Mutex
}

// SetMountDir records the FUSE mountpoint so commit-time writable-MAP_SHARED
// quiescence can translate a process's /proc/<pid>/maps paths to stage copies.
// Set once at startup, before serving.
func (b *Backend) SetMountDir(dir string) {
	if dir != "" {
		b.mountDir = filepath.Clean(dir)
	}
}

// SetInvalidateCallback registers a function invoked after a rollback with the
// tracked logical paths whose versions were removed, so the FUSE layer can
// invalidate stale kernel dentry cache entries. Must be set before serving.
func (b *Backend) SetInvalidateCallback(fn func(paths []string)) {
	b.invalidateFn = fn
}

// NewBackend creates a Backend. stagingDir is the version-store root (write
// side) and also holds the persisted state under metadata/. trackedDir is the
// original filesystem root being shadowed.
//
// FAIL CLOSED on legacy state: a v1 checkpoint/WAL (pre-MVCC) or an
// unreadable v2 snapshot aborts startup instead of silently starting fresh.
func NewBackend(stagingDir, trackedDir string) (*Backend, error) {
	if err := detectLegacyState(stagingDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(metadataDir(stagingDir), 0o755); err != nil {
		return nil, fmt.Errorf("create staging metadata dir: %w", err)
	}
	b := &Backend{
		stagingDir:          stagingDir,
		trackedDir:          filepath.Clean(trackedDir),
		epochs:              make(map[EpochID]*EpochState),
		activeEpochByCgroup: make(map[string]EpochID),
		versionsByObject:    make(map[ObjectID][]VersionID),
		versionByID:         make(map[VersionID]*FileVersion),
		visibleHead:         make(map[ObjectID]VersionID),
		dependents:          make(map[EpochID]map[EpochID]struct{}),
		dependsOn:           make(map[EpochID]map[EpochID]struct{}),
		nextVersion:         1,
		publishDirs:         make(map[string]struct{}),
		persistPath:         persistFilePath(stagingDir),
		walPath:             walFilePath(stagingDir),
		walNotify:           make(chan struct{}, 1),
		walStop:             make(chan struct{}),
		walDone:             make(chan struct{}),
		abortedSeq:          make(map[int64]bool),
		openFDs:             make(map[EpochID][]*TrackedFD),
		chkptTrigger:        make(chan struct{}, 1),
		stopCh:              make(chan struct{}),
		chkptDone:           make(chan struct{}),
		activeGroups:        make(map[int]*finalizeGroup),
		epochWALBuf:         make(map[EpochID][]WALRecord),
		epochStats:          make(map[EpochID]*EpochStats),
	}
	b.applyCond = sync.NewCond(&b.mu)

	// Check if WAL file already exists. If so, both the file and its
	// directory entry are already durable from a previous run.
	if _, err := os.Stat(b.walPath); err == nil {
		b.walFileExists = true
		b.walDirSynced = true
	}

	// --- Crash recovery (fail closed on unreadable state) ---
	if _, err := os.Stat(b.persistPath); err == nil {
		state, loadErr := loadFromDisk(b.persistPath)
		if loadErr != nil {
			return nil, fmt.Errorf("load persisted state: %w", loadErr)
		}
		if err := b.loadState(state); err != nil {
			return nil, err
		}
	}
	// Replay WAL records written after the last checkpoint.
	records, err := loadWAL(b.walPath)
	if err != nil {
		return nil, fmt.Errorf("load WAL: %w", err)
	}
	if len(records) > 0 {
		if err := b.replayWAL(records); err != nil {
			return nil, fmt.Errorf("replay WAL: %w", err)
		}
	}
	// NOTE: epochs are NOT auto-authorized on recovery. An epoch is
	// authorized only if a durable "commit" WAL record was replayed above.
	// Re-derive Finalized states after recovery: every promoteVersion is
	// idempotent, so this is safe to run and reconstructs the durable
	// finalized set from the authorized epochs. A crash mid-promotion
	// recovers as AuthorizedPending/Finalizing (fenced, retryable) — pending
	// is never mistaken for finalized.
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
// checkpoint already loaded into memory) are skipped. For mutation records
// the on-disk stage state is also REDONE via materializeVersionLocked (run
// BEFORE the version is inserted into the chain, exactly like live apply, so
// the copy-up source resolution is identical).
func (b *Backend) replayWAL(records []WALRecord) error {
	snapshotSeq := b.seq
	applied := 0
	for i := range records {
		rec := &records[i]
		recSeq := rec.SeqNum
		if recSeq != 0 && recSeq <= snapshotSeq {
			continue // already in snapshot
		}
		if rec.ControlOp != "" {
			switch rec.ControlOp {
			case "begin_epoch":
				b.beginEpochInternal(EpochID(rec.EpochID), rec.CgroupID, rec.SessionID)
			case "commit":
				// Authorize only; the trailing tryPromoteAll in NewBackend
				// drives promotion/finalization once ALL records are in. Two
				// different non-empty hashes for one epoch indicate a rejected
				// concurrent authorization reached the WAL and must fail closed.
				ep := b.ensureEpoch(EpochID(rec.EpochID), rec.CgroupID)
				if rec.PolicyHash != "" {
					if ep.PolicyHash != "" && ep.PolicyHash != rec.PolicyHash {
						return fmt.Errorf("WAL policy_hash conflict for epoch %q: %q vs %q",
							rec.EpochID, ep.PolicyHash, rec.PolicyHash)
					}
					ep.PolicyHash = rec.PolicyHash
				}
				if ep.State < AuthorizedPending {
					ep.State = AuthorizedPending
				}
			case "rollback":
				_ = b.rollbackInternal(EpochID(rec.EpochID))
			case "read_dep":
				b.readDepInternal(EpochID(rec.EpochID), VersionID(rec.ReadVersion))
			case "release_ack":
				b.ackReleaseInternal(EpochID(rec.EpochID))
			case "group_prepare":
				members := make([]EpochID, 0, len(rec.Members))
				for _, m := range rec.Members {
					members = append(members, EpochID(m))
				}
				if rec.GroupID > 0 {
					b.activeGroups[rec.GroupID] = &finalizeGroup{
						id:       rec.GroupID,
						members:  members,
						graphGen: rec.GraphGeneration,
						state:    "pending",
					}
					if rec.GroupID > b.nextGroupID {
						b.nextGroupID = rec.GroupID
					}
				}
			case "group_delete":
				delete(b.activeGroups, rec.GroupID)
			default:
				log.Printf("[backend] WAL: unknown control op %q", rec.ControlOp)
			}
			if recSeq > b.seq {
				b.seq = recSeq
			}
			applied++
			continue
		}
		if rec.Version == nil {
			continue
		}
		v := unmarshalVersion(rec.Version)
		if uint64(v.ID) >= b.nextVersion {
			b.nextVersion = uint64(v.ID) + 1
		}
		if _, dup := b.versionByID[v.ID]; dup {
			continue // already folded into the snapshot
		}
		// REDO the stage-side mutation idempotently BEFORE inserting, so the
		// copy-up base resolves against the pre-insert chain (same as live).
		if err := b.materializeVersionLocked(v); err != nil {
			log.Printf("[backend] WAL redo version %d (%s %q): %v", v.ID, v.Operation, v.LogicalPath, err)
		}
		b.insertVersionLocked(v)
		if v.Seq > b.seq {
			b.seq = v.Seq
		}
		applied++
	}
	log.Printf("[backend] WAL replayed: %d/%d records (filtered by snapshot seq=%d)", applied, len(records), snapshotSeq)
	return nil
}

// --- Group-commit WAL (write-ahead with batched fsync) ---
//
// Every mutating method follows this protocol:
//
//  1. opRW.RLock() for the full operation (gates against checkpoint).
//  2. mu.Lock(); allocate seq, build the WAL record(s); mu.Unlock().
//  3. submitWAL(rec) hands the record(s) to walWorker and returns a
//     waiter channel. Block on the waiter — when it fires, the record
//     is fsync'd to disk (group commit).
//  4. applyTurnWait(seq) blocks under mu until our seq is the next one
//     allowed to apply. Then idempotently apply the stage mutation and
//     update the version graph. Finally applyTurnDone(seq); release mu.
//  5. opRW.RUnlock().

// submitWAL hands one or more records to walWorker for batched fsync and
// returns a channel that fires (with the shared fsync result) once the
// records are durable.
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
// behalf of all submitWAL callers.
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
	// Optimization 1+4: write WAL without fsync (deferred to FlushEpochWAL).
	// Fix 3: skipDirSync only if dir was ALREADY synced (not just file created).
	skipDirSync := b.walDirSynced
	err := appendWALEx(b.walPath, allRecs, skipDirSync, true) // true = skipFileSync
	if err == nil {
		// Mark WAL file as existing after first successful append.
		// Note: walDirSynced is NOT set here — it's set by FlushEpochWAL
		// after the actual dir fsync (Fix 3).
		b.walFileExists = true
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
// Synchronisation: opRW.Lock() waits until every in-flight op has reached
// opRW.RUnlock(). At that point the in-memory state and the on-disk WAL are
// consistent. flushPending() before taking the writer lock makes sure
// pending waiters are unblocked so they can complete and release their
// RLock.
func (b *Backend) checkpoint() {
	b.flushPending()

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

// StagingDir returns the staging directory passed to NewBackend.
func (b *Backend) StagingDir() string { return b.stagingDir }

// SetDebugLog enables or disables per-object debug logging. When disabled
// (default), only epoch-level summary statistics are logged.
func SetDebugLog(enabled bool) { debugLog.Store(enabled) }

// --- Epoch-local WAL buffer (Optimization 1: batched persistence) ---

// bufferWALRecord adds a WAL record to the epoch's local buffer instead of
// immediately submitting for fsync. The record will be persisted when
// FlushEpochWAL is called.
func (b *Backend) bufferWALRecord(epochID EpochID, rec WALRecord) {
	b.epochWALMu.Lock()
	b.epochWALBuf[epochID] = append(b.epochWALBuf[epochID], rec)
	b.epochWALMu.Unlock()
}

// FlushEpochWAL fsyncs the WAL file to ensure all previously written
// (but not yet synced) records are durable. This is the WAL barrier that
// must succeed before the epoch's results are released to the agent.
//
// Recovery rule: if the system crashes before this barrier, the epoch is
// treated as incomplete and its orphan staging files are cleaned up.
func (b *Backend) FlushEpochWAL(epochID EpochID) error {
	// Fsync the WAL file to make all buffered writes durable.
	f, err := os.OpenFile(b.walPath, os.O_WRONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no WAL file yet, nothing to sync
		}
		return fmt.Errorf("flush epoch WAL %q: open: %w", epochID, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("flush epoch WAL %q: fsync: %w", epochID, err)
	}
	f.Close()

	// Fix 3: fsync parent dir if it hasn't been synced yet (first creation).
	// walDirSynced is separate from walFileExists: the file can exist
	// (written without fsync) while the dir entry is not yet durable.
	if !b.walDirSynced {
		if err := fsyncDir(filepath.Dir(b.walPath)); err != nil {
			return fmt.Errorf("flush epoch WAL %q: dir fsync: %w", epochID, err)
		}
		b.walDirSynced = true
	}

	// Update epoch stats.
	b.epochStatsMu.Lock()
	if stats := b.epochStats[epochID]; stats != nil {
		stats.WALFlushes++
	}
	b.epochStatsMu.Unlock()

	if debugLog.Load() {
		log.Printf("[backend] FlushEpochWAL: epoch=%q WAL fsync complete", epochID)
	}
	return nil
}

// --- Epoch statistics (Optimization 5: summary logging) ---

// getEpochStats returns or creates the stats accumulator for an epoch.
func (b *Backend) getEpochStats(epochID EpochID) *EpochStats {
	b.epochStatsMu.Lock()
	defer b.epochStatsMu.Unlock()
	stats := b.epochStats[epochID]
	if stats == nil {
		stats = &EpochStats{}
		b.epochStats[epochID] = stats
	}
	return stats
}

// LogEpochSummary logs the accumulated statistics for an epoch and clears
// the accumulator. Called at epoch finalization or release.
func (b *Backend) LogEpochSummary(epochID EpochID) {
	b.epochStatsMu.Lock()
	stats := b.epochStats[epochID]
	delete(b.epochStats, epochID)
	b.epochStatsMu.Unlock()

	if stats == nil || stats.Versions == 0 {
		return
	}
	log.Printf("[backend] epoch=%q summary: versions=%d creates=%d renames=%d whiteouts=%d mkdirs=%d wal_flushes=%d file_fsyncs=%d dir_fsyncs=%d promote_time=%v",
		epochID, stats.Versions, stats.Creates, stats.Renames, stats.Whiteouts,
		stats.Mkdirs, stats.WALFlushes, stats.FileFsyncs, stats.DirFsyncs, stats.PromoteTime)
}

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

// RegisterFD associates a tracked fd with an epoch. The fd will be
// force-closed if the epoch is cleaned up by a cascade rollback.
func (b *Backend) RegisterFD(epochID EpochID, tfd *TrackedFD) {
	b.openFDsMu.Lock()
	b.openFDs[epochID] = append(b.openFDs[epochID], tfd)
	b.openFDsMu.Unlock()
}

// UnregisterFD removes a tracked fd from an epoch. Called when the FUSE
// Release handler fires. Safe to call even if the fd was already removed by
// CloseEpochFDs.
func (b *Backend) UnregisterFD(epochID EpochID, tfd *TrackedFD) {
	b.openFDsMu.Lock()
	fds := b.openFDs[epochID]
	for i, f := range fds {
		if f == tfd {
			b.openFDs[epochID] = append(fds[:i], fds[i+1:]...)
			break
		}
	}
	if len(b.openFDs[epochID]) == 0 {
		delete(b.openFDs, epochID)
	}
	b.openFDsMu.Unlock()
}

// CloseEpochFDs force-closes every tracked fd belonging to the given epoch.
// Called during cascade rollback so processes receive EBADF on their next
// I/O rather than silently accessing a rolled-back version through a
// dangling fd.
func (b *Backend) CloseEpochFDs(epochID EpochID) {
	b.openFDsMu.Lock()
	fds := b.openFDs[epochID]
	delete(b.openFDs, epochID)
	b.openFDsMu.Unlock()
	for _, tfd := range fds {
		if err := tfd.Close(); err != nil {
			log.Printf("[backend] CloseEpochFDs: epoch=%q fd=%d: %v", epochID, tfd.FD(), err)
		}
	}
	if len(fds) > 0 {
		log.Printf("[backend] CloseEpochFDs: epoch=%q closed %d fd(s)", epochID, len(fds))
	}
}

// flushEpochFDs fsyncs every tracked fd of the epoch so that any data the
// kernel has written back through the FUSE data path — including dirty pages
// of a writable MAP_SHARED mmap the process already msync'd — is durable on
// the stage copy BEFORE promotion moves it onto orig. Any fsync failure aborts
// finalization fail-closed.
func (b *Backend) flushEpochFDs(epochID EpochID) error {
	b.openFDsMu.Lock()
	fds := make([]*TrackedFD, len(b.openFDs[epochID]))
	copy(fds, b.openFDs[epochID])
	b.openFDsMu.Unlock()
	var errs []string
	for _, tfd := range fds {
		if tfd.IsClosed() {
			continue
		}
		if err := syscall.Fsync(tfd.FD()); err != nil {
			msg := fmt.Sprintf("fd=%d: %v", tfd.FD(), err)
			log.Printf("[backend] flushEpochFDs: epoch=%q %s", epochID, msg)
			errs = append(errs, msg)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("fsync tracked fd(s): %s", strings.Join(errs, "; "))
	}
	return nil
}

// --- Commit-time writable MAP_SHARED quiescence ---

// mapRegion is one writable MAP_SHARED region of a frozen process that is
// backed by a file under the ShadowFS mount.
type mapRegion struct {
	start, end, offset uint64
	mountPath          string
}

// parseWritableSharedMaps extracts every writable MAP_SHARED region whose
// backing file lives under mountDir from a /proc/<pid>/maps blob.
func parseWritableSharedMaps(maps, mountDir string) []mapRegion {
	var out []mapRegion
	root := strings.TrimSuffix(mountDir, "/")
	prefix := root + "/"
	for _, line := range strings.Split(maps, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue // no pathname -> anonymous shared mapping, skip
		}
		perms := fields[1]
		if len(perms) < 4 || perms[1] != 'w' || perms[3] != 's' {
			continue
		}
		path := strings.Join(fields[5:], " ")
		if path != root && !strings.HasPrefix(path, prefix) {
			continue
		}
		dash := strings.IndexByte(fields[0], '-')
		if dash < 0 {
			continue
		}
		start, err1 := strconv.ParseUint(fields[0][:dash], 16, 64)
		end, err2 := strconv.ParseUint(fields[0][dash+1:], 16, 64)
		off, err3 := strconv.ParseUint(fields[2], 16, 64)
		if err1 != nil || err2 != nil || err3 != nil || end <= start {
			continue
		}
		out = append(out, mapRegion{start: start, end: end, offset: off, mountPath: path})
	}
	return out
}

// cgroupPIDs reads the member PIDs of a cgroup from its cgroup.procs file.
func cgroupPIDs(cgroupID string) ([]int, error) {
	p := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(cgroupID, "/"), "cgroup.procs")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, tok := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(tok); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// quiesceMappings captures the current contents of every FROZEN process's
// writable MAP_SHARED mappings of ShadowFS-backed files into the acting
// epoch's stage copies, so promotion carries the latest in-memory writes even
// for dirty mmap pages the (frozen) process never got to write back.
//
// FAIL CLOSED: if ANY writable MAP_SHARED region of a ShadowFS-backed file is
// found but cannot be fully captured, an error is returned and the caller
// MUST abort finalization. Vacuous success (no such mappings, or the
// cgroup/processes are already gone, e.g. during WAL replay) returns nil.
// Must be called with b.mu held.
func (b *Backend) quiesceMappings(ep *EpochState) error {
	if b.mountDir == "" || ep.CgroupID == "" {
		return nil // mountpoint or attribution unknown -> nothing to match
	}
	pids, err := cgroupPIDs(ep.CgroupID)
	if err != nil {
		return fmt.Errorf("read cgroup processes for %q: %w", ep.CgroupID, err)
	}
	flushed := 0
	var errs []string
	for _, pid := range pids {
		maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
		if err != nil {
			if os.IsNotExist(err) {
				continue // process exited between listing and read
			}
			errs = append(errs, fmt.Sprintf("pid %d: read /proc/maps: %v", pid, err))
			continue
		}
		regions := parseWritableSharedMaps(string(maps), b.mountDir)
		if len(regions) == 0 {
			continue
		}
		mem, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_RDONLY, 0)
		if err != nil {
			errs = append(errs, fmt.Sprintf("pid %d: open /proc/mem: %v", pid, err))
			continue
		}
		for _, r := range regions {
			if err := b.quiesceRegion(ep, mem, r); err != nil {
				errs = append(errs, fmt.Sprintf("pid %d %q: %v", pid, r.mountPath, err))
			} else {
				flushed++
			}
		}
		mem.Close()
	}
	if flushed > 0 {
		log.Printf("[backend] quiesceMappings: epoch=%q flushed %d writable MAP_SHARED region(s)",
			ep.ID, flushed)
	}
	if len(errs) > 0 {
		return fmt.Errorf("quiesce failed for %d writable MAP_SHARED region(s): %s",
			len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// quiesceRegion copies one region's bytes from the frozen process's memory
// into the epoch's own stage copy at the mapped file offset. Returns nil only
// on a COMPLETE capture + fsync. Must be called with b.mu held.
func (b *Backend) quiesceRegion(ep *EpochState, mem *os.File, r mapRegion) error {
	root := strings.TrimSuffix(b.mountDir, "/")
	rel := strings.TrimPrefix(r.mountPath, root)
	origPath := filepath.Join(b.trackedDir, rel)
	// A writable shared mapping of a tracked file requires the epoch to own
	// a content-bearing version of it (the O_RDWR open that backs the
	// mapping went through PrepareWrite). Fail closed otherwise: promoting
	// would publish a file that silently misses the dirty mmap pages.
	v := b.latestOwnVersionLocked(ep.ID, filepath.Clean(origPath))
	if v == nil || v.Operation == OpWhiteout || v.StagePath == "" {
		return fmt.Errorf("no owned stage copy for mapped file (dirty mmap pages would be lost)")
	}
	if st, serr := os.Lstat(v.StagePath); serr != nil || st.IsDir() {
		return fmt.Errorf("no stage copy for mapped file (dirty mmap pages would be lost)")
	}
	out, err := os.OpenFile(v.StagePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open stage copy: %w", err)
	}
	defer out.Close()
	const chunk = 1 << 20 // 1 MiB
	buf := make([]byte, chunk)
	total := r.end - r.start
	for done := uint64(0); done < total; {
		n := chunk
		if remaining := total - done; remaining < uint64(n) {
			n = int(remaining)
		}
		rn, rerr := mem.ReadAt(buf[:n], int64(r.start+done))
		if rn > 0 {
			if _, werr := out.WriteAt(buf[:rn], int64(r.offset+done)); werr != nil {
				return fmt.Errorf("write stage copy at %#x: %w", r.offset+done, werr)
			}
			done += uint64(rn)
		}
		if rerr != nil {
			if done >= total {
				break // final chunk returned data + EOF together
			}
			return fmt.Errorf("read process memory at %#x: %w", r.start+done, rerr)
		}
		if rn == 0 {
			return fmt.Errorf("short read of process memory at %#x", r.start+done)
		}
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync stage copy: %w", err)
	}
	return nil
}

// --- Dependency graph (epoch -> epoch) ---

func (b *Backend) addDependency(on, dependent EpochID) {
	if on == dependent {
		return
	}
	set, ok := b.dependents[on]
	if !ok {
		set = make(map[EpochID]struct{})
		b.dependents[on] = set
	}
	if _, exists := set[dependent]; !exists {
		set[dependent] = struct{}{}
		b.graphGen++
		log.Printf("[backend] addDependency: %q depends on %q", dependent, on)
	}
	rev, ok := b.dependsOn[dependent]
	if !ok {
		rev = make(map[EpochID]struct{})
		b.dependsOn[dependent] = rev
	}
	rev[on] = struct{}{}
}

func (b *Backend) reachableFrom(start EpochID) map[EpochID]struct{} {
	visited := make(map[EpochID]struct{})
	var dfs func(EpochID)
	dfs = func(id EpochID) {
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

// --- Epoch management ---

// ensureEpoch returns the epoch record, creating a Speculative one when
// missing. cgroupID (if non-empty) refreshes kernel attribution. Must be
// called with b.mu held.
func (b *Backend) ensureEpoch(id EpochID, cgroupID string) *EpochState {
	ep, ok := b.epochs[id]
	if !ok {
		ep = &EpochState{ID: id, ReadFrom: make(map[VersionID]struct{})}
		b.epochs[id] = ep
	}
	if cgroupID != "" && ep.CgroupID == "" {
		ep.CgroupID = cgroupID
	}
	return ep
}

// BeginEpoch registers an explicit epoch and binds it as the active epoch of
// cgroupID, so subsequent FUSE operations from that cgroup are attributed to
// it. Durable (WAL) so the binding survives a crash.
func (b *Backend) BeginEpoch(epochID EpochID, cgroupID, sessionID string) error {
	if epochID == "" {
		return fmt.Errorf("begin_epoch: empty epoch id")
	}
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	if ep, ok := b.epochs[epochID]; ok && ep.State >= Finalizing {
		st := ep.State
		b.mu.Unlock()
		return fmt.Errorf("begin_epoch: epoch %q already %s", epochID, st)
	}
	seqNum := b.nextSeq()
	rec := WALRecord{EpochID: string(epochID), CgroupID: cgroupID,
		SessionID: sessionID, SeqNum: seqNum, ControlOp: "begin_epoch"}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return fmt.Errorf("begin_epoch WAL: %w", err)
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	b.beginEpochInternal(epochID, cgroupID, sessionID)
	return nil
}

// beginEpochInternal performs the in-memory effect of BeginEpoch. Must be
// called with b.mu held. Used both by BeginEpoch and by replayWAL.
func (b *Backend) beginEpochInternal(epochID EpochID, cgroupID, sessionID string) {
	ep := b.ensureEpoch(epochID, cgroupID)
	if sessionID != "" {
		ep.SessionID = sessionID
	}
	if cgroupID != "" {
		ep.CgroupID = cgroupID
		b.activeEpochByCgroup[cgroupID] = epochID
	}
	b.graphGen++
	log.Printf("[backend] BeginEpoch: epoch=%q cgroup=%q session=%q", epochID, cgroupID, sessionID)
}

// EpochForCgroup returns the explicitly active epoch that FUSE operations from
// cgroupID should be attributed to. Production paths fail closed when no active
// epoch exists or the epoch has already entered Finalizing/Finalized; creating
// implicit epochs after release would produce speculative state with no
// orchestrator/policy owner.
func (b *Backend) EpochForCgroup(cgroupID string) (EpochID, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if id, ok := b.activeEpochByCgroup[cgroupID]; ok {
		if ep, live := b.epochs[id]; live && ep.State < Finalizing {
			return id, nil
		}
		return "", fmt.Errorf("no writable active epoch for cgroup %q (epoch %q is closed or missing)", cgroupID, id)
	}
	return "", fmt.Errorf("no explicit active epoch for cgroup %q", cgroupID)
}

// ActiveEpochForCgroup reports the currently-bound epoch of a cgroup without
// creating one.
func (b *Backend) ActiveEpochForCgroup(cgroupID string) (EpochID, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id, ok := b.activeEpochByCgroup[cgroupID]
	return id, ok
}

// EpochCgroup returns the kernel attribution of an epoch ("" if unknown).
func (b *Backend) EpochCgroup(epochID EpochID) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ep, ok := b.epochs[epochID]; ok {
		return ep.CgroupID
	}
	return ""
}

// EpochInfo is a read-only epoch summary for the control API.
type EpochInfo struct {
	ID         string `json:"epoch_id"`
	CgroupID   string `json:"cgroup_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	State      string `json:"state"`
	Versions   int    `json:"versions"`
	PolicyHash string `json:"policy_hash,omitempty"`
}

// ListEpochs returns a summary of every tracked epoch.
func (b *Backend) ListEpochs() []EpochInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]EpochInfo, 0, len(b.epochs))
	for _, ep := range b.epochs {
		out = append(out, EpochInfo{
			ID:         string(ep.ID),
			CgroupID:   ep.CgroupID,
			SessionID:  ep.SessionID,
			State:      ep.State.String(),
			Versions:   len(ep.Versions),
			PolicyHash: ep.PolicyHash,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (b *Backend) nextSeq() int64 { b.seq++; return b.seq }

// --- Version chain internals (b.mu held) ---

// sortChainBySeq sorts a slice of version IDs by their versions' seq.
func (b *Backend) sortChainBySeq(chain []VersionID) {
	sort.Slice(chain, func(i, j int) bool {
		vi, vj := b.versionByID[chain[i]], b.versionByID[chain[j]]
		if vi == nil || vj == nil {
			return chain[i] < chain[j]
		}
		return vi.Seq < vj.Seq
	})
}

// latestOwnVersionLocked returns the epoch's newest version of obj, or nil.
func (b *Backend) latestOwnVersionLocked(epochID EpochID, obj ObjectID) *FileVersion {
	chain := b.versionsByObject[obj]
	for i := len(chain) - 1; i >= 0; i-- {
		if v := b.versionByID[chain[i]]; v != nil && v.Owner == epochID {
			return v
		}
	}
	return nil
}

// headVersionLocked returns the globally visible head version of obj, or nil
// when the backing file is the visible state.
func (b *Backend) headVersionLocked(obj ObjectID) *FileVersion {
	head, ok := b.visibleHead[obj]
	if !ok {
		return nil
	}
	return b.versionByID[head]
}

// viewVersionLocked returns the version obj resolves to in epochID's view:
// the epoch's own newest version if it has one, else the global head. nil
// means the backing file is the visible state.
func (b *Backend) viewVersionLocked(epochID EpochID, obj ObjectID) *FileVersion {
	if own := b.latestOwnVersionLocked(epochID, obj); own != nil {
		return own
	}
	return b.headVersionLocked(obj)
}

// insertVersionLocked links a new version into the object chain, updates the
// visible head, records epoch ownership and adds the write-write ordering
// edge (previous head's owner -> new writer). Parent is (re)computed here so
// live apply and WAL replay derive identical chains.
func (b *Backend) insertVersionLocked(v *FileVersion) {
	obj := v.LogicalPath
	prevHead := b.headVersionLocked(obj)
	v.Parent = 0
	if prevHead != nil {
		v.Parent = prevHead.ID
	}
	b.versionByID[v.ID] = v
	chain := append(b.versionsByObject[obj], v.ID)
	// Seqs are allocated monotonically and applied in seq order, so the
	// append preserves ordering; sort defensively for replay paths.
	if len(chain) > 1 {
		if prev := b.versionByID[chain[len(chain)-2]]; prev != nil && prev.Seq > v.Seq {
			b.sortChainBySeq(chain)
		}
	}
	b.versionsByObject[obj] = chain
	if prevHead == nil || v.Seq >= prevHead.Seq {
		b.visibleHead[obj] = v.ID
	}
	ep := b.ensureEpoch(v.Owner, "")
	ep.Versions = append(ep.Versions, v.ID)
	// Write-write ordering edge: overwriting another live epoch's version
	// means our version's fate is tied to theirs (rolling THEM back removes
	// the base we built on, so we must cascade).
	if prevHead != nil && prevHead.Owner != v.Owner {
		if owner, ok := b.epochs[prevHead.Owner]; ok && owner.State != Finalized {
			b.addDependency(prevHead.Owner, v.Owner)
		}
	}
}

// removeVersionFromEpoch drops vid from ep.Versions (order preserved).
func removeVersionFromEpoch(ep *EpochState, vid VersionID) {
	for i, id := range ep.Versions {
		if id == vid {
			ep.Versions = append(ep.Versions[:i], ep.Versions[i+1:]...)
			return
		}
	}
}

// --- Resolve (per-epoch view) + read-from dependency recording ---

// resolveLocked resolves obj in epochID's view WITHOUT recording any
// dependency. Must be called with b.mu held.
func (b *Backend) resolveLocked(epochID EpochID, obj ObjectID) ResolveResult {
	// Ancestor whiteouts: a deleted ancestor directory hides the whole
	// subtree. Walk strict ancestors below the tracked root.
	for anc := filepath.Dir(obj); isAncestor(b.trackedDir, anc); anc = filepath.Dir(anc) {
		av := b.viewVersionLocked(epochID, anc)
		if av != nil && av.Operation == OpWhiteout {
			return ResolveResult{Version: av.ID, Producer: av.Owner, Exists: false, Op: OpWhiteout}
		}
	}
	v := b.viewVersionLocked(epochID, obj)
	if v == nil {
		return ResolveResult{PhysicalPath: obj, Version: 0, Producer: "", Exists: true}
	}
	if v.Operation == OpWhiteout {
		return ResolveResult{Version: v.ID, Producer: v.Owner, Exists: false, Op: OpWhiteout}
	}
	return ResolveResult{PhysicalPath: v.StagePath, Version: v.ID, Producer: v.Owner, Exists: true, Op: v.Operation}
}

// needsReadDepLocked reports whether observing res from epochID constitutes a
// NEW read-from dependency that must be durably recorded.
func (b *Backend) needsReadDepLocked(epochID EpochID, res ResolveResult) bool {
	if res.Version == 0 || res.Producer == "" || res.Producer == epochID {
		return false
	}
	producer, ok := b.epochs[res.Producer]
	if !ok || producer.State == Finalized {
		return false // durable (or gone): can never cascade a rollback
	}
	if ep, ok := b.epochs[epochID]; ok {
		if _, dup := ep.ReadFrom[res.Version]; dup {
			return false
		}
	}
	return true
}

// Resolve resolves origPath for epochID's view and, when the observed
// version belongs to another live (non-finalized) epoch, durably records the
// producer -> consumer read-from edge. This is THE dependency primitive: a
// reader depends exactly on the versions it actually saw, never on the whole
// writer history of the path.
func (b *Backend) Resolve(epochID EpochID, origPath string) ResolveResult {
	obj := filepath.Clean(origPath)
	b.mu.Lock()
	res := b.resolveLocked(epochID, obj)
	need := b.needsReadDepLocked(epochID, res)
	b.mu.Unlock()
	if need {
		if err := b.recordReadDep(epochID, res.Version, obj); err != nil {
			res.Err = err
			res.Exists = false
			res.PhysicalPath = ""
			return res
		}
		b.mu.Lock()
		_, stillPresent := b.versionByID[res.Version]
		b.mu.Unlock()
		if !stillPresent {
			res.Err = fmt.Errorf("resolved version %d disappeared while recording read dependency", res.Version)
			res.Exists = false
			res.PhysicalPath = ""
		}
	}
	return res
}

// recordReadDep durably records a read-from edge (WAL "read_dep") and applies
// it. Follows the standard write-ahead protocol.
func (b *Backend) recordReadDep(epochID EpochID, vid VersionID, obj ObjectID) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	ep := b.ensureEpoch(epochID, "")
	if _, dup := ep.ReadFrom[vid]; dup {
		b.mu.Unlock()
		return nil
	}
	seqNum := b.nextSeq()
	rec := WALRecord{EpochID: string(epochID), SeqNum: seqNum,
		ControlOp: "read_dep", ReadVersion: uint64(vid), ObjectPath: obj}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] recordReadDep WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return err
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	b.readDepInternal(epochID, vid)
	return nil
}

// readDepInternal applies a read-from edge. Must be called with b.mu held.
// Used both by recordReadDep and by replayWAL.
func (b *Backend) readDepInternal(epochID EpochID, vid VersionID) {
	ep := b.ensureEpoch(epochID, "")
	ep.ReadFrom[vid] = struct{}{}
	v, ok := b.versionByID[vid]
	if !ok || v.Owner == epochID {
		return // producer version already gone (rolled back / promoted)
	}
	if owner, ok := b.epochs[v.Owner]; ok && owner.State != Finalized {
		b.addDependency(v.Owner, epochID)
	}
}

// MergeReaddirVersions lists the merged view of origDir for epochID: backing
// entries overlaid with each object's resolved version, whiteouts hiding
// deleted names. Every foreign version observed by the enumeration gets a
// read-from edge — directory listing IS a namespace read.
func (b *Backend) MergeReaddirVersions(epochID EpochID, origDir string) ([]MergedDirEntry, error) {
	dir := filepath.Clean(origDir)

	type override struct {
		physical string // "" = hidden by whiteout
	}
	overrides := make(map[string]override)
	type dep struct {
		vid VersionID
		obj ObjectID
	}
	var deps []dep

	b.mu.Lock()
	for obj := range b.versionsByObject {
		if filepath.Dir(obj) != dir {
			continue
		}
		v := b.viewVersionLocked(epochID, obj)
		if v == nil {
			continue
		}
		name := filepath.Base(obj)
		if v.Operation == OpWhiteout {
			overrides[name] = override{physical: ""}
		} else {
			overrides[name] = override{physical: v.StagePath}
		}
		if b.needsReadDepLocked(epochID, ResolveResult{Version: v.ID, Producer: v.Owner}) {
			deps = append(deps, dep{vid: v.ID, obj: obj})
		}
	}
	b.mu.Unlock()

	// Record the namespace read-from edges durably (outside b.mu). If any
	// dependency cannot be persisted, fail closed: returning a directory listing
	// without its read-from edge would make a later producer rollback invisible.
	for _, d := range deps {
		if err := b.recordReadDep(epochID, d.vid, d.obj); err != nil {
			return nil, err
		}
	}

	result := make([]MergedDirEntry, 0, len(overrides))
	if oents, err := os.ReadDir(dir); err == nil {
		for _, e := range oents {
			name := e.Name()
			if _, overridden := overrides[name]; overridden {
				continue
			}
			info, ierr := e.Info()
			if ierr != nil {
				continue
			}
			result = append(result, MergedDirEntry{
				Name: name,
				Mode: info.Mode(),
				Ino:  inodeOf(info),
			})
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	for name, ov := range overrides {
		if ov.physical == "" {
			continue // whiteout
		}
		st, err := os.Lstat(ov.physical)
		if err != nil {
			continue // payload not materialized yet (fresh create pre-open)
		}
		result = append(result, MergedDirEntry{
			Name: name,
			Mode: st.Mode(),
			Ino:  inodeOf(st),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
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

// --- Version creation (write path) ---

// versionSpec describes the version a Record*/Prepare* call wants to create.
type versionSpec struct {
	op         VersionOp
	mode       uint32
	rdev       uint64
	renameFrom string
	linkTarget string
	dir        bool
}

// materializeVersionLocked idempotently produces the PHYSICAL stage payload
// for v. It must run BEFORE insertVersionLocked so the copy-up base resolves
// against the pre-insert chain — live apply and WAL-replay redo therefore
// derive the identical source. Must be called with b.mu held.
func (b *Backend) materializeVersionLocked(v *FileVersion) error {
	switch v.Operation {
	case OpWhiteout:
		// Whiteouts are purely logical; the marker is debug-only.
		if marker, err := whiteoutMarkerFor(b.stagingDir, b.trackedDir, v.Owner, v.LogicalPath); err == nil {
			_ = writeWhiteoutMarker(marker)
		}
		return nil

	case OpRename:
		// Optimization 2: OpRename is namespace-only; NO physical stage
		// payload is created. The new path references the old path's
		// physical version. Copy-up is deferred until the renamed path
		// is actually written (via PrepareWrite on the new path).
		return nil

	case OpMkdir:
		if err := ensureParentDir(v.StagePath); err != nil {
			return err
		}
		mode := os.FileMode(v.Mode)
		if mode == 0 {
			mode = 0o755
		}
		if err := os.Mkdir(v.StagePath, mode); err != nil && !os.IsExist(err) {
			return fmt.Errorf("stage mkdir %q: %w", v.StagePath, err)
		}
		return nil

	case OpMknod:
		if err := ensureParentDir(v.StagePath); err != nil {
			return err
		}
		if err := syscall.Mknod(v.StagePath, v.Mode, int(v.Rdev)); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("stage mknod %q: %w", v.StagePath, err)
		}
		return nil

	case OpLink:
		if err := ensureParentDir(v.StagePath); err != nil {
			return err
		}
		if _, err := os.Lstat(v.StagePath); err == nil {
			return nil // already materialized (redo)
		}
		src := b.resolveLocked(v.Owner, filepath.Clean(v.LinkTarget))
		if !src.Exists {
			return syscall.ENOENT
		}
		if st, err := os.Lstat(src.PhysicalPath); err != nil || st.IsDir() {
			return syscall.ENOENT
		}
		// Prefer a real hard link (shared inode within the epoch's view);
		// fall back to a copy across staging trees / devices.
		if err := os.Link(src.PhysicalPath, v.StagePath); err != nil {
			if os.IsExist(err) {
				return nil
			}
			if cerr := copyUpFile(src.PhysicalPath, v.StagePath); cerr != nil {
				return fmt.Errorf("stage link %q -> %q: %w", src.PhysicalPath, v.StagePath, cerr)
			}
		}
		return nil

	default: // OpWrite / OpXattr: content payload
		if v.RenameFrom != "" {
			// Rename destination: materialize as a copy of the SOURCE as
			// seen in the owner's view (file or whole directory tree). The
			// source object is hidden by its whiteout version, so the copy
			// is not moved: the whole epoch rolls back atomically.
			if _, err := os.Lstat(v.StagePath); err == nil {
				return nil // already materialized (redo)
			}
			src := b.resolveLocked(v.Owner, filepath.Clean(v.RenameFrom))
			if !src.Exists {
				return syscall.ENOENT
			}
			st, err := os.Lstat(src.PhysicalPath)
			if err != nil {
				return err
			}
			if st.IsDir() {
				return copyUpDir(src.PhysicalPath, v.StagePath)
			}
			return copyUpFile(src.PhysicalPath, v.StagePath)
		}
		// Plain write / copy-up. copyUpFile publishes atomically (temp +
		// rename), so an existing stage payload is COMPLETE by construction
		// — never re-copy over it: on WAL replay it may already carry user
		// writes made after the original copy-up.
		if _, err := os.Lstat(v.StagePath); err == nil {
			return nil
		}
		base := b.resolveLocked(v.Owner, v.LogicalPath)
		if base.Exists && base.PhysicalPath != "" {
			if _, err := os.Lstat(base.PhysicalPath); err == nil {
				return copyUpFile(base.PhysicalPath, v.StagePath)
			}
		}
		// Fresh create: just make sure the parent exists; the FUSE caller
		// populates the file via open(O_CREAT).
		return ensureParentDir(v.StagePath)
	}
}

// createVersion runs the full write-ahead protocol for ONE new version and
// returns it. The caller-facing Record*/Prepare* methods are thin wrappers.
func (b *Backend) createVersion(epochID EpochID, origPath string, spec versionSpec) (*FileVersion, error) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	obj := filepath.Clean(origPath)
	if _, err := relFromTracked(b.trackedDir, obj); err != nil {
		return nil, err
	}

	// --- compute (under mu) ---
	b.mu.Lock()
	if spec.op == OpWrite && spec.renameFrom == "" {
		view := b.resolveLocked(epochID, obj)
		if view.Exists && view.PhysicalPath != "" {
			if st, lerr := os.Lstat(view.PhysicalPath); lerr == nil && st.Mode()&os.ModeSymlink != 0 {
				b.mu.Unlock()
				return nil, syscall.EOPNOTSUPP
			}
		}
		if own := b.latestOwnVersionLocked(epochID, obj); own != nil &&
			b.visibleHead[obj] == own.ID && own.Operation != OpWhiteout && own.StagePath != "" {
			b.mu.Unlock()
			if debugLog.Load() {
				log.Printf("[backend] createVersion: epoch=%q path=%q reuse v%d", epochID, obj, own.ID)
			}
			return own, nil
		}
	}
	seqNum := b.nextSeq()
	vid := VersionID(b.nextVersion)
	b.nextVersion++
	stage := ""
	if spec.op != OpWhiteout {
		var err error
		stage, err = stagePathFor(b.stagingDir, b.trackedDir, epochID, vid, obj)
		if err != nil {
			b.mu.Unlock()
			return nil, err
		}
	}
	v := &FileVersion{
		ID:          vid,
		Owner:       epochID,
		LogicalPath: obj,
		StagePath:   stage,
		Seq:         seqNum,
		Operation:   spec.op,
		State:       VSpeculative,
		Mode:        spec.mode,
		Rdev:        spec.rdev,
		RenameFrom:  spec.renameFrom,
		LinkTarget:  spec.linkTarget,
		Dir:         spec.dir,
	}
	pv := marshalVersion(v)
	rec := WALRecord{EpochID: string(epochID), SeqNum: seqNum, Version: &pv}
	b.mu.Unlock()

	// Optimization 1: WAL write without fsync (group-commit worker handles
	// the write; fsync is deferred to FlushEpochWAL at commit time).
	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return nil, err
	}

	// --- apply (in seq order, under mu) ---
	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	if err := b.materializeVersionLocked(v); err != nil {
		b.insertVersionLocked(v)
		return nil, fmt.Errorf("materialize %s %q: %w", spec.op, obj, err)
	}
	b.insertVersionLocked(v)

	// Optimization 5: update epoch stats.
	stats := b.getEpochStats(epochID)
	stats.Versions++
	switch spec.op {
	case OpWrite:
		if spec.renameFrom == "" {
			stats.Creates++
		}
	case OpMkdir:
		stats.Mkdirs++
	case OpWhiteout:
		stats.Whiteouts++
	}

	if debugLog.Load() {
		log.Printf("[backend] createVersion: epoch=%q op=%s path=%q v%d parent=v%d",
			epochID, spec.op, obj, v.ID, v.Parent)
	}
	return v, nil
}

// PrepareWrite ensures the epoch owns a content-bearing version of origPath
// (copy-up from its resolved view if needed) and returns the stage path the
// caller should open for writing.
func (b *Backend) PrepareWrite(epochID EpochID, origPath string) (string, error) {
	v, err := b.createVersion(epochID, origPath, versionSpec{op: OpWrite})
	if err != nil {
		return "", err
	}
	return v.StagePath, nil
}

// PrepareCreate prepares a version for a brand new file at origPath.
// Identical to PrepareWrite (a missing base simply means a fresh create).
func (b *Backend) PrepareCreate(epochID EpochID, origPath string) (string, error) {
	return b.PrepareWrite(epochID, origPath)
}

// RecordMkdir records a directory created speculatively by the epoch.
func (b *Backend) RecordMkdir(epochID EpochID, origPath string, mode uint32) error {
	_, err := b.createVersion(epochID, origPath, versionSpec{op: OpMkdir, mode: mode})
	return err
}

// RecordUnlink records a file deletion as a whiteout version.
func (b *Backend) RecordUnlink(epochID EpochID, origPath string) error {
	_, err := b.createVersion(epochID, origPath, versionSpec{op: OpWhiteout})
	return err
}

// RecordRmdir records a directory removal as a recursive whiteout version.
func (b *Backend) RecordRmdir(epochID EpochID, origPath string) error {
	_, err := b.createVersion(epochID, origPath, versionSpec{op: OpWhiteout, dir: true})
	return err
}

// RecordMknod records a special file (FIFO / socket / device) creation.
func (b *Backend) RecordMknod(epochID EpochID, origPath string, mode uint32, rdev uint64) error {
	_, err := b.createVersion(epochID, origPath, versionSpec{op: OpMknod, mode: mode, rdev: rdev})
	return err
}

// RecordLink creates a hard link version at linkOrig pointing to targetOrig.
// The target's actually-resolved version is recorded as a read-from
// dependency (the link's content derives from it). Hard links to directories
// are rejected (EPERM), matching link(2). Returns the link's stage path.
func (b *Backend) RecordLink(epochID EpochID, targetOrig, linkOrig string) (string, error) {
	tgt := b.Resolve(epochID, targetOrig) // records the read-from edge
	if tgt.Err != nil {
		return "", tgt.Err
	}
	if !tgt.Exists {
		return "", syscall.ENOENT
	}
	if st, lerr := os.Lstat(tgt.PhysicalPath); lerr == nil && st.IsDir() {
		return "", syscall.EPERM
	}
	v, err := b.createVersion(epochID, linkOrig, versionSpec{op: OpLink, linkTarget: filepath.Clean(targetOrig)})
	if err != nil {
		return "", err
	}
	return v.StagePath, nil
}

// RecordXattrWrite ensures origPath is copied up and versioned, so a
// subsequent Setxattr/Removexattr applied to the returned stage path is
// captured for rollback and promotion. ACLs are stored as xattrs, so this
// covers them.
func (b *Backend) RecordXattrWrite(epochID EpochID, origPath string) (string, error) {
	return b.PrepareWrite(epochID, origPath)
}

// RecordRename records a rename as a version PAIR sharing one WAL fsync: a
// namespace-only OpRename version at newPath plus a whiteout version at
// oldPath. Both carry consecutive seqs so replay reconstructs the same order.
//
// Optimization 2: OpRename does NOT copy the source file. StagePath stores
// the source's physical path. At promotion, the source is moved atomically
// to the destination. Promotion order is guaranteed: OpRename before OpWhiteout.
func (b *Backend) RecordRename(epochID EpochID, oldPath, newPath string) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	cleanOld := filepath.Clean(oldPath)
	cleanNew := filepath.Clean(newPath)
	// rename(x, x) is a POSIX no-op.
	if cleanOld == cleanNew {
		return nil
	}
	// Cycle detection: prevent rename("dir", "dir/subdir/...").
	if strings.HasPrefix(cleanNew, cleanOld+string(os.PathSeparator)) {
		return fmt.Errorf("rename %q into its own subdirectory %q is not allowed", oldPath, newPath)
	}
	if _, err := relFromTracked(b.trackedDir, cleanNew); err != nil {
		return err
	}
	if _, err := relFromTracked(b.trackedDir, cleanOld); err != nil {
		return err
	}

	// --- compute (under mu) ---
	b.mu.Lock()
	src := b.resolveLocked(epochID, cleanOld)
	if !src.Exists {
		b.mu.Unlock()
		return syscall.ENOENT
	}
	srcIsDir := false
	if st, serr := os.Lstat(src.PhysicalPath); serr == nil {
		srcIsDir = st.IsDir()
	}
	needSrcDep := b.needsReadDepLocked(epochID, src)
	seq1 := b.nextSeq()
	seq2 := b.nextSeq()
	dstVid := VersionID(b.nextVersion)
	srcVid := VersionID(b.nextVersion + 1)
	b.nextVersion += 2

	// Fix 4: OpRename stores the source's VERSION IDENTITY (not a physical
	// path that could be moved by another rename). The rename batch planner
	// resolves the actual physical path at promotion time.
	// StagePath is empty for OpRename (no stage file created).
	dstV := &FileVersion{
		ID: dstVid, Owner: epochID, LogicalPath: cleanNew, StagePath: "",
		Seq: seq1, Operation: OpRename, State: VSpeculative, RenameFrom: cleanOld,
		Dir: srcIsDir, SourceVersion: src.Version,
	}
	srcV := &FileVersion{
		ID: srcVid, Owner: epochID, LogicalPath: cleanOld,
		Seq: seq2, Operation: OpWhiteout, State: VSpeculative, Dir: srcIsDir,
	}
	pv1 := marshalVersion(dstV)
	pv2 := marshalVersion(srcV)
	recs := []WALRecord{
		{EpochID: string(epochID), SeqNum: seq1, Version: &pv1},
		{EpochID: string(epochID), SeqNum: seq2, Version: &pv2},
	}

	// The rename READS the source version it moves: record that dependency.
	if needSrcDep {
		b.readDepInternal(epochID, src.Version)
	}
	b.mu.Unlock()

	// WAL write without fsync (deferred to FlushEpochWAL).
	if err := <-b.submitWAL(recs...); err != nil {
		b.applyTurnAbort(seq1)
		b.applyTurnAbort(seq2)
		return err
	}

	b.mu.Lock()
	b.applyTurnWait(seq1)
	defer func() {
		b.applyTurnDone(seq1)
		b.applyTurnDone(seq2)
		b.mu.Unlock()
	}()

	// Materialize + insert the destination FIRST, then the source whiteout.
	if err := b.materializeVersionLocked(dstV); err != nil {
		b.insertVersionLocked(dstV)
		b.insertVersionLocked(srcV)
		return fmt.Errorf("materialize rename %q -> %q: %w", cleanOld, cleanNew, err)
	}
	b.insertVersionLocked(dstV)
	_ = b.materializeVersionLocked(srcV)
	b.insertVersionLocked(srcV)

	// Update epoch stats.
	stats := b.getEpochStats(epochID)
	stats.Versions += 2
	stats.Renames++

	if debugLog.Load() {
		log.Printf("[backend] RecordRename: epoch=%q %q -> %q (v%d, v%d)", epochID, cleanOld, cleanNew, dstVid, srcVid)
	}
	return nil
}

// --- Rollback ---

// AffectedSet reports the epochs (and their cgroup attributions) touched by
// a cascade rollback.
type AffectedSet struct {
	Epochs  []string
	Cgroups []string
}

// rollbackBlockedBy returns the first epoch id in `ids` whose promotion has
// STARTED (State >= Finalizing) and is therefore no longer safely rollable.
// Returns "" if none. Must be called with b.mu held.
//
// This is the AUTHORITATIVE rollback gate. It lives inside rollbackInternal
// so that BOTH live apply AND WAL replay enforce the identical rule.
func (b *Backend) rollbackBlockedBy(ids map[EpochID]struct{}) EpochID {
	for id := range ids {
		if ep := b.epochs[id]; ep != nil && ep.State >= Finalizing {
			return id
		}
	}
	return ""
}

// Rollback discards every version produced by the named epoch and every
// epoch that transitively depends on it (read-from or write-write edges).
func (b *Backend) Rollback(epochID EpochID) error {
	_, err := b.RollbackWithAffected(epochID)
	return err
}

// discardEpochWALBuf removes any buffered WAL records for an epoch.
// Called during rollback — the records are discarded, not persisted.
func (b *Backend) discardEpochWALBuf(epochID EpochID) {
	b.epochWALMu.Lock()
	delete(b.epochWALBuf, epochID)
	b.epochWALMu.Unlock()
}

// RollbackWithAffected performs a cascading rollback and returns the
// affected epoch set (including the target itself) so the orchestrator can
// coordinate the process layer.
func (b *Backend) RollbackWithAffected(epochID EpochID) (AffectedSet, error) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	if _, ok := b.epochs[epochID]; !ok {
		b.mu.Unlock()
		log.Printf("[backend] Rollback: epoch %q not found, no-op", epochID)
		return AffectedSet{}, nil
	}
	// Fast-path pre-check (before allocating a seq / writing WAL). The
	// AUTHORITATIVE gate is inside rollbackInternal, which also catches the
	// race where a lower-seq commit moves an epoch to Finalizing after this
	// check but before apply.
	if blk := b.rollbackBlockedBy(b.reachableFrom(epochID)); blk != "" {
		st := b.epochs[blk].State
		b.mu.Unlock()
		return AffectedSet{}, fmt.Errorf("rollback refused: epoch %q is %s (promotion started; published state cannot be undone)", blk, st)
	}
	seqNum := b.nextSeq()
	rec := WALRecord{EpochID: string(epochID), SeqNum: seqNum, ControlOp: "rollback"}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] Rollback WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return AffectedSet{}, err
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()

	// Compute affected set before rollback executes cleanup.
	set := b.affectedSetLocked(epochID)
	err := b.rollbackInternal(epochID)
	return set, err
}

// affectedSetLocked snapshots the cascade set of epochID. Must be called
// with b.mu held.
func (b *Backend) affectedSetLocked(epochID EpochID) AffectedSet {
	var set AffectedSet
	cgSeen := make(map[string]struct{})
	for id := range b.reachableFrom(epochID) {
		set.Epochs = append(set.Epochs, string(id))
		if ep := b.epochs[id]; ep != nil && ep.CgroupID != "" {
			if _, dup := cgSeen[ep.CgroupID]; !dup {
				cgSeen[ep.CgroupID] = struct{}{}
				set.Cgroups = append(set.Cgroups, ep.CgroupID)
			}
		}
	}
	sort.Strings(set.Epochs)
	sort.Strings(set.Cgroups)
	return set
}

// GetAffected returns the epochs that would be affected by a rollback of the
// given epoch, without performing it.
func (b *Backend) GetAffected(epochID EpochID) AffectedSet {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.epochs[epochID]; !ok {
		return AffectedSet{}
	}
	return b.affectedSetLocked(epochID)
}

// rollbackInternal performs the cascading rollback: remove every affected
// epoch's versions from the chains (re-exposing predecessor versions), drop
// the epochs and their staging trees. Must be called with b.mu held. Used
// both by RollbackWithAffected and by replayWAL.
func (b *Backend) rollbackInternal(epochID EpochID) error {
	if _, ok := b.epochs[epochID]; !ok {
		return nil
	}
	affected := b.reachableFrom(epochID)
	// Authoritative guard (shared by live apply AND WAL replay): refuse if
	// the target or ANY epoch this rollback would cascade into has entered
	// Finalizing/Finalized. On replay the return is ignored, so a durable
	// rollback record that raced a lower-seq commit becomes a safe no-op.
	if blk := b.rollbackBlockedBy(affected); blk != "" {
		log.Printf("[backend] Rollback refused: epoch=%q is %s (promotion started)", blk, b.epochs[blk].State)
		return fmt.Errorf("rollback refused: epoch %q is %s (promotion started; published state cannot be undone)", blk, b.epochs[blk].State)
	}
	memberList := make([]EpochID, 0, len(affected))
	for id := range affected {
		memberList = append(memberList, id)
	}
	log.Printf("[backend] Rollback: epoch=%q cascading to %v", epochID, memberList)

	// Force-close every tracked fd of affected epochs BEFORE the version
	// files disappear, so processes get EBADF instead of stale data.
	// Also discard buffered WAL records — they won't be persisted.
	for id := range affected {
		b.CloseEpochFDs(id)
		b.discardEpochWALBuf(id)
	}

	// Collect touched objects and rebuild their chains without the affected
	// epochs' versions. The new tail (if any) is RE-EXPOSED as the head.
	touched := make(map[ObjectID]struct{})
	for id := range affected {
		ep := b.epochs[id]
		for _, vid := range ep.Versions {
			if v, ok := b.versionByID[vid]; ok {
				touched[v.LogicalPath] = struct{}{}
			}
			delete(b.versionByID, vid)
		}
	}
	for obj := range touched {
		chain := b.versionsByObject[obj]
		kept := chain[:0]
		for _, vid := range chain {
			if _, alive := b.versionByID[vid]; alive {
				kept = append(kept, vid)
			}
		}
		if len(kept) == 0 {
			delete(b.versionsByObject, obj)
			delete(b.visibleHead, obj)
		} else {
			b.versionsByObject[obj] = kept
			b.visibleHead[obj] = kept[len(kept)-1]
		}
	}

	// Remove staging payload and epoch records, then prune graph edges.
	for id := range affected {
		if err := os.RemoveAll(epochDirFor(b.stagingDir, id)); err != nil {
			log.Printf("[backend] Rollback: remove stage dir of %q: %v", id, err)
		}
	}
	b.cleanupEpochs(affected)

	if b.invalidateFn != nil && len(touched) > 0 {
		paths := make([]string, 0, len(touched))
		for p := range touched {
			paths = append(paths, p)
		}
		b.invalidateFn(paths)
	}
	return nil
}

// cleanupEpochs drops the affected epochs and every graph edge touching
// them. Must be called with b.mu held.
func (b *Backend) cleanupEpochs(affected map[EpochID]struct{}) {
	b.graphGen++
	for id := range affected {
		delete(b.epochs, id)
		delete(b.dependents, id)
		delete(b.dependsOn, id)
	}
	for src, dsts := range b.dependents {
		for id := range affected {
			delete(dsts, id)
		}
		if len(dsts) == 0 {
			delete(b.dependents, src)
		}
	}
	for src, dsts := range b.dependsOn {
		for id := range affected {
			delete(dsts, id)
		}
		if len(dsts) == 0 {
			delete(b.dependsOn, src)
		}
	}
	for cg, ep := range b.activeEpochByCgroup {
		if _, gone := affected[ep]; gone {
			delete(b.activeEpochByCgroup, cg)
		}
	}
}

// --- Commit / finalization ---

// PromoteFailure records why a single object's promotion failed.
type PromoteFailure struct {
	Path string `json:"path"`
	Op   string `json:"op"`
	Err  string `json:"err"`
}

// CommitResult is returned by Commit / RetryFinalize. It reports the epoch's
// resulting lifecycle state, whether it is now safe to release, and any
// promotion failures that must be retried before release. A non-nil error is
// reserved for infrastructure failures (WAL); promotion failures are
// surfaced via Failures + a non-Finalized State so the orchestrator keeps
// the workload fenced and retries.
type CommitResult struct {
	State      AgentLifecycle   `json:"state"`
	CanRelease bool             `json:"can_release"`
	Finalized  []string         `json:"finalized,omitempty"`
	Failures   []PromoteFailure `json:"failures,omitempty"`
}

// Commit AUTHORIZES the epoch (policy approved) and then attempts to drive
// it to Finalized. Authorization alone does NOT permit release: the epoch
// only becomes releasable once every object whose chain it participates in
// has been durably promoted and every upstream dependency is Finalized.
//
// Authorize records an independent policy decision for one epoch. It only
// advances Speculative -> AuthorizedPending and does NOT quiesce/promote; group
// finalization is allowed only after every SCC member has been authorized by
// its own policy path.
func (b *Backend) Authorize(epochID EpochID, policyHash string) (CommitResult, error) {
	if policyHash == "" {
		return CommitResult{}, fmt.Errorf("authorize: policy_hash required for epoch %q", epochID)
	}
	// Serialize independent authorization per backend instance. This prevents two
	// different policy hashes for the same epoch from both passing the pre-WAL
	// check and reaching durable storage; replay also rejects such conflicts.
	b.opRW.Lock()
	defer b.opRW.Unlock()

	b.mu.Lock()
	if ep := b.epochs[epochID]; ep != nil && ep.State >= AuthorizedPending {
		if ep.PolicyHash != "" && ep.PolicyHash != policyHash {
			b.mu.Unlock()
			return CommitResult{}, fmt.Errorf("authorize: policy_hash mismatch for epoch %q", epochID)
		}
		if ep.PolicyHash == "" {
			ep.PolicyHash = policyHash
		}
		res := b.lifecycleResultLocked(epochID)
		b.mu.Unlock()
		return res, nil
	}
	seqNum := b.nextSeq()
	rec := WALRecord{EpochID: string(epochID), SeqNum: seqNum, ControlOp: "commit", PolicyHash: policyHash}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		log.Printf("[backend] Authorize WAL: %v", err)
		b.applyTurnAbort(seqNum)
		return CommitResult{}, fmt.Errorf("authorize WAL: %w", err)
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	ep := b.ensureEpoch(epochID, "")
	if ep.PolicyHash != "" && ep.PolicyHash != policyHash {
		return CommitResult{}, fmt.Errorf("authorize apply: policy_hash mismatch for epoch %q", epochID)
	}
	ep.PolicyHash = policyHash
	if ep.State < AuthorizedPending {
		ep.State = AuthorizedPending
		log.Printf("[backend] Authorize: epoch=%q authorized (pending finalization)", epochID)
	}
	return b.lifecycleResultLocked(epochID), nil
}

// Commit authorizes an epoch and immediately tries to finalize it. It is kept
// for single-epoch compatibility; SCC flows should call Authorize for each
// independently approved member, then BeginFinalize for the group.
func (b *Backend) Commit(epochID EpochID) (CommitResult, error) {
	if _, err := b.Authorize(epochID, "legacy-allow-all"); err != nil {
		return CommitResult{}, err
	}

	// Optimization 1: Flush buffered WAL records before promotion.
	// This is the WAL barrier — all epoch records are persisted with one fsync.
	if err := b.FlushEpochWAL(epochID); err != nil {
		log.Printf("[backend] Commit: epoch=%q WAL flush failed: %v", epochID, err)
		return CommitResult{}, err
	}

	b.opRW.RLock()
	defer b.opRW.RUnlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	ep := b.ensureEpoch(epochID, "")
	if err := b.quiesceMappings(ep); err != nil {
		ep.FinalizeErr = fmt.Sprintf("mmap quiesce: %v", err)
		log.Printf("[backend] Commit: epoch=%q finalization ABORTED: %v", epochID, err)
		return b.lifecycleResultLocked(epochID), nil
	}
	if err := b.flushEpochFDs(epochID); err != nil {
		ep.FinalizeErr = fmt.Sprintf("flush fds: %v", err)
		log.Printf("[backend] Commit: epoch=%q finalization ABORTED: %v", epochID, err)
		return b.lifecycleResultLocked(epochID), nil
	}
	_ = b.tryPromoteAll()
	return b.lifecycleResultLocked(epochID), nil
}

// commitInternal is used only by old replay-compatible paths that already hold
// b.mu. New group flows authorize explicitly, then finalize the whole SCC.
func (b *Backend) commitInternal(epochID EpochID) {
	ep := b.ensureEpoch(epochID, "")
	if ep.State < AuthorizedPending {
		ep.State = AuthorizedPending
		log.Printf("[backend] Commit: epoch=%q authorized (pending finalization)", epochID)
	}
	// Capture the (frozen) processes' dirty writable MAP_SHARED pages into
	// the epoch's stage copies BEFORE promotion. FAIL CLOSED: an incomplete
	// capture aborts finalization (epoch stays AuthorizedPending with
	// FinalizeErr set, releasable=false).
	if err := b.quiesceMappings(ep); err != nil {
		ep.FinalizeErr = fmt.Sprintf("mmap quiesce: %v", err)
		log.Printf("[backend] Commit: epoch=%q finalization ABORTED: %v", epochID, err)
		return
	}
	// Then fsync the tracked fds so promotion moves fully up-to-date stage
	// copies.
	if err := b.flushEpochFDs(epochID); err != nil {
		ep.FinalizeErr = fmt.Sprintf("flush fds: %v", err)
		log.Printf("[backend] Commit: epoch=%q finalization ABORTED: %v", epochID, err)
		return
	}
	_ = b.tryPromoteAll()
}

// RetryFinalize re-runs the promotion/finalization pass for a stuck epoch
// (one left in AuthorizedPending/Finalizing by an earlier promotion failure).
// Safe to call repeatedly: every promoteVersion is idempotent.
func (b *Backend) RetryFinalize(epochID EpochID) (CommitResult, error) {
	// Optimization 1: Flush any remaining buffered WAL records.
	if err := b.FlushEpochWAL(epochID); err != nil {
		log.Printf("[backend] RetryFinalize: epoch=%q WAL flush failed: %v", epochID, err)
		return CommitResult{}, err
	}

	b.opRW.RLock()
	defer b.opRW.RUnlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	ep, ok := b.epochs[epochID]
	if !ok {
		return CommitResult{}, fmt.Errorf("retry_finalize: epoch %q not found", epochID)
	}
	if ep.State < AuthorizedPending {
		return CommitResult{}, fmt.Errorf("retry_finalize: epoch %q not authorized (state=%s)", epochID, ep.State)
	}
	if err := b.quiesceMappings(ep); err != nil {
		ep.FinalizeErr = fmt.Sprintf("mmap quiesce: %v", err)
		log.Printf("[backend] RetryFinalize: epoch=%q ABORTED: %v", epochID, err)
		return b.lifecycleResultLocked(epochID), nil
	}
	if err := b.flushEpochFDs(epochID); err != nil {
		ep.FinalizeErr = fmt.Sprintf("flush fds: %v", err)
		log.Printf("[backend] RetryFinalize: epoch=%q ABORTED: %v", epochID, err)
		return b.lifecycleResultLocked(epochID), nil
	}
	_ = b.tryPromoteAll()
	return b.lifecycleResultLocked(epochID), nil
}

// lifecycleResultLocked builds a CommitResult snapshot for epochID. Must be
// called with b.mu held.
func (b *Backend) lifecycleResultLocked(epochID EpochID) CommitResult {
	res := CommitResult{}
	ep, ok := b.epochs[epochID]
	if !ok {
		res.State = Speculative
		res.CanRelease = false
		return res
	}
	res.State = ep.State
	res.CanRelease = ep.State == Finalized
	if ep.FinalizeErr != "" {
		res.Failures = append(res.Failures, PromoteFailure{
			Path: "", Op: "promote", Err: ep.FinalizeErr,
		})
	}
	return res
}

// GetLifecycle reports an epoch's current lifecycle state and any pending
// promotion failure, without mutating anything. An unknown epoch reports
// state "unknown" and CanRelease=false (fail-closed).
func (b *Backend) GetLifecycle(epochID EpochID) (state string, canRelease bool, finalizeErr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ep, ok := b.epochs[epochID]
	if !ok {
		return "unknown", false, ""
	}
	return ep.State.String(), ep.State == Finalized, ep.FinalizeErr
}

// AckRelease is called by the orchestrator AFTER it has successfully
// released a Finalized epoch's external effects. Only then is the terminal
// record cleaned up. Refuses to drop an epoch that has not reached Finalized
// (fail-closed).
func (b *Backend) AckRelease(epochID EpochID) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	ep, ok := b.epochs[epochID]
	if !ok {
		b.mu.Unlock()
		return nil // already cleaned up: idempotent
	}
	if ep.State != Finalized {
		state := ep.State
		b.mu.Unlock()
		return fmt.Errorf("ack_release: epoch %q is %s, not finalized", epochID, state)
	}
	seqNum := b.nextSeq()
	rec := WALRecord{EpochID: string(epochID), SeqNum: seqNum, ControlOp: "release_ack"}
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
	b.ackReleaseInternal(epochID)
	return nil
}

// ackReleaseInternal drops a Finalized epoch's terminal record and its
// (already-consumed) staging tree. Must be called with b.mu held. Idempotent.
func (b *Backend) ackReleaseInternal(epochID EpochID) {
	ep, ok := b.epochs[epochID]
	if !ok {
		return
	}
	if ep.State != Finalized {
		// Only a finalized epoch may be acked. On replay this guards
		// against a stale release_ack for an epoch that (post-checkpoint)
		// is not yet finalized: leave it in place to be re-finalized.
		return
	}
	delete(b.epochs, epochID)
	if ep.CgroupID != "" && b.activeEpochByCgroup[ep.CgroupID] == epochID {
		delete(b.activeEpochByCgroup, ep.CgroupID)
	}
	if err := os.RemoveAll(epochDirFor(b.stagingDir, epochID)); err != nil {
		log.Printf("[backend] release_ack: remove stage dir of %q: %v", epochID, err)
	}
	b.graphGen++
	log.Printf("[backend] release_ack: dropped finalized epoch=%q", epochID)
}

// publishBarrier fsyncs every orig parent directory accumulated by
// promotions since the last barrier, then clears the set. This is the
// crash-atomic group-publish durability point: it runs BEFORE any epoch in
// the group is marked Finalized. Must be called with b.mu held.
func (b *Backend) publishBarrier() error {
	var errs []string
	for dir := range b.publishDirs {
		if err := fsyncDir(dir); err != nil && !os.IsNotExist(err) {
			msg := fmt.Sprintf("%q: %v", dir, err)
			log.Printf("[backend] publishBarrier fsync %s", msg)
			errs = append(errs, msg)
			continue
		}
		delete(b.publishDirs, dir)
	}
	if len(errs) > 0 {
		return fmt.Errorf("publish barrier fsync: %s", strings.Join(errs, "; "))
	}
	return nil
}

// renameEntry is one OpRename collected by the batch planner.
type renameEntry struct {
	v       *FileVersion
	srcPath string // resolved physical path of source
}

// resolveRenameSource recursively resolves the physical path for an OpRename's
// source. Fix 4: handles rename chains (a→tmp, b→a, tmp→b) by following
// SourceVersion links. A visited set prevents infinite loops from corrupt WAL.
func (b *Backend) resolveRenameSource(v *FileVersion, visited map[VersionID]bool) (string, error) {
	if v.SourceVersion == 0 {
		// Source is the backing file.
		return v.RenameFrom, nil
	}
	if visited[v.SourceVersion] {
		return "", fmt.Errorf("rename source cycle detected at version %d", v.SourceVersion)
	}
	visited[v.SourceVersion] = true
	src := b.versionByID[v.SourceVersion]
	if src == nil {
		// Source version gone (already promoted/cleaned). Use logical path.
		return v.RenameFrom, nil
	}
	if src.Operation == OpRename {
		// Recursive: source is itself a rename.
		return b.resolveRenameSource(src, visited)
	}
	if src.StagePath != "" {
		return src.StagePath, nil
	}
	return src.LogicalPath, nil
}

// planRenames resolves OpRename source paths for independent renames.
// Fix 2: Does NOT move files — only sets StagePath for fast-path promotion.
// Conflicting renames (chains, swaps, overlaps) are left with empty StagePath
// and fall back to safe copy-up promotion via promoteVersion.
// Must be called with b.mu held.
func (b *Backend) planRenames() {
	// Collect all OpRename heads.
	var renames []renameEntry
	for obj, headVid := range b.visibleHead {
		head := b.versionByID[headVid]
		if head == nil || head.Operation != OpRename {
			continue
		}
		// Resolve source physical path recursively (Fix 4).
		visited := make(map[VersionID]bool)
		srcPath, err := b.resolveRenameSource(head, visited)
		if err != nil {
			log.Printf("[backend] planRenames: resolve %q: %v", obj, err)
			continue
		}
		renames = append(renames, renameEntry{v: head, srcPath: srcPath})
	}
	if len(renames) == 0 {
		return
	}

	// Build conflict graph: detect chains, swaps, and overlaps.
	srcToIdx := make(map[string][]int)
	for i, r := range renames {
		srcToIdx[r.srcPath] = append(srcToIdx[r.srcPath], i)
	}

	conflicting := make([]bool, len(renames))
	for i, r := range renames {
		// Conflict: destination is another rename's source.
		if _, ok := srcToIdx[r.v.LogicalPath]; ok {
			conflicting[i] = true
			for _, j := range srcToIdx[r.v.LogicalPath] {
				conflicting[j] = true
			}
		}
		// Conflict: multiple renames share the same source.
		if len(srcToIdx[r.srcPath]) > 1 {
			for _, j := range srcToIdx[r.srcPath] {
				conflicting[j] = true
			}
		}
	}

	// Fix 2: Only set StagePath for independent renames (fast path).
	// Conflicting renames keep empty StagePath and use safe fallback.
	for i, r := range renames {
		if !conflicting[i] {
			r.v.StagePath = r.srcPath
		}
		// Conflicting renames: StagePath stays empty, promoteVersion
		// will fall back to RenameFrom (logical path) which triggers
		// copy-up behavior — safe but not zero-copy.
	}
}

// tryPromoteAll iterates over every object with a speculative head and
// promotes those whose whole chain is owned by authorized epochs (with
// all-finalized external upstreams). Promotion of one object may finalize an
// epoch which in turn unblocks downstream epochs, so the loop runs until no
// progress is made. Returns the joined error of any promotion failures
// encountered (nil if all succeeded). Must be called with b.mu held.
func (b *Backend) tryPromoteAll() error {
	for {
		// Fix 4: resolve OpRename source paths and detect conflicts.
		b.planRenames()

		var errs []error
		objects := make([]string, 0, len(b.versionsByObject))
		for obj := range b.versionsByObject {
			objects = append(objects, obj)
		}
		// Promote deeper paths first so that e.g. child whiteouts empty a
		// directory on the backing side before the directory itself is
		// renamed/removed by its own head version.
		// Optimization 2: OpRename MUST be promoted before OpWhiteout to
		// ensure the source file is moved before the whiteout deletes it.
		sort.Slice(objects, func(i, j int) bool {
			hi := b.versionByID[b.visibleHead[objects[i]]]
			hj := b.versionByID[b.visibleHead[objects[j]]]
			// Prioritize OpRename over OpWhiteout.
			if hi != nil && hj != nil {
				if hi.Operation == OpRename && hj.Operation == OpWhiteout {
					return true
				}
				if hi.Operation == OpWhiteout && hj.Operation == OpRename {
					return false
				}
			}
			di := strings.Count(objects[i], string(os.PathSeparator))
			dj := strings.Count(objects[j], string(os.PathSeparator))
			if di != dj {
				return di > dj
			}
			return objects[i] > objects[j]
		})
		// SCC membership for this pass. NO epoch is auto-authorized here: an
		// epoch must be explicitly committed (policy-approved) to advance,
		// even if it made no filesystem writes — a pure-read epoch may still
		// have process / network / output effects that policy must gate.
		sccOf := b.sccMembership()
		progress := false
		for _, obj := range objects {
			ran, err := b.tryPromoteObject(obj, sccOf)
			if ran {
				progress = true
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		// Finalize whole strongly-connected components at once so
		// dependency cycles (A -> B -> A) resolve together, and never
		// before every member's promotion has succeeded.
		if b.tryFinalizeSCCs() {
			progress = true
		}
		if !progress {
			return errors.Join(errs...)
		}
	}
}

// tryPromoteObject attempts to promote the object's visible-head version to
// the backing filesystem. It requires that EVERY owner in the object's chain
// is authorized AND that none of those owners has an un-finalized upstream
// dependency outside its SCC (chain co-owners are promoted together as a
// unit and do not block each other).
//
// All-or-nothing per object: if the head's promotion fails, NOTHING is torn
// down — the chain, stage payloads and graph state are ALL preserved, the
// involved owners are left in Finalizing with FinalizeErr set, and
// (false, err) is returned. promoteVersion is idempotent, so RetryFinalize
// re-runs the same promotion. Must be called with b.mu held.
func (b *Backend) tryPromoteObject(obj ObjectID, sccOf map[EpochID]int) (bool, error) {
	chain := b.versionsByObject[obj]
	if len(chain) == 0 {
		return false, nil
	}
	owners := make(map[EpochID]struct{})
	for _, vid := range chain {
		if v := b.versionByID[vid]; v != nil {
			owners[v.Owner] = struct{}{}
		}
	}
	for w := range owners {
		ep, ok := b.epochs[w]
		if !ok || !ep.approved() {
			return false, nil
		}
		for up := range b.dependsOn[w] {
			upEp, ok := b.epochs[up]
			if !ok {
				continue // upstream gone => finalized and acked
			}
			if upEp.State == Finalized {
				continue
			}
			// Chain co-owners promote together as a unit; their mutual
			// (write-write) dependency does not block this object.
			if _, co := owners[up]; co {
				continue
			}
			// Strong semantics: an un-finalized upstream OUTSIDE this
			// owner's SCC blocks promotion. Its group must Finalize first,
			// otherwise a later reject of that upstream could cascade into
			// state we already published. Intra-SCC upstreams do NOT block:
			// the whole cycle promotes and finalizes together.
			if sccOf[up] == sccOf[w] {
				continue
			}
			return false, nil
		}
	}

	head := b.versionByID[b.visibleHead[obj]]
	if head == nil {
		return false, nil
	}

	// Fix 1: If the head was already physically promoted by the rename
	// batch planner (VPromoted), skip promoteVersion but still clean up
	// the chain and record publishDirs.
	alreadyPromoted := head.State == VPromoted

	// Promotion has started for this object: move its (authorized) owners
	// to Finalizing so a normal rollback is refused from here on.
	for w := range owners {
		if ep := b.epochs[w]; ep != nil && ep.State == AuthorizedPending {
			ep.State = Finalizing
		}
	}

	if !alreadyPromoted {
		// git 的 link-unlink 模式：写 tmp_obj → link(tmp, final) → unlink(tmp)。
		// tmp 的 visible head 是 OpWhiteout，永远不会被提升到 orig，但 OpLink
		// 的 LinkTarget 指向 tmp 的 orig 路径。提升前先把 tmp 的 WRITE 版本
		// 从 stage 落盘到 orig，否则 os.Link 会永久 ENOENT。
		if head.Operation == OpLink && head.LinkTarget != "" {
			if _, statErr := os.Lstat(head.LinkTarget); os.IsNotExist(statErr) {
				b.ensureLinkTarget(head.LinkTarget)
			}
		}

		if err := promoteVersion(head); err != nil {
			// FAIL CLOSED: preserve ALL recovery state so the exact same
			// promotion can be retried. Record why on every owner.
			msg := fmt.Sprintf("promote %q: %v", obj, err)
			log.Printf("[backend] Promote: %s", msg)
			for w := range owners {
				if ep := b.epochs[w]; ep != nil {
					ep.FinalizeErr = msg
				}
			}
			return false, fmt.Errorf("%s", msg)
		}
	}

	// Head published durably. Tear down the WHOLE chain: superseded
	// intermediate versions are cleared together with the head.
	for _, vid := range chain {
		v := b.versionByID[vid]
		if v == nil {
			continue
		}
		if ep := b.epochs[v.Owner]; ep != nil {
			removeVersionFromEpoch(ep, vid)
			ep.FinalizeErr = ""
		}
		if v.StagePath != "" && vid != head.ID {
			// The head's payload was consumed by movePath; superseded
			// payloads are dropped best-effort.
			if st, serr := os.Lstat(v.StagePath); serr == nil {
				if st.IsDir() {
					_ = os.RemoveAll(v.StagePath)
				} else {
					_ = os.Remove(v.StagePath)
				}
			}
		}
		delete(b.versionByID, vid)
	}
	delete(b.versionsByObject, obj)
	delete(b.visibleHead, obj)

	// Record this object's orig parent dir for the group publish barrier.
	b.publishDirs[filepath.Dir(obj)] = struct{}{}
	log.Printf("[backend] Promote: obj=%q head=v%d promoted (%d chain version(s) cleared)", obj, head.ID, len(chain))
	return true, nil
}

// ensureLinkTarget 在提升 OpLink 版本前，确保 link 目标文件在 orig 中存在。
// git 的 finalize_object_file 用 link(tmp_obj, final) + unlink(tmp_obj) 模式：
// tmp_obj 的 visible head 是 OpWhiteout（被 unlink 覆盖），永远不会被正常
// 提升到 orig。但 tmp_obj 的 WRITE 版本仍在版本链里，其 stage 副本可用。
// 本方法把 stage 内容落盘到 orig，使后续的 os.Link 能成功。
// Must be called with b.mu held.
func (b *Backend) ensureLinkTarget(target string) {
	targetObj := ObjectID(target)
	tChain := b.versionsByObject[targetObj]
	for _, vid := range tChain {
		tv := b.versionByID[vid]
		if tv == nil || tv.StagePath == "" {
			continue
		}
		if tv.Operation != OpWrite {
			continue
		}
		if _, err := os.Lstat(tv.StagePath); err != nil {
			continue
		}
		_ = os.MkdirAll(filepath.Dir(target), 0o755)
		if err := copyFileContents(tv.StagePath, target); err != nil {
			log.Printf("[backend] ensureLinkTarget: copy %q -> %q: %v",
				tv.StagePath, target, err)
		} else {
			log.Printf("[backend] ensureLinkTarget: materialized %q from stage v%d",
				target, tv.ID)
		}
		return
	}
}

// finalizeEpoch performs the state mutation of finalizing one epoch: drop
// its dependency edges (a finalized epoch's changes are durable and can no
// longer cascade a rollback), then set State=Finalized. The epoch record
// itself is RETAINED until AckRelease. Must be called with b.mu held.
func (b *Backend) finalizeEpoch(epochID EpochID) {
	ep, ok := b.epochs[epochID]
	if !ok {
		return
	}
	log.Printf("[backend] finalize: epoch=%q", epochID)
	for src := range b.dependsOn[epochID] {
		if dsts, ok := b.dependents[src]; ok {
			delete(dsts, epochID)
			if len(dsts) == 0 {
				delete(b.dependents, src)
			}
		}
	}
	delete(b.dependsOn, epochID)
	for s := range b.dependents[epochID] {
		if preds, ok := b.dependsOn[s]; ok {
			delete(preds, epochID)
			if len(preds) == 0 {
				delete(b.dependsOn, s)
			}
		}
	}
	delete(b.dependents, epochID)
	ep.State = Finalized
	ep.FinalizeErr = ""
}

// computeSCCs returns the strongly-connected components of the current
// dependency graph (edges: dependent -> upstream, from b.dependsOn) using
// iterative Tarjan. Every tracked epoch appears in exactly one component.
// Must be called with b.mu held.
func (b *Backend) computeSCCs() [][]EpochID {
	index := make(map[EpochID]int, len(b.epochs))
	lowlink := make(map[EpochID]int, len(b.epochs))
	onStack := make(map[EpochID]bool, len(b.epochs))
	var stack []EpochID
	var sccs [][]EpochID
	next := 0

	type frame struct {
		node EpochID
		succ []EpochID
		i    int
	}
	successors := func(id EpochID) []EpochID {
		out := make([]EpochID, 0, len(b.dependsOn[id]))
		for up := range b.dependsOn[id] {
			if _, ok := b.epochs[up]; ok {
				out = append(out, up)
			}
		}
		return out
	}

	// Sort epoch IDs for deterministic SCC numbering (stable group IDs).
	epochIDs := make([]EpochID, 0, len(b.epochs))
	for id := range b.epochs {
		epochIDs = append(epochIDs, id)
	}
	sort.Slice(epochIDs, func(i, j int) bool { return epochIDs[i] < epochIDs[j] })

	for _, id := range epochIDs {
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
				var comp []EpochID
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

// sccMembership maps each tracked epoch to an integer identifying its
// strongly-connected component. Must be called with b.mu held.
func (b *Backend) sccMembership() map[EpochID]int {
	m := make(map[EpochID]int, len(b.epochs))
	for i, comp := range b.computeSCCs() {
		for _, id := range comp {
			m[id] = i
		}
	}
	return m
}

// tryFinalizeSCCs finalizes every strongly-connected component that is
// READY, treating each SCC as an atomic unit. An SCC becomes Finalized iff:
//
//	(1) every member's policy is approved, AND
//	(2) every member owns no remaining versions (all objects it wrote have
//	    been promoted — a failed/pending promotion leaves versions), AND
//	(3) every upstream OUTSIDE the SCC is already Finalized (a pure-read
//	    upstream with no versions of its own does not block once
//	    finalized/acked).
//
// Must be called with b.mu held.
func (b *Backend) tryFinalizeSCCs() bool {
	progress := false
	for _, scc := range b.computeSCCs() {
		if b.finalizeSCCIfReady(scc) {
			progress = true
		}
	}
	return progress
}

func (b *Backend) finalizeSCCIfReady(scc []EpochID) bool {
	inSCC := make(map[EpochID]bool, len(scc))
	for _, id := range scc {
		inSCC[id] = true
	}
	// (1)+(2): every member approved, none already finalized, and no member
	// has pending/failed promotions (owned version set must be empty).
	anyPending := false
	for _, id := range scc {
		ep := b.epochs[id]
		if ep == nil {
			return false
		}
		if ep.State == Finalized {
			return false // component already finalized; nothing to do
		}
		if !ep.approved() {
			return false
		}
		if len(ep.Versions) > 0 {
			anyPending = true
		}
	}
	if anyPending {
		return false // a member's promotion is not done: keep the SCC fenced
	}
	// (3): every external upstream must be Finalized.
	for _, id := range scc {
		for up := range b.dependsOn[id] {
			if inSCC[up] {
				continue // intra-SCC edge: satisfied by finalizing together
			}
			upEp, ok := b.epochs[up]
			if !ok {
				continue // gone => finalized and acked
			}
			if upEp.State != Finalized {
				return false
			}
		}
	}
	// Ready: finalize the whole component atomically. Publish barrier FIRST
	// so the group's on-disk state is durable as a unit before ANY member
	// becomes releasable.
	if err := b.publishBarrier(); err != nil {
		for _, id := range scc {
			if ep := b.epochs[id]; ep != nil {
				ep.FinalizeErr = err.Error()
			}
		}
		return false
	}
	if len(scc) > 1 {
		log.Printf("[backend] finalize SCC (cycle) as a unit: %v", scc)
	}
	for _, id := range scc {
		b.finalizeEpoch(id)
	}
	return true
}

// --- Release gating ---

// CanRelease reports whether the external side effects of the given epoch
// are safe to externalize. TRUE only when the epoch has reached Finalized.
// FAIL CLOSED: an unknown / untracked epoch is NOT releasable.
func (b *Backend) CanRelease(epochID EpochID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	ep, ok := b.epochs[epochID]
	if !ok {
		return false // fail closed: unknown epoch is never releasable
	}
	return ep.State == Finalized
}

// --- Inspection (tests / control API) ---

// VersionCount returns the total number of live speculative versions.
func (b *Backend) VersionCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.versionByID)
}

// EpochVersionCount returns the number of live versions owned by an epoch.
func (b *Backend) EpochVersionCount(epochID EpochID) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	ep, ok := b.epochs[epochID]
	if !ok {
		return 0
	}
	return len(ep.Versions)
}

// DependsOn reports whether rolling back `on` would cascade to `dependent`.
func (b *Backend) DependsOn(dependent, on EpochID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.reachableFrom(on)[dependent]
	return ok
}

// HeadVersion reports the visible head of a logical path: its VersionID and
// producer epoch (0/"" when the backing file is visible).
func (b *Backend) HeadVersion(origPath string) (VersionID, EpochID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.headVersionLocked(filepath.Clean(origPath))
	if v == nil {
		return 0, ""
	}
	return v.ID, v.Owner
}

// --- Group-level finalization (Phase 3) ---

// PrepareResolutionResult is returned by PrepareResolution.
type PrepareResolutionResult struct {
	GroupID         int      `json:"group_id"`
	Members         []string `json:"members"`
	GraphGeneration int64    `json:"graph_generation"`
}

// PrepareResolution computes the SCC containing the given epoch and returns
// its members plus the current dependency-graph generation. The orchestrator
// freezes all members, then calls BeginFinalize with the same graph_generation
// to detect TOCTOU changes (a new dependency inserted between prepare and
// finalize would change the generation and cause BeginFinalize to refuse).
func (b *Backend) PrepareResolution(epochID EpochID) (PrepareResolutionResult, error) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()
	b.mu.Lock()

	ep, ok := b.epochs[epochID]
	if !ok {
		b.mu.Unlock()
		return PrepareResolutionResult{}, fmt.Errorf("prepare_resolution: epoch %q not found", epochID)
	}
	if ep.State >= Finalizing {
		b.mu.Unlock()
		return PrepareResolutionResult{}, fmt.Errorf("prepare_resolution: epoch %q already %s", epochID, ep.State)
	}

	sccs := b.computeSCCs()
	var group []EpochID
	for _, scc := range sccs {
		for _, id := range scc {
			if id == epochID {
				group = scc
				break
			}
		}
		if group != nil {
			break
		}
	}
	if group == nil {
		b.mu.Unlock()
		return PrepareResolutionResult{}, fmt.Errorf("prepare_resolution: epoch %q not in any SCC", epochID)
	}

	b.nextGroupID++
	gid := b.nextGroupID
	members := make([]string, 0, len(group))
	for _, id := range group {
		members = append(members, string(id))
	}
	sort.Strings(members)
	graphGen := b.graphGen
	seqNum := b.nextSeq()
	rec := WALRecord{SeqNum: seqNum, ControlOp: "group_prepare",
		GroupID: gid, Members: members, GraphGeneration: graphGen}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return PrepareResolutionResult{}, fmt.Errorf("prepare_resolution WAL: %w", err)
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	defer func() {
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
	}()
	b.activeGroups[gid] = &finalizeGroup{
		id:       gid,
		members:  group,
		graphGen: graphGen,
		state:    "pending",
	}

	log.Printf("[backend] PrepareResolution: epoch=%q group_id=%d members=%v graph_gen=%d",
		epochID, gid, members, graphGen)
	return PrepareResolutionResult{
		GroupID:         gid,
		Members:         members,
		GraphGeneration: graphGen,
	}, nil
}

// BeginFinalizeResult reports the outcome of starting group finalization.
type BeginFinalizeResult struct {
	Status string `json:"status"` // "pending", "finalized", "failed"
}

// BeginFinalize starts the promote/finalize pass for an entire group (SCC).
// The graph_generation must match the current b.graphGen; a mismatch means
// the dependency graph changed between PrepareResolution and BeginFinalize
// (TOCTOU) and the call is refused. Every member must already be independently
// AuthorizedPending; this function must not authorize one member on behalf of
// another.
func (b *Backend) BeginFinalize(groupID int, graphGeneration int64) (BeginFinalizeResult, error) {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	g, ok := b.activeGroups[groupID]
	if !ok {
		b.mu.Unlock()
		return BeginFinalizeResult{}, fmt.Errorf("begin_finalize: group %d not found", groupID)
	}
	if g.state == "finalized" {
		b.mu.Unlock()
		return BeginFinalizeResult{Status: "finalized"}, nil
	}
	if b.graphGen != graphGeneration {
		b.mu.Unlock()
		return BeginFinalizeResult{}, fmt.Errorf(
			"begin_finalize: graph_generation mismatch (caller=%d, current=%d): dependency graph changed (TOCTOU)",
			graphGeneration, b.graphGen)
	}
	// Verify every member is still present, independently authorized, and not
	// already finalizing. A primary epoch's policy decision must not authorize
	// its SCC siblings.
	for _, id := range g.members {
		ep, ok := b.epochs[id]
		if !ok {
			b.mu.Unlock()
			return BeginFinalizeResult{}, fmt.Errorf("begin_finalize: member %q disappeared", id)
		}
		if ep.State < AuthorizedPending {
			b.mu.Unlock()
			return BeginFinalizeResult{}, fmt.Errorf("begin_finalize: member %q not independently authorized (state=%s)", id, ep.State)
		}
		if ep.State >= Finalizing {
			b.mu.Unlock()
			return BeginFinalizeResult{}, fmt.Errorf("begin_finalize: member %q already %s", id, ep.State)
		}
	}

	members := append([]EpochID(nil), g.members...)
	g.state = "finalizing"
	g.finalizeErr = ""
	b.mu.Unlock()

	// Fix 2: WAL durability barrier BEFORE any promotion. This ensures
	// authorization records and all version records are durable before
	// files are published to the backing store.
	for _, id := range members {
		if err := b.FlushEpochWAL(id); err != nil {
			b.mu.Lock()
			g.state = "failed"
			g.finalizeErr = fmt.Sprintf("WAL barrier: %v", err)
			b.mu.Unlock()
			return BeginFinalizeResult{}, fmt.Errorf("begin_finalize: WAL barrier for %q: %w", id, err)
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Quiesce + flush each member, then promote.
	var firstErr string
	for _, id := range members {
		ep := b.epochs[id]
		if ep == nil || ep.State >= Finalized {
			continue
		}
		if err := b.quiesceMappings(ep); err != nil {
			ep.FinalizeErr = fmt.Sprintf("mmap quiesce: %v", err)
			if firstErr == "" {
				firstErr = fmt.Sprintf("member %q: mmap quiesce: %v", id, err)
			}
			log.Printf("[backend] BeginFinalize: epoch=%q ABORTED: %v", id, err)
			continue
		}
		if err := b.flushEpochFDs(id); err != nil {
			ep.FinalizeErr = fmt.Sprintf("flush fds: %v", err)
			if firstErr == "" {
				firstErr = fmt.Sprintf("member %q: flush fds: %v", id, err)
			}
			log.Printf("[backend] BeginFinalize: epoch=%q ABORTED: %v", id, err)
			continue
		}
	}
	_ = b.tryPromoteAll()

	// Update group state based on member outcomes.
	allFinalized := true
	for _, id := range members {
		ep := b.epochs[id]
		if ep == nil || ep.State != Finalized {
			allFinalized = false
			if ep != nil && ep.FinalizeErr != "" && firstErr == "" {
				firstErr = ep.FinalizeErr
			}
		}
	}
	if allFinalized {
		g.state = "finalized"
		g.finalizeErr = ""
	} else if firstErr != "" {
		g.state = "failed"
		g.finalizeErr = firstErr
	} else {
		g.state = "pending"
	}

	log.Printf("[backend] BeginFinalize: group=%d state=%s", groupID, g.state)
	return BeginFinalizeResult{Status: g.state}, nil
}

// GetFinalizeStatusResult reports the current state of a group finalization.
type GetFinalizeStatusResult struct {
	State       string `json:"state"`        // "pending", "finalized", "failed"
	FinalizeErr string `json:"finalize_err"` // first error if failed
}

// GetFinalizeStatus reports the current state of a group. Re-evaluates member
// states so that external retry_finalize calls are reflected.
func (b *Backend) GetFinalizeStatus(groupID int) (GetFinalizeStatusResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	g, ok := b.activeGroups[groupID]
	if !ok {
		return GetFinalizeStatusResult{}, fmt.Errorf("get_finalize_status: group %d not found", groupID)
	}
	// Re-evaluate state from member epochs.
	allFinalized := true
	var firstErr string
	for _, id := range g.members {
		ep, ok := b.epochs[id]
		if !ok {
			allFinalized = false
			continue
		}
		if ep.State != Finalized {
			allFinalized = false
			if ep.FinalizeErr != "" && firstErr == "" {
				firstErr = ep.FinalizeErr
			}
		}
	}
	if allFinalized {
		g.state = "finalized"
		g.finalizeErr = ""
	} else if firstErr != "" {
		g.state = "failed"
		g.finalizeErr = firstErr
	} else {
		g.state = "pending"
	}
	return GetFinalizeStatusResult{State: g.state, FinalizeErr: g.finalizeErr}, nil
}

// CancelGroup drops an in-flight prepare_resolution group that the orchestrator
// intentionally abandons before begin_finalize/release, for example because an
// SCC sibling has not yet reached AuthorizedPending. A finalized group cannot
// be cancelled; it must be completed via AckReleaseGroup so terminal epoch
// records are not lost.
func (b *Backend) CancelGroup(groupID int) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	g, ok := b.activeGroups[groupID]
	if !ok {
		b.mu.Unlock()
		return nil
	}
	if g.state != "pending" {
		b.mu.Unlock()
		return fmt.Errorf("cancel_group: group %d is %s; use retry/ack group flow", groupID, g.state)
	}
	seqNum := b.nextSeq()
	rec := WALRecord{SeqNum: seqNum, ControlOp: "group_delete", GroupID: groupID}
	b.mu.Unlock()

	if err := <-b.submitWAL(rec); err != nil {
		b.applyTurnAbort(seqNum)
		return fmt.Errorf("cancel_group WAL: %w", err)
	}

	b.mu.Lock()
	b.applyTurnWait(seqNum)
	delete(b.activeGroups, groupID)
	b.applyTurnDone(seqNum)
	b.mu.Unlock()
	log.Printf("[backend] CancelGroup: group=%d", groupID)
	return nil
}

// AckReleaseGroup releases all members of a finalized group. Writes WAL
// release_ack records for all members as a single batch, then drops their
// terminal records. Refuses if the group has not reached "finalized".
func (b *Backend) AckReleaseGroup(groupID int) error {
	b.opRW.RLock()
	defer b.opRW.RUnlock()

	b.mu.Lock()
	g, ok := b.activeGroups[groupID]
	if !ok {
		b.mu.Unlock()
		return fmt.Errorf("ack_release_group: group %d not found", groupID)
	}
	if g.state != "finalized" {
		state := g.state
		b.mu.Unlock()
		return fmt.Errorf("ack_release_group: group %d is %s, not finalized", groupID, state)
	}
	// Filter to members that still exist and are Finalized.
	pending := make([]EpochID, 0, len(g.members))
	for _, id := range g.members {
		if ep, ok := b.epochs[id]; ok && ep.State == Finalized {
			pending = append(pending, id)
		}
	}
	if len(pending) == 0 {
		seqNum := b.nextSeq()
		rec := WALRecord{SeqNum: seqNum, ControlOp: "group_delete", GroupID: groupID}
		b.mu.Unlock()
		if err := <-b.submitWAL(rec); err != nil {
			b.applyTurnAbort(seqNum)
			return fmt.Errorf("ack_release_group delete WAL: %w", err)
		}
		b.mu.Lock()
		b.applyTurnWait(seqNum)
		delete(b.activeGroups, groupID)
		b.applyTurnDone(seqNum)
		b.mu.Unlock()
		log.Printf("[backend] AckReleaseGroup: group=%d already fully acked", groupID)
		return nil
	}

	seqNums := make([]int64, 0, len(pending)+1)
	recs := make([]WALRecord, 0, len(pending)+1)
	for _, id := range pending {
		seqNum := b.nextSeq()
		seqNums = append(seqNums, seqNum)
		recs = append(recs, WALRecord{EpochID: string(id), SeqNum: seqNum, ControlOp: "release_ack"})
	}
	deleteSeq := b.nextSeq()
	seqNums = append(seqNums, deleteSeq)
	recs = append(recs, WALRecord{SeqNum: deleteSeq, ControlOp: "group_delete", GroupID: groupID})
	b.mu.Unlock()

	if err := <-b.submitWAL(recs...); err != nil {
		for _, sn := range seqNums {
			b.applyTurnAbort(sn)
		}
		return fmt.Errorf("ack_release_group WAL: %w", err)
	}

	b.mu.Lock()
	for i, sn := range seqNums {
		b.applyTurnWait(sn)
		if i < len(pending) {
			b.ackReleaseInternal(pending[i])
		} else {
			delete(b.activeGroups, groupID)
		}
		b.applyTurnDone(sn)
	}
	b.mu.Unlock()

	log.Printf("[backend] AckReleaseGroup: group=%d released (%d members)", groupID, len(pending))
	return nil
}
