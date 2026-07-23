package backend

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const stateFileName = ".shadow_state.json"
const walFileName = ".shadow_wal"

// PersistState is the top-level structure serialized to disk.
type PersistState struct {
	Agents     map[string]*PersistAgent `json:"agents"`
	Dependents map[string][]string      `json:"dependents"`
	DependsOn  map[string][]string      `json:"depends_on"`
	FileDirty  map[string][]string      `json:"file_dirty"`
	Seq        int64                    `json:"seq"`
}

// PersistAgent is the per-agent state serialized to disk.
type PersistAgent struct {
	CgroupID   string              `json:"cgroup_id"`
	UndoLog    []SerializableEntry `json:"undo_log"`
	DirtyFiles []string            `json:"dirty_files"`
	// State is the explicit lifecycle (see AgentLifecycle). Committed is the
	// legacy field kept ONLY for reading checkpoints written before the
	// lifecycle refactor: loadState maps a legacy Committed=true to
	// AuthorizedPending and lets recovery re-derive Finalized. New checkpoints
	// always write State and leave Committed at its zero value.
	State         AgentLifecycle `json:"state"`
	Committed     bool           `json:"committed,omitempty"`
	FinalizeErr   string         `json:"finalize_err,omitempty"`
	EpochOpen     bool           `json:"epoch_open,omitempty"`
	EpochStartSeq int64          `json:"epoch_start_seq,omitempty"`
}

// snapshot creates a deep copy of the backend state for serialization.
// Must be called with b.mu held.
func (b *Backend) snapshot() *PersistState {
	state := &PersistState{
		Agents:     make(map[string]*PersistAgent, len(b.agents)),
		Dependents: make(map[string][]string, len(b.dependents)),
		DependsOn:  make(map[string][]string, len(b.dependsOn)),
		FileDirty:  make(map[string][]string, len(b.fileDirty)),
		Seq:        b.seq,
	}

	for id, agent := range b.agents {
		pa := &PersistAgent{
			CgroupID:      agent.CgroupID,
			UndoLog:       make([]SerializableEntry, 0, len(agent.UndoLog)),
			DirtyFiles:    make([]string, 0, len(agent.DirtyFiles)),
			State:         agent.State,
			FinalizeErr:   agent.FinalizeErr,
			EpochOpen:     agent.EpochOpen,
			EpochStartSeq: agent.EpochStartSeq,
		}
		for _, entry := range agent.UndoLog {
			pa.UndoLog = append(pa.UndoLog, MarshalEntry(entry))
		}
		for path := range agent.DirtyFiles {
			pa.DirtyFiles = append(pa.DirtyFiles, path)
		}
		state.Agents[id] = pa
	}

	for src, dsts := range b.dependents {
		list := make([]string, 0, len(dsts))
		for d := range dsts {
			list = append(list, d)
		}
		state.Dependents[src] = list
	}
	for src, dsts := range b.dependsOn {
		list := make([]string, 0, len(dsts))
		for d := range dsts {
			list = append(list, d)
		}
		state.DependsOn[src] = list
	}
	for path, writers := range b.fileDirty {
		list := make([]string, 0, len(writers))
		for w := range writers {
			list = append(list, w)
		}
		state.FileDirty[path] = list
	}
	return state
}

// loadState restores all internal fields from a PersistState.
// Must be called with b.mu held (or before the backend is shared).
func (b *Backend) loadState(state *PersistState) {
	b.seq = state.Seq

	b.agents = make(map[string]*AgentState, len(state.Agents))
	for id, pa := range state.Agents {
		agent := &AgentState{
			CgroupID:      pa.CgroupID,
			UndoLog:       make([]LogEntry, 0, len(pa.UndoLog)),
			DirtyFiles:    make(map[string]struct{}, len(pa.DirtyFiles)),
			State:         pa.State,
			FinalizeErr:   pa.FinalizeErr,
			EpochOpen:     pa.EpochOpen,
			EpochStartSeq: pa.EpochStartSeq,
		}
		// Backward compatibility: a checkpoint written before the lifecycle
		// refactor has State==Speculative(0) but may carry Committed=true.
		// Map that to AuthorizedPending; recovery's tryPromoteAll re-derives
		// Finalized where promotions succeed.
		if agent.State == Speculative && pa.Committed {
			agent.State = AuthorizedPending
		}
		for _, se := range pa.UndoLog {
			if entry := UnmarshalEntry(se); entry != nil {
				agent.UndoLog = append(agent.UndoLog, entry)
			}
		}
		for _, path := range pa.DirtyFiles {
			agent.DirtyFiles[path] = struct{}{}
		}
		b.agents[id] = agent
	}

	b.dependents = make(map[string]map[string]struct{}, len(state.Dependents))
	for src, dsts := range state.Dependents {
		set := make(map[string]struct{}, len(dsts))
		for _, d := range dsts {
			set[d] = struct{}{}
		}
		b.dependents[src] = set
	}
	b.dependsOn = make(map[string]map[string]struct{}, len(state.DependsOn))
	for src, dsts := range state.DependsOn {
		set := make(map[string]struct{}, len(dsts))
		for _, d := range dsts {
			set[d] = struct{}{}
		}
		b.dependsOn[src] = set
	}
	b.fileDirty = make(map[string]map[string]struct{}, len(state.FileDirty))
	for path, writers := range state.FileDirty {
		set := make(map[string]struct{}, len(writers))
		for _, w := range writers {
			set[w] = struct{}{}
		}
		b.fileDirty[path] = set
	}

	totalEntries := 0
	for _, agent := range b.agents {
		totalEntries += len(agent.UndoLog)
	}
	log.Printf("[backend] state recovered: %d agents, %d total undo entries", len(b.agents), totalEntries)
}

// saveToDisk atomically writes the state to disk.
func saveToDisk(path string, state *PersistState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	tmpPath := path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open tmp state file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write tmp state file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync tmp state file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close tmp state file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename state file: %w", err)
	}
	if err := fsyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("fsync state dir: %w", err)
	}
	return nil
}

// loadFromDisk reads and deserializes the persisted state.
func loadFromDisk(path string) (*PersistState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state file: %w", err)
	}
	var state PersistState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state file: %w", err)
	}
	return &state, nil
}

// persistFilePath returns the full path to the state file.
func persistFilePath(stagingDir string) string {
	return filepath.Join(stagingDir, stateFileName)
}

// fsyncDir fsyncs the given directory.
func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// --- WAL (Write-Ahead Log) ---

// WALRecord represents a single WAL entry. Each mutation operation appends
// one record. The record captures the serialized log entry plus the overlay
// paths that need fsync when the group commit fires.
//
// SeqNum is a record-level sequence number used by replay to skip records
// already incorporated into the latest checkpoint snapshot. For mutation
// records it mirrors Entry.SeqNum; for control records (Commit/Rollback)
// it is allocated via Backend.nextSeq.
//
// ControlOp marks the record as a state-management op rather than a
// mutation. Empty means "normal mutation". Recognised values: "commit",
// "rollback", "rollback_last", "begin_epoch", "commit_epoch",
// "rollback_epoch", "read_dep".
type WALRecord struct {
	CgroupID          string            `json:"cgroup_id"`
	SeqNum            int64             `json:"seq"`
	ControlOp         string            `json:"control_op,omitempty"`
	Entry             SerializableEntry `json:"entry"`
	DirtyOverlayPaths []string          `json:"dirty_overlay_paths,omitempty"`
}

// walFilePath returns the full path to the WAL file.
func walFilePath(stagingDir string) string {
	return filepath.Join(stagingDir, walFileName)
}

// appendWAL atomically appends a batch of records to the WAL file
// (newline-delimited JSON) and fsyncs both the file and its parent
// directory to guarantee durability.
//
// All records are serialized into a single in-memory buffer first, then
// written with one Write call. This ensures atomicity: if the write
// fails mid-batch, no partial (orphan) records are left in the file.
// Without this, a partial failure would leave record N in the file
// while its waiter received an error and aborted the mutation — replay
// would then silently re-apply an "aborted" operation.
func appendWAL(path string, records []WALRecord) error {
	// Serialize all records into a single buffer first.
	var buf []byte
	for _, rec := range records {
		data, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal WAL record: %w", err)
		}
		buf = append(buf, data...)
		buf = append(buf, '\n')
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open WAL file: %w", err)
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return fmt.Errorf("write WAL batch: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync WAL file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close WAL file: %w", err)
	}
	// fsync the parent directory so the WAL file's directory entry is
	// durable (critical when the file is first created).
	if err := fsyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("fsync WAL dir: %w", err)
	}
	return nil
}

// loadWAL reads all WAL records from the file. Returns nil slice if the
// file does not exist.
func loadWAL(path string) ([]WALRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open WAL for read: %w", err)
	}
	defer f.Close()

	var records []WALRecord
	scanner := bufio.NewScanner(f)
	// Allow large lines (up to 4MB per record).
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec WALRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			// Partial/corrupt record at tail — stop here (crash mid-write).
			log.Printf("[backend] WAL: skipping corrupt record: %v", err)
			break
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return records, fmt.Errorf("scan WAL: %w", err)
	}
	return records, nil
}

// truncateWAL empties the WAL file and fsyncs it plus the parent directory
// to ensure the truncation is durable.
func truncateWAL(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("truncate WAL: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync WAL after truncate: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close WAL after truncate: %w", err)
	}
	if err := fsyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("fsync WAL dir after truncate: %w", err)
	}
	return nil
}

// fsyncFile opens the named file and fsyncs it. Used by group commit to
// flush dirty overlay data pages.
func fsyncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // file removed between record and commit — OK
		}
		return err
	}
	defer f.Close()
	return f.Sync()
}
