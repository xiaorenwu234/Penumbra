package backend

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"path/filepath"
)

const stateFileName = ".shadow_state.json"
const walFileName = ".shadow_wal"

// persistFormatVersion is the on-disk format generation. v2 introduced the
// MVCC version graph (epochs + FileVersions). There is NO migration from v1:
// a legacy checkpoint/WAL is refused at startup (fail closed) — the staging
// area must be cleared to restart fresh.
const persistFormatVersion = 2

// legacyStateFileName / legacyWALFileName are the v1 locations (staging
// root). Their presence indicates un-migrated v1 state and aborts startup.
const legacyStateFileName = ".shadow_state.json"
const legacyWALFileName = ".shadow_wal"

// PersistState is the top-level v2 checkpoint structure: the complete
// version graph, not just a dirty-path set.
type PersistState struct {
	FormatVersion int                      `json:"format_version"`
	Seq           int64                    `json:"seq"`
	NextVersion   uint64                   `json:"next_version"`
	ImplicitCtr   int64                    `json:"implicit_ctr,omitempty"`
	NextGroupID   int                      `json:"next_group_id,omitempty"`
	Epochs        map[string]*PersistEpoch `json:"epochs"`
	Versions      []PersistVersion         `json:"versions"`
	VisibleHead   map[string]uint64        `json:"visible_head"`
	Dependents    map[string][]string      `json:"dependents"`
	DependsOn     map[string][]string      `json:"depends_on"`
	ActiveEpochs  map[string]string        `json:"active_epochs"` // cgroupID -> epochID
	ActiveGroups  map[int]*PersistGroup    `json:"active_groups,omitempty"`
}

// PersistEpoch is the per-epoch state serialized to disk. The epoch's
// Versions list is rebuilt from the global Versions slice (seq order), so it
// is not stored redundantly.
type PersistEpoch struct {
	ID          string         `json:"id"`
	CgroupID    string         `json:"cgroup_id,omitempty"`
	SessionID   string         `json:"session_id,omitempty"`
	State       AgentLifecycle `json:"state"`
	FinalizeErr string         `json:"finalize_err,omitempty"`
	PolicyHash  string         `json:"policy_hash,omitempty"`
	ReadFrom    []uint64       `json:"read_from,omitempty"`
}

// PersistGroup preserves an in-flight/finalized SCC group across checkpoint
// recovery so ack_release_group can remain fail-closed and retryable.
type PersistGroup struct {
	ID          int      `json:"id"`
	Members     []string `json:"members"`
	GraphGen    int64    `json:"graph_gen"`
	State       string   `json:"state"`
	FinalizeErr string   `json:"finalize_err,omitempty"`
}

// PersistVersion is the flat serialized form of a FileVersion. Shared by the
// checkpoint (Versions slice) and WAL mutation records.
type PersistVersion struct {
	ID          uint64 `json:"id"`
	Owner       string `json:"owner"`
	LogicalPath string `json:"path"`
	StagePath   string `json:"stage_path,omitempty"`
	Parent      uint64 `json:"parent,omitempty"`
	Seq         int64  `json:"seq"`
	Op          int    `json:"op"`
	State       int    `json:"state,omitempty"`
	Mode        uint32 `json:"mode,omitempty"`
	Rdev        uint64 `json:"rdev,omitempty"`
	RenameFrom  string `json:"rename_from,omitempty"`
	LinkTarget  string `json:"link_target,omitempty"`
	Dir         bool   `json:"dir,omitempty"`
}

// marshalVersion converts a FileVersion to its serializable form.
func marshalVersion(v *FileVersion) PersistVersion {
	return PersistVersion{
		ID:          uint64(v.ID),
		Owner:       string(v.Owner),
		LogicalPath: v.LogicalPath,
		StagePath:   v.StagePath,
		Parent:      uint64(v.Parent),
		Seq:         v.Seq,
		Op:          int(v.Operation),
		State:       int(v.State),
		Mode:        v.Mode,
		Rdev:        v.Rdev,
		RenameFrom:  v.RenameFrom,
		LinkTarget:  v.LinkTarget,
		Dir:         v.Dir,
	}
}

// unmarshalVersion converts a PersistVersion back to a FileVersion.
func unmarshalVersion(p *PersistVersion) *FileVersion {
	return &FileVersion{
		ID:          VersionID(p.ID),
		Owner:       EpochID(p.Owner),
		LogicalPath: p.LogicalPath,
		StagePath:   p.StagePath,
		Parent:      VersionID(p.Parent),
		Seq:         p.Seq,
		Operation:   VersionOp(p.Op),
		State:       VersionState(p.State),
		Mode:        p.Mode,
		Rdev:        p.Rdev,
		RenameFrom:  p.RenameFrom,
		LinkTarget:  p.LinkTarget,
		Dir:         p.Dir,
	}
}

// snapshot creates a deep copy of the backend state for serialization.
// Must be called with b.mu held.
func (b *Backend) snapshot() *PersistState {
	state := &PersistState{
		FormatVersion: persistFormatVersion,
		Seq:           b.seq,
		NextVersion:   b.nextVersion,
		ImplicitCtr:   b.implicitCtr,
		NextGroupID:   b.nextGroupID,
		Epochs:        make(map[string]*PersistEpoch, len(b.epochs)),
		Versions:      make([]PersistVersion, 0, len(b.versionByID)),
		VisibleHead:   make(map[string]uint64, len(b.visibleHead)),
		Dependents:    make(map[string][]string, len(b.dependents)),
		DependsOn:     make(map[string][]string, len(b.dependsOn)),
		ActiveEpochs:  make(map[string]string, len(b.activeEpochByCgroup)),
		ActiveGroups:  make(map[int]*PersistGroup, len(b.activeGroups)),
	}

	for id, ep := range b.epochs {
		pe := &PersistEpoch{
			ID:          string(ep.ID),
			CgroupID:    ep.CgroupID,
			SessionID:   ep.SessionID,
			State:       ep.State,
			FinalizeErr: ep.FinalizeErr,
			PolicyHash:  ep.PolicyHash,
		}
		for vid := range ep.ReadFrom {
			pe.ReadFrom = append(pe.ReadFrom, uint64(vid))
		}
		state.Epochs[string(id)] = pe
	}
	// Serialize versions in per-object chain order so loadState can rebuild
	// the chains by simple append.
	for obj, chain := range b.versionsByObject {
		_ = obj
		for _, vid := range chain {
			if v, ok := b.versionByID[vid]; ok {
				state.Versions = append(state.Versions, marshalVersion(v))
			}
		}
	}
	for obj, head := range b.visibleHead {
		state.VisibleHead[obj] = uint64(head)
	}
	for src, dsts := range b.dependents {
		list := make([]string, 0, len(dsts))
		for d := range dsts {
			list = append(list, string(d))
		}
		state.Dependents[string(src)] = list
	}
	for src, dsts := range b.dependsOn {
		list := make([]string, 0, len(dsts))
		for d := range dsts {
			list = append(list, string(d))
		}
		state.DependsOn[string(src)] = list
	}
	for cg, ep := range b.activeEpochByCgroup {
		state.ActiveEpochs[cg] = string(ep)
	}
	for gid, g := range b.activeGroups {
		pg := &PersistGroup{
			ID:          g.id,
			Members:     make([]string, 0, len(g.members)),
			GraphGen:    g.graphGen,
			State:       g.state,
			FinalizeErr: g.finalizeErr,
		}
		for _, id := range g.members {
			pg.Members = append(pg.Members, string(id))
		}
		state.ActiveGroups[gid] = pg
	}
	return state
}

// loadState restores all internal fields from a PersistState. Must be called
// with b.mu held (or before the backend is shared). Returns an error for a
// non-v2 snapshot (fail closed; no silent fresh start).
func (b *Backend) loadState(state *PersistState) error {
	if state.FormatVersion != persistFormatVersion {
		return fmt.Errorf("unsupported checkpoint format %d (want %d): clear the staging dir to start fresh",
			state.FormatVersion, persistFormatVersion)
	}
	b.seq = state.Seq
	b.nextVersion = state.NextVersion
	b.implicitCtr = state.ImplicitCtr
	b.nextGroupID = state.NextGroupID

	b.epochs = make(map[EpochID]*EpochState, len(state.Epochs))
	for id, pe := range state.Epochs {
		ep := &EpochState{
			ID:          EpochID(pe.ID),
			CgroupID:    pe.CgroupID,
			SessionID:   pe.SessionID,
			State:       pe.State,
			FinalizeErr: pe.FinalizeErr,
			PolicyHash:  pe.PolicyHash,
			ReadFrom:    make(map[VersionID]struct{}, len(pe.ReadFrom)),
		}
		for _, vid := range pe.ReadFrom {
			ep.ReadFrom[VersionID(vid)] = struct{}{}
		}
		b.epochs[EpochID(id)] = ep
	}

	b.versionByID = make(map[VersionID]*FileVersion, len(state.Versions))
	b.versionsByObject = make(map[ObjectID][]VersionID)
	for i := range state.Versions {
		v := unmarshalVersion(&state.Versions[i])
		b.versionByID[v.ID] = v
		b.versionsByObject[v.LogicalPath] = append(b.versionsByObject[v.LogicalPath], v.ID)
		if ep, ok := b.epochs[v.Owner]; ok {
			ep.Versions = append(ep.Versions, v.ID)
		}
	}
	// Chains were serialized in seq order per object, but interleaved across
	// objects; normalize each chain and each epoch's version list by seq.
	for obj := range b.versionsByObject {
		b.sortChainBySeq(b.versionsByObject[obj])
	}
	for _, ep := range b.epochs {
		b.sortChainBySeq(ep.Versions)
	}

	b.visibleHead = make(map[ObjectID]VersionID, len(state.VisibleHead))
	for obj, head := range state.VisibleHead {
		b.visibleHead[obj] = VersionID(head)
	}

	b.dependents = make(map[EpochID]map[EpochID]struct{}, len(state.Dependents))
	for src, dsts := range state.Dependents {
		set := make(map[EpochID]struct{}, len(dsts))
		for _, d := range dsts {
			set[EpochID(d)] = struct{}{}
		}
		b.dependents[EpochID(src)] = set
	}
	b.dependsOn = make(map[EpochID]map[EpochID]struct{}, len(state.DependsOn))
	for src, dsts := range state.DependsOn {
		set := make(map[EpochID]struct{}, len(dsts))
		for _, d := range dsts {
			set[EpochID(d)] = struct{}{}
		}
		b.dependsOn[EpochID(src)] = set
	}
	b.activeEpochByCgroup = make(map[string]EpochID, len(state.ActiveEpochs))
	for cg, ep := range state.ActiveEpochs {
		b.activeEpochByCgroup[cg] = EpochID(ep)
	}
	b.activeGroups = make(map[int]*finalizeGroup, len(state.ActiveGroups))
	for gid, pg := range state.ActiveGroups {
		if pg == nil {
			continue
		}
		members := make([]EpochID, 0, len(pg.Members))
		for _, id := range pg.Members {
			members = append(members, EpochID(id))
		}
		id := pg.ID
		if id == 0 {
			id = gid
		}
		b.activeGroups[gid] = &finalizeGroup{
			id:          id,
			members:     members,
			graphGen:    pg.GraphGen,
			state:       pg.State,
			finalizeErr: pg.FinalizeErr,
		}
		if gid > b.nextGroupID {
			b.nextGroupID = gid
		}
	}

	log.Printf("[backend] state recovered: %d epochs, %d versions, %d heads",
		len(b.epochs), len(b.versionByID), len(b.visibleHead))
	return nil
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

// persistFilePath returns the full path to the v2 state file.
func persistFilePath(stagingDir string) string {
	return filepath.Join(metadataDir(stagingDir), stateFileName)
}

// walFilePath returns the full path to the v2 WAL file.
func walFilePath(stagingDir string) string {
	return filepath.Join(metadataDir(stagingDir), walFileName)
}

// detectLegacyState reports an error when un-migrated v1 persistence files
// exist at the staging root. Fail closed: silently ignoring them could
// resurrect stale overlay content or lose tracked speculative state.
func detectLegacyState(stagingDir string) error {
	for _, name := range []string{legacyStateFileName, legacyWALFileName} {
		p := filepath.Join(stagingDir, name)
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("legacy v1 staging state %q found: no migration is supported, clear the staging dir to start fresh", p)
		}
	}
	return nil
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

// WALRecord represents a single v2 WAL entry inside a transaction envelope.
//
// SeqNum is a record-level sequence number used by replay to skip records
// already incorporated into the latest checkpoint snapshot.
//
// ControlOp marks the record as a state-management op rather than a
// mutation. Empty means "normal mutation" (Version != nil). Recognised
// values: "begin_epoch", "commit", "rollback", "read_dep", "release_ack",
// "group_prepare", "group_delete". The "commit" record carries PolicyHash
// when used as an independent authorization record.
type WALRecord struct {
	// Format is the WAL record generation (persistFormatVersion). Records
	// without it are legacy v1 records and abort recovery.
	Format    int    `json:"v"`
	EpochID   string `json:"epoch_id,omitempty"`
	CgroupID  string `json:"cgroup_id,omitempty"`  // begin_epoch payload
	SessionID string `json:"session_id,omitempty"` // begin_epoch payload
	SeqNum    int64  `json:"seq"`
	ControlOp string `json:"control_op,omitempty"`
	PolicyHash string `json:"policy_hash,omitempty"`
	// Version carries the mutation payload (nil for control records).
	Version *PersistVersion `json:"version,omitempty"`
	// ReadVersion + ObjectPath carry a read_dep record's observed version.
	ReadVersion uint64 `json:"read_version,omitempty"`
	ObjectPath  string `json:"object_path,omitempty"`
	// GroupID/Members/GraphGeneration carry group_prepare/group_delete records.
	GroupID         int      `json:"group_id,omitempty"`
	Members         []string `json:"members,omitempty"`
	GraphGeneration int64    `json:"graph_generation,omitempty"`
}

type walFrame struct {
	Format   int    `json:"v"`
	Op       string `json:"wal_op"`
	TxID     string `json:"tx_id,omitempty"`
	Count    int    `json:"count,omitempty"`
	Checksum uint32 `json:"checksum,omitempty"`
}

// appendWAL appends one transaction envelope to the WAL file and fsyncs both
// the file and its parent directory to guarantee durability.
//
// The transaction format is:
//
//	tx_begin(tx_id, count, checksum), record..., tx_commit(tx_id)
//
// Replay applies only complete transactions whose record payload checksum
// matches the begin frame. An incomplete tail transaction is discarded; corrupt
// or incomplete transactions followed by later data fail closed during load.
func appendWAL(path string, records []WALRecord) error {
	if len(records) == 0 {
		return nil
	}
	var recordsBuf []byte
	for i := range records {
		records[i].Format = persistFormatVersion
		data, err := json.Marshal(&records[i])
		if err != nil {
			return fmt.Errorf("marshal WAL record: %w", err)
		}
		recordsBuf = append(recordsBuf, data...)
		recordsBuf = append(recordsBuf, '\n')
	}
	txID := fmt.Sprintf("%d:%d", records[0].SeqNum, len(records))
	checksum := crc32.ChecksumIEEE(recordsBuf)
	begin, err := json.Marshal(walFrame{Format: persistFormatVersion, Op: "tx_begin", TxID: txID, Count: len(records), Checksum: checksum})
	if err != nil {
		return fmt.Errorf("marshal WAL tx_begin: %w", err)
	}
	commit, err := json.Marshal(walFrame{Format: persistFormatVersion, Op: "tx_commit", TxID: txID})
	if err != nil {
		return fmt.Errorf("marshal WAL tx_commit: %w", err)
	}

	var buf []byte
	buf = append(buf, begin...)
	buf = append(buf, '\n')
	buf = append(buf, recordsBuf...)
	buf = append(buf, commit...)
	buf = append(buf, '\n')

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open WAL file: %w", err)
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return fmt.Errorf("write WAL transaction: %w", err)
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

// loadWAL reads complete WAL transactions from the file. Returns nil slice if
// the file does not exist. Unsupported format, standalone records, or non-tail
// corrupt transactions are hard errors (fail closed), NOT silent skips.
func loadWAL(path string) ([]WALRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open WAL for read: %w", err)
	}
	defer f.Close()

	var lines [][]byte
	scanner := bufio.NewScanner(f)
	// Allow large lines (up to 4MB per record).
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(line) != 0 {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan WAL: %w", err)
	}

	var records []WALRecord
	var tx *walFrame
	var txRecords []WALRecord
	var txBuf []byte

	for i, line := range lines {
		lastLine := i == len(lines)-1
		var frame walFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			if lastLine {
				log.Printf("[backend] WAL: discarding corrupt tail line: %v", err)
				break
			}
			return nil, fmt.Errorf("WAL corrupt non-tail line %d: %w", i+1, err)
		}
		if frame.Format != persistFormatVersion {
			return nil, fmt.Errorf("WAL record format %d unsupported (want %d): clear the staging dir to start fresh",
				frame.Format, persistFormatVersion)
		}

		switch frame.Op {
		case "tx_begin":
			if tx != nil {
				return nil, fmt.Errorf("WAL transaction %q missing commit before line %d", tx.TxID, i+1)
			}
			if frame.TxID == "" || frame.Count < 0 {
				return nil, fmt.Errorf("WAL malformed tx_begin at line %d", i+1)
			}
			begin := frame
			tx = &begin
			txRecords = nil
			txBuf = nil
		case "tx_commit":
			if tx == nil {
				return nil, fmt.Errorf("WAL tx_commit without tx_begin at line %d", i+1)
			}
			if frame.TxID != tx.TxID || len(txRecords) != tx.Count || crc32.ChecksumIEEE(txBuf) != tx.Checksum {
				if lastLine {
					log.Printf("[backend] WAL: discarding incomplete/corrupt tail transaction %q", tx.TxID)
					return records, nil
				}
				return nil, fmt.Errorf("WAL transaction %q failed integrity check at line %d", tx.TxID, i+1)
			}
			records = append(records, txRecords...)
			tx = nil
			txRecords = nil
			txBuf = nil
		case "":
			if tx == nil {
				return nil, fmt.Errorf("WAL record outside transaction at line %d", i+1)
			}
			var rec WALRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				return nil, fmt.Errorf("unmarshal WAL record at line %d: %w", i+1, err)
			}
			if rec.Format != persistFormatVersion {
				return nil, fmt.Errorf("WAL record format %d unsupported (want %d): clear the staging dir to start fresh",
					rec.Format, persistFormatVersion)
			}
			txRecords = append(txRecords, rec)
			txBuf = append(txBuf, line...)
			txBuf = append(txBuf, '\n')
		default:
			return nil, fmt.Errorf("WAL unknown frame %q at line %d", frame.Op, i+1)
		}
	}
	if tx != nil {
		log.Printf("[backend] WAL: discarding incomplete tail transaction %q", tx.TxID)
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

// fsyncFile opens the named file and fsyncs it. Used by promotion to flush
// promoted data pages.
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
