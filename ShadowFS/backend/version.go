package backend

// This file defines the MVCC data model that replaces the old shared-overlay
// tracking (AgentState.UndoLog + fileDirty). The core ideas:
//
//   - EpochID is the unit of speculation, authorization, rollback and
//     finalization. It is DISTINCT from the cgroup ID: the cgroup only
//     provides kernel attribution (which process produced a FUSE op), while
//     the epoch owns file versions, dependency edges and lifecycle state.
//   - Every mutation creates a FileVersion owned by exactly one epoch. All
//     versions of one logical path form a chain ordered by WAL seq; the
//     newest chain entry is the globally visible head. Rolling an epoch back
//     removes its versions and RE-EXPOSES the predecessor version (or the
//     backing file when the chain empties).
//   - Readers resolve the exact version they observe (Resolve) and record a
//     producer -> consumer read-from edge for it, instead of depending on
//     every historical writer of the path.

// EpochID identifies one speculative epoch. Explicit epochs are registered by
// the orchestrator via begin_epoch; operations arriving from a cgroup with no
// registered epoch are attributed to an auto-created "implicit:<cgroupID>"
// epoch so legacy cgroup-only flows keep working.
type EpochID string

// VersionID is a globally monotonic identifier for one FileVersion. It is
// allocated independently of the WAL seq. 0 is reserved for "the backing
// (orig) file", i.e. no speculative version.
type VersionID uint64

// ObjectID is the canonical logical identity of a tracked filesystem object:
// the cleaned absolute orig-side path.
type ObjectID = string

// VersionOp classifies what a FileVersion represents.
type VersionOp int

const (
	// OpWrite: file content (create / modify / copy-up target / setattr / xattr change). StagePath holds the content.
	OpWrite VersionOp = iota
	// OpMkdir: a directory created speculatively.
	OpMkdir
	// OpWhiteout: the object was deleted (unlink / rmdir / rename source).
	// Dir distinguishes rmdir (recursive promote) from unlink.
	OpWhiteout
	// OpLink: a hard link created at LogicalPath pointing at LinkTarget.
	OpLink
	// OpMknod: a special file (FIFO / socket / device node).
	OpMknod
	// OpXattr is reserved for standalone metadata versions; the current
	// implementation routes xattr/metadata changes through OpWrite copy-up.
	OpXattr
	// OpRename: a namespace-only rename. The new path references the old
	// path's physical version without copying content. Copy-up is deferred
	// until the renamed path is written. RenameFrom holds the source path.
	OpRename
)

func (op VersionOp) String() string {
	switch op {
	case OpWrite:
		return "write"
	case OpMkdir:
		return "mkdir"
	case OpWhiteout:
		return "whiteout"
	case OpLink:
		return "link"
	case OpMknod:
		return "mknod"
	case OpXattr:
		return "xattr"
	case OpRename:
		return "rename"
	default:
		return "unknown"
	}
}

// VersionState tracks a version's promotion status. Rolled-back versions are
// deleted from the graph immediately, so no explicit state exists for them.
type VersionState int

const (
	VSpeculative VersionState = iota
	VPromoted
)

// FileVersion is one node in an object's version chain.
type FileVersion struct {
	ID          VersionID
	Owner       EpochID
	LogicalPath ObjectID // canonical orig-side path
	StagePath   string   // staging/epochs/<epoch>/files/<rel>; "" for whiteouts
	// Parent is the version that was the visible head when this version was
	// created (0 = the backing file). Recomputed from chain order on WAL
	// replay; the checkpoint persists the applied value.
	Parent    VersionID
	Seq       int64 // WAL seq; total order within one object's chain
	Operation VersionOp
	State     VersionState

	// Op-specific payload.
	Mode       uint32 // mkdir / mknod mode (incl. S_IFMT bits for mknod)
	Rdev       uint64 // mknod device number
	RenameFrom string // OpRename: source logical path
	LinkTarget string // OpLink: orig path of the link target
	Dir        bool   // OpWhiteout: true when the deleted object is a directory
	// Fix 4: SourceVersion identifies the version whose physical content
	// this rename references. 0 = backing file. Used by the rename batch
	// planner to resolve the actual physical path at promotion time,
	// instead of relying on a potentially-stale StagePath.
	SourceVersion VersionID
}

// EpochState holds the lifecycle and version ownership of a single epoch.
type EpochState struct {
	ID        EpochID
	CgroupID  string // kernel attribution only; may be "" for control-only epochs
	SessionID string
	// State reuses the AgentLifecycle ladder: Speculative ->
	// AuthorizedPending -> Finalizing -> Finalized.
	State       AgentLifecycle
	FinalizeErr string
	// PolicyHash is the stable hash of the process-layer policy durably bound
	// to this epoch when it entered AuthorizedPending. Empty means legacy/no
	// policy hash and must be treated fail-closed by new orchestrators.
	PolicyHash string
	// Versions lists the VersionIDs owned by this epoch in seq order.
	Versions []VersionID
	// ReadFrom is the set of foreign versions this epoch actually observed
	// (the materialized read-from edges). Used to dedupe read_dep WAL
	// records: each (epoch, version) pair is logged at most once.
	ReadFrom map[VersionID]struct{}
}

// approved reports whether the epoch's policy has been approved (it has
// reached AuthorizedPending or beyond).
func (e *EpochState) approved() bool { return e.State >= AuthorizedPending }

// ResolveResult is the outcome of resolving a logical path for one epoch's
// view. PhysicalPath is where the bytes live (a version StagePath or the
// backing orig path); Version/Producer identify the observed version so the
// caller can attribute a read-from dependency. Exists=false means the path is
// hidden by a whiteout version (PhysicalPath is then empty). Note that
// Exists=true with Version==0 only means "no speculative version": the
// backing file itself may or may not exist — callers lstat PhysicalPath.
type ResolveResult struct {
	PhysicalPath string
	Version      VersionID // 0 = backing base
	Producer     EpochID   // "" = backing
	Exists       bool
	// Err is set when resolving would require a dependency edge that could not
	// be durably recorded. Callers must fail closed instead of reading the path.
	Err error
	// Op is the observed version's operation (meaningful when Version != 0).
	Op VersionOp
}
