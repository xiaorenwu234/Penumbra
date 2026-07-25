package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"wokron/shadowfs/backend"
)

// SocketServer provides a Unix socket control API for the ShadowFS backend.
type SocketServer struct {
	listener net.Listener
	sockPath string
}

// Request is the JSON request format for the socket API.
//
// EpochID is the PRIMARY addressing key (epochs own versions, policy and
// finalization). CgroupID is accepted as a legacy fallback: it resolves to
// the cgroup's currently-bound active epoch. begin_epoch takes both (epoch
// identity + kernel attribution).
type Request struct {
	Action    string `json:"action"`
	EpochID   string `json:"epoch_id,omitempty"`
	CgroupID  string `json:"cgroup_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`

	// Group-level finalization (Phase 3).
	GroupID         int   `json:"group_id,omitempty"`
	GraphGeneration int64 `json:"graph_generation,omitempty"`
}

// Response is the JSON response format for the socket API.
type Response struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	// EpochID echoes the epoch the action was applied to (useful when the
	// caller addressed by cgroup_id, or when begin_epoch generated one).
	EpochID string `json:"epoch_id,omitempty"`
	// Affected lists the CGROUPS touched by a cascade rollback (legacy
	// consumers coordinate the process layer per cgroup); AffectedEpochs
	// lists the epoch IDs.
	Affected       []string `json:"affected,omitempty"`
	AffectedEpochs []string `json:"affected_epochs,omitempty"`
	// Agents lists epoch IDs (legacy field name); AgentsInfo carries the
	// full per-epoch summaries.
	Agents     []string            `json:"agents,omitempty"`
	AgentsInfo []backend.EpochInfo `json:"agents_info,omitempty"`
	// Releasable reports whether the epoch's external side effects are safe
	// to externalize (i.e. it reached Finalized). Pointer so a false value
	// is still serialized.
	Releasable *bool `json:"releasable,omitempty"`
	// State is the epoch's lifecycle position: "speculative",
	// "authorized_pending", "finalizing", "finalized", or "unknown".
	State string `json:"state,omitempty"`
	// FinalizeErr, when non-empty, explains why an epoch is stuck short of
	// Finalized (e.g. a promotion I/O error to retry via retry_finalize).
	FinalizeErr string `json:"finalize_err,omitempty"`

	// Group-level finalization (Phase 3).
	GroupID         int      `json:"group_id,omitempty"`
	Members         []string `json:"members,omitempty"`
	GraphGeneration int64    `json:"graph_generation,omitempty"`
}

// NewSocketServer creates and starts a Unix socket server at the given path.
//
// The control socket is the ONLY control interface. It is hardened against a
// co-located unprivileged agent: the socket lives in a 0700 directory and is
// itself 0600, and every accepted connection is peer-authenticated
// (SO_PEERCRED) to the daemon's own uid.
func NewSocketServer(sockPath string) (*SocketServer, error) {
	// Remove stale socket file if it exists
	os.Remove(sockPath)

	// Restrict the containing directory to the daemon's uid (0700) so no other
	// user can even reach the socket path.
	if dir := filepath.Dir(sockPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		_ = os.Chmod(dir, 0o700)
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	// Restrict the socket file itself to owner rw only (0600).
	if err := os.Chmod(sockPath, 0o600); err != nil {
		listener.Close()
		return nil, err
	}

	s := &SocketServer{
		listener: listener,
		sockPath: sockPath,
	}

	go s.acceptLoop()
	log.Printf("[socket] listening on %s (0600, peer-authenticated)", sockPath)
	return s, nil
}

// Close shuts down the socket server.
func (s *SocketServer) Close() {
	s.listener.Close()
	os.Remove(s.sockPath)
}

func (s *SocketServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("[socket] accept error: %v", err)
			}
			return
		}
		// Peer authentication: reject any client whose uid is not the daemon's
		// own (defense-in-depth beyond the 0600 socket perms).
		if !authorizedPeer(conn) {
			conn.Close()
			continue
		}
		go s.handleConn(conn)
	}
}

// authorizedPeer verifies the connecting peer's uid via SO_PEERCRED and only
// admits a process running as the daemon's own uid (the orchestrator). Any
// other uid (e.g. a sandboxed agent) is rejected.
func authorizedPeer(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		log.Printf("[socket] reject: non-unix connection")
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		log.Printf("[socket] reject: SyscallConn: %v", err)
		return false
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		log.Printf("[socket] reject: Control: %v", err)
		return false
	}
	if credErr != nil {
		log.Printf("[socket] reject: SO_PEERCRED: %v", credErr)
		return false
	}
	self := uint32(os.Geteuid())
	if cred.Uid != self {
		log.Printf("[socket] reject: peer uid=%d pid=%d != daemon uid=%d",
			cred.Uid, cred.Pid, self)
		return false
	}
	return true
}

func (s *SocketServer) handleConn(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	encoder := json.NewEncoder(conn)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			encoder.Encode(Response{Status: "error", Message: "invalid JSON: " + err.Error()})
			continue
		}

		resp := s.handleRequest(req)
		encoder.Encode(resp)
	}
}

// resolveEpoch maps a request to the epoch it addresses: epoch_id when
// given, else the cgroup's active epoch. When the cgroup has no bound epoch,
// create=true lazily registers one (implicit-epoch compat for legacy
// cgroup-only callers, logged as deprecated); create=false returns an error.
func resolveEpoch(req Request, create bool) (backend.EpochID, error) {
	if req.EpochID != "" {
		return backend.EpochID(req.EpochID), nil
	}
	if req.CgroupID == "" {
		return "", fmt.Errorf("epoch_id or cgroup_id required")
	}
	if id, ok := shadowBackend.ActiveEpochForCgroup(req.CgroupID); ok {
		log.Printf("[socket] DEPRECATED cgroup-only addressing: cgroup=%q -> epoch=%q", req.CgroupID, id)
		return id, nil
	}
	if !create {
		return "", fmt.Errorf("no active epoch for cgroup %q", req.CgroupID)
	}
	id, err := shadowBackend.EpochForCgroup(req.CgroupID)
	if err != nil {
		return "", err
	}
	log.Printf("[socket] DEPRECATED cgroup-only addressing: cgroup=%q -> new implicit epoch=%q", req.CgroupID, id)
	return id, nil
}

func (s *SocketServer) handleRequest(req Request) Response {
	switch req.Action {
	case "begin_epoch":
		// Explicit epoch registration. epoch_id + cgroup_id preferred; a
		// legacy cgroup-only caller gets a generated epoch id back.
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		epochID := req.EpochID
		if epochID == "" {
			epochID = fmt.Sprintf("epoch-%s-%d", filepath.Base(req.CgroupID), time.Now().UnixNano())
			log.Printf("[socket] DEPRECATED begin_epoch without epoch_id: generated %q", epochID)
		}
		log.Printf("[socket] begin_epoch epoch=%q cgroup=%q session=%q", epochID, req.CgroupID, req.SessionID)
		if err := shadowBackend.BeginEpoch(backend.EpochID(epochID), req.CgroupID, req.SessionID); err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok", EpochID: epochID}

	case "authorize":
		epochID, err := resolveEpoch(req, true)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		log.Printf("[socket] authorize epoch=%q", epochID)
		res, err := shadowBackend.Authorize(epochID)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		r := res.CanRelease
		return Response{Status: "ok", EpochID: string(epochID), State: res.State.String(),
			Releasable: &r, FinalizeErr: firstFailure(res)}

	case "commit":
		epochID, err := resolveEpoch(req, true)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		log.Printf("[socket] commit epoch=%q", epochID)
		res, err := shadowBackend.Commit(epochID)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		r := res.CanRelease
		return Response{Status: "ok", EpochID: string(epochID), State: res.State.String(),
			Releasable: &r, FinalizeErr: firstFailure(res)}

	case "retry_finalize":
		epochID, err := resolveEpoch(req, false)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		log.Printf("[socket] retry_finalize epoch=%q", epochID)
		res, err := shadowBackend.RetryFinalize(epochID)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		r := res.CanRelease
		return Response{Status: "ok", EpochID: string(epochID), State: res.State.String(),
			Releasable: &r, FinalizeErr: firstFailure(res)}

	case "get_lifecycle":
		epochID, err := resolveEpoch(req, false)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		state, canRel, ferr := shadowBackend.GetLifecycle(epochID)
		r := canRel
		return Response{Status: "ok", EpochID: string(epochID), State: state,
			Releasable: &r, FinalizeErr: ferr}

	case "ack_release":
		epochID, err := resolveEpoch(req, false)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		log.Printf("[socket] ack_release epoch=%q", epochID)
		if err := shadowBackend.AckRelease(epochID); err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok", EpochID: string(epochID)}

	case "rollback", "rollback_epoch":
		// The epoch IS the rollback unit: both actions cascade through the
		// dependency graph (read-from + write-write edges).
		epochID, err := resolveEpoch(req, false)
		if err != nil {
			// Nothing bound to this cgroup: nothing to roll back.
			if req.CgroupID != "" && req.EpochID == "" {
				return Response{Status: "ok", Message: "no active epoch, no-op"}
			}
			return Response{Status: "error", Message: err.Error()}
		}
		log.Printf("[socket] %s epoch=%q", req.Action, epochID)
		set, err := shadowBackend.RollbackWithAffected(epochID)
		if err != nil {
			// Refused (e.g. promotion already started): surface the error so
			// the orchestrator does NOT roll back the process/network layer.
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok", EpochID: string(epochID),
			Affected: set.Cgroups, AffectedEpochs: set.Epochs}

	case "rollback_affected":
		epochID, err := resolveEpoch(req, false)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		set := shadowBackend.GetAffected(epochID)
		return Response{Status: "ok", EpochID: string(epochID),
			Affected: set.Cgroups, AffectedEpochs: set.Epochs}

	case "can_release":
		epochID, err := resolveEpoch(req, false)
		if err != nil {
			// Fail closed: an unresolvable target is never releasable.
			f := false
			return Response{Status: "ok", Releasable: &f, Message: err.Error()}
		}
		r := shadowBackend.CanRelease(epochID)
		return Response{Status: "ok", EpochID: string(epochID), Releasable: &r}

	case "list_agents":
		infos := shadowBackend.ListEpochs()
		ids := make([]string, 0, len(infos))
		for _, in := range infos {
			ids = append(ids, in.ID)
		}
		return Response{Status: "ok", Agents: ids, AgentsInfo: infos}

	case "commit_epoch":
		// Legacy marker-only op: with MVCC epochs the marker is meaningless
		// (an epoch's changes stay speculative until "commit" authorizes and
		// finalizes them). Accepted as a no-op for compatibility.
		epochID, err := resolveEpoch(req, false)
		if err != nil {
			return Response{Status: "ok", Message: "no active epoch, no-op"}
		}
		log.Printf("[socket] commit_epoch epoch=%q (marker-only no-op; use 'commit')", epochID)
		return Response{Status: "ok", EpochID: string(epochID)}

	case "prepare_resolution":
		// Compute the SCC containing the given epoch and return its members
		// plus the current dependency-graph generation. The orchestrator
		// freezes all members, then calls begin_finalize with the same
		// graph_generation to detect TOCTOU changes.
		epochID, err := resolveEpoch(req, false)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		log.Printf("[socket] prepare_resolution epoch=%q", epochID)
		res, err := shadowBackend.PrepareResolution(epochID)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok", EpochID: string(epochID),
			GroupID: res.GroupID, Members: res.Members,
			GraphGeneration: res.GraphGeneration}

	case "begin_finalize":
		// Start the promote/finalize pass for an entire group (SCC).
		// graph_generation must match the value from prepare_resolution.
		if req.GroupID == 0 {
			return Response{Status: "error", Message: "group_id required"}
		}
		log.Printf("[socket] begin_finalize group_id=%d graph_gen=%d", req.GroupID, req.GraphGeneration)
		res, err := shadowBackend.BeginFinalize(req.GroupID, req.GraphGeneration)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok", GroupID: req.GroupID, State: res.Status}

	case "get_finalize_status":
		// Poll the state of a group finalization.
		if req.GroupID == 0 {
			return Response{Status: "error", Message: "group_id required"}
		}
		res, err := shadowBackend.GetFinalizeStatus(req.GroupID)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok", GroupID: req.GroupID,
			State: res.State, FinalizeErr: res.FinalizeErr}

	case "cancel_group":
		// Drop a prepared group that was abandoned before begin_finalize/release.
		if req.GroupID == 0 {
			return Response{Status: "error", Message: "group_id required"}
		}
		log.Printf("[socket] cancel_group group_id=%d", req.GroupID)
		if err := shadowBackend.CancelGroup(req.GroupID); err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok", GroupID: req.GroupID}

	case "ack_release_group":
		// Release all members of a finalized group.
		if req.GroupID == 0 {
			return Response{Status: "error", Message: "group_id required"}
		}
		log.Printf("[socket] ack_release_group group_id=%d", req.GroupID)
		if err := shadowBackend.AckReleaseGroup(req.GroupID); err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok", GroupID: req.GroupID}

	default:
		return Response{Status: "error", Message: "unknown action: " + req.Action}
	}
}

// firstFailure returns a human-readable summary of the first promotion failure
// in a CommitResult, or "" if there are none. Surfaced as Response.FinalizeErr
// so the orchestrator can log why an epoch did not finalize.
func firstFailure(res backend.CommitResult) string {
	if len(res.Failures) == 0 {
		return ""
	}
	f := res.Failures[0]
	if f.Path != "" {
		return f.Op + " " + f.Path + ": " + f.Err
	}
	return f.Err
}
