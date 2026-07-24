package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"wokron/shadowfs/backend"
)

// SocketServer provides a Unix socket control API for the ShadowFS backend.
type SocketServer struct {
	listener net.Listener
	sockPath string
}

// Request is the JSON request format for the socket API.
type Request struct {
	Action   string `json:"action"`
	CgroupID string `json:"cgroup_id,omitempty"`
}

// Response is the JSON response format for the socket API.
type Response struct {
	Status   string   `json:"status"`
	Message  string   `json:"message,omitempty"`
	Affected []string `json:"affected,omitempty"`
	Agents   []string `json:"agents,omitempty"`
	// Releasable is set by the can_release / commit / retry_finalize /
	// get_lifecycle actions. It reports whether the cgroup's external side
	// effects are safe to externalize (i.e. the agent has reached Finalized).
	// Pointer so a false value is still serialized.
	Releasable *bool `json:"releasable,omitempty"`
	// State is the agent's lifecycle position: "speculative",
	// "authorized_pending", "finalizing", "finalized", or "unknown".
	State string `json:"state,omitempty"`
	// FinalizeErr, when non-empty, explains why an agent is stuck short of
	// Finalized (e.g. a promotion I/O error to retry via retry_finalize).
	FinalizeErr string `json:"finalize_err,omitempty"`
}

// NewSocketServer creates and starts a Unix socket server at the given path.
//
// The control socket is the ONLY control interface (the in-mount .shadow.ctl
// file was removed). It is hardened against a co-located unprivileged agent:
// the socket lives in a 0700 directory and is itself 0600, and every accepted
// connection is peer-authenticated (SO_PEERCRED) to the daemon's own uid.
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

func (s *SocketServer) handleRequest(req Request) Response {
	switch req.Action {
	case "commit":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		log.Printf("[socket] commit agent=%q", req.CgroupID)
		res, err := shadowBackend.Commit(req.CgroupID)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		r := res.CanRelease
		return Response{Status: "ok", State: res.State.String(),
			Releasable: &r, FinalizeErr: firstFailure(res)}

	case "retry_finalize":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		log.Printf("[socket] retry_finalize agent=%q", req.CgroupID)
		res, err := shadowBackend.RetryFinalize(req.CgroupID)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		r := res.CanRelease
		return Response{Status: "ok", State: res.State.String(),
			Releasable: &r, FinalizeErr: firstFailure(res)}

	case "get_lifecycle":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		state, canRel, ferr := shadowBackend.GetLifecycle(req.CgroupID)
		r := canRel
		return Response{Status: "ok", State: state, Releasable: &r, FinalizeErr: ferr}

	case "ack_release":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		log.Printf("[socket] ack_release agent=%q", req.CgroupID)
		if err := shadowBackend.AckRelease(req.CgroupID); err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok"}

	case "rollback":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		log.Printf("[socket] rollback agent=%q", req.CgroupID)
		affected, err := shadowBackend.RollbackWithAffected(req.CgroupID)
		if err != nil {
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok", Affected: affected}

	case "rollback_affected":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		affected := shadowBackend.GetAffected(req.CgroupID)
		return Response{Status: "ok", Affected: affected}

	case "can_release":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		r := shadowBackend.CanRelease(req.CgroupID)
		return Response{Status: "ok", Releasable: &r}

	case "list_agents":
		agents := shadowBackend.ListAgents()
		return Response{Status: "ok", Agents: agents}

	case "begin_epoch":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		log.Printf("[socket] begin_epoch agent=%q", req.CgroupID)
		shadowBackend.BeginEpoch(req.CgroupID)
		return Response{Status: "ok"}

	case "commit_epoch":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		log.Printf("[socket] commit_epoch agent=%q", req.CgroupID)
		shadowBackend.CommitEpoch(req.CgroupID)
		return Response{Status: "ok"}

	case "rollback_epoch":
		if req.CgroupID == "" {
			return Response{Status: "error", Message: "cgroup_id required"}
		}
		log.Printf("[socket] rollback_epoch agent=%q", req.CgroupID)
		if err := shadowBackend.RollbackEpoch(req.CgroupID); err != nil {
			// Refused (e.g. promotion already started): surface the error so
			// the orchestrator does NOT roll back the process/network layer.
			return Response{Status: "error", Message: err.Error()}
		}
		return Response{Status: "ok"}

	default:
		return Response{Status: "error", Message: "unknown action: " + req.Action}
	}
}

// firstFailure returns a human-readable summary of the first promotion failure
// in a CommitResult, or "" if there are none. Surfaced as Response.FinalizeErr
// so the orchestrator can log why an agent did not finalize.
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
