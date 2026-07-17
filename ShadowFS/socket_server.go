package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
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
	// Releasable is set by the can_release action. It reports whether the
	// cgroup's external side effects are safe to externalize (i.e. all of
	// its upstream dependencies are committed). Pointer so a false value is
	// still serialized.
	Releasable *bool `json:"releasable,omitempty"`
}

// NewSocketServer creates and starts a Unix socket server at the given path.
func NewSocketServer(sockPath string) (*SocketServer, error) {
	// Remove stale socket file if it exists
	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	s := &SocketServer{
		listener: listener,
		sockPath: sockPath,
	}

	go s.acceptLoop()
	log.Printf("[socket] listening on %s", sockPath)
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
		go s.handleConn(conn)
	}
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
		shadowBackend.Commit(req.CgroupID)
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

	default:
		return Response{Status: "error", Message: "unknown action: " + req.Action}
	}
}
