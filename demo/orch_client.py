#!/usr/bin/env python3
"""
orch_client.py - Simple Unix socket JSON-line client for the orchestrator.

Usage:
    python3 orch_client.py <socket_path> <action> [key=value ...]

Examples:
    python3 orch_client.py /tmp/shadow-orch.sock commit cgroup_id=/shadow-demo
    python3 orch_client.py /tmp/shadow-orch.sock rollback cgroup_id=/shadow-demo
    python3 orch_client.py /tmp/shadow-orch.sock list_agents
    python3 orch_client.py /tmp/shadow-orch.sock list_frozen
    python3 orch_client.py /tmp/shadow-orch.sock list_frozen cgroup_id=/shadow-demo
    python3 orch_client.py /tmp/shadow-orch.sock get_affected cgroup_id=/shadow-demo
    python3 orch_client.py /tmp/shadow-orch.sock add_cgroup cgroup_path=/sys/fs/cgroup/foo
"""

import json
import socket
import sys


def send_request(sock_path: str, request: dict) -> dict:
    """Send a JSON-line request to a Unix socket and return the response."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    try:
        f = sock.makefile("rw", buffering=1)
        f.write(json.dumps(request) + "\n")
        f.flush()
        resp_line = f.readline()
        if not resp_line:
            return {"status": "error", "message": "Connection closed"}
        return json.loads(resp_line)
    finally:
        sock.close()


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    sock_path = sys.argv[1]
    action = sys.argv[2]

    request = {"action": action}
    for arg in sys.argv[3:]:
        if "=" in arg:
            key, value = arg.split("=", 1)
            request[key] = value

    try:
        resp = send_request(sock_path, request)
    except Exception as e:
        resp = {"status": "error", "message": str(e)}

    print(json.dumps(resp, indent=2, ensure_ascii=False))
    sys.exit(0 if resp.get("status") == "ok" else 1)


if __name__ == "__main__":
    main()
