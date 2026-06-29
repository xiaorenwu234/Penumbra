#!/usr/bin/env python3
"""
Integration test for ShadowFS + ShadowProc orchestration.

Requirements:
- Must run as root (for eBPF and cgroup operations)
- ShadowFS and ShadowProc binaries must be built
- A test cgroup must be available

Usage:
    sudo python3 tests/integration_test.py
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "orchestrator"))
from shadow_orchestrator import ShadowOrchestrator, SocketClient

# Paths (adjust as needed)
PROJECT_ROOT = Path(__file__).parent.parent
SHADOWFS_BIN = PROJECT_ROOT / "ShadowFS" / "shadowfs"
SHADOWPROC_BIN = PROJECT_ROOT / "ShadowProc" / "target" / "release" / "shadow-proc"

# Test configuration
TEST_CGROUP_PATH = "/sys/fs/cgroup/shadow-test"
SHADOWFS_SOCK = "/tmp/shadow-test-fs.sock"
SHADOWPROC_SOCK = "/tmp/shadow-test-proc.sock"
ORCH_SOCK = "/tmp/shadow-test-orch.sock"


class TestEnvironment:
    """Manages test environment: temp dirs, cgroup, subprocess lifecycle."""

    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="shadow-test-")
        self.orig_dir = os.path.join(self.tmpdir, "orig")
        self.staging_dir = os.path.join(self.tmpdir, "staging")
        self.mnt_dir = os.path.join(self.tmpdir, "mnt")
        self.procs = []

        os.makedirs(self.orig_dir)
        os.makedirs(self.staging_dir)
        os.makedirs(self.mnt_dir)

    def setup_cgroup(self):
        """Create a test cgroup."""
        if not os.path.exists(TEST_CGROUP_PATH):
            os.makedirs(TEST_CGROUP_PATH, exist_ok=True)
            print(f"[setup] Created cgroup: {TEST_CGROUP_PATH}")

    def start_shadowfs(self):
        """Start the ShadowFS FUSE daemon."""
        cmd = [
            str(SHADOWFS_BIN),
            "-staging", self.staging_dir,
            "-sock", SHADOWFS_SOCK,
            self.mnt_dir,
            self.orig_dir,
        ]
        print(f"[setup] Starting ShadowFS: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.procs.append(("shadowfs", proc))
        time.sleep(1)  # Wait for mount
        return proc

    def start_shadowproc(self):
        """Start the ShadowProc daemon."""
        cmd = [
            str(SHADOWPROC_BIN),
            "--sock", SHADOWPROC_SOCK,
            "--cgroup-path", TEST_CGROUP_PATH,
        ]
        print(f"[setup] Starting ShadowProc: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE)
        self.procs.append(("shadowproc", proc))
        time.sleep(1)  # Wait for BPF to load
        return proc

    def create_test_file(self, name: str, content: str):
        """Create a file in the orig directory."""
        path = os.path.join(self.orig_dir, name)
        with open(path, "w") as f:
            f.write(content)
        return path

    def read_mounted_file(self, name: str) -> str:
        """Read a file from the mounted view."""
        path = os.path.join(self.mnt_dir, name)
        with open(path, "r") as f:
            return f.read()

    def write_mounted_file(self, name: str, content: str):
        """Write to a file in the mounted view."""
        path = os.path.join(self.mnt_dir, name)
        with open(path, "w") as f:
            f.write(content)

    def cleanup(self):
        """Stop all processes and clean up."""
        for name, proc in self.procs:
            print(f"[cleanup] Stopping {name} (pid={proc.pid})")
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)

        # Unmount if still mounted
        subprocess.run(["fusermount", "-uz", self.mnt_dir],
                       capture_output=True)

        # Remove temp dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

        # Remove sockets
        for sock in [SHADOWFS_SOCK, SHADOWPROC_SOCK, ORCH_SOCK]:
            if os.path.exists(sock):
                os.remove(sock)

        print("[cleanup] Done")


def test_socket_connectivity():
    """Test that we can connect to both socket APIs."""
    print("\n=== Test: Socket Connectivity ===")

    # Test ShadowFS socket
    fs_client = SocketClient(SHADOWFS_SOCK)
    fs_client.connect()
    resp = fs_client.request({"action": "list_agents"})
    assert resp["status"] == "ok", f"ShadowFS list_agents failed: {resp}"
    print(f"  ShadowFS: OK (agents={resp.get('agents', [])})")
    fs_client.close()

    # Test ShadowProc socket
    proc_client = SocketClient(SHADOWPROC_SOCK)
    proc_client.connect()
    resp = proc_client.request({"action": "list_all_frozen"})
    assert resp["status"] == "ok", f"ShadowProc list_all_frozen failed: {resp}"
    print(f"  ShadowProc: OK (frozen={resp.get('frozen', [])})")
    proc_client.close()

    print("  PASSED")


def test_orchestrator_commit(env: TestEnvironment):
    """Test commit flow through orchestrator."""
    print("\n=== Test: Orchestrator Commit ===")

    orch = ShadowOrchestrator(SHADOWFS_SOCK, SHADOWPROC_SOCK)

    # Create a test file and modify it through the mount
    env.create_test_file("test_commit.txt", "original content")

    # Read the file through mount to register the agent
    content = env.read_mounted_file("test_commit.txt")
    assert content == "original content"

    # Commit (should be a no-op for read-only agent)
    agents = orch.list_agents()
    print(f"  Agents before commit: {agents}")

    # Write through the mount to create a real agent
    env.write_mounted_file("test_commit.txt", "modified content")

    agents = orch.list_agents()
    print(f"  Agents after write: {agents}")

    if agents:
        result = orch.commit(agents[0])
        print(f"  Commit result: {result}")
        assert result["status"] == "ok"

    # Verify the orig file was updated
    with open(os.path.join(env.orig_dir, "test_commit.txt"), "r") as f:
        final = f.read()
    print(f"  Final orig content: {repr(final)}")
    assert final == "modified content", f"Expected 'modified content', got {repr(final)}"

    orch.close()
    print("  PASSED")


def test_orchestrator_rollback(env: TestEnvironment):
    """Test rollback flow through orchestrator."""
    print("\n=== Test: Orchestrator Rollback ===")

    orch = ShadowOrchestrator(SHADOWFS_SOCK, SHADOWPROC_SOCK)

    # Create and modify a file
    env.create_test_file("test_rollback.txt", "original")
    env.write_mounted_file("test_rollback.txt", "modified")

    agents = orch.list_agents()
    print(f"  Agents: {agents}")
    assert len(agents) > 0, "Expected at least one agent"

    # Rollback
    result = orch.rollback(agents[0])
    print(f"  Rollback result: {result}")
    assert result["status"] == "ok"

    # Verify orig is unchanged
    with open(os.path.join(env.orig_dir, "test_rollback.txt"), "r") as f:
        content = f.read()
    assert content == "original", f"Expected 'original', got {repr(content)}"

    orch.close()
    print("  PASSED")


def test_add_cgroup():
    """Test dynamic cgroup addition."""
    print("\n=== Test: Add Cgroup ===")

    proc_client = SocketClient(SHADOWPROC_SOCK)
    proc_client.connect()

    # This test only verifies the API works, actual cgroup monitoring
    # requires the cgroup to exist
    test_cgroup = "/sys/fs/cgroup/shadow-test-dynamic"
    if os.path.exists(test_cgroup):
        resp = proc_client.request({
            "action": "add_cgroup",
            "cgroup_path": test_cgroup,
        })
        print(f"  add_cgroup response: {resp}")
        assert resp["status"] == "ok"
        print("  PASSED")
    else:
        print("  SKIPPED (cgroup path doesn't exist)")

    proc_client.close()


def main():
    if os.geteuid() != 0:
        print("ERROR: This test must be run as root (for eBPF and cgroup operations)")
        sys.exit(1)

    if not SHADOWFS_BIN.exists():
        print(f"ERROR: ShadowFS binary not found at {SHADOWFS_BIN}")
        print("  Build it with: cd ShadowFS && go build -o shadowfs")
        sys.exit(1)

    if not SHADOWPROC_BIN.exists():
        print(f"ERROR: ShadowProc binary not found at {SHADOWPROC_BIN}")
        print("  Build it with: cd ShadowProc && cargo build --release")
        sys.exit(1)

    env = TestEnvironment()
    try:
        env.setup_cgroup()
        env.start_shadowfs()
        env.start_shadowproc()

        # Wait for services to be ready
        time.sleep(2)

        # Run tests
        test_socket_connectivity()
        test_orchestrator_commit(env)
        test_orchestrator_rollback(env)
        test_add_cgroup()

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)

    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        env.cleanup()


if __name__ == "__main__":
    main()
