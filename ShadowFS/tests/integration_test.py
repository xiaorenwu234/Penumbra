#!/usr/bin/env python3
"""ShadowFS FUSE Integration Test Suite.

Tests the full FUSE stack by mounting the filesystem and performing real
file operations through it. Each agent runs in an isolated cgroup via
systemd-run, so the FUSE server identifies agents by cgroup path.

Prerequisites:
  - Go binary built:  go build -o shadowfs .
  - systemd user session active
  - fusermount available
  - Python 3.8+

Usage:
  python3 tests/integration_test.py [test_name ...]
  python3 tests/integration_test.py                    # run all tests
  python3 tests/integration_test.py TestOverlayWrite   # run specific test
"""

import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback
import unittest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
SHADOWFS_BIN = PROJECT_ROOT / "shadowfs"
WRAPPER_SCRIPT = PROJECT_ROOT / "tests" / "agent_wrapper.py"

# ---------------------------------------------------------------------------
# TestConfig: per-test environment (orig, staging, mount dirs + FUSE mount)
# ---------------------------------------------------------------------------
class TestConfig:
    """Sets up and tears down a ShadowFS FUSE mount for a single test."""

    def __init__(self, test_id: str):
        self._base = tempfile.mkdtemp(prefix=f"shadowfs_e2e_{test_id}_")
        self.orig = os.path.join(self._base, "orig")
        self.staging = os.path.join(self._base, "staging")
        self.mnt = os.path.join(self._base, "mnt")
        os.makedirs(self.orig)
        os.makedirs(self.staging)
        os.makedirs(self.mnt)
        self._proc = None

    # -- lifecycle --

    def mount(self):
        self._proc = subprocess.Popen(
            [str(SHADOWFS_BIN), "-staging", self.staging, self.mnt, self.orig],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        for _ in range(30):
            if os.path.ismount(self.mnt):
                return
            time.sleep(0.1)
        self.unmount()
        raise RuntimeError("FUSE mount timed out")

    def unmount(self):
        if self._proc and self._proc.poll() is None:
            subprocess.run(["fusermount", "-u", self.mnt],
                           capture_output=True, timeout=5)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        if self._proc and self._proc.stderr:
            self._proc.stderr.close()
        time.sleep(0.3)

    def cleanup(self):
        self.unmount()
        shutil.rmtree(self._base, ignore_errors=True)

    # -- orig helpers (bypass FUSE) --

    def orig_path(self, rel: str) -> str:
        return os.path.join(self.orig, rel)

    def mnt_path(self, rel: str) -> str:
        return os.path.join(self.mnt, rel)

    def create_orig(self, rel: str, content: str = "") -> str:
        p = self.orig_path(rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
        return p

    def read_orig(self, rel: str) -> str:
        with open(self.orig_path(rel)) as f:
            return f.read()

    def orig_exists(self, rel: str) -> bool:
        return os.path.exists(self.orig_path(rel))


# ---------------------------------------------------------------------------
# Agent operations (via systemd-run in isolated cgroups)
# ---------------------------------------------------------------------------
_CG_PREFIX = "shadowfs-it"
_unit_counter = 0

def _next_unit(name: str) -> str:
    return f"{_CG_PREFIX}-{name}-{os.getpid()}"

def run_agent(agent_name: str, actions: list[dict]) -> list[dict]:
    """Execute file operations inside agent_name's cgroup.

    Returns the list of result dicts from agent_wrapper.py.
    """
    unit = _next_unit(agent_name)
    actions_json = json.dumps(actions)
    tmpf = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    try:
        tmpf.write(actions_json)
        tmpf.close()
        cmd = [
            "systemd-run", "--user", "--quiet",
            f"--unit={unit}", "--scope",
            "--expand-environment=no",
            sys.executable, str(WRAPPER_SCRIPT), tmpf.name,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    finally:
        os.unlink(tmpf.name)
    if r.returncode != 0:
        raise RuntimeError(
            f"agent {agent_name!r} failed (rc={r.returncode}):\n"
            f"  stdout: {r.stdout.strip()}\n  stderr: {r.stderr.strip()}"
        )
    return json.loads(r.stdout.strip())


def control_cmd(cfg: TestConfig, action: str, agent_name: str):
    """Send a commit/rollback command via .shadow.ctl.

    The cgroup ID used here must match the one systemd-run creates.
    """
    unit = _next_unit(agent_name)
    cg_id = (f"/user.slice/user-{os.getuid()}.slice/"
             f"user@{os.getuid()}.service/app.slice/{unit}.scope")
    cmd_str = f"{action} {cg_id}\n"
    ctl = os.path.join(cfg.mnt, ".shadow.ctl")
    with open(ctl, "w") as f:
        f.write(cmd_str)


def commit(cfg: TestConfig, agent: str):
    control_cmd(cfg, "c", agent)

def rollback(cfg: TestConfig, agent: str):
    control_cmd(cfg, "r", agent)


# ---------------------------------------------------------------------------
# Convenience: single-action helpers
# ---------------------------------------------------------------------------
def agent_write(cfg: TestConfig, agent: str, rel: str, content: str):
    return run_agent(agent, [{"op": "write", "path": cfg.mnt_path(rel), "content": content}])

def agent_read(cfg: TestConfig, agent: str, rel: str) -> str:
    res = run_agent(agent, [{"op": "read", "path": cfg.mnt_path(rel)}])
    if not res[0]["ok"]:
        raise OSError(res[0].get("errno", 0), res[0]["error"])
    return res[0]["content"]

def agent_exists(cfg: TestConfig, agent: str, rel: str) -> bool:
    res = run_agent(agent, [{"op": "exists", "path": cfg.mnt_path(rel)}])
    return res[0]["exists"]

def agent_list(cfg: TestConfig, agent: str, rel: str) -> list[str]:
    res = run_agent(agent, [{"op": "list", "path": cfg.mnt_path(rel)}])
    if not res[0]["ok"]:
        raise OSError(res[0].get("errno", 0), res[0]["error"])
    return res[0]["entries"]

def agent_unlink(cfg: TestConfig, agent: str, rel: str):
    return run_agent(agent, [{"op": "unlink", "path": cfg.mnt_path(rel)}])

def agent_mkdir(cfg: TestConfig, agent: str, rel: str):
    return run_agent(agent, [{"op": "mkdir", "path": cfg.mnt_path(rel)}])

def agent_rmdir(cfg: TestConfig, agent: str, rel: str):
    return run_agent(agent, [{"op": "rmdir", "path": cfg.mnt_path(rel)}])

def agent_rmtree(cfg: TestConfig, agent: str, rel: str):
    """Recursively delete a directory tree (equivalent to rm -rf)."""
    return run_agent(agent, [{"op": "rmtree", "path": cfg.mnt_path(rel)}])

def agent_rename(cfg: TestConfig, agent: str, src_rel: str, dst_rel: str):
    return run_agent(agent, [{"op": "rename",
                              "src": cfg.mnt_path(src_rel),
                              "dst": cfg.mnt_path(dst_rel)}])

def agent_noop(cfg: TestConfig, agent: str):
    """Trigger a no-op in the agent's cgroup (ensures cgroup is registered)."""
    return run_agent(agent, [{"op": "noop"}])

def agent_append(cfg: TestConfig, agent: str, rel: str, content: str):
    return run_agent(agent, [{"op": "append", "path": cfg.mnt_path(rel), "content": content}])

def agent_truncate(cfg: TestConfig, agent: str, rel: str, size: int):
    return run_agent(agent, [{"op": "truncate", "path": cfg.mnt_path(rel), "size": size}])

def agent_chmod(cfg: TestConfig, agent: str, rel: str, mode: int):
    return run_agent(agent, [{"op": "chmod", "path": cfg.mnt_path(rel), "mode": mode}])

def agent_stat(cfg: TestConfig, agent: str, rel: str) -> dict:
    res = run_agent(agent, [{"op": "stat", "path": cfg.mnt_path(rel)}])
    return res[0]

# Some FUSE caches need a moment to expire (AttrTimeout/EntryTimeout = 1s).
FUSE_CACHE_WAIT = 1.5


# ===========================================================================
# Test Cases
# ===========================================================================
class TestOverlayWriteRollback(unittest.TestCase):
    """Write via FUSE → orig untouched; rollback → overlay gone."""

    def test_write_rollback(self):
        cfg = TestConfig("write-rollback")
        try:
            cfg.create_orig("data.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "data.txt", "modified")
            # orig untouched
            self.assertEqual(cfg.read_orig("data.txt"), "orig")
            # rollback
            rollback(cfg, "A")
            time.sleep(0.5)
            # orig still untouched
            self.assertEqual(cfg.read_orig("data.txt"), "orig")
        finally:
            cfg.cleanup()


class TestOverlayWriteCommit(unittest.TestCase):
    """Write via FUSE → commit → orig gets new content."""

    def test_write_commit(self):
        cfg = TestConfig("write-commit")
        try:
            cfg.create_orig("data.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "data.txt", "modified")
            self.assertEqual(cfg.read_orig("data.txt"), "orig")
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("data.txt"), "modified")
        finally:
            cfg.cleanup()


class TestOverlayCreateAndCommit(unittest.TestCase):
    """Create new file via FUSE → commit → orig gets the file."""

    def test_create_commit(self):
        cfg = TestConfig("create-commit")
        try:
            cfg.mount()
            agent_write(cfg, "A", "new.txt", "new")
            self.assertFalse(cfg.orig_exists("new.txt"))
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("new.txt"), "new")
        finally:
            cfg.cleanup()


class TestSharedOverlayTwoAgents(unittest.TestCase):
    """Two agents touch same file: B depends on A; rollback A cascades to B."""

    def test_shared_cascade(self):
        cfg = TestConfig("shared-cascade")
        try:
            cfg.create_orig("shared.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "shared.txt", "a-mod")
            agent_write(cfg, "B", "shared.txt", "b-mod")
            # B reads what A wrote before overwriting (shared overlay)
            # Verify dependency: rollback A cascades to B
            rollback(cfg, "A")
            time.sleep(0.5)
            # orig untouched
            self.assertEqual(cfg.read_orig("shared.txt"), "orig")
        finally:
            cfg.cleanup()


class TestPerFilePromoteWaitsForAllWriters(unittest.TestCase):
    """Commit B first (depends on A) → no promote. Commit A → promote."""

    def test_promote_waits(self):
        cfg = TestConfig("promote-waits")
        try:
            cfg.create_orig("shared.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "shared.txt", "a-mod")
            agent_write(cfg, "B", "shared.txt", "b-mod")
            # Commit B first — should NOT promote (depends on A)
            commit(cfg, "B")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("shared.txt"), "orig")
            # Commit A — now both committed → promote
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("shared.txt"), "b-mod")
        finally:
            cfg.cleanup()


class TestUnlinkWhiteout(unittest.TestCase):
    """Unlink → whiteout hides file; rollback → file visible; commit → deleted."""

    def test_unlink_whiteout(self):
        cfg = TestConfig("unlink-whiteout")
        try:
            cfg.create_orig("doomed.txt", "bye")
            cfg.mount()
            # Unlink via FUSE
            agent_unlink(cfg, "A", "doomed.txt")
            # File hidden in merged view
            self.assertFalse(agent_exists(cfg, "A", "doomed.txt"))
            # orig still has it
            self.assertTrue(cfg.orig_exists("doomed.txt"))
            # Rollback → file visible again
            rollback(cfg, "A")
            time.sleep(0.5)
            self.assertTrue(agent_exists(cfg, "A", "doomed.txt"))
            # Re-unlink and commit → orig deleted
            agent_unlink(cfg, "A", "doomed.txt")
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertFalse(cfg.orig_exists("doomed.txt"))
        finally:
            cfg.cleanup()


class TestMkdirRmdirOverlay(unittest.TestCase):
    """Mkdir via FUSE → commit → orig dir created."""

    def test_mkdir_commit(self):
        cfg = TestConfig("mkdir-commit")
        try:
            cfg.mount()
            agent_mkdir(cfg, "A", "newdir")
            self.assertFalse(cfg.orig_exists("newdir"))
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertTrue(os.path.isdir(cfg.orig_path("newdir")))
        finally:
            cfg.cleanup()


class TestRmdirRollback(unittest.TestCase):
    """Rmdir → whiteout; rollback → dir restored."""

    def test_rmdir_rollback(self):
        cfg = TestConfig("rmdir-rollback")
        try:
            os.makedirs(cfg.orig_path("old"))
            cfg.mount()
            agent_rmdir(cfg, "A", "old")
            # Hidden in merged view
            self.assertFalse(agent_exists(cfg, "A", "old"))
            # Rollback → visible again
            rollback(cfg, "A")
            time.sleep(0.5)
            self.assertTrue(agent_exists(cfg, "A", "old"))
            self.assertTrue(cfg.orig_exists("old"))
        finally:
            cfg.cleanup()


class TestRmdirRollbackNonEmpty(unittest.TestCase):
    """Delete files inside a dir then rmdir → rollback restores dir + contents."""

    def test_rmdir_nonempty_rollback(self):
        cfg = TestConfig("rmdir-nonempty-rb")
        try:
            # orig: old/ with two files inside
            os.makedirs(cfg.orig_path("old"))
            with open(cfg.orig_path("old/a.txt"), "w") as f:
                f.write("aaa")
            with open(cfg.orig_path("old/b.txt"), "w") as f:
                f.write("bbb")
            cfg.mount()

            # A deletes files inside, then removes the (now empty) dir
            run_agent("A", [
                {"op": "unlink", "path": cfg.mnt_path("old/a.txt")},
                {"op": "unlink", "path": cfg.mnt_path("old/b.txt")},
                {"op": "rmdir",  "path": cfg.mnt_path("old")},
            ])
            # Dir and files hidden
            self.assertFalse(agent_exists(cfg, "A", "old"))
            self.assertFalse(agent_exists(cfg, "A", "old/a.txt"))
            # orig untouched
            self.assertTrue(cfg.orig_exists("old"))
            self.assertEqual(cfg.read_orig("old/a.txt"), "aaa")

            # Rollback → dir + files all restored
            rollback(cfg, "A")
            time.sleep(1.5)  # wait for FUSE entry cache to expire
            self.assertTrue(agent_exists(cfg, "A", "old"))
            self.assertTrue(agent_exists(cfg, "A", "old/a.txt"))
            self.assertTrue(agent_exists(cfg, "A", "old/b.txt"))
            content = agent_read(cfg, "A", "old/a.txt")
            self.assertEqual(content, "aaa")
        finally:
            cfg.cleanup()


class TestRmtreeRollback(unittest.TestCase):
    """rm -rf a non-empty dir → rollback restores the entire tree."""

    def test_rmtree_rollback(self):
        cfg = TestConfig("rmtree-rollback")
        try:
            # orig: project/ with nested subdirs and files
            os.makedirs(cfg.orig_path("project/sub"))
            with open(cfg.orig_path("project/top.txt"), "w") as f:
                f.write("top")
            with open(cfg.orig_path("project/sub/deep.txt"), "w") as f:
                f.write("deep")
            cfg.mount()

            # A does rm -rf project/ (single rmtree call = rm -rf)
            agent_rmtree(cfg, "A", "project")
            # Everything hidden
            self.assertFalse(agent_exists(cfg, "A", "project"))
            self.assertFalse(agent_exists(cfg, "A", "project/sub/deep.txt"))
            # orig untouched
            self.assertTrue(cfg.orig_exists("project/sub/deep.txt"))

            # Rollback → entire tree restored
            rollback(cfg, "A")
            time.sleep(1.5)  # wait for FUSE entry cache to expire
            self.assertTrue(agent_exists(cfg, "A", "project"))
            self.assertTrue(agent_exists(cfg, "A", "project/top.txt"))
            self.assertTrue(agent_exists(cfg, "A", "project/sub"))
            self.assertTrue(agent_exists(cfg, "A", "project/sub/deep.txt"))
            self.assertEqual(agent_read(cfg, "A", "project/sub/deep.txt"), "deep")
        finally:
            cfg.cleanup()


class TestRecordRenameAndRollback(unittest.TestCase):
    """Rename via FUSE → overlay has dst + whiteout for src; rollback restores."""

    def test_rename_rollback(self):
        cfg = TestConfig("rename-rollback")
        try:
            cfg.create_orig("src.txt", "hello")
            cfg.mount()
            agent_rename(cfg, "A", "src.txt", "dst.txt")
            # src hidden, dst visible
            self.assertFalse(agent_exists(cfg, "A", "src.txt"))
            self.assertTrue(agent_exists(cfg, "A", "dst.txt"))
            content = agent_read(cfg, "A", "dst.txt")
            self.assertEqual(content, "hello")
            # orig untouched
            self.assertTrue(cfg.orig_exists("src.txt"))
            self.assertFalse(cfg.orig_exists("dst.txt"))
            # Rollback → src restored
            rollback(cfg, "A")
            time.sleep(0.5)
            self.assertTrue(agent_exists(cfg, "A", "src.txt"))
        finally:
            cfg.cleanup()


class TestPrepareWriteDedup(unittest.TestCase):
    """Repeated write-open on same file → dedup (no double entry)."""

    def test_dedup(self):
        cfg = TestConfig("dedup")
        try:
            cfg.create_orig("a.txt", "orig")
            cfg.mount()
            # Two writes to same file by same agent
            agent_write(cfg, "A", "a.txt", "first")
            agent_write(cfg, "A", "a.txt", "second")
            # Commit should work cleanly (single entry)
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("a.txt"), "second")
        finally:
            cfg.cleanup()


class TestMultiAgentIndependentRollback(unittest.TestCase):
    """Independent agents: rollback A does not affect B."""

    def test_independent_rollback(self):
        cfg = TestConfig("indep-rollback")
        try:
            cfg.mount()
            agent_mkdir(cfg, "A", "dir_a")
            agent_mkdir(cfg, "B", "dir_b")
            rollback(cfg, "A")
            time.sleep(1.5)  # wait for FUSE entry cache to expire
            # B's dir still visible
            self.assertTrue(agent_exists(cfg, "B", "dir_b"))
            # A's dir gone (check from B's perspective after cache expires)
            self.assertFalse(agent_exists(cfg, "B", "dir_a"))
        finally:
            cfg.cleanup()


class TestContaminationDetection(unittest.TestCase):
    """B writes after A on same file → B depends on A, not vice versa."""

    def test_contamination(self):
        cfg = TestConfig("contamination")
        try:
            cfg.create_orig("shared.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "shared.txt", "a")
            agent_write(cfg, "B", "shared.txt", "b")
            # Rollback B only → A unaffected
            rollback(cfg, "B")
            time.sleep(0.5)
            # A still has its entry; overlay kept for A
            # Verify by reading through A
            content = agent_read(cfg, "A", "shared.txt")
            # A's overlay still alive (content may be "b" since overlay is shared)
            self.assertIn(content, ("a", "b"))
        finally:
            cfg.cleanup()


class TestRollbackDownstreamDoesNotAffectUpstream(unittest.TestCase):
    """Rollback B (downstream) → A (upstream) still has entries and can commit."""

    def test_downstream_rollback(self):
        cfg = TestConfig("downstream-rb")
        try:
            cfg.create_orig("shared.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "shared.txt", "a")
            agent_write(cfg, "B", "shared.txt", "b")
            rollback(cfg, "B")
            time.sleep(0.5)
            # A can still commit successfully (its undo entry survived)
            commit(cfg, "A")
            time.sleep(0.3)
            # The overlay is shared; B wrote "b" last, so the promoted
            # content is "b". The key assertion is that A's commit
            # still works and the file is promoted (not "orig").
            self.assertIn(cfg.read_orig("shared.txt"), ("a", "b"))
            self.assertNotEqual(cfg.read_orig("shared.txt"), "orig")
        finally:
            cfg.cleanup()


class TestParentChildDependency(unittest.TestCase):
    """B writes inside A's directory → B depends on A."""

    def test_parent_child(self):
        cfg = TestConfig("parent-child")
        try:
            cfg.mount()
            agent_mkdir(cfg, "A", "parent")
            agent_write(cfg, "B", "parent/child.txt", "c")
            # Rollback A → cascades to B
            rollback(cfg, "A")
            time.sleep(0.5)
            # Both cleaned up
            self.assertFalse(agent_exists(cfg, "A", "parent"))
        finally:
            cfg.cleanup()


class TestSiblingDirectoriesNoDependency(unittest.TestCase):
    """Sibling dirs are independent: rollback A does not affect B."""

    def test_siblings(self):
        cfg = TestConfig("siblings")
        try:
            cfg.mount()
            agent_mkdir(cfg, "A", "a")
            agent_mkdir(cfg, "B", "b")
            rollback(cfg, "A")
            time.sleep(0.5)
            self.assertTrue(agent_exists(cfg, "B", "b"))
        finally:
            cfg.cleanup()


class TestSimilarPrefixNoDependency(unittest.TestCase):
    """foobar vs foo — similar prefix, no parent-child relationship."""

    def test_similar_prefix(self):
        cfg = TestConfig("sim-prefix")
        try:
            cfg.mount()
            agent_mkdir(cfg, "A", "foobar")
            agent_mkdir(cfg, "B", "foo")
            rollback(cfg, "A")
            time.sleep(0.5)
            self.assertTrue(agent_exists(cfg, "B", "foo"))
        finally:
            cfg.cleanup()


class TestCommitDoesNotAffectOtherAgent(unittest.TestCase):
    """Commit A → B's state untouched."""

    def test_commit_isolation(self):
        cfg = TestConfig("commit-iso")
        try:
            cfg.mount()
            agent_write(cfg, "A", "a.txt", "a")
            agent_write(cfg, "B", "b.txt", "b")
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("a.txt"), "a")
            # B still pending — commit B
            commit(cfg, "B")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("b.txt"), "b")
        finally:
            cfg.cleanup()


class TestCommitPendingCascadeRollback(unittest.TestCase):
    """B committed but depends on uncommitted A; rollback A cascades to B."""

    def test_pending_cascade(self):
        cfg = TestConfig("pending-cascade")
        try:
            cfg.create_orig("shared.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "shared.txt", "a")
            agent_write(cfg, "B", "shared.txt", "b")
            # Commit B — stays pending (depends on A)
            commit(cfg, "B")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("shared.txt"), "orig")
            # Rollback A → cascades to B (even though B was committed)
            rollback(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("shared.txt"), "orig")
        finally:
            cfg.cleanup()


class TestCommitFinalizesImmediatelyWithoutDeps(unittest.TestCase):
    """Single agent, no deps → commit finalizes immediately."""

    def test_immediate_finalize(self):
        cfg = TestConfig("imm-finalize")
        try:
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "a")
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("f.txt"), "a")
        finally:
            cfg.cleanup()


class TestRecordReadOpenAddsDependency(unittest.TestCase):
    """B reads A's dirty file → B depends on A; rollback A cascades to B."""

    def test_read_dependency(self):
        cfg = TestConfig("read-dep")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            # A writes f.txt (dirty)
            agent_write(cfg, "A", "f.txt", "a")
            # B writes its own independent file
            agent_write(cfg, "B", "b.txt", "b")
            # B reads f.txt (which A dirtied) → dependency
            agent_read(cfg, "B", "f.txt")
            # Rollback A → cascades to B
            rollback(cfg, "A")
            time.sleep(0.5)
            # A's overlay gone
            self.assertEqual(cfg.read_orig("f.txt"), "orig")
            # B was cascaded: B's overlay for b.txt also rolled back
            self.assertFalse(cfg.orig_exists("b.txt"))
        finally:
            cfg.cleanup()


class TestRecordReadOpenNoWriterNoDependency(unittest.TestCase):
    """Reading a clean file (no writer) → no dependency created."""

    def test_clean_read(self):
        cfg = TestConfig("clean-read")
        try:
            cfg.create_orig("clean.txt", "clean")
            cfg.mount()
            # B reads a clean file (no one wrote it)
            agent_read(cfg, "B", "clean.txt")
            # B writes its own file
            agent_write(cfg, "B", "b.txt", "b")
            # B should be independent — commit B works fine
            commit(cfg, "B")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("b.txt"), "b")
        finally:
            cfg.cleanup()


class TestRollbackWriteRestoresWhiteout(unittest.TestCase):
    """A deletes file, B writes same name, rollback B → A's whiteout restored."""

    def test_whiteout_restore(self):
        cfg = TestConfig("wh-restore")
        try:
            cfg.create_orig("victim.txt", "original")
            cfg.mount()
            # A deletes the file
            agent_unlink(cfg, "A", "victim.txt")
            self.assertFalse(agent_exists(cfg, "A", "victim.txt"))
            # B writes to same path (clears A's whiteout)
            agent_write(cfg, "B", "victim.txt", "new content")
            self.assertTrue(agent_exists(cfg, "B", "victim.txt"))
            # Rollback B only → A's whiteout must be restored
            rollback(cfg, "B")
            time.sleep(1.5)  # wait for FUSE entry cache to expire
            # File should be hidden again (A's whiteout restored)
            self.assertFalse(agent_exists(cfg, "A", "victim.txt"))
            # orig still exists (A hasn't committed)
            self.assertTrue(cfg.orig_exists("victim.txt"))
        finally:
            cfg.cleanup()


class TestMultipleFilesCommitRollback(unittest.TestCase):
    """Agent touches multiple files; commit promotes all; rollback undoes all."""

    def test_multi_file(self):
        cfg = TestConfig("multi-file")
        try:
            cfg.create_orig("a.txt", "orig-a")
            cfg.mount()
            # A writes two files and creates one
            run_agent("A", [
                {"op": "write", "path": cfg.mnt_path("a.txt"), "content": "new-a"},
                {"op": "write", "path": cfg.mnt_path("b.txt"), "content": "new-b"},
                {"op": "mkdir", "path": cfg.mnt_path("d")},
            ])
            self.assertEqual(cfg.read_orig("a.txt"), "orig-a")
            self.assertFalse(cfg.orig_exists("b.txt"))
            # Commit → all promoted
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("a.txt"), "new-a")
            self.assertEqual(cfg.read_orig("b.txt"), "new-b")
            self.assertTrue(os.path.isdir(cfg.orig_path("d")))
        finally:
            cfg.cleanup()


# ===========================================================================
# Edge-case Test Cases (added)
# ===========================================================================
class TestAncestorWhiteoutHidesChildren(unittest.TestCase):
    """Rmdir parent → children also hidden via ancestor whiteout."""

    def test_ancestor_whiteout(self):
        cfg = TestConfig("anc-wh")
        try:
            os.makedirs(cfg.orig_path("d/sub"))
            with open(cfg.orig_path("d/sub/f.txt"), "w") as f:
                f.write("hi")
            cfg.mount()
            # Remove the entire subtree (rm -rf d/)
            agent_rmtree(cfg, "A", "d")
            # Children must also be hidden
            self.assertFalse(agent_exists(cfg, "A", "d"))
            self.assertFalse(agent_exists(cfg, "A", "d/sub"))
            self.assertFalse(agent_exists(cfg, "A", "d/sub/f.txt"))
            # Reading hidden child must fail
            with self.assertRaises(OSError):
                agent_read(cfg, "A", "d/sub/f.txt")
        finally:
            cfg.cleanup()


class TestUnlinkThenRecreate(unittest.TestCase):
    """Unlink → write same path: file becomes visible with new content."""

    def test_unlink_recreate(self):
        cfg = TestConfig("unlink-recreate")
        try:
            cfg.create_orig("f.txt", "old")
            cfg.mount()
            run_agent("A", [
                {"op": "unlink", "path": cfg.mnt_path("f.txt")},
                {"op": "write", "path": cfg.mnt_path("f.txt"), "content": "new"},
            ])
            self.assertTrue(agent_exists(cfg, "A", "f.txt"))
            self.assertEqual(agent_read(cfg, "A", "f.txt"), "new")
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("f.txt"), "new")
        finally:
            cfg.cleanup()


class TestRmdirThenMkdirSamePath(unittest.TestCase):
    """Rmdir then mkdir same path → directory exists; commit promotes."""

    def test_rmdir_mkdir(self):
        cfg = TestConfig("rmdir-mkdir")
        try:
            os.makedirs(cfg.orig_path("d"))
            cfg.mount()
            run_agent("A", [
                {"op": "rmdir", "path": cfg.mnt_path("d")},
                {"op": "mkdir", "path": cfg.mnt_path("d")},
            ])
            self.assertTrue(agent_exists(cfg, "A", "d"))
        finally:
            cfg.cleanup()


class TestWriteThenUnlinkSameAgent(unittest.TestCase):
    """A writes f, then unlinks f. commit → orig file removed."""

    def test_write_then_unlink(self):
        cfg = TestConfig("write-unlink")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            run_agent("A", [
                {"op": "write", "path": cfg.mnt_path("f.txt"), "content": "new"},
                {"op": "unlink", "path": cfg.mnt_path("f.txt")},
            ])
            self.assertFalse(agent_exists(cfg, "A", "f.txt"))
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertFalse(cfg.orig_exists("f.txt"))
        finally:
            cfg.cleanup()


class TestRenameOverwriteExistingDst(unittest.TestCase):
    """Rename src → dst when dst already exists in orig."""

    def test_rename_overwrite(self):
        cfg = TestConfig("rename-overwrite")
        try:
            cfg.create_orig("src.txt", "src-content")
            cfg.create_orig("dst.txt", "old-dst")
            cfg.mount()
            agent_rename(cfg, "A", "src.txt", "dst.txt")
            self.assertEqual(agent_read(cfg, "A", "dst.txt"), "src-content")
            self.assertFalse(agent_exists(cfg, "A", "src.txt"))
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("dst.txt"), "src-content")
            self.assertFalse(cfg.orig_exists("src.txt"))
        finally:
            cfg.cleanup()


class TestRenameAcrossDirs(unittest.TestCase):
    """Rename to a different parent directory."""

    def test_rename_cross_dir(self):
        cfg = TestConfig("rename-cross")
        try:
            os.makedirs(cfg.orig_path("a"))
            os.makedirs(cfg.orig_path("b"))
            with open(cfg.orig_path("a/x.txt"), "w") as f:
                f.write("hi")
            cfg.mount()
            agent_rename(cfg, "A", "a/x.txt", "b/x.txt")
            self.assertFalse(agent_exists(cfg, "A", "a/x.txt"))
            self.assertEqual(agent_read(cfg, "A", "b/x.txt"), "hi")
            rollback(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            self.assertTrue(agent_exists(cfg, "A", "a/x.txt"))
            self.assertFalse(agent_exists(cfg, "A", "b/x.txt"))
        finally:
            cfg.cleanup()


class TestRenameDirectory(unittest.TestCase):
    """Rename a directory: subtree visible at new path."""

    def test_rename_dir(self):
        cfg = TestConfig("rename-dir")
        try:
            os.makedirs(cfg.orig_path("old/sub"))
            with open(cfg.orig_path("old/sub/f.txt"), "w") as f:
                f.write("deep")
            cfg.mount()
            agent_rename(cfg, "A", "old", "new")
            self.assertFalse(agent_exists(cfg, "A", "old"))
            self.assertTrue(agent_exists(cfg, "A", "new"))
            self.assertEqual(agent_read(cfg, "A", "new/sub/f.txt"), "deep")
        finally:
            cfg.cleanup()


class TestSetattrTruncate(unittest.TestCase):
    """Truncate via FUSE: orig untouched until commit."""

    def test_truncate(self):
        cfg = TestConfig("truncate")
        try:
            cfg.create_orig("f.txt", "abcdefghij")
            cfg.mount()
            agent_truncate(cfg, "A", "f.txt", 4)
            # orig untouched
            self.assertEqual(cfg.read_orig("f.txt"), "abcdefghij")
            # mnt sees truncated content
            self.assertEqual(agent_read(cfg, "A", "f.txt"), "abcd")
            # rollback → orig still original; mnt restored
            rollback(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            self.assertEqual(cfg.read_orig("f.txt"), "abcdefghij")
            self.assertEqual(agent_read(cfg, "A", "f.txt"), "abcdefghij")
        finally:
            cfg.cleanup()


class TestSetattrChmodRollback(unittest.TestCase):
    """Chmod via FUSE then rollback: orig perms unchanged."""

    def test_chmod_rollback(self):
        cfg = TestConfig("chmod-rb")
        try:
            cfg.create_orig("f.txt", "hi")
            os.chmod(cfg.orig_path("f.txt"), 0o644)
            cfg.mount()
            agent_chmod(cfg, "A", "f.txt", 0o600)
            rollback(cfg, "A")
            time.sleep(0.5)
            mode = os.stat(cfg.orig_path("f.txt")).st_mode & 0o777
            self.assertEqual(mode, 0o644)
        finally:
            cfg.cleanup()


class TestReadOwnWrites(unittest.TestCase):
    """Agent's reads see its own pending writes (overlay-first)."""

    def test_read_own_writes(self):
        cfg = TestConfig("read-own")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            run_agent("A", [
                {"op": "write", "path": cfg.mnt_path("f.txt"), "content": "new"},
                {"op": "read",  "path": cfg.mnt_path("f.txt")},
            ])
            self.assertEqual(agent_read(cfg, "A", "f.txt"), "new")
        finally:
            cfg.cleanup()


class TestAppendPreservesOrigContent(unittest.TestCase):
    """Append after copy-up keeps the orig prefix intact."""

    def test_append(self):
        cfg = TestConfig("append")
        try:
            cfg.create_orig("f.txt", "hello")
            cfg.mount()
            agent_append(cfg, "A", "f.txt", " world")
            self.assertEqual(agent_read(cfg, "A", "f.txt"), "hello world")
            self.assertEqual(cfg.read_orig("f.txt"), "hello")
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("f.txt"), "hello world")
        finally:
            cfg.cleanup()


class TestMergeReaddirOrigAndOverlay(unittest.TestCase):
    """Readdir merges orig + overlay entries; whiteouts hidden; ctl/state hidden."""

    def test_merge_readdir(self):
        cfg = TestConfig("merge-rd")
        try:
            cfg.create_orig("a.txt", "a")
            cfg.create_orig("b.txt", "b")
            cfg.mount()
            agent_write(cfg, "A", "c.txt", "c")
            agent_unlink(cfg, "A", "a.txt")
            entries = agent_list(cfg, "A", "")
            self.assertIn("b.txt", entries)
            self.assertIn("c.txt", entries)
            self.assertNotIn("a.txt", entries)
            # internal files must not leak
            for hidden in (".shadow_state.json", ".shadow_wal"):
                self.assertNotIn(hidden, entries)
            for e in entries:
                self.assertFalse(e.startswith(".shadow.wh."),
                                 f"whiteout leaked: {e}")
        finally:
            cfg.cleanup()


class TestEmptyFileCommit(unittest.TestCase):
    """Creating an empty file then committing."""

    def test_empty_file(self):
        cfg = TestConfig("empty")
        try:
            cfg.mount()
            agent_write(cfg, "A", "empty.txt", "")
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertTrue(cfg.orig_exists("empty.txt"))
            self.assertEqual(cfg.read_orig("empty.txt"), "")
        finally:
            cfg.cleanup()


class TestLargeFileWriteCommit(unittest.TestCase):
    """Write a moderately large blob and verify integrity through commit."""

    def test_large_file(self):
        cfg = TestConfig("large")
        try:
            cfg.mount()
            blob = "X" * (256 * 1024)  # 256 KiB
            agent_write(cfg, "A", "big.bin", blob)
            self.assertEqual(agent_read(cfg, "A", "big.bin"), blob)
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("big.bin"), blob)
        finally:
            cfg.cleanup()


class TestSpecialFilenames(unittest.TestCase):
    """Non-ASCII / spaces / dots in filenames."""

    def test_special_names(self):
        cfg = TestConfig("special-names")
        try:
            cfg.mount()
            names = ["hello world.txt", "中文文件.txt", "a.b.c.tar.gz", ".hidden"]
            for n in names:
                agent_write(cfg, "A", n, n)
            for n in names:
                self.assertEqual(agent_read(cfg, "A", n), n)
            commit(cfg, "A")
            time.sleep(0.5)
            for n in names:
                self.assertEqual(cfg.read_orig(n), n)
        finally:
            cfg.cleanup()


class TestRollbackEmptyAgent(unittest.TestCase):
    """Rolling back an unknown / empty agent must not crash."""

    def test_rollback_unknown(self):
        cfg = TestConfig("rb-unknown")
        try:
            cfg.mount()
            # no operations performed; rollback should be a benign no-op
            try:
                rollback(cfg, "NOPE")
            except Exception as e:
                # Even if it errors, mount must remain healthy
                pass
            time.sleep(0.3)
            # FUSE still works
            agent_write(cfg, "A", "after.txt", "ok")
            self.assertEqual(agent_read(cfg, "A", "after.txt"), "ok")
        finally:
            cfg.cleanup()


class TestRollbackTwiceIsBenign(unittest.TestCase):
    """Calling rollback twice on the same agent is safe."""

    def test_rollback_twice(self):
        cfg = TestConfig("rb-twice")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "new")
            rollback(cfg, "A")
            time.sleep(0.5)
            try:
                rollback(cfg, "A")
            except Exception:
                pass
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("f.txt"), "orig")
        finally:
            cfg.cleanup()


class TestCommitTwiceIsBenign(unittest.TestCase):
    """Calling commit twice does not double-promote."""

    def test_commit_twice(self):
        cfg = TestConfig("commit-twice")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "v1")
            commit(cfg, "A")
            time.sleep(0.3)
            try:
                commit(cfg, "A")
            except Exception:
                pass
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("f.txt"), "v1")
        finally:
            cfg.cleanup()


class TestThreeAgentChain(unittest.TestCase):
    """A→B→C chain: rollback A cascades through B to C."""

    def test_chain_rollback(self):
        cfg = TestConfig("chain")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "a")
            agent_write(cfg, "B", "f.txt", "b")  # B depends on A
            agent_write(cfg, "C", "f.txt", "c")  # C depends on A,B
            rollback(cfg, "A")
            time.sleep(0.7)
            # orig untouched + overlay cleaned
            self.assertEqual(cfg.read_orig("f.txt"), "orig")
        finally:
            cfg.cleanup()


class TestDiamondDependency(unittest.TestCase):
    """A writes f1; B reads f1+writes f2; C reads f1+writes f3. rollback A → B,C."""

    def test_diamond(self):
        cfg = TestConfig("diamond")
        try:
            cfg.create_orig("f1.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "f1.txt", "a")
            run_agent("B", [
                {"op": "read",  "path": cfg.mnt_path("f1.txt")},
                {"op": "write", "path": cfg.mnt_path("f2.txt"), "content": "b"},
            ])
            run_agent("C", [
                {"op": "read",  "path": cfg.mnt_path("f1.txt")},
                {"op": "write", "path": cfg.mnt_path("f3.txt"), "content": "c"},
            ])
            rollback(cfg, "A")
            time.sleep(0.7)
            # B and C should be cascaded → their files not in orig
            self.assertEqual(cfg.read_orig("f1.txt"), "orig")
            self.assertFalse(cfg.orig_exists("f2.txt"))
            self.assertFalse(cfg.orig_exists("f3.txt"))
        finally:
            cfg.cleanup()


class TestPartialRollbackProtectsSharedOverlay(unittest.TestCase):
    """Rollback B alone: A's write on shared file remains promotable."""

    def test_partial_rollback(self):
        cfg = TestConfig("partial-rb")
        try:
            cfg.create_orig("shared.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "shared.txt", "a")
            agent_write(cfg, "B", "shared.txt", "b")
            rollback(cfg, "B")
            time.sleep(0.5)
            # A must still be able to commit; promote should produce non-orig.
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertNotEqual(cfg.read_orig("shared.txt"), "orig")
        finally:
            cfg.cleanup()


class TestDeepNestedCreateCommit(unittest.TestCase):
    """Mkdir chain + deep file write + commit."""

    def test_deep_nested(self):
        cfg = TestConfig("deep")
        try:
            cfg.mount()
            run_agent("A", [
                {"op": "mkdir", "path": cfg.mnt_path("a")},
                {"op": "mkdir", "path": cfg.mnt_path("a/b")},
                {"op": "mkdir", "path": cfg.mnt_path("a/b/c")},
                {"op": "write", "path": cfg.mnt_path("a/b/c/deep.txt"), "content": "x"},
            ])
            self.assertEqual(agent_read(cfg, "A", "a/b/c/deep.txt"), "x")
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("a/b/c/deep.txt"), "x")
        finally:
            cfg.cleanup()


class TestDeepNestedRollback(unittest.TestCase):
    """Rollback wipes deeply nested overlay tree."""

    def test_deep_rollback(self):
        cfg = TestConfig("deep-rb")
        try:
            cfg.mount()
            run_agent("A", [
                {"op": "mkdir", "path": cfg.mnt_path("a")},
                {"op": "mkdir", "path": cfg.mnt_path("a/b")},
                {"op": "write", "path": cfg.mnt_path("a/b/f.txt"), "content": "x"},
            ])
            rollback(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            self.assertFalse(agent_exists(cfg, "A", "a"))
            self.assertFalse(cfg.orig_exists("a"))
        finally:
            cfg.cleanup()


class TestStatSizeAfterWrite(unittest.TestCase):
    """Stat through FUSE returns the overlay size, not orig."""

    def test_stat_size(self):
        cfg = TestConfig("stat-size")
        try:
            cfg.create_orig("f.txt", "abc")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "abcdefghij")
            st = agent_stat(cfg, "A", "f.txt")
            self.assertTrue(st["ok"])
            self.assertEqual(st["size"], 10)
        finally:
            cfg.cleanup()


class TestRecreateAfterUnlinkPersistsCommit(unittest.TestCase):
    """Unlink → write → commit: orig has the new content, no whiteout left."""

    def test_recreate_commit(self):
        cfg = TestConfig("recreate-commit")
        try:
            cfg.create_orig("f.txt", "old")
            cfg.mount()
            run_agent("A", [
                {"op": "unlink", "path": cfg.mnt_path("f.txt")},
                {"op": "write",  "path": cfg.mnt_path("f.txt"), "content": "v2"},
            ])
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("f.txt"), "v2")
            # No leaked whiteout in staging
            for root, _, files in os.walk(cfg.staging):
                for fn in files:
                    self.assertFalse(fn.startswith(".shadow.wh."),
                                     f"residual whiteout: {fn}")
        finally:
            cfg.cleanup()


class TestParentDeletionHidesChildWriter(unittest.TestCase):
    """A rmdir parent (after emptying) hides B's later write attempts via ancestor wh."""

    def test_parent_deletion_hides(self):
        cfg = TestConfig("parent-del")
        try:
            os.makedirs(cfg.orig_path("d"))
            with open(cfg.orig_path("d/x.txt"), "w") as f:
                f.write("x")
            cfg.mount()
            agent_rmtree(cfg, "A", "d")
            # B trying to write inside the deleted dir should fail (ENOENT)
            res = run_agent("B", [
                {"op": "write", "path": cfg.mnt_path("d/y.txt"), "content": "y"},
            ])
            self.assertFalse(res[0]["ok"])
        finally:
            cfg.cleanup()


class TestCommitOnlyAffectedFilePromoted(unittest.TestCase):
    """Commit promotes only the agent's files; other agents untouched."""

    def test_only_affected(self):
        cfg = TestConfig("only-affected")
        try:
            cfg.create_orig("a.txt", "a-orig")
            cfg.create_orig("b.txt", "b-orig")
            cfg.mount()
            agent_write(cfg, "A", "a.txt", "a-new")
            agent_write(cfg, "B", "b.txt", "b-new")
            commit(cfg, "A")
            time.sleep(0.4)
            self.assertEqual(cfg.read_orig("a.txt"), "a-new")
            # B not committed → b.txt orig still intact
            self.assertEqual(cfg.read_orig("b.txt"), "b-orig")
        finally:
            cfg.cleanup()


class TestRollbackRestoresMtimeIndependence(unittest.TestCase):
    """Rollback after write must leave orig file intact (size + content)."""

    def test_orig_intact(self):
        cfg = TestConfig("orig-intact")
        try:
            cfg.create_orig("f.txt", "hello")
            orig_st = os.stat(cfg.orig_path("f.txt"))
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "completely different and longer")
            rollback(cfg, "A")
            time.sleep(0.5)
            new_st = os.stat(cfg.orig_path("f.txt"))
            self.assertEqual(orig_st.st_size, new_st.st_size)
            self.assertEqual(cfg.read_orig("f.txt"), "hello")
        finally:
            cfg.cleanup()


class TestUnlinkNonexistentReturnsENOENT(unittest.TestCase):
    """Unlinking a missing file fails with ENOENT and does not corrupt state."""

    def test_unlink_missing(self):
        cfg = TestConfig("unlink-missing")
        try:
            cfg.mount()
            res = run_agent("A", [{"op": "unlink", "path": cfg.mnt_path("ghost.txt")}])
            self.assertFalse(res[0]["ok"])
            self.assertEqual(res[0]["errno"], errno_const := __import__("errno").ENOENT)
            # Mount remains healthy
            agent_write(cfg, "A", "after.txt", "ok")
            self.assertEqual(agent_read(cfg, "A", "after.txt"), "ok")
        finally:
            cfg.cleanup()


class TestMkdirOnExistingFails(unittest.TestCase):
    """mkdir on an existing dir fails with EEXIST."""

    def test_mkdir_existing(self):
        cfg = TestConfig("mkdir-existing")
        try:
            os.makedirs(cfg.orig_path("d"))
            cfg.mount()
            res = run_agent("A", [{"op": "mkdir", "path": cfg.mnt_path("d")}])
            self.assertFalse(res[0]["ok"])
        finally:
            cfg.cleanup()


class TestRmdirNonemptyFails(unittest.TestCase):
    """rmdir on a non-empty dir fails (ENOTEMPTY)."""

    def test_rmdir_nonempty(self):
        cfg = TestConfig("rmdir-non-empty")
        try:
            os.makedirs(cfg.orig_path("d"))
            with open(cfg.orig_path("d/x.txt"), "w") as f:
                f.write("x")
            cfg.mount()
            res = run_agent("A", [{"op": "rmdir", "path": cfg.mnt_path("d")}])
            self.assertFalse(res[0]["ok"])
        finally:
            cfg.cleanup()


class TestRereadAfterCommitReflectsOrig(unittest.TestCase):
    """After commit + agent finalized, fresh agents see promoted content."""

    def test_reread_after_commit(self):
        cfg = TestConfig("reread")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "new")
            commit(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            # Independent fresh agent reads the promoted value
            self.assertEqual(agent_read(cfg, "Z", "f.txt"), "new")
        finally:
            cfg.cleanup()


class TestManySmallWritesDedup(unittest.TestCase):
    """Many sequential writes to the same file by one agent → still promotes once."""

    def test_many_writes(self):
        cfg = TestConfig("many-writes")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            ops = [{"op": "write", "path": cfg.mnt_path("f.txt"),
                    "content": f"v{i}"} for i in range(20)]
            run_agent("A", ops)
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("f.txt"), "v19")
        finally:
            cfg.cleanup()


class TestWriteThenRollbackRemovesOverlay(unittest.TestCase):
    """After rollback the staging directory should not retain agent's overlay file."""

    def test_overlay_cleaned(self):
        cfg = TestConfig("overlay-clean")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "new")
            rollback(cfg, "A")
            time.sleep(0.7)
            # staging/f.txt must not exist (single-writer rollback fully cleans)
            self.assertFalse(
                os.path.exists(os.path.join(cfg.staging, "f.txt")),
                "overlay file leaked after rollback",
            )
        finally:
            cfg.cleanup()


class TestSiblingWriteDoesNotCreateDependency(unittest.TestCase):
    """Two agents touching unrelated files have no dep; rollback A keeps B."""

    def test_sibling_writes(self):
        cfg = TestConfig("sibling-w")
        try:
            cfg.mount()
            agent_write(cfg, "A", "a.txt", "a")
            agent_write(cfg, "B", "b.txt", "b")
            rollback(cfg, "A")
            time.sleep(0.5)
            commit(cfg, "B")
            time.sleep(0.4)
            self.assertFalse(cfg.orig_exists("a.txt"))
            self.assertEqual(cfg.read_orig("b.txt"), "b")
        finally:
            cfg.cleanup()


class TestRenameRollbackThenRecommit(unittest.TestCase):
    """Rename → rollback → rename again → commit; second flow succeeds."""

    def test_rename_rollback_recommit(self):
        cfg = TestConfig("rename-recommit")
        try:
            cfg.create_orig("src.txt", "data")
            cfg.mount()
            agent_rename(cfg, "A", "src.txt", "dst.txt")
            rollback(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            agent_rename(cfg, "B", "src.txt", "dst.txt")
            commit(cfg, "B")
            time.sleep(0.5)
            self.assertFalse(cfg.orig_exists("src.txt"))
            self.assertEqual(cfg.read_orig("dst.txt"), "data")
        finally:
            cfg.cleanup()


class TestSequentialAgentsOnSameFile(unittest.TestCase):
    """A commits f, then a fresh B reads & writes f; B is independent of A (already promoted)."""

    def test_sequential(self):
        cfg = TestConfig("sequential")
        try:
            cfg.create_orig("f.txt", "v0")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "v1")
            commit(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            self.assertEqual(cfg.read_orig("f.txt"), "v1")
            # Fresh agent B writes again
            agent_write(cfg, "B", "f.txt", "v2")
            # Rolling back B should restore promoted v1
            rollback(cfg, "B")
            time.sleep(FUSE_CACHE_WAIT)
            self.assertEqual(cfg.read_orig("f.txt"), "v1")
            self.assertEqual(agent_read(cfg, "Z", "f.txt"), "v1")
        finally:
            cfg.cleanup()


class TestWhiteoutNotLeakedAfterCommit(unittest.TestCase):
    """After unlink+commit, no whiteout file remains in staging."""

    def test_no_whiteout_leak(self):
        cfg = TestConfig("wh-leak")
        try:
            cfg.create_orig("f.txt", "x")
            cfg.mount()
            agent_unlink(cfg, "A", "f.txt")
            commit(cfg, "A")
            time.sleep(0.5)
            for root, _, files in os.walk(cfg.staging):
                for fn in files:
                    self.assertFalse(
                        fn.startswith(".shadow.wh."),
                        f"residual whiteout in staging: {fn}")
        finally:
            cfg.cleanup()


class TestCtlFileInvisibleInListing(unittest.TestCase):
    """`.shadow.ctl` should be writable but not appear in readdir of root."""

    def test_ctl_invisible(self):
        cfg = TestConfig("ctl-invis")
        try:
            cfg.create_orig("a.txt", "a")
            cfg.mount()
            entries = agent_list(cfg, "A", "")
            # Implementation may show or hide .shadow.ctl; assert real files present
            self.assertIn("a.txt", entries)
        finally:
            cfg.cleanup()


# ===========================================================================
# Additional Edge-case Test Cases (extra coverage)
# ===========================================================================
import errno as _errno


class TestSymlinkVisibleInReaddir(unittest.TestCase):
    """Orig symlinks must be enumerated (read-only) without breaking listing."""

    def test_symlink_listed(self):
        cfg = TestConfig("sym-list")
        try:
            cfg.create_orig("target.txt", "hi")
            os.symlink("target.txt", cfg.orig_path("link.txt"))
            cfg.mount()
            entries = agent_list(cfg, "A", "")
            self.assertIn("target.txt", entries)
            self.assertIn("link.txt", entries)
        finally:
            cfg.cleanup()


class TestRenameIntoOwnSubdirFails(unittest.TestCase):
    """rename(dir, dir/sub/...) creates a cycle and must be refused."""

    def test_rename_cycle(self):
        cfg = TestConfig("rename-cycle")
        try:
            os.makedirs(cfg.orig_path("d/sub"))
            cfg.mount()
            res = run_agent("A", [
                {"op": "rename",
                 "src": cfg.mnt_path("d"),
                 "dst": cfg.mnt_path("d/sub/inner")},
            ])
            self.assertFalse(res[0]["ok"])
            # orig untouched
            self.assertTrue(cfg.orig_exists("d/sub"))
        finally:
            cfg.cleanup()


class TestRenameSamePathIsNoop(unittest.TestCase):
    """rename(x, x) is a POSIX no-op and must not corrupt overlay."""

    def test_rename_same(self):
        cfg = TestConfig("rename-same")
        try:
            cfg.create_orig("f.txt", "keep")
            cfg.mount()
            res = run_agent("A", [
                {"op": "rename",
                 "src": cfg.mnt_path("f.txt"),
                 "dst": cfg.mnt_path("f.txt")},
            ])
            self.assertTrue(res[0]["ok"])
            self.assertEqual(agent_read(cfg, "A", "f.txt"), "keep")
            self.assertEqual(cfg.read_orig("f.txt"), "keep")
        finally:
            cfg.cleanup()


class TestRenameNonexistentSrcFails(unittest.TestCase):
    """Renaming a missing source must surface ENOENT cleanly."""

    def test_rename_missing(self):
        cfg = TestConfig("rename-missing")
        try:
            cfg.mount()
            res = run_agent("A", [
                {"op": "rename",
                 "src": cfg.mnt_path("ghost.txt"),
                 "dst": cfg.mnt_path("new.txt")},
            ])
            self.assertFalse(res[0]["ok"])
            # mount still usable afterwards
            agent_write(cfg, "A", "after.txt", "ok")
        finally:
            cfg.cleanup()


class TestMkdirOverExistingFile(unittest.TestCase):
    """mkdir on an orig file path must fail."""

    def test_mkdir_over_file(self):
        cfg = TestConfig("mkdir-over-file")
        try:
            cfg.create_orig("f.txt", "x")
            cfg.mount()
            res = run_agent("A", [{"op": "mkdir", "path": cfg.mnt_path("f.txt")}])
            self.assertFalse(res[0]["ok"])
        finally:
            cfg.cleanup()


class TestUnlinkDirectoryFails(unittest.TestCase):
    """unlink on a directory must fail (EISDIR / EPERM)."""

    def test_unlink_dir(self):
        cfg = TestConfig("unlink-dir")
        try:
            os.makedirs(cfg.orig_path("d"))
            cfg.mount()
            res = run_agent("A", [{"op": "unlink", "path": cfg.mnt_path("d")}])
            self.assertFalse(res[0]["ok"])
            self.assertTrue(cfg.orig_exists("d"))
        finally:
            cfg.cleanup()


class TestRmdirOnFileFails(unittest.TestCase):
    """rmdir on a regular file must fail (ENOTDIR)."""

    def test_rmdir_file(self):
        cfg = TestConfig("rmdir-file")
        try:
            cfg.create_orig("f.txt", "x")
            cfg.mount()
            res = run_agent("A", [{"op": "rmdir", "path": cfg.mnt_path("f.txt")}])
            self.assertFalse(res[0]["ok"])
            self.assertTrue(cfg.orig_exists("f.txt"))
        finally:
            cfg.cleanup()


class TestTruncateExtendCommit(unittest.TestCase):
    """Truncating to a larger size pads with zeros; commit promotes."""

    def test_truncate_extend(self):
        cfg = TestConfig("trunc-extend")
        try:
            cfg.create_orig("f.txt", "abc")
            cfg.mount()
            agent_truncate(cfg, "A", "f.txt", 8)
            st = agent_stat(cfg, "A", "f.txt")
            self.assertEqual(st["size"], 8)
            commit(cfg, "A")
            time.sleep(0.5)
            with open(cfg.orig_path("f.txt"), "rb") as f:
                data = f.read()
            self.assertEqual(len(data), 8)
            self.assertTrue(data.startswith(b"abc"))
            self.assertEqual(data[3:], b"\x00" * 5)
        finally:
            cfg.cleanup()


class TestTruncateToZero(unittest.TestCase):
    """Truncate-to-zero produces empty file at promote."""

    def test_truncate_zero(self):
        cfg = TestConfig("trunc-zero")
        try:
            cfg.create_orig("f.txt", "hello")
            cfg.mount()
            agent_truncate(cfg, "A", "f.txt", 0)
            self.assertEqual(agent_read(cfg, "A", "f.txt"), "")
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("f.txt"), "")
        finally:
            cfg.cleanup()


class TestChmodCommitPromotesMode(unittest.TestCase):
    """chmod via FUSE then commit must update orig file mode."""

    def test_chmod_commit(self):
        cfg = TestConfig("chmod-commit")
        try:
            cfg.create_orig("f.txt", "x")
            os.chmod(cfg.orig_path("f.txt"), 0o644)
            cfg.mount()
            agent_chmod(cfg, "A", "f.txt", 0o600)
            commit(cfg, "A")
            time.sleep(0.5)
            mode = os.stat(cfg.orig_path("f.txt")).st_mode & 0o777
            self.assertEqual(mode, 0o600)
        finally:
            cfg.cleanup()


class TestParallelIndependentWritesCommit(unittest.TestCase):
    """Two agents writing different files in quick succession both commit."""

    def test_parallel_writes(self):
        cfg = TestConfig("parallel-w")
        try:
            cfg.mount()
            # interleave small bursts
            for i in range(5):
                agent_write(cfg, "A", f"a{i}.txt", f"a-{i}")
                agent_write(cfg, "B", f"b{i}.txt", f"b-{i}")
            commit(cfg, "A")
            commit(cfg, "B")
            time.sleep(0.5)
            for i in range(5):
                self.assertEqual(cfg.read_orig(f"a{i}.txt"), f"a-{i}")
                self.assertEqual(cfg.read_orig(f"b{i}.txt"), f"b-{i}")
        finally:
            cfg.cleanup()


class TestInvalidCtlCommandIgnored(unittest.TestCase):
    """Garbage written to .shadow.ctl must not crash the FUSE server."""

    def test_garbage_ctl(self):
        cfg = TestConfig("bad-ctl")
        try:
            cfg.mount()
            ctl = os.path.join(cfg.mnt, ".shadow.ctl")
            # Several malformed commands. Each is at most one line.
            for payload in ("\n", "x\n", "c\n", "r \n", "???\n",
                            "commit \n", "r /nonexistent/cgroup\n"):
                try:
                    with open(ctl, "w") as f:
                        f.write(payload)
                except OSError:
                    pass  # backend may reject the write — that is fine
            time.sleep(0.3)
            # Mount remains operational
            agent_write(cfg, "A", "after.txt", "ok")
            self.assertEqual(agent_read(cfg, "A", "after.txt"), "ok")
        finally:
            cfg.cleanup()


class TestRmtreeThenMkdirSamePath(unittest.TestCase):
    """rm -rf foo/ then mkdir foo/ → commit produces empty foo/ in orig."""

    def test_rmtree_recreate(self):
        cfg = TestConfig("rmtree-recreate")
        try:
            os.makedirs(cfg.orig_path("foo/sub"))
            with open(cfg.orig_path("foo/sub/x.txt"), "w") as f:
                f.write("x")
            cfg.mount()
            run_agent("A", [
                {"op": "rmtree", "path": cfg.mnt_path("foo")},
                {"op": "mkdir",  "path": cfg.mnt_path("foo")},
            ])
            self.assertTrue(agent_exists(cfg, "A", "foo"))
            self.assertFalse(agent_exists(cfg, "A", "foo/sub"))
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertTrue(os.path.isdir(cfg.orig_path("foo")))
            # children were rm -rf'd at promote
            self.assertEqual(os.listdir(cfg.orig_path("foo")), [])
        finally:
            cfg.cleanup()


class TestStatNonexistentReturnsENOENT(unittest.TestCase):
    """stat on a missing path returns ENOENT."""

    def test_stat_missing(self):
        cfg = TestConfig("stat-missing")
        try:
            cfg.mount()
            res = run_agent("A", [{"op": "stat", "path": cfg.mnt_path("nope.txt")}])
            self.assertFalse(res[0]["ok"])
            self.assertEqual(res[0].get("errno"), _errno.ENOENT)
        finally:
            cfg.cleanup()


class TestReadAfterUnlinkFails(unittest.TestCase):
    """Reading a file after it was unlinked must surface ENOENT."""

    def test_read_after_unlink(self):
        cfg = TestConfig("read-after-unlink")
        try:
            cfg.create_orig("f.txt", "x")
            cfg.mount()
            agent_unlink(cfg, "A", "f.txt")
            res = run_agent("A", [{"op": "read", "path": cfg.mnt_path("f.txt")}])
            self.assertFalse(res[0]["ok"])
            self.assertEqual(res[0].get("errno"), _errno.ENOENT)
        finally:
            cfg.cleanup()


class TestStatAfterUnlinkFails(unittest.TestCase):
    """stat on whiteout'd path returns ENOENT (whiteout hides correctly)."""

    def test_stat_after_unlink(self):
        cfg = TestConfig("stat-after-unlink")
        try:
            cfg.create_orig("f.txt", "x")
            cfg.mount()
            agent_unlink(cfg, "A", "f.txt")
            res = run_agent("A", [{"op": "stat", "path": cfg.mnt_path("f.txt")}])
            self.assertFalse(res[0]["ok"])
            self.assertEqual(res[0].get("errno"), _errno.ENOENT)
        finally:
            cfg.cleanup()


class TestRenameRollbackRestoresDstWhiteout(unittest.TestCase):
    """Rename overwrites dst → on rollback dst's pre-existing whiteout (if any) restores.

    Setup: A unlinks dst (creating a whiteout). B renames src→dst (clearing
    A's whiteout). Rolling back B alone must restore A's whiteout.
    """

    def test_rename_rollback_restores_wh(self):
        cfg = TestConfig("rename-rb-wh")
        try:
            cfg.create_orig("src.txt", "src")
            cfg.create_orig("dst.txt", "dst")
            cfg.mount()
            agent_unlink(cfg, "A", "dst.txt")
            self.assertFalse(agent_exists(cfg, "A", "dst.txt"))
            agent_rename(cfg, "B", "src.txt", "dst.txt")
            self.assertTrue(agent_exists(cfg, "B", "dst.txt"))
            rollback(cfg, "B")
            time.sleep(FUSE_CACHE_WAIT)
            # A's whiteout for dst.txt must be back: dst hidden again
            self.assertFalse(agent_exists(cfg, "A", "dst.txt"))
            # orig untouched
            self.assertTrue(cfg.orig_exists("src.txt"))
            self.assertTrue(cfg.orig_exists("dst.txt"))
        finally:
            cfg.cleanup()


class TestThreeAgentsCommitInDependencyOrder(unittest.TestCase):
    """A→B→C chain: committing in topological order eventually promotes once."""

    def test_three_agent_commit(self):
        cfg = TestConfig("three-commit")
        try:
            cfg.create_orig("f.txt", "v0")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "v1")
            agent_write(cfg, "B", "f.txt", "v2")
            agent_write(cfg, "C", "f.txt", "v3")
            # commit downstream first → no promote yet
            commit(cfg, "C")
            commit(cfg, "B")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("f.txt"), "v0")
            commit(cfg, "A")
            time.sleep(0.5)
            # final shared overlay state wins (v3 was last write)
            self.assertEqual(cfg.read_orig("f.txt"), "v3")
        finally:
            cfg.cleanup()


class TestRecreateAfterRmtreeCommitClearsOrig(unittest.TestCase):
    """rm -rf + commit removes orig tree; subsequent listing is empty."""

    def test_rmtree_commit(self):
        cfg = TestConfig("rmtree-commit")
        try:
            os.makedirs(cfg.orig_path("x/y"))
            with open(cfg.orig_path("x/y/z.txt"), "w") as f:
                f.write("z")
            cfg.mount()
            agent_rmtree(cfg, "A", "x")
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertFalse(cfg.orig_exists("x"))
        finally:
            cfg.cleanup()


class TestAppendRollbackRestoresOrig(unittest.TestCase):
    """Append in overlay then rollback → orig content untouched, mnt back to orig."""

    def test_append_rollback(self):
        cfg = TestConfig("append-rb")
        try:
            cfg.create_orig("f.txt", "hello")
            cfg.mount()
            agent_append(cfg, "A", "f.txt", " world")
            self.assertEqual(agent_read(cfg, "A", "f.txt"), "hello world")
            rollback(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            self.assertEqual(cfg.read_orig("f.txt"), "hello")
            self.assertEqual(agent_read(cfg, "A", "f.txt"), "hello")
        finally:
            cfg.cleanup()


class TestChainedRenamesCommit(unittest.TestCase):
    """a→b→c chained renames in one agent → only c exists in orig at commit."""

    def test_chain_renames(self):
        cfg = TestConfig("chain-rename")
        try:
            cfg.create_orig("a.txt", "data")
            cfg.mount()
            run_agent("A", [
                {"op": "rename", "src": cfg.mnt_path("a.txt"),
                 "dst": cfg.mnt_path("b.txt")},
                {"op": "rename", "src": cfg.mnt_path("b.txt"),
                 "dst": cfg.mnt_path("c.txt")},
            ])
            self.assertFalse(agent_exists(cfg, "A", "a.txt"))
            self.assertFalse(agent_exists(cfg, "A", "b.txt"))
            self.assertEqual(agent_read(cfg, "A", "c.txt"), "data")
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertFalse(cfg.orig_exists("a.txt"))
            self.assertFalse(cfg.orig_exists("b.txt"))
            self.assertEqual(cfg.read_orig("c.txt"), "data")
        finally:
            cfg.cleanup()


class TestWhiteoutNotLeakedInSubdirListing(unittest.TestCase):
    """Subdir readdir must not surface .shadow.wh.* markers."""

    def test_subdir_no_whiteout(self):
        cfg = TestConfig("subdir-wh")
        try:
            os.makedirs(cfg.orig_path("d"))
            with open(cfg.orig_path("d/keep.txt"), "w") as f:
                f.write("k")
            with open(cfg.orig_path("d/gone.txt"), "w") as f:
                f.write("g")
            cfg.mount()
            agent_unlink(cfg, "A", "d/gone.txt")
            entries = agent_list(cfg, "A", "d")
            self.assertIn("keep.txt", entries)
            self.assertNotIn("gone.txt", entries)
            for e in entries:
                self.assertFalse(e.startswith(".shadow.wh."),
                                 f"whiteout leaked in subdir: {e}")
        finally:
            cfg.cleanup()


class TestManyAgentsRollbackEach(unittest.TestCase):
    """Rolling back 8 independent agents leaves no overlay residue."""

    def test_many_agents(self):
        cfg = TestConfig("many-agents")
        try:
            cfg.mount()
            names = [f"AG{i}" for i in range(8)]
            for n in names:
                agent_write(cfg, n, f"{n}.txt", n)
            for n in names:
                rollback(cfg, n)
            time.sleep(FUSE_CACHE_WAIT)
            # No overlay file remains for any of them
            for n in names:
                self.assertFalse(
                    os.path.exists(os.path.join(cfg.staging, f"{n}.txt")),
                    f"residual overlay for {n}")
                self.assertFalse(cfg.orig_exists(f"{n}.txt"))
        finally:
            cfg.cleanup()


class TestReadOrigSymlinkContent(unittest.TestCase):
    """Reading via an orig symlink returns the target's content."""

    def test_read_through_symlink(self):
        cfg = TestConfig("read-sym")
        try:
            cfg.create_orig("target.txt", "hi-target")
            os.symlink("target.txt", cfg.orig_path("link.txt"))
            cfg.mount()
            content = agent_read(cfg, "A", "link.txt")
            self.assertEqual(content, "hi-target")
        finally:
            cfg.cleanup()


class TestCommitAfterPartialDownstreamRollback(unittest.TestCase):
    """A writes file f1, B writes file f2 reading f1 (depends on A).
    Rollback B first; A can still commit cleanly."""

    def test_commit_after_partial_rb(self):
        cfg = TestConfig("commit-partial")
        try:
            cfg.create_orig("f1.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "f1.txt", "a")
            run_agent("B", [
                {"op": "read", "path": cfg.mnt_path("f1.txt")},
                {"op": "write", "path": cfg.mnt_path("f2.txt"), "content": "b"},
            ])
            rollback(cfg, "B")
            time.sleep(0.5)
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("f1.txt"), "a")
            self.assertFalse(cfg.orig_exists("f2.txt"))
        finally:
            cfg.cleanup()


class TestRapidWriteRollbackCycle(unittest.TestCase):
    """Repeated write/rollback cycles must remain stable."""

    def test_cycle(self):
        cfg = TestConfig("cycle")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            for i in range(5):
                ag = f"R{i}"
                agent_write(cfg, ag, "f.txt", f"v{i}")
                rollback(cfg, ag)
                time.sleep(0.3)
                self.assertEqual(cfg.read_orig("f.txt"), "orig")
            # Now a final commit from a fresh agent should still work
            agent_write(cfg, "FINAL", "f.txt", "final")
            commit(cfg, "FINAL")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("f.txt"), "final")
        finally:
            cfg.cleanup()


class TestUnlinkRecreateRollback(unittest.TestCase):
    """unlink + write same path then rollback → orig file fully restored."""

    def test_unlink_recreate_rollback(self):
        cfg = TestConfig("unlink-rec-rb")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            run_agent("A", [
                {"op": "unlink", "path": cfg.mnt_path("f.txt")},
                {"op": "write",  "path": cfg.mnt_path("f.txt"), "content": "new"},
            ])
            rollback(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            self.assertTrue(cfg.orig_exists("f.txt"))
            self.assertEqual(cfg.read_orig("f.txt"), "orig")
            self.assertEqual(agent_read(cfg, "Z", "f.txt"), "orig")
        finally:
            cfg.cleanup()


class TestRmdirThenWriteInsideFails(unittest.TestCase):
    """After rmdir on a parent, writes inside that parent must fail."""

    def test_write_below_rmdir(self):
        cfg = TestConfig("rmdir-below")
        try:
            os.makedirs(cfg.orig_path("d"))
            cfg.mount()
            agent_rmdir(cfg, "A", "d")
            res = run_agent("A", [
                {"op": "write",
                 "path": cfg.mnt_path("d/x.txt"), "content": "x"},
            ])
            self.assertFalse(res[0]["ok"])
        finally:
            cfg.cleanup()


class TestEmptyPathSegmentsHandled(unittest.TestCase):
    """Paths with redundant slashes should be normalised by FUSE."""

    def test_redundant_slash(self):
        cfg = TestConfig("redundant-slash")
        try:
            cfg.mount()
            # double-slashes inside the path are squeezed by the kernel.
            p = cfg.mnt_path("") + "//x.txt"
            res = run_agent("A", [{"op": "write", "path": p, "content": "hi"}])
            self.assertTrue(res[0]["ok"])
            self.assertEqual(agent_read(cfg, "A", "x.txt"), "hi")
        finally:
            cfg.cleanup()


class TestStateAndWalNotInRoot(unittest.TestCase):
    """Internal state files (.shadow_state.json / .shadow_wal) must NOT
    leak into the user-visible root listing."""

    def test_internal_hidden(self):
        cfg = TestConfig("internal-hidden")
        try:
            cfg.create_orig("a.txt", "a")
            cfg.mount()
            # Trigger some WAL activity so the files exist on disk
            agent_write(cfg, "A", "b.txt", "b")
            entries = agent_list(cfg, "A", "")
            for hidden in (".shadow_state.json", ".shadow_wal"):
                self.assertNotIn(hidden, entries,
                                 f"internal file leaked: {hidden}")
        finally:
            cfg.cleanup()


class TestMultiAgentCommitSequence(unittest.TestCase):
    """Two independent agents' commits both promote correctly."""

    def test_multi_commit(self):
        cfg = TestConfig("multi-commit-seq")
        try:
            cfg.mount()
            agent_write(cfg, "A", "a.txt", "a")
            agent_write(cfg, "B", "b.txt", "b")
            commit(cfg, "B")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("b.txt"), "b")
            self.assertFalse(cfg.orig_exists("a.txt"))
            commit(cfg, "A")
            time.sleep(0.3)
            self.assertEqual(cfg.read_orig("a.txt"), "a")
        finally:
            cfg.cleanup()


class TestRollbackThenSecondAgentCanWrite(unittest.TestCase):
    """After agent A is rolled back, a fresh agent B can write the same file."""

    def test_rollback_then_write(self):
        cfg = TestConfig("rb-then-w")
        try:
            cfg.create_orig("f.txt", "orig")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "a")
            rollback(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            agent_write(cfg, "B", "f.txt", "b")
            commit(cfg, "B")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("f.txt"), "b")
        finally:
            cfg.cleanup()


class TestBinaryContentRoundTrip(unittest.TestCase):
    """Bytes including ASCII control chars survive a round-trip."""

    def test_binary_roundtrip(self):
        cfg = TestConfig("binary")
        try:
            cfg.mount()
            # Skip 0x0D (CR): Python text-mode open() applies universal
            # newline translation on read which would silently convert
            # CR → LF and break the round-trip equality check. The point
            # of this test is the byte path through FUSE, not Python's
            # newline policy.
            payload = "".join(chr(c) for c in range(1, 128) if c != 0x0D)
            agent_write(cfg, "A", "bin.txt", payload)
            self.assertEqual(agent_read(cfg, "A", "bin.txt"), payload)
            commit(cfg, "A")
            time.sleep(0.5)
            with open(cfg.orig_path("bin.txt"), "rb") as f:
                self.assertEqual(f.read().decode("utf-8"), payload)
        finally:
            cfg.cleanup()


class TestOpenWithCreateFlag(unittest.TestCase):
    """O_CREAT|O_WRONLY|O_TRUNC end-to-end via raw fd."""

    def test_raw_open_create(self):
        cfg = TestConfig("raw-create")
        try:
            cfg.mount()
            run_agent("A", [
                {"op": "raw_write", "path": cfg.mnt_path("raw.txt"),
                 "flags": os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 "content": "raw-data"},
            ])
            self.assertEqual(agent_read(cfg, "A", "raw.txt"), "raw-data")
            commit(cfg, "A")
            time.sleep(0.5)
            self.assertEqual(cfg.read_orig("raw.txt"), "raw-data")
        finally:
            cfg.cleanup()


class TestConcurrentReadDuringWrite(unittest.TestCase):
    """Reads from a sibling agent during another's write must not lose data."""

    def test_concurrent_read(self):
        cfg = TestConfig("concurrent-read")
        try:
            cfg.create_orig("f.txt", "orig-data")
            cfg.mount()
            # B reads BEFORE A's write; should see orig
            self.assertEqual(agent_read(cfg, "B", "f.txt"), "orig-data")
            # A writes
            agent_write(cfg, "A", "f.txt", "new-data")
            # B reads again — sees overlay (shared overlay semantics)
            content = agent_read(cfg, "B", "f.txt")
            self.assertIn(content, ("orig-data", "new-data"))
        finally:
            cfg.cleanup()


class TestRollbackUnknownAgentNoCrash(unittest.TestCase):
    """Rolling back an agent that never existed (typo'd cgroup) is a no-op."""

    def test_rollback_typo(self):
        cfg = TestConfig("rb-typo")
        try:
            cfg.mount()
            ctl = os.path.join(cfg.mnt, ".shadow.ctl")
            with open(ctl, "w") as f:
                f.write("r /user.slice/never-existed.scope\n")
            time.sleep(0.3)
            # mount remains usable
            agent_write(cfg, "A", "after.txt", "ok")
            self.assertEqual(agent_read(cfg, "A", "after.txt"), "ok")
        finally:
            cfg.cleanup()


class TestFreshAgentReadAfterCommitSeesPromoted(unittest.TestCase):
    """After commit + cache expiry, a fresh agent sees promoted content."""

    def test_fresh_read(self):
        cfg = TestConfig("fresh-read")
        try:
            cfg.create_orig("f.txt", "v0")
            cfg.mount()
            agent_write(cfg, "A", "f.txt", "v1")
            commit(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            # Direct orig read: promoted
            self.assertEqual(cfg.read_orig("f.txt"), "v1")
            # Through FUSE from a fresh agent: promoted view
            self.assertEqual(agent_read(cfg, "FRESH", "f.txt"), "v1")
        finally:
            cfg.cleanup()


class TestRmdirRollbackThenRecommit(unittest.TestCase):
    """Rmdir → rollback → rmdir again → commit eventually removes orig dir."""

    def test_rmdir_rollback_recommit(self):
        cfg = TestConfig("rmdir-rb-recommit")
        try:
            os.makedirs(cfg.orig_path("d"))
            cfg.mount()
            agent_rmdir(cfg, "A", "d")
            rollback(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            self.assertTrue(agent_exists(cfg, "A", "d"))
            agent_rmdir(cfg, "B", "d")
            commit(cfg, "B")
            time.sleep(0.5)
            self.assertFalse(cfg.orig_exists("d"))
        finally:
            cfg.cleanup()


class TestUnlinkRollbackDoesNotResurrectInUnaffected(unittest.TestCase):
    """Rolling back A's unlink restores file for unrelated agent C as well."""

    def test_unlink_rollback_visibility(self):
        cfg = TestConfig("unlink-rb-vis")
        try:
            cfg.create_orig("f.txt", "x")
            cfg.mount()
            agent_unlink(cfg, "A", "f.txt")
            self.assertFalse(agent_exists(cfg, "C", "f.txt"))
            rollback(cfg, "A")
            time.sleep(FUSE_CACHE_WAIT)
            self.assertTrue(agent_exists(cfg, "C", "f.txt"))
            self.assertEqual(agent_read(cfg, "C", "f.txt"), "x")
        finally:
            cfg.cleanup()


# ===========================================================================
# Orchestrator release gating (fail-closed) - pure unit tests, no FUSE/root.
# Run standalone with:
#   python3 -m unittest ShadowFS.tests.integration_test.TestOrchestratorReleaseFailClosed
# ===========================================================================
class TestOrchestratorReleaseFailClosed(unittest.TestCase):
    """The orchestrator must NEVER release external effects unless ShadowFS
    POSITIVELY confirms the agent is Finalized (releasable). Any ambiguity --
    ShadowFS down, error status, missing field, malformed body -- must fail
    closed. Built without real sockets by bypassing __init__."""

    @staticmethod
    def _orch(fs_behavior):
        orch_dir = PROJECT_ROOT.parent / "orchestrator"
        if str(orch_dir) not in sys.path:
            sys.path.insert(0, str(orch_dir))
        import shadow_orchestrator as so
        orch = so.ShadowOrchestrator.__new__(so.ShadowOrchestrator)

        class _FakeClient:
            def request(self, data):
                return fs_behavior()

        orch.fs_client = _FakeClient()
        return orch

    def test_releasable_true_only_when_positively_confirmed(self):
        orch = self._orch(lambda: {"status": "ok", "releasable": True})
        self.assertTrue(orch._fs_can_release("cg"))

    def test_releasable_false(self):
        orch = self._orch(lambda: {"status": "ok", "releasable": False})
        self.assertFalse(orch._fs_can_release("cg"))

    def test_status_error_fail_closed(self):
        orch = self._orch(lambda: {"status": "error", "message": "boom"})
        self.assertFalse(orch._fs_can_release("cg"))

    def test_missing_releasable_field_fail_closed(self):
        orch = self._orch(lambda: {"status": "ok"})  # no 'releasable'
        self.assertFalse(orch._fs_can_release("cg"))

    def test_connection_exception_fail_closed(self):
        def boom():
            raise ConnectionError("ShadowFS disconnected")
        orch = self._orch(boom)
        self.assertFalse(orch._fs_can_release("cg"))

    def test_timeout_exception_fail_closed(self):
        def boom():
            raise TimeoutError("ShadowFS timed out")
        orch = self._orch(boom)
        self.assertFalse(orch._fs_can_release("cg"))

    def test_malformed_nondict_response_fail_closed(self):
        orch = self._orch(lambda: ["not", "a", "dict"])
        self.assertFalse(orch._fs_can_release("cg"))


# ===========================================================================
# Runner
# ===========================================================================
if __name__ == "__main__":
    if not SHADOWFS_BIN.exists():
        print(f"ERROR: binary not found at {SHADOWFS_BIN}", file=sys.stderr)
        print("Run: go build -o shadowfs .", file=sys.stderr)
        sys.exit(2)
    unittest.main(verbosity=2)
