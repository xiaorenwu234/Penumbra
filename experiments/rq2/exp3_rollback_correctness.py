#!/usr/bin/env python3
"""
Experiment 3: File, Process, and Output Rollback Correctness

Every lifecycle step goes through the real ShadowOrchestrator session API
(framework.orch.OrchClient):

    session_open -> session_begin_epoch -> session_run -> session_resolve_epoch

so rollback is exercised by the SYSTEM (decision="deny" rolls the epoch back
losslessly; decision="allow" audits the sealed trace and commits), never by the
harness poking ShadowFS/ShadowProc directly.

What each trial proves, and how it is checked:
  * File content / permission / rename / hard link / whiteout: after deny the
    backing store must match the epoch-start snapshot, AND the next command run
    in the SAME logical session (now served by the restored baseline) must
    observe the original state -- not just an external read of the backing store.
  * Child-process termination (the recovery guarantee): the candidate forks a
    long-lived child, we confirm the child joined the epoch's process tree, deny
    the epoch, then confirm the candidate AND every descendant are gone and the
    next session command runs normally on the recovered baseline.
  * Environment / CWD: candidate-side ``cd``/``export`` must not survive into
    the baseline that serves the next command after rollback.
  * Provisional output: output produced inside a denied epoch must be removed
    from the committed transcript.
  * Commit-exactly-once / allow-matches-native: an allowed epoch commits once
    and yields the state a native (unshadowed) write would produce.

Outcome classification (framework.errors): a lifecycle failure (orchestrator or
ShadowObserve unreachable, epoch open, resolve fail-closed, fence never happened,
session unusable after rollback) is an INFRA_ERROR and makes the run exit
non-zero. It is never counted as a pass.

Usage:
    SHADOW_RUN_RQ2_EXPERIMENTS=1 python3 exp3_rollback_correctness.py --repeats 10
"""

import argparse
import os
import sys
import tempfile
import time
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(os.path.dirname(_HERE))  # .../speculative_shadow
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)          # framework.*
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)          # policy.*

from framework.errors import InfrastructureError, infra
from framework.metrics import MetricsCollector
from framework.orch import OrchClient, orch_sock_path
from framework.client import ShadowObserveClient
from framework.oracle import EffectOracle, FileSnapshot, DirSnapshot
from framework.paths import (
    fuse_path, harness_path, ensure_fuse_dirs, is_fuse_mounted,
    SHADOWFS_MNT, SHADOWFS_ORIG, SHADOWFS_STAGING,
)

RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ2_EXPERIMENTS") == "1"

# Note: the FILESYSTEM read op is named "OPEN" in policy/effect_schema.json
# ("READ" is not a valid policy event_type). Kept in sync with exp2.
FS_OPS = ("OPEN", "WRITE", "CREATE", "DELETE", "RENAME", "LINK", "SYMLINK",
          "TRUNCATE", "CHMOD", "CHOWN", "MKDIR", "RMDIR")

# ShadowFS/backend/overlay.go:35 -- prefix of the debug whiteout marker that
# materializeVersionLocked() writes into the epoch's staging tree. It is
# internal bookkeeping and must never become visible through the FUSE mount.
WHITEOUT_PREFIX = ".shadow-wh."

# `ls -1 <dir> | sed 's/^/E /'` tags each entry so _parse_listing() can tell
# real directory entries apart from any other shell output in the transcript.
_LISTING_CMD = "ls -1 {dir} 2>/dev/null | sed 's/^/E /'"


def wildcard_allow():
    """allowed_ops that permit everything (covers FORK/EXIT lifecycle events)."""
    return [{"event_type": "*", "action": "allow", "path_pattern": "/"}]


class Experiment3:
    """Rollback-correctness experiment driven entirely by the session API."""

    def __init__(self, repeats: int = 10):
        self.repeats = repeats
        self.run_id = str(int(time.time() * 1000))[-8:]
        self.orch = OrchClient()
        self.oracle = EffectOracle(tempfile.mkdtemp(prefix="shadow-exp3-oracle-"))
        self.metrics = MetricsCollector("exp3_rollback_correctness")
        self._open_sessions = []
        self._agent_seq = 0

        self.metrics.add_counter("rollback_content_mismatch")
        self.metrics.add_counter("rollback_metadata_mismatch")
        self.metrics.add_counter("rollback_direntry_mismatch")
        self.metrics.add_counter("child_process_survived")
        self.metrics.add_counter("provisional_output_not_removed")
        self.metrics.add_counter("commit_not_exactly_once")
        self.metrics.add_counter("rollback_state_leak")
        self.metrics.add_counter("env_cwd_not_restored")
        self.metrics.add_counter("whiteout_not_cleaned")
        self.metrics.add_counter("memory_state_leaked")

    # ── setup / teardown ────────────────────────────────────────────────

    def setup(self):
        if os.geteuid() != 0:
            raise InfrastructureError(
                "privileges", "Experiment 3 requires root privileges")
        self.orch.require_listening()
        try:
            observe = ShadowObserveClient()
            observe.connect()
            observe.close()
        except (FileNotFoundError, ConnectionError, OSError) as exc:
            raise InfrastructureError(
                "shadowobserve_socket",
                "ShadowObserve is not reachable; the allow/commit path audits a "
                "sealed trace and cannot run without it", exc)
        if not is_fuse_mounted():
            raise InfrastructureError(
                "fuse_mount",
                f"ShadowFS FUSE is not mounted at {SHADOWFS_MNT}; file "
                f"operations would bypass ShadowFS")
        ensure_fuse_dirs("exp3")
        self.metrics.metadata.update({
            "orch_sock": orch_sock_path(),
            "shadowfs_mount": SHADOWFS_MNT,
            "backing_store": SHADOWFS_ORIG,
            "repeats": self.repeats,
            "run_id": self.run_id,
        })
        print(f"[exp3] orchestrator={orch_sock_path()} mount={SHADOWFS_MNT}")

    def teardown(self):
        for sid in list(self._open_sessions):
            try:
                self.orch.session_close(sid)
            except Exception as exc:  # noqa: BLE001 - teardown is best effort
                print(f"[exp3] WARNING: session_close({sid}) failed: {exc}")
        self._open_sessions.clear()

    # ── session helpers ─────────────────────────────────────────────────

    def _next_agent(self, tag: str) -> str:
        self._agent_seq += 1
        return f"exp3-{tag}-{self.run_id}-{self._agent_seq}"

    def _open_session(self, tag: str):
        agent = self._next_agent(tag)
        resp = self.orch.session_open(
            agent_id=agent,
            cgroup_name=f"exp3-{tag}-{self.run_id}-{self._agent_seq}")
        sid, cg = resp.get("session_id"), resp.get("cgroup_id")
        if not sid or not cg:
            raise InfrastructureError(
                "session_open", f"session_open returned no id: {resp}")
        self._open_sessions.append(sid)
        return sid, cg, agent

    def _begin_epoch(self, sid: str, agent: str):
        try:
            return self.orch.session_begin_epoch(sid, agent)
        except InfrastructureError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise infra("begin_epoch", str(exc), exc)

    def _close_session(self, sid: str):
        try:
            self.orch.session_close(sid)
        except Exception as exc:  # noqa: BLE001
            print(f"[exp3] WARNING: session_close({sid}) failed: {exc}")
        finally:
            if sid in self._open_sessions:
                self._open_sessions.remove(sid)

    def _resolve(self, sid: str, agent: str, decision: str, allowed_ops=None):
        """Raw resolve reply (never raises on status!=ok) so the caller can
        classify a fail-closed error (INFRA) separately from a system decision."""
        return self.orch.request(
            "session_resolve_epoch", timeout=180.0,
            session_id=sid, agent_id=agent, decision=decision,
            allowed_ops=allowed_ops)

    def _run(self, sid: str, command: str, timeout: float = 30.0) -> str:
        """Run one command in the session's live shell and return its output."""
        return self.orch.session_run(sid, command, timeout=timeout).get(
            "output", "")

    def _baseline_run(self, sid: str, agent: str, command: str,
                      timeout: float = 30.0) -> str:
        """Run a FUSE-touching command on the post-rollback baseline.

        A resolved (denied) epoch is closed, and ShadowFS fails closed with
        EIO for any cgroup that has no active epoch -- by design. So the
        "next command served by the restored baseline" is exercised the way
        the system actually serves it: begin a fresh epoch (which re-arms
        the session cgroup's epoch attribution), run the read there, and
        allow-commit it (read-only, wildcard policy).
        """
        self._begin_epoch(sid, agent)
        try:
            out = self._run(sid, command, timeout=timeout)
        finally:
            reply = self._resolve(sid, agent, "allow", wildcard_allow())
            if reply.get("status") != "ok":
                raise infra("baseline_resolve",
                            f"baseline epoch resolve failed: "
                            f"{reply.get('message', reply)}")
        return out

    @staticmethod
    def _kv(output: str, key: str):
        for line in (output or "").splitlines():
            line = line.strip()
            if line.startswith(key + "="):
                return line[len(key) + 1:]
        return None

    @staticmethod
    def _ppid(pid: int):
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        return int(line.split()[1])
        except (OSError, ValueError, IndexError):
            pass
        return None

    def _wait_alive(self, pid: int, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.oracle.check_process_alive(pid):
                return True
            time.sleep(0.05)
        return self.oracle.check_process_alive(pid)

    def _wait_dead(self, pid: int, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.oracle.check_process_alive(pid):
                return True
            time.sleep(0.05)
        return not self.oracle.check_process_alive(pid)

    @staticmethod
    def _backing(rel: str) -> str:
        return harness_path(rel)

    # ── direntry-level rollback reconciliation ─────────────────────────

    @staticmethod
    def _staging_residue(epoch_id: str, limit: int = 8):
        """List what the rolled-back epoch left behind in the staging tree.

        Returns [] when the epoch's staging directory is gone (correct), and
        otherwise the relative paths of up to `limit` surviving files. The
        epoch directory name is matched both verbatim and url-unquoted because
        ShadowFS builds it with Go's url.PathEscape.
        """
        if not epoch_id:
            return ["<no epoch_id reported>"]
        root = os.path.join(SHADOWFS_STAGING, "epochs")
        try:
            names = os.listdir(root)
        except OSError:
            return []                      # no staging epochs at all
        hit = None
        for n in names:
            if n == epoch_id or urllib.parse.unquote(n) == epoch_id:
                hit = os.path.join(root, n)
                break
        if hit is None:
            return []
        residue = []
        for dirpath, _dirnames, filenames in os.walk(hit):
            for f in filenames:
                residue.append(os.path.relpath(os.path.join(dirpath, f), hit))
                if len(residue) >= limit:
                    return residue
        return residue or [f"<surviving empty dir {hit}>"]

    @staticmethod
    def _parse_listing(output: str):
        """Extract the ``E ``-prefixed directory entries from a baseline run."""
        entries = set()
        for line in (output or "").splitlines():
            line = line.strip()
            if line.startswith("E "):
                name = line[2:].strip()
                if name and name not in (".", ".."):
                    entries.add(name)
        return entries

    def _check_direntry(self, t, label: str, epoch_id: str,
                        dir_before: DirSnapshot, dir_after: DirSnapshot,
                        baseline_output: str,
                        expect_present, expect_absent,
                        absent_prefixes=()) -> bool:
        """Three-way direntry reconciliation after a rolled-back epoch.

        This is what the ``rollback_direntry_mismatch`` counter measures. That
        counter used to be dead -- registered in __init__ and never referenced
        -- so the direntry-level guarantee was only covered INDIRECTLY, by
        single-path existence checks (rollback_state_leak, whiteout_not_cleaned,
        baseline_sees_source/file). None of those looks at a directory LISTING,
        which is exactly where residue shows up. The three views:

          1. backing store  DirSnapshot(orig/<parent>) after rollback must
                            equal the epoch-start snapshot: no leftover entry,
                            no lost entry, no type change.
          2. FUSE listing   a fresh epoch's ``ls`` of <parent> must show every
                            entry that should be present and hide every entry
                            that should be absent -- i.e. what the next command
                            actually enumerates, not what an external stat says.
          3. staging tree   backend.go's rollback runs
                            os.RemoveAll(epochDirFor(staging, id)) for every
                            affected epoch but only LOGS the error, so a silent
                            failure leaves the whole epoch staging tree behind
                            (including the ".shadow.wh." debug whiteout markers
                            written by materializeVersionLocked) while the API
                            still reports status=ok.
        """
        backing_ok = dir_before.matches(dir_after)
        listing = self._parse_listing(baseline_output)
        missing = sorted(set(expect_present) - listing)
        leaked = sorted(set(expect_absent) & listing)
        # Internal bookkeeping names must never surface in the user-visible
        # namespace, whether or not the epoch was rolled back.
        internal = sorted(n for n in listing
                          if any(n.startswith(p) for p in absent_prefixes))
        fuse_ok = not missing and not leaked and not internal
        residue = self._staging_residue(epoch_id)
        staging_ok = not residue

        before_after_diff = {}
        if not backing_ok:
            before_after_diff = {
                "added": sorted(set(dir_after.entries) - set(dir_before.entries)),
                "removed": sorted(set(dir_before.entries) - set(dir_after.entries)),
            }
        return t.check(
            "rollback_direntry_mismatch",
            backing_ok and fuse_ok and staging_ok,
            counter="rollback_direntry_mismatch",
            detail=f"{label}: backing_dir_restored={backing_ok}"
                   f"{f' diff={before_after_diff}' if before_after_diff else ''}"
                   f" fuse_listing_ok={fuse_ok}"
                   f"{f' missing={missing}' if missing else ''}"
                   f"{f' leaked={leaked}' if leaked else ''}"
                   f"{f' internal_names_visible={internal}' if internal else ''}"
                   f" staging_residue={residue if residue else 'none'}",
            label=label, epoch_id=epoch_id)

    def _spawn_child(self, sid: str, key: str):
        """Fork a long-lived child in the candidate and return (child, parent).

        ``sleep 300 &`` backgrounds inside the candidate shell, so session_run
        returns immediately while the child stays alive as an epoch descendant.
        """
        out = self._run(sid, f"sleep 300 & echo {key}=$!", timeout=30.0)
        child = self._kv(out, key)
        if not child or not child.isdigit():
            raise infra("fork_child", f"could not start epoch child: {out!r}")
        child = int(child)
        if not self._wait_alive(child, timeout=5.0):
            raise infra("fork_child", f"epoch child {child} never became alive")
        return child, self._ppid(child)

    # ── Test 1: file content rollback ───────────────────────────────────

    def test_file_content_rollback(self):
        """After deny, file content must equal the epoch-start state, verified
        both externally and through the next command in the same session."""
        for i in range(self.repeats):
            rel = f"exp3/content-{self.run_id}-{i}.txt"
            target, backing = fuse_path(rel), self._backing(rel)
            os.makedirs(os.path.dirname(backing), exist_ok=True)
            original = b"ORIGINAL_CONTENT\n"
            with open(backing, "wb") as f:
                f.write(original)
            sid = None
            with self.metrics.open_trial(
                    f"file-content-rollback-{i}",
                    scenario="file_content_rollback") as t:
                try:
                    sid, cg, agent = self._open_session("content")
                    self._begin_epoch(sid, agent)
                    self._run(sid, f"printf 'MUTATED' > {target}")
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)  # let the FUSE cache expire
                    with open(backing, "rb") as f:
                        backing_after = f.read()
                    # Next command in the SAME session, served by the restored
                    # baseline (a fresh read-only epoch; see _baseline_run).
                    seen = self._baseline_run(sid, agent, f"cat {target}").strip()
                    t.check("rollback_content_mismatch",
                            backing_after == original,
                            counter="rollback_content_mismatch",
                            detail=f"backing={backing_after!r} expected={original!r}")
                    t.check("baseline_sees_original",
                            seen == original.decode().strip(),
                            f"next-command cat={seen!r}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 2: permission / owner rollback ─────────────────────────────

    def test_permission_rollback(self):
        """After deny, file permissions must be unchanged (external + session)."""
        for i in range(self.repeats):
            rel = f"exp3/perm-{self.run_id}-{i}.txt"
            target, backing = fuse_path(rel), self._backing(rel)
            os.makedirs(os.path.dirname(backing), exist_ok=True)
            with open(backing, "w") as f:
                f.write("permission test")
            os.chmod(backing, 0o644)
            mode_before = os.stat(backing).st_mode & 0o7777
            sid = None
            with self.metrics.open_trial(
                    f"permission-rollback-{i}",
                    scenario="permission_rollback") as t:
                try:
                    sid, cg, agent = self._open_session("perm")
                    self._begin_epoch(sid, agent)
                    self._run(sid, f"chmod 600 {target}")
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)
                    mode_after = os.stat(backing).st_mode & 0o7777
                    seen = self._baseline_run(
                        sid, agent, f"stat -c %a {target}").strip()
                    t.check("rollback_metadata_mismatch",
                            mode_after == mode_before,
                            counter="rollback_metadata_mismatch",
                            detail=f"mode {oct(mode_before)}->{oct(mode_after)}")
                    t.check("baseline_sees_original_mode",
                            seen == "644", f"next-command stat={seen!r}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 3 (problem 6): child process termination on rollback ───────

    def test_child_process_termination(self):
        """The recovery guarantee, exercised for real:

          1. open a persistent session (baseline process);
          2. begin an epoch (candidate forks from the baseline);
          3. the candidate forks a long-lived child that joins the epoch tree;
          4. deny the epoch -> the SYSTEM rolls back and kills candidate+kin;
          5. confirm the candidate and every descendant are gone;
          6. run the next command in the SAME session and confirm it is served
             normally by the recovered baseline.
        """
        for i in range(self.repeats):
            sid = None
            with self.metrics.open_trial(
                    f"child-process-termination-{i}",
                    scenario="child_process_termination") as t:
                try:
                    sid, cg, agent = self._open_session("child")
                    self._begin_epoch(sid, agent)
                    child, candidate = self._spawn_child(sid, "CHILD_PID")

                    # Confirm the child actually joined the candidate's tree
                    # (the fork happened inside the epoch, not in the harness).
                    tree_before = self.oracle.get_process_tree(candidate) \
                        if candidate else []
                    joined = child in tree_before
                    t.check("epoch_child_joined", joined,
                            f"candidate={candidate} child={child} "
                            f"tree={tree_before}")

                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue

                    child_dead = self._wait_dead(child, timeout=8.0)
                    cand_dead = (self._wait_dead(candidate, timeout=8.0)
                                 if candidate else True)
                    survivors = [p for p in tree_before
                                 if self.oracle.check_process_alive(p)]
                    t.check("child_process_survived",
                            child_dead and cand_dead and not survivors,
                            counter="child_process_survived",
                            detail=f"child_dead={child_dead} "
                            f"candidate_dead={cand_dead} survivors={survivors}")

                    # The session must still work, now on the restored baseline.
                    try:
                        out = self._run(sid, "echo BASELINE_OK", timeout=30.0)
                    except InfrastructureError as exc:
                        t.infra_error(exc, stage="baseline_unusable")
                        continue
                    t.check("baseline_serves_next_command",
                            "BASELINE_OK" in out, f"output={out.strip()!r}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 4: rename rollback (dual path) ─────────────────────────────

    def test_rename_link_rollback(self):
        """After deny, a rename must be undone: source restored, dest removed."""
        for i in range(self.repeats):
            src_rel = f"exp3/rename-src-{self.run_id}-{i}.txt"
            dst_rel = f"exp3/rename-dst-{self.run_id}-{i}.txt"
            src_b, dst_b = self._backing(src_rel), self._backing(dst_rel)
            os.makedirs(os.path.dirname(src_b), exist_ok=True)
            with open(src_b, "w") as f:
                f.write("rename test")
            if os.path.exists(dst_b):
                os.unlink(dst_b)
            snap_before = FileSnapshot.capture(src_b)
            parent_b = os.path.dirname(src_b)
            dir_before = DirSnapshot.capture(parent_b)
            sid = None
            with self.metrics.open_trial(
                    f"rename-rollback-{i}", scenario="rename_rollback") as t:
                try:
                    sid, cg, agent = self._open_session("rename")
                    ep = self._begin_epoch(sid, agent)
                    epoch_id = (ep or {}).get("epoch_id", "")
                    self._run(sid, f"mv {fuse_path(src_rel)} {fuse_path(dst_rel)}")
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)
                    src_restored = snap_before.matches(FileSnapshot.capture(src_b))
                    dst_removed = not os.path.exists(dst_b)
                    # Captured BEFORE the baseline epoch is opened, so the
                    # comparison covers the rollback alone.
                    dir_after = DirSnapshot.capture(parent_b)
                    seen = self._baseline_run(
                        sid, agent,
                        _LISTING_CMD.format(
                            dir=fuse_path(os.path.dirname(src_rel)))
                        + f"; test -f {fuse_path(src_rel)} "
                        f"&& echo SRC_EXISTS").strip()
                    t.check("rollback_state_leak",
                            src_restored and dst_removed,
                            counter="rollback_state_leak",
                            detail=f"src_restored={src_restored} "
                            f"dst_removed={dst_removed}")
                    t.check("baseline_sees_source",
                            "SRC_EXISTS" in seen, f"next-command={seen!r}")
                    self._check_direntry(
                        t, f"rename-{i}", epoch_id, dir_before, dir_after, seen,
                        expect_present=[os.path.basename(src_b)],
                        expect_absent=[os.path.basename(dst_b)],
                        absent_prefixes=(WHITEOUT_PREFIX,))
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 5: whiteout cleanup (delete rollback) ──────────────────────

    def test_whiteout_cleanup(self):
        """After deny of a delete, the file must be restored (whiteout undone)."""
        for i in range(self.repeats):
            rel = f"exp3/whiteout-{self.run_id}-{i}.txt"
            target, backing = fuse_path(rel), self._backing(rel)
            os.makedirs(os.path.dirname(backing), exist_ok=True)
            with open(backing, "w") as f:
                f.write("delete me")
            parent_b = os.path.dirname(backing)
            dir_before = DirSnapshot.capture(parent_b)
            sid = None
            with self.metrics.open_trial(
                    f"whiteout-cleanup-{i}", scenario="whiteout_cleanup") as t:
                try:
                    sid, cg, agent = self._open_session("whiteout")
                    ep = self._begin_epoch(sid, agent)
                    epoch_id = (ep or {}).get("epoch_id", "")
                    self._run(sid, f"rm -f {target}")
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)
                    restored = os.path.exists(backing)
                    dir_after = DirSnapshot.capture(parent_b)
                    seen = self._baseline_run(
                        sid, agent,
                        _LISTING_CMD.format(
                            dir=fuse_path(os.path.dirname(rel)))
                        + f"; test -f {target} && echo EXISTS").strip()
                    t.check("whiteout_not_cleaned", restored,
                            counter="whiteout_not_cleaned",
                            detail=f"backing exists={restored}")
                    t.check("baseline_sees_file",
                            "EXISTS" in seen, f"next-command={seen!r}")
                    # The whiteout case is the one that actually creates a
                    # ".shadow.wh." marker in staging (materializeVersionLocked,
                    # OpWhiteout), so its residue check has real teeth.
                    self._check_direntry(
                        t, f"whiteout-{i}", epoch_id, dir_before, dir_after, seen,
                        expect_present=[os.path.basename(backing)],
                        expect_absent=[],
                        absent_prefixes=(WHITEOUT_PREFIX,))
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 6: commit exactly once ─────────────────────────────────────

    def test_commit_exactly_once(self):
        """After allow+commit the effect must appear exactly once (no duplicate
        from syscall restart)."""
        for i in range(self.repeats):
            rel = f"exp3/once-{self.run_id}-{i}.txt"
            target, backing = fuse_path(rel), self._backing(rel)
            os.makedirs(os.path.dirname(backing), exist_ok=True)
            if os.path.exists(backing):
                os.unlink(backing)
            sid = None
            with self.metrics.open_trial(
                    f"commit-exactly-once-{i}", scenario="commit_once") as t:
                try:
                    sid, cg, agent = self._open_session("once")
                    self._begin_epoch(sid, agent)
                    self._run(sid, f"printf 'SHADOW_EFFECT_DATA' > {target}")
                    reply = self._resolve(sid, agent, "allow", wildcard_allow())
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="resolve_fail_closed")
                        continue
                    if not (reply.get("audit") or {}).get("audited"):
                        t.infra_error(
                            "orchestrator did not audit a sealed trace",
                            stage="audit_not_performed")
                        continue
                    time.sleep(0.3)
                    with open(backing, "r") as f:
                        content = f.read()
                    count = content.count("SHADOW_EFFECT_DATA")
                    t.check("commit_not_exactly_once", count == 1,
                            counter="commit_not_exactly_once",
                            detail=f"effect appeared {count} times")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 7: hard link rollback (dual path) ──────────────────────────

    def test_hardlink_rollback(self):
        """After deny, a hard link must be undone: nlink restored, link removed."""
        for i in range(self.repeats):
            src_rel = f"exp3/hlink-src-{self.run_id}-{i}.txt"
            dst_rel = f"exp3/hlink-dst-{self.run_id}-{i}.txt"
            src_b, dst_b = self._backing(src_rel), self._backing(dst_rel)
            os.makedirs(os.path.dirname(src_b), exist_ok=True)
            with open(src_b, "w") as f:
                f.write("hardlink target")
            if os.path.exists(dst_b):
                os.unlink(dst_b)
            nlink_before = os.stat(src_b).st_nlink
            parent_b = os.path.dirname(src_b)
            dir_before = DirSnapshot.capture(parent_b)
            sid = None
            with self.metrics.open_trial(
                    f"hardlink-rollback-{i}", scenario="hardlink_rollback") as t:
                try:
                    sid, cg, agent = self._open_session("hlink")
                    ep = self._begin_epoch(sid, agent)
                    epoch_id = (ep or {}).get("epoch_id", "")
                    self._run(sid, f"ln {fuse_path(src_rel)} {fuse_path(dst_rel)}")
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)
                    nlink_after = (os.stat(src_b).st_nlink
                                   if os.path.exists(src_b) else 0)
                    dst_removed = not os.path.exists(dst_b)
                    dir_after = DirSnapshot.capture(parent_b)
                    seen = self._baseline_run(
                        sid, agent,
                        _LISTING_CMD.format(
                            dir=fuse_path(os.path.dirname(src_rel)))
                        + f"; test -f {fuse_path(dst_rel)} "
                        f"&& echo DST_EXISTS").strip()
                    t.check("rollback_state_leak",
                            nlink_after == nlink_before and dst_removed,
                            counter="rollback_state_leak",
                            detail=f"nlink {nlink_before}->{nlink_after} "
                            f"dst_removed={dst_removed}")
                    self._check_direntry(
                        t, f"hardlink-{i}", epoch_id, dir_before, dir_after, seen,
                        expect_present=[os.path.basename(src_b)],
                        expect_absent=[os.path.basename(dst_b)],
                        absent_prefixes=(WHITEOUT_PREFIX,))
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 8: environment / CWD restoration ───────────────────────────

    def test_env_cwd_restoration(self):
        """Candidate-side cd/export must not leak into the baseline that serves
        the next command after rollback."""
        for i in range(self.repeats):
            leak_key = f"SHADOW_LEAK_{self.run_id}_{i}"
            sid = None
            with self.metrics.open_trial(
                    f"env-cwd-restoration-{i}",
                    scenario="env_cwd_restoration") as t:
                try:
                    sid, cg, agent = self._open_session("env")
                    # Baseline cwd BEFORE the epoch (reference for restoration).
                    baseline_cwd = self._run(sid, "pwd").strip()
                    self._begin_epoch(sid, agent)
                    self._run(sid, f"cd /tmp; export {leak_key}=leaked; "
                                   f"echo DONE")
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    out = self._run(sid, f"pwd; echo LEAK=${{{leak_key}:-unset}}")
                    cwd_after = out.splitlines()[0].strip() if out else ""
                    leak_after = self._kv(out, "LEAK")
                    cwd_restored = (cwd_after == baseline_cwd)
                    env_restored = (leak_after == "unset")
                    t.check("env_cwd_not_restored",
                            cwd_restored and env_restored,
                            counter="env_cwd_not_restored",
                            detail=f"cwd {baseline_cwd!r}->{cwd_after!r} "
                            f"leak={leak_after!r}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 9: file offset restoration ─────────────────────────────────

    def test_file_offset_restoration(self):
        """An external reader's view must not be corrupted by a provisional
        write that is rolled back; the session must also read the original."""
        for i in range(self.repeats):
            rel = f"exp3/offset-{self.run_id}-{i}.txt"
            target, backing = fuse_path(rel), self._backing(rel)
            os.makedirs(os.path.dirname(backing), exist_ok=True)
            original = b"AAAAABBBBBCCCCCDDDDD"  # 20 bytes
            with open(backing, "wb") as f:
                f.write(original)
            sid = None
            with self.metrics.open_trial(
                    f"file-offset-restoration-{i}",
                    scenario="file_offset") as t:
                try:
                    sid, cg, agent = self._open_session("offset")
                    self._begin_epoch(sid, agent)
                    with open(backing, "rb") as ext:
                        first = ext.read(5)
                        self._run(sid, f"printf 'MUTATED_LONGER' > {target}")
                        reply = self._resolve(sid, agent, "deny")
                        if reply.get("status") != "ok":
                            t.infra_error(reply.get("message", reply),
                                          stage="rollback")
                            continue
                        time.sleep(0.3)
                        rest = ext.read()
                    full = first + rest
                    seen = self._baseline_run(sid, agent, f"cat {target}").strip()
                    t.check("rollback_content_mismatch", full == original,
                            counter="rollback_content_mismatch",
                            detail=f"external read {len(full)}B "
                            f"expected {len(original)}B")
                    t.check("baseline_sees_original",
                            seen == original.decode(), f"next-command={seen!r}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 10: provisional output removal ─────────────────────────────

    def test_provisional_output_removal(self):
        """Output produced inside a denied epoch must be removed from the
        committed transcript, and its file effect must not reach the backing
        store."""
        for i in range(self.repeats):
            secret = f"PROVISIONAL_SECRET_{self.run_id}_{i}"
            rel = f"exp3/output-{self.run_id}-{i}.txt"
            target, backing = fuse_path(rel), self._backing(rel)
            os.makedirs(os.path.dirname(backing), exist_ok=True)
            if os.path.exists(backing):
                os.unlink(backing)
            sid = None
            with self.metrics.open_trial(
                    f"provisional-output-removal-{i}",
                    scenario="provisional_output") as t:
                try:
                    sid, cg, agent = self._open_session("output")
                    self._begin_epoch(sid, agent)
                    self._run(sid, f"echo {secret}; printf 'X' > {target}")
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)
                    transcript = self.orch.session_get_output(sid)
                    leaked_output = secret in transcript
                    leaked_file = os.path.exists(backing)
                    t.check("provisional_output_not_removed",
                            not leaked_output and not leaked_file,
                            counter="provisional_output_not_removed",
                            detail=f"output_leaked={leaked_output} "
                            f"file_leaked={leaked_file}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 11: memory state rollback ──────────────────────────────────

    def test_memory_state_rollback(self):
        """A denied epoch's live process memory must vanish (child killed) and
        its file-backed mutation must not persist."""
        for i in range(self.repeats):
            rel = f"exp3/memstate-{self.run_id}-{i}.txt"
            target, backing = fuse_path(rel), self._backing(rel)
            os.makedirs(os.path.dirname(backing), exist_ok=True)
            original = b"ORIGINAL_MMAP_CONTENT"
            with open(backing, "wb") as f:
                f.write(original)
            sid = None
            with self.metrics.open_trial(
                    f"memory-state-rollback-{i}",
                    scenario="memory_state") as t:
                try:
                    sid, cg, agent = self._open_session("mem")
                    self._begin_epoch(sid, agent)
                    child, candidate = self._spawn_child(sid, "MEM_CHILD")
                    self._run(sid, f"printf 'MEM_MUTATED' > {target}")
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    child_dead = self._wait_dead(child, timeout=8.0)
                    time.sleep(0.3)
                    with open(backing, "rb") as f:
                        after = f.read()
                    content_ok = (after == original)
                    t.check("memory_state_leaked",
                            child_dead and content_ok,
                            counter="memory_state_leaked",
                            detail=f"child_dead={child_dead} "
                            f"content_ok={content_ok} after={after!r}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 12: allow matches native execution ─────────────────────────

    def test_allow_matches_native(self):
        """After allow+commit the resulting state must match what a native
        (unshadowed) write of the same data produces."""
        for i in range(self.repeats):
            rel = f"exp3/native-{self.run_id}-{i}.txt"
            ref_rel = f"exp3/native-ref-{self.run_id}-{i}.txt"
            target, backing = fuse_path(rel), self._backing(rel)
            ref_backing = self._backing(ref_rel)
            os.makedirs(os.path.dirname(backing), exist_ok=True)
            data = "NATIVE_REFERENCE_DATA"
            with open(backing, "w") as f:
                f.write("initial state\n")
            if os.path.exists(ref_backing):
                os.unlink(ref_backing)
            sid = None
            with self.metrics.open_trial(
                    f"allow-matches-native-{i}",
                    scenario="allow_matches_native") as t:
                try:
                    sid, cg, agent = self._open_session("native")
                    self._begin_epoch(sid, agent)
                    self._run(sid, f"printf '{data}' > {target}")
                    reply = self._resolve(sid, agent, "allow", wildcard_allow())
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="resolve_fail_closed")
                        continue
                    if not (reply.get("audit") or {}).get("audited"):
                        t.infra_error(
                            "orchestrator did not audit a sealed trace",
                            stage="audit_not_performed")
                        continue
                    time.sleep(0.3)
                    # Native reference: harness writes the same bytes directly.
                    with open(ref_backing, "w") as f:
                        f.write(data)
                    shadow_snap = FileSnapshot.capture(backing)
                    native_snap = FileSnapshot.capture(ref_backing)
                    mismatch = not shadow_snap.matches(native_snap)
                    t.check("allow_matches_native", not mismatch,
                            counter="rollback_content_mismatch",
                            detail=f"shadow_size={shadow_snap.size} "
                            f"native_size={native_snap.size}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── driver ──────────────────────────────────────────────────────────

    def run(self):
        self.setup()
        print(f"\n{'=' * 70}")
        print("  EXPERIMENT 3: Rollback Correctness (real orchestrator sessions)")
        print(f"  Repeats: {self.repeats}")
        print(f"{'=' * 70}\n")

        tests = [
            ("File content rollback", self.test_file_content_rollback),
            ("Permission/owner rollback", self.test_permission_rollback),
            ("Child process termination", self.test_child_process_termination),
            ("Rename rollback (dual path)", self.test_rename_link_rollback),
            ("Whiteout cleanup", self.test_whiteout_cleanup),
            ("Commit exactly once", self.test_commit_exactly_once),
            ("Hard link rollback (dual path)", self.test_hardlink_rollback),
            ("Environment/CWD restoration", self.test_env_cwd_restoration),
            ("File offset restoration", self.test_file_offset_restoration),
            ("Provisional output removal", self.test_provisional_output_removal),
            ("Memory state rollback", self.test_memory_state_rollback),
            ("Allow matches native execution", self.test_allow_matches_native),
        ]
        try:
            for idx, (label, fn) in enumerate(tests, 1):
                print(f"  [{idx}/{len(tests)}] {label} ...", flush=True)
                fn()
        except KeyboardInterrupt:
            print("\n[exp3] Interrupted")
        finally:
            self.metrics.finish()
            self.teardown()

        self.metrics.print_report()
        return self.metrics


def main():
    parser = argparse.ArgumentParser(
        description="RQ2 Experiment 3: Rollback Correctness")
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output-dir", type=str, default="./results")
    args = parser.parse_args()

    if not RUN_EXPERIMENTS:
        print("ERROR: Set SHADOW_RUN_RQ2_EXPERIMENTS=1")
        sys.exit(1)

    exp = Experiment3(repeats=args.repeats)
    try:
        metrics = exp.run()
    except InfrastructureError as exc:
        print(f"\n[exp3] FATAL INFRASTRUCTURE ERROR: {exc}")
        sys.exit(2)
    metrics.save_report(args.output_dir)
    sys.exit(metrics.exit_code)


if __name__ == "__main__":
    main()
