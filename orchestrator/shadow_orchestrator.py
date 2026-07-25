#!/usr/bin/env python3
"""
ShadowOrchestrator - Unified orchestrator for ShadowFS, ShadowProc, and ShadowObserve.

Manages the lifecycle of all three components and coordinates commit/rollback
operations across the filesystem layer (ShadowFS), the process layer
(ShadowProc), and the observation/enforcement layer (ShadowObserve).

Usage:
    # As a library
    from shadow_orchestrator import ShadowOrchestrator
    orch = ShadowOrchestrator(shadowfs_sock="/tmp/shadowfs.sock",
                               shadowproc_sock="/tmp/shadowproc.sock",
                               shadowobserve_sock="/tmp/shadowobserve.sock")
    orch.start_observe("/shadow-demo", cgroup_inode=12345)
    orch.submit_policy("/shadow-demo", allowed_ops=[...])

    # As a standalone server
    python shadow_orchestrator.py --shadowfs-sock /tmp/shadowfs.sock \
                                   --shadowproc-sock /tmp/shadowproc.sock \
                                   --shadowobserve-sock /tmp/shadowobserve.sock \
                                   --listen /tmp/shadow-orch.sock
"""

import json
import hashlib
import socket
import os
import sys
import argparse
import logging
import threading
import signal
import tempfile
import time
import uuid
from typing import Optional, List, Dict, Any, Tuple

# Add project root to path so policy.policy_ir is importable.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from policy.policy_ir import PolicyIR
from session_proxy import SessionProxy, NotAdmissibleError

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("orchestrator")


class SocketClient:
    """Simple Unix socket JSON-line client."""

    def __init__(self, sock_path: str):
        self.sock_path = sock_path
        self._sock: Optional[socket.socket] = None
        # Serializes request/response round-trips: the orchestrator now issues
        # requests from multiple threads (e.g. the background finalize-retry
        # loop and the main request handler), and a shared socket stream must
        # not have two exchanges interleaved.
        self._io_lock = threading.Lock()

    def connect(self):
        """Connect to the Unix socket."""
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(self.sock_path)
        self._file = self._sock.makefile("rw", buffering=1)

    def close(self):
        """Close the connection."""
        if self._sock:
            self._sock.close()
            self._sock = None

    def request(self, data: dict) -> dict:
        """Send a JSON request and return the JSON response (thread-safe)."""
        with self._io_lock:
            if not self._sock:
                self.connect()
            line = json.dumps(data) + "\n"
            self._file.write(line)
            self._file.flush()
            resp_line = self._file.readline()
            if not resp_line:
                raise ConnectionError(f"Connection to {self.sock_path} closed")
            return json.loads(resp_line)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


class JournalCorruptError(RuntimeError):
    """The durable journal is corrupt in a non-torn-tail way (a record BEFORE
    the last one is unparseable). For a security control plane this must FAIL
    CLOSED: recovery cannot trust a journal with holes in the middle, so the
    orchestrator refuses to start until the operator inspects/moves the file.
    """


class _OrchestratorJournal:
    """Append-only durable journal of session-finalization decisions.

    The orchestrator's session map, pending-release set and committed output
    live only in memory. A crash BETWEEN the file layer finalizing an epoch and
    the process/output being released would otherwise leave the caller's result
    undetermined on restart. This journal records the decision points so restart
    recovery resolves every epoch to a DETERMINISTIC outcome:

      op=open           {sid, cgroup}          a session exists
      op=close          {sid}                  session torn down
      op=commit_intent  {sid, cgroup}          commit started; FS not yet confirmed
      op=fs_committed   {sid, cgroup, output}  DECISION POINT: the file layer
                        finalized durably, so the canonical outcome is COMMITTED
                        and the committed transcript is captured here.
      op=commit_done    {sid, cgroup}          process committed + output released
      op=release_intent {sid, cgroup,          group-level release intent (Phase 3):
                        group_id, members,     the group was finalized and the
                        graph_generation,      intent to release all members was
                        epoch}                 durably recorded.
      op=rollback       {sid, cgroup}          epoch rolled back (not committed)

    Records are newline-delimited JSON, fsync'd on append so a record is durable
    BEFORE the corresponding externally-visible step proceeds (write-ahead).
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()

    def append(self, op: str, **fields) -> None:
        rec = {"op": op, "ts": time.time()}
        rec.update(fields)
        line = json.dumps(rec) + "\n"
        with self._lock:
            # Open/append/fsync per record: the journal is low-frequency
            # (session lifecycle + commit decisions), so per-record fsync is
            # affordable and gives strict write-ahead durability.
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode())
                os.fsync(fd)
            finally:
                os.close(fd)

    def load(self) -> list:
        """Parse the journal. FAIL CLOSED on corruption: only the LAST record
        may be unparseable (a torn write from a crash mid-append) and is then
        dropped; a bad record anywhere BEFORE the tail means the journal was
        truncated/tampered/bit-rotted and raises JournalCorruptError instead of
        silently recovering from partial history.
        """
        try:
            with open(self.path, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return []
        out = []
        last = len(lines) - 1
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                if i == last:
                    # Torn final record (crash mid-write): safe to drop.
                    continue
                raise JournalCorruptError(
                    f"{self.path}: unparseable record at line {i + 1} "
                    f"(not the tail) -- refusing to recover from a corrupt "
                    f"journal (fail closed)")
        return out

    @staticmethod
    def replay(records: list) -> dict:
        """Fold the journal into recovery state. Returns a dict with:
            sessions:       {sid: cgroup}             currently-open sessions
            committed:      {sid: (cgroup, output)}   epochs whose FS layer committed
                            durably but whose release was never journaled done
            undecided:      {sid: cgroup}             commit_intent w/o fs_committed
            release_groups: {group_id: {members,      group-level release intents
                            graph_generation, cgroup,  (Phase 3): a group whose
                            epoch, sid}}              finalization was durably
                                                     recorded.
        """
        sessions: Dict[str, Any] = {}
        stage: Dict[str, str] = {}       # sid -> intent|fs|done|rollback
        cgroup: Dict[str, Any] = {}
        output: Dict[str, str] = {}
        release_groups: Dict[int, Any] = {}
        sid_groups: Dict[str, set] = {}
        for rec in records:
            op = rec.get("op")
            sid = rec.get("sid")
            cg = rec.get("cgroup")
            if op == "authorization_tombstone" and rec.get("epoch"):
                continue
            if op in ("authorization_intent", "authorized"):
                # Replayed by ShadowOrchestrator._recover_from_journal into the
                # in-memory policy cache; the folded state only needs release
                # decisions below.
                continue
            if op == "release_intent":
                gid = rec.get("group_id")
                if gid is not None:
                    release_groups[gid] = {
                        "members": rec.get("members", []),
                        "graph_generation": rec.get("graph_generation", 0),
                        "cgroup": cg,
                        "epoch": rec.get("epoch", ""),
                        "sid": sid,
                        "released_cgroups": set(),
                    }
                    if sid:
                        sid_groups.setdefault(sid, set()).add(gid)
                continue
            if op == "group_release_done":
                gid = rec.get("group_id")
                if gid is not None:
                    release_groups.pop(gid, None)
                continue
            if op == "release_member_done":
                gid = rec.get("group_id")
                if gid in release_groups and cg:
                    release_groups[gid].setdefault("released_cgroups", set()).add(cg)
                continue
            if not sid:
                continue
            if op == "open":
                sessions[sid] = cg
            elif op == "close":
                sessions.pop(sid, None)
                stage.pop(sid, None)
                cgroup.pop(sid, None)
                output.pop(sid, None)
            elif op == "commit_intent":
                stage[sid] = "intent"
                cgroup[sid] = cg
            elif op == "fs_committed":
                stage[sid] = "fs"
                cgroup[sid] = cg
                output[sid] = rec.get("output", "")
                gid = rec.get("group_id")
                if gid is not None and gid not in release_groups:
                    release_groups[gid] = {
                        "members": rec.get("members", []),
                        "graph_generation": rec.get("graph_generation", 0),
                        "cgroup": cg,
                        "epoch": rec.get("epoch", ""),
                        "sid": sid,
                        "released_cgroups": set(),
                    }
                    if sid:
                        sid_groups.setdefault(sid, set()).add(gid)
            elif op == "commit_done":
                stage[sid] = "done"
                for gid in sid_groups.get(sid, set()):
                    release_groups.pop(gid, None)
            elif op == "rollback":
                stage[sid] = "rollback"
                output.pop(sid, None)
        committed = {sid: (cgroup.get(sid), output.get(sid, ""))
                     for sid, st in stage.items() if st == "fs"}
        undecided = {sid: cgroup.get(sid)
                     for sid, st in stage.items() if st == "intent"}
        for info in release_groups.values():
            if isinstance(info.get("released_cgroups"), set):
                info["released_cgroups"] = sorted(info["released_cgroups"])
        return {"sessions": sessions, "committed": committed,
                "undecided": undecided, "release_groups": release_groups}

    def rewrite(self, records: list) -> None:
        """Atomically replace the journal with `records` (compaction on clean
        shutdown, to bound growth)."""
        tmp = self.path + ".tmp"
        with self._lock:
            with open(tmp, "w") as f:
                for rec in records:
                    f.write(json.dumps(rec) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)


class ShadowOrchestrator:
    """
    Orchestrates ShadowFS (file layer), ShadowProc (process layer),
    and ShadowObserve (observation/enforcement layer).

    Coordinates commit and rollback operations:
    - Commit: resume frozen processes, then commit filesystem changes.
    - Rollback: rollback filesystem (cascade), then kill affected frozen processes.
    - Submit Policy: freeze → audit → commit/rollback based on audit result.
    """

    def __init__(self, shadowfs_sock: str, shadowproc_sock: str,
                 shadowobserve_sock: Optional[str] = None,
                 journal_path: Optional[str] = None,
                 shadowfs_mount: Optional[str] = None,
                 backing_dir: Optional[str] = None):
        self.fs_client = SocketClient(shadowfs_sock)
        self.proc_client = SocketClient(shadowproc_sock)
        self.observe_client = None
        self.fs_client.connect()
        self.proc_client.connect()
        # Speculation domain isolation parameters (passed to SessionProxy so
        # each candidate bash runs inside its own mount namespace with a
        # read-only root, per-candidate tmpfs, and blocked backing dir).
        self._shadowfs_mount = shadowfs_mount
        self._backing_dir = backing_dir

        if shadowobserve_sock:
            self.observe_client = SocketClient(shadowobserve_sock)
            self.observe_client.connect()
            log.info("Connected to ShadowFS (%s), ShadowProc (%s), ShadowObserve (%s)",
                     shadowfs_sock, shadowproc_sock, shadowobserve_sock)
        else:
            log.info("Connected to ShadowFS (%s) and ShadowProc (%s)",
                     shadowfs_sock, shadowproc_sock)

        # Track observation state: cgroup_id → {log_path, cgroup_inode}
        self._observe_state: Dict[str, Dict[str, Any]] = {}

        # Per-epoch policy decisions that have passed audit and been recorded
        # in ShadowFS via authorize(epoch), but whose SCC may not yet be ready
        # to finalize. Keyed by epoch_id; values include cgroup/proc_policy and
        # a stable policy_hash so delayed release never falls back to allow-all.
        self._authorized_epochs: Dict[str, Dict[str, Any]] = {}
        self._authorized_lock = threading.Lock()

        # Group-level retry records. These replace cgroup-only retry sets for
        # SCC release/ack paths so retries keep group_id, members, per-member
        # cgroups and policies instead of degrading to single-epoch APIs.
        self._pending_groups: Dict[int, Dict[str, Any]] = {}
        self._pending_group_lock = threading.Lock()

        # Track stdout buffer files: cgroup_id → output_file_path
        # Populated via register_output(); flushed on commit; discarded on rollback.
        self._output_buffers: Dict[str, str] = {}
        self._epoch_results: Dict[str, Dict[str, Any]] = {}

        # Deferred external-operation release.
        #
        # A cgroup may be committed (user intent) while its upstream
        # dependencies in ShadowFS are not yet fully committed. In that
        # window ShadowFS holds the agent's file changes un-promoted so a
        # cascade rollback can still undo them. ShadowProc MUST likewise
        # keep the agent's processes frozen so their IPC / network side
        # effects don't escape prematurely. Such cgroups are parked here
        # and released once ShadowFS reports their upstreams are committed
        # (see _try_release_pending).
        self._pending_release: set = set()
        self._pending_lock = threading.Lock()

        # Ack-only retry set.
        #
        # Once a cgroup's external effects HAVE been released (processes
        # resumed AND buffered output delivered), the only remaining step is
        # telling ShadowFS it may drop the Finalized terminal record
        # (ack_release). If that ack fails, the effects are already out -- we
        # must NOT re-resume or re-flush. Such cgroups are parked here and the
        # background loop retries ONLY the ack (AckRelease is idempotent).
        self._pending_ack: set = set()
        self._pending_ack_lock = threading.Lock()

        # Serializes ALL multi-service release/finalize interactions (commit
        # release path, _try_release_pending, and the background retry loop) so
        # their requests over the shared fs/proc sockets never interleave.
        self._release_lock = threading.RLock()

        # Background finalize-retry loop. A promotion can fail on a transient
        # I/O error, leaving an agent AuthorizedPending/Finalizing (fenced).
        # This loop periodically asks ShadowFS to retry_finalize the pending
        # cgroups and releases them once they reach Finalized, so a blip does
        # not wedge an agent forever. Daemon thread; stops on close().
        self._retry_stop = threading.Event()
        self._retry_interval = 2.0
        self._retry_thread = threading.Thread(
            target=self._finalize_retry_loop, name="finalize-retry", daemon=True)

        # ── Speculative bash-session support ──
        # A SessionProxy drives long-lived bash sessions and their ShadowProc
        # baseline/candidate epochs (process layer). The orchestrator layers
        # ShadowFS epoch commit/rollback on top so a session's file changes and
        # process state for one epoch are committed/rolled back together.
        # Created lazily (needs root + cgroup_exec) on first session_open.
        self._shadowproc_sock = shadowproc_sock
        self._proxy: Optional[SessionProxy] = None
        self._sessions: Dict[str, str] = {}  # session_id → cgroup_id
        # session_id → ShadowFS epoch_id of the session's CURRENT open epoch.
        # The epoch (not the cgroup) is the ShadowFS unit of versioning /
        # authorization / finalization; the cgroup only provides kernel
        # attribution. Cleared on commit/rollback of the epoch.
        self._session_epochs: Dict[str, str] = {}
        self._sessions_lock = threading.Lock()

        # ── Durable finalization journal + crash recovery ──
        # Records session lifecycle and the epoch-commit decision points so a
        # crash between 'file layer finalized' and 'process/output released'
        # resolves to a DETERMINISTIC result on restart (recovered committed
        # transcripts remain retrievable; see _recover_from_journal).
        if journal_path is None:
            journal_path = os.path.join(tempfile.gettempdir(),
                                        "shadow-orchestrator.journal")
        self._journal = _OrchestratorJournal(journal_path)
        # sid → committed transcript recovered from the journal (delivered by
        # session_get_output when the live session did not survive the crash).
        self._recovered_outputs: Dict[str, str] = {}
        self._recover_from_journal()
        # Start the retry loop only after journal recovery has rebuilt pending
        # group state; otherwise it can race with replay and degrade recovery
        # ordering.
        self._retry_thread.start()

    def close(self):
        """Close connections to all services."""
        self._retry_stop.set()
        # Do not compact the journal to only open sessions: it may contain
        # authorized policy decisions, release_intent/member_done and pending
        # group ack state that are still required for crash-safe recovery. The
        # append-only journal is intentionally preserved until a future
        # checkpoint format can retain all unfinished release state atomically.
        self.fs_client.close()
        self.proc_client.close()
        if self.observe_client:
            self.observe_client.close()

    def _recover_from_journal(self) -> None:
        """Replay the durable journal at startup and resolve every epoch to a
        deterministic outcome. Reconstructs the session→cgroup map, makes the
        committed transcript of any FS-committed-but-unreleased epoch
        retrievable, and reconciles undecided commits against ShadowFS (the
        authoritative WAL-backed layer). A corrupt journal FAILS CLOSED: the
        JournalCorruptError propagates and the orchestrator refuses to start,
        so a caller can never observe results derived from partial history.
        """
        records = self._journal.load()
        if not records:
            return
        state = _OrchestratorJournal.replay(records)
        # Restore independently authorized policy decisions before any pending
        # group retry. Without this, a delayed release after restart would lose
        # proc_policy and could degrade into allow-all.
        if hasattr(self, "_authorized_lock"):
            with self._authorized_lock:
                for rec in records:
                    if rec.get("op") == "authorization_tombstone" and rec.get("epoch"):
                        self._authorized_epochs.pop(rec["epoch"], None)
                    elif rec.get("op") in ("authorization_intent", "authorized") and rec.get("epoch"):
                        self._authorized_epochs[rec["epoch"]] = {
                            "epoch_id": rec.get("epoch"),
                            "cgroup_id": rec.get("cgroup", ""),
                            "proc_policy": rec.get("proc_policy") or {},
                            "policy_hash": rec.get("policy_hash", ""),
                        }
        with self._sessions_lock:
            self._sessions.update(state["sessions"])
        # FS-committed but release not confirmed: canonical outcome is COMMITTED,
        # but external release/ShadowFS ack may still be incomplete. Never write
        # commit_done here; release_groups below must finish the write-ahead
        # release state machine first.
        for sid, (cg, output) in state["committed"].items():
            self._recovered_outputs[sid] = output
            log.warning("RECOVERY sid=%s cgroup=%s: epoch was FS-committed before "
                        "crash -> result is COMMITTED, release still requires "
                        "journal-guided completion (%d bytes recovered)",
                        sid, cg, len(output or ""))
            if cg:
                try:
                    # Nudge ShadowFS to (idempotently) finish finalizing the
                    # committed file state it already durably accepted.
                    self.fs_client.request({"action": "retry_finalize",
                                            "cgroup_id": cg})
                except Exception as e:  # noqa: BLE001
                    log.warning("  retry_finalize(%s) during recovery: %s", cg, e)
        # Commit started but FS decision never confirmed durable: reconcile with
        # ShadowFS. If it reports the epoch finalized, treat as committed; else
        # the epoch is NOT committed and no output is released (fail-closed).
        for sid, cg in state["undecided"].items():
            finalized = self._fs_can_release(cg) if cg else False
            log.warning("RECOVERY sid=%s cgroup=%s: undecided commit; ShadowFS "
                        "finalized=%s -> resolving as %s", sid, cg, finalized,
                        "COMMITTED" if finalized else "NOT committed (output withheld)")
        for gid, info in state.get("release_groups", {}).items():
            members = info.get("members", [])
            primary_cg = info.get("cgroup", "")
            epoch = info.get("epoch", "")
            released = set(info.get("released_cgroups", []))
            log.info("RECOVERY group_id=%d: release_intent recorded (members=%s "
                     "graph_gen=%d released=%s) -- completing release before ack",
                     gid, members, info.get("graph_generation", 0), sorted(released))
            member_cgroups = self._resolve_member_cgroups(members, primary_cg)
            policies = self._member_policies(members)
            if member_cgroups is None or policies is None:
                if member_cgroups is None:
                    member_cgroups = []
                self._park_pending_group(gid, members,
                                         info.get("graph_generation", 0),
                                         member_cgroups, policies,
                                         released_cgroups=released,
                                         ack_pending=False,
                                         primary_cgroup=primary_cg,
                                         epoch_id=epoch or "")
                log.warning("  recovery group %d: cannot resolve member cgroups "
                            "or policies -- leaving group release pending", gid)
                continue
            failed = []
            for idx, mcg in enumerate(member_cgroups):
                if mcg in released:
                    continue
                member_policy = None
                if idx < len(members):
                    member_policy = policies.get(members[idx], {}).get("proc_policy")
                ok, _ = self._release_proc(mcg, skip_ack=True,
                                           proc_policy=member_policy)
                if ok:
                    self._journal.append("release_member_done", cgroup=mcg,
                                         group_id=gid, epoch=epoch)
                    released.add(mcg)
                else:
                    failed.append(mcg)
            if failed:
                self._park_pending_group(gid, members,
                                         info.get("graph_generation", 0),
                                         member_cgroups, policies,
                                         released_cgroups=released,
                                         ack_pending=False,
                                         primary_cgroup=primary_cg,
                                         epoch_id=epoch or "")
                log.warning("  recovery group %d: release failed for %s -- not "
                            "acking group", gid, failed)
                continue
            if self._fs_group_ack(gid, primary_cg, epoch):
                sid = info.get("sid")
                if sid:
                    self._journal.append("commit_done", sid=sid, cgroup=primary_cg)
                if hasattr(self, "_pending_lock"):
                    for mcg in member_cgroups:
                        with self._pending_lock:
                            self._pending_release.discard(mcg)
            else:
                self._park_pending_group(gid, members,
                                         info.get("graph_generation", 0),
                                         member_cgroups, policies,
                                         released_cgroups=set(member_cgroups),
                                         ack_pending=True,
                                         primary_cgroup=primary_cg,
                                         epoch_id=epoch or "")
                log.warning("  recovery group %d: ack failed -- parked for "
                            "group ack retry", gid)
        log.info("Journal recovery: %d session(s), %d committed-pending, %d undecided",
                 len(state["sessions"]), len(state["committed"]), len(state["undecided"]))

    def add_cgroup(self, cgroup_path: str) -> dict:
        """
        Register a new cgroup for monitoring by ShadowProc.

        Args:
            cgroup_path: Filesystem path to the cgroup
                         (e.g., /sys/fs/cgroup/user.slice/shadow)
        """
        resp = self.proc_client.request({
            "action": "add_cgroup",
            "cgroup_path": cgroup_path,
        })
        if resp["status"] != "ok":
            log.error("add_cgroup failed: %s", resp.get("message"))
        else:
            log.info("Registered cgroup: %s", cgroup_path)
        return resp

    def register_output(self, cgroup_id: str, output_file: str) -> dict:
        """
        Register a stdout/stderr buffer file for a cgroup.

        Launchers (e.g. cgroup_exec via SHADOW_OUTPUT_FILE env) redirect the
        agent's stdout/stderr into this file. The buffered output is only
        released to the caller on commit; on rollback it is discarded.
        """
        self._output_buffers[cgroup_id] = output_file
        log.info("Registered stdout buffer for cgroup=%s → %s",
                 cgroup_id, output_file)
        return {"status": "ok", "output_file": output_file}

    def _peek_output(self, cgroup_id: str) -> Tuple[bool, str]:
        """Read the buffered stdout for a cgroup WITHOUT removing the record or
        deleting the file.

        Returns (ok, content). A missing buffer (never registered or file
        already gone) is success with empty content. A genuine read error
        (OSError) returns (False, "") and leaves the buffer intact, so the
        caller can fail closed BEFORE resuming any process.
        """
        output_file = self._output_buffers.get(cgroup_id)
        if not output_file:
            return True, ""
        try:
            with open(output_file, "r", errors="replace") as f:
                return True, f.read()
        except FileNotFoundError:
            return True, ""
        except OSError as e:
            log.warning("Failed to read buffered stdout %s: %s -- preserving "
                        "buffer for retry", output_file, e)
            return False, ""

    def _consume_output(self, cgroup_id: str) -> None:
        """Remove the buffer record and unlink its file. Called ONLY after the
        output has been successfully pre-read (see _peek_output) AND the
        processes have been resumed, so a failure earlier cannot lose output.
        """
        output_file = self._output_buffers.pop(cgroup_id, None)
        if output_file:
            try:
                os.unlink(output_file)
            except OSError:
                pass

    def _discard_output(self, cgroup_id: str) -> None:
        """Discard the buffered stdout for a cgroup (used on rollback)."""
        output_file = self._output_buffers.pop(cgroup_id, None)
        if output_file:
            try:
                os.unlink(output_file)
            except OSError:
                pass

    def get_buffered_output(self, cgroup_id: str) -> dict:
        """Return the current buffered stdout for a cgroup without flushing it."""
        output_file = self._output_buffers.get(cgroup_id)
        if not output_file:
            return {"status": "ok", "output": "", "buffered": False}
        try:
            with open(output_file, "r", errors="replace") as f:
                content = f.read()
            return {"status": "ok", "output": content, "buffered": True,
                    "output_file": output_file}
        except FileNotFoundError:
            return {"status": "ok", "output": "", "buffered": False}
        except OSError as e:
            return {"status": "error", "message": str(e)}

    def _fs_can_release(self, cgroup_id: str, epoch_id: Optional[str] = None) -> bool:
        """Ask ShadowFS whether a cgroup's external side effects are safe to
        release. Safe == the agent has reached the Finalized lifecycle state
        (all file promotions durable, all upstreams finalized).

        FAIL CLOSED in every ambiguous case:
          - request raised (ShadowFS down / timeout / disconnect) -> False
          - response is not status==ok                            -> False
          - response is missing the 'releasable' field            -> False
          - unknown cgroup (ShadowFS reports not releasable)       -> False
        Never defaults to True.
        """
        try:
            req = {"action": "can_release", "cgroup_id": cgroup_id}
            if epoch_id:
                req["epoch_id"] = epoch_id
            resp = self.fs_client.request(req)
        except Exception as e:  # noqa: BLE001 - any socket/JSON error = fail closed
            log.warning("  can_release(%s): ShadowFS unreachable (%s) -- "
                        "NOT releasing (fail closed)", cgroup_id, e)
            return False
        if not isinstance(resp, dict) or resp.get("status") != "ok":
            log.warning("  can_release(%s): ShadowFS error/malformed response "
                        "(%r) -- NOT releasing (fail closed)", cgroup_id, resp)
            return False
        if "releasable" not in resp:
            log.warning("  can_release(%s): response missing 'releasable' -- "
                        "NOT releasing (fail closed)", cgroup_id)
            return False
        return bool(resp.get("releasable"))

    def _fs_retry_finalize(self, cgroup_id: str, epoch_id: Optional[str] = None) -> dict:
        """Ask ShadowFS to re-run promotion/finalization for a stuck epoch.
        Returns the response dict (or an error dict on failure). Idempotent.
        """
        try:
            req = {"action": "retry_finalize", "cgroup_id": cgroup_id}
            if epoch_id:
                req["epoch_id"] = epoch_id
            return self.fs_client.request(req)
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

    def _fs_ack_release(self, cgroup_id: str, epoch_id: Optional[str] = None) -> bool:
        """Tell ShadowFS the external effects for a Finalized agent have been
        released, so it may drop the terminal record. AckRelease is idempotent
        on the ShadowFS side (unknown agent -> ok), so retrying is safe.

        Returns True iff ShadowFS acknowledged (status==ok). On a socket error
        or a non-ok response returns False so the caller can park the cgroup
        for an ack-only retry (a failed ack would otherwise leave a permanent
        Finalized record in ShadowFS).
        """
        try:
            req = {"action": "ack_release", "cgroup_id": cgroup_id}
            if epoch_id:
                req["epoch_id"] = epoch_id
            resp = self.fs_client.request(req)
        except Exception as e:  # noqa: BLE001
            log.warning("  ack_release(%s) failed: %s", cgroup_id, e)
            return False
        if not isinstance(resp, dict) or resp.get("status") != "ok":
            log.debug("  ack_release(%s): %s", cgroup_id,
                      resp.get("message") if isinstance(resp, dict) else resp)
            return False
        return True

    def _ensure_group_state(self) -> None:
        if not hasattr(self, "_authorized_lock"):
            self._authorized_lock = threading.Lock()
        if not hasattr(self, "_authorized_epochs"):
            self._authorized_epochs = {}
        if not hasattr(self, "_pending_group_lock"):
            self._pending_group_lock = threading.Lock()
        if not hasattr(self, "_pending_groups"):
            self._pending_groups = {}

    def _policy_hash(self, proc_policy: Optional[Dict]) -> str:
        blob = json.dumps(proc_policy or {}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def _allow_all_proc_policy(self) -> Dict:
        return PolicyIR.from_allowed_ops([
            {"event_type": "*", "action": "allow", "path_pattern": "/"}
        ]).to_proc_policy()

    def _record_authorized_epoch(self, epoch_id: str, cgroup_id: str,
                                 proc_policy: Optional[Dict]) -> str:
        policy_hash = self._policy_hash(proc_policy)
        self._ensure_group_state()
        with self._authorized_lock:
            self._authorized_epochs[epoch_id] = {
                "epoch_id": epoch_id,
                "cgroup_id": cgroup_id,
                "proc_policy": proc_policy,
                "policy_hash": policy_hash,
            }
        if hasattr(self, "_journal"):
            self._journal.append("authorization_intent", epoch=epoch_id, cgroup=cgroup_id,
                                 policy_hash=policy_hash,
                                 proc_policy=proc_policy or {})
        return policy_hash

    def _member_policies(self, members: List[str]) -> Optional[Dict[str, Dict]]:
        self._ensure_group_state()
        with self._authorized_lock:
            missing = [m for m in members if m not in self._authorized_epochs]
            if missing:
                return None
            out = {m: dict(self._authorized_epochs[m]) for m in members}
            for m, info in out.items():
                if not info.get("policy_hash"):
                    log.warning("  member %s has no policy_hash -- refusing release", m)
                    return None
                if info.get("proc_policy") is None:
                    log.warning("  member %s has no proc_policy -- refusing release", m)
                    return None
            return out

    def _drop_authorized_members(self, members: List[str]) -> None:
        self._ensure_group_state()
        with self._authorized_lock:
            for m in members:
                self._authorized_epochs.pop(m, None)
        if hasattr(self, "_journal"):
            for m in members:
                self._journal.append("authorization_tombstone", epoch=m)

    def _cancel_group(self, group_id: int) -> None:
        try:
            self.fs_client.request({"action": "cancel_group", "group_id": group_id})
        except Exception as e:  # noqa: BLE001
            log.warning("  cancel_group(%s) failed: %s", group_id, e)

    def _fs_group_finalize(self, epoch_id: str, cgroup_id: str,
                           proc_policy: Optional[Dict] = None) -> dict:
        """Group-level ShadowFS finalization: prepare_resolution → begin_finalize →
        poll get_finalize_status. Replaces the single-epoch "commit" +
        "can_release" pair with the group-aware flow (Phase 3).

        Returns dict with:
          - status: "ok" or "error"
          - group_id: int (on success)
          - members: list[str] epoch IDs (on success)
          - graph_generation: int64 (on success)
          - state: "finalized", "failed", or "pending" (on success)
          - finalize_err: str (on failure)
          - message: str (on error)
        """
        # Step 1: prepare_resolution — compute the SCC, get group_id + graph_gen.
        prep_req = {"action": "prepare_resolution", "cgroup_id": cgroup_id}
        if epoch_id:
            prep_req["epoch_id"] = epoch_id
        try:
            prep = self.fs_client.request(prep_req)
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": f"prepare_resolution: {e}"}
        if prep.get("status") != "ok":
            return prep

        group_id = prep["group_id"]
        members = prep["members"]
        graph_gen = prep["graph_generation"]
        log.info("  prepare_resolution: group_id=%d members=%s graph_gen=%d",
                 group_id, members, graph_gen)

        # Record this epoch's own authorization decision before considering
        # SCC finalization. Missing siblings are not errors: they mean this
        # epoch is authorized_pending and must remain fenced until their policy
        # paths independently authorize them.
        policy_hash = self._record_authorized_epoch(epoch_id or members[0],
                                                    cgroup_id, proc_policy)
        auth_req = {"action": "authorize", "cgroup_id": cgroup_id,
                    "policy_hash": policy_hash}
        if epoch_id:
            auth_req["epoch_id"] = epoch_id
        try:
            auth = self.fs_client.request(auth_req)
        except Exception as e:  # noqa: BLE001
            self._cancel_group(group_id)
            return {"status": "error", "message": f"authorize: {e}"}
        if not isinstance(auth, dict) or auth.get("status") != "ok":
            self._cancel_group(group_id)
            return auth
        authorized_epoch = auth.get("epoch_id") or epoch_id or members[0]
        if authorized_epoch != (epoch_id or members[0]):
            policy_hash = self._record_authorized_epoch(authorized_epoch,
                                                        cgroup_id, proc_policy)
        if auth.get("policy_hash") and auth.get("policy_hash") != policy_hash:
            self._cancel_group(group_id)
            return {"status": "error", "message": "ShadowFS policy_hash mismatch"}
        if hasattr(self, "_journal"):
            self._journal.append("authorized", epoch=authorized_epoch,
                                 cgroup=cgroup_id, policy_hash=policy_hash)

        policies = self._member_policies(members)
        if policies is None:
            missing = []
            with self._authorized_lock:
                missing = [m for m in members if m not in self._authorized_epochs]
            self._cancel_group(group_id)
            return {"status": "ok", "group_id": group_id, "members": members,
                    "graph_generation": graph_gen, "state": "authorized_pending",
                    "finalize_err": "waiting for independent member authorization",
                    "missing_members": missing}

        member_cgroups = [policies[m]["cgroup_id"] for m in members]

        # Freeze every independently authorized SCC member before ShadowFS
        # captures mmap/writeback state. A primary-only freeze lets siblings run
        # concurrently with sealing/finalization, so fail closed if any member
        # cannot be proven stopped by ShadowProc.
        proc_client = getattr(self, "proc_client", None)
        if proc_client is not None:
            for mcg in member_cgroups:
                try:
                    freeze_resp = proc_client.request({
                        "action": "freeze_by_cgroup",
                        "cgroup_id": mcg,
                    })
                except Exception as e:  # noqa: BLE001
                    self._cancel_group(group_id)
                    return {"status": "error", "message": f"freeze {mcg}: {e}"}
                if not isinstance(freeze_resp, dict) or freeze_resp.get("status") != "ok":
                    self._cancel_group(group_id)
                    return {"status": "error",
                            "message": f"freeze {mcg}: {freeze_resp}"}

        # Step 2: begin_finalize — promote only after all members are already
        # independently AuthorizedPending.
        # The graph_generation is checked by ShadowFS for TOCTOU: if the
        # dependency graph changed between prepare and begin, it refuses.
        try:
            fin = self.fs_client.request({
                "action": "begin_finalize",
                "group_id": group_id,
                "graph_generation": graph_gen,
            })
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": f"begin_finalize: {e}"}
        if fin.get("status") != "ok":
            return fin

        # Step 3: poll get_finalize_status until finalized or failed.
        state = fin.get("state", "pending")
        poll_count = 0
        while state == "pending":
            poll_count += 1
            if poll_count > 300:  # 30s timeout
                log.warning("  finalize poll timeout (30s) for group %d", group_id)
                return {"status": "ok", "group_id": group_id, "members": members,
                        "graph_generation": graph_gen, "state": "pending",
                        "finalize_err": "poll timeout",
                        "member_cgroups": member_cgroups,
                        "member_policies": policies}
            time.sleep(0.1)
            try:
                status = self.fs_client.request({
                    "action": "get_finalize_status",
                    "group_id": group_id,
                })
            except Exception as e:  # noqa: BLE001
                return {"status": "error", "message": f"get_finalize_status: {e}"}
            if status.get("status") != "ok":
                return status
            state = status.get("state", "pending")

        finalize_err = ""
        if state == "failed":
            try:
                status = self.fs_client.request({
                    "action": "get_finalize_status",
                    "group_id": group_id,
                })
                finalize_err = status.get("finalize_err", "") if isinstance(status, dict) else ""
            except Exception:
                pass

        return {"status": "ok", "group_id": group_id, "members": members,
                "graph_generation": graph_gen, "state": state,
                "finalize_err": finalize_err,
                "member_cgroups": member_cgroups,
                "member_policies": policies}

    def _fs_group_ack(self, group_id: int, cgroup_id: str,
                      epoch_id: str = "") -> bool:
        """Group-level ack_release: tells ShadowFS to drop the terminal records
        for ALL finalized members of a group. Returns True on success, False on
        failure (caller parks for ack-only retry)."""
        try:
            resp = self.fs_client.request({
                "action": "ack_release_group",
                "group_id": group_id,
            })
        except Exception as e:  # noqa: BLE001
            log.warning("  ack_release_group(%d) failed: %s", group_id, e)
            return False
        if not isinstance(resp, dict) or resp.get("status") != "ok":
            log.warning("  ack_release_group(%d): %s", group_id,
                        resp.get("message") if isinstance(resp, dict) else resp)
            return False
        return True

    def _resolve_member_cgroups(self, members: List[str],
                                primary_cgroup: str) -> Optional[List[str]]:
        """Map every epoch ID in a finalized group to its cgroup ID.

        Fail closed: every member must resolve. Falling back to only the primary
        would let ShadowFS ack a group while sibling process/output effects stay
        frozen or unreleased.
        """
        if len(members) <= 1:
            return [primary_cgroup]
        try:
            agents = self.fs_client.request({"action": "list_agents"})
        except Exception as e:  # noqa: BLE001
            log.warning("  list_agents failed while resolving release group: %s", e)
            return None
        if not isinstance(agents, dict) or agents.get("status") != "ok":
            log.warning("  list_agents returned %r -- refusing group release", agents)
            return None
        cgroup_map = {}
        for info in agents.get("agents_info", []):
            eid = info.get("epoch_id", "")
            cg = info.get("cgroup_id", "")
            if eid and cg:
                cgroup_map[eid] = cg
        result = []
        missing = []
        for epoch in members:
            cg = cgroup_map.get(epoch)
            if cg:
                result.append(cg)
            else:
                missing.append(epoch)
        if missing:
            log.warning("  cannot resolve all release-group members; missing=%s", missing)
            return None
        return result

    def _park_pending_group(self, group_id: int, members: List[str],
                            graph_generation: int, member_cgroups: List[str],
                            policies: Optional[Dict[str, Dict]],
                            released_cgroups: Optional[set] = None,
                            ack_pending: bool = False,
                            primary_cgroup: str = "", epoch_id: str = "") -> None:
        self._ensure_group_state()
        with self._pending_group_lock:
            self._pending_groups[group_id] = {
                "group_id": group_id,
                "members": list(members),
                "graph_generation": graph_generation,
                "member_cgroups": list(member_cgroups),
                "policies": policies or {},
                "released_cgroups": set(released_cgroups or set()),
                "ack_pending": ack_pending,
                "primary_cgroup": primary_cgroup,
                "epoch_id": epoch_id or "",
            }

    def _release_group_members(self, group_id: int, members: List[str],
                               graph_generation: int,
                               primary_cgroup: str,
                               proc_policy: Optional[Dict] = None,
                               journal_release_intent: bool = False,
                               journal_sid: str = None,
                               epoch_id: str = "") -> Tuple[Dict[str, str], bool]:
        """Release ALL members of a finalized SCC group (P0-7).

        Previously commit / submit_policy / resolve_epoch each inlined a
        release sequence that touched only the PRIMARY cgroup, leaving the
        group's other members frozen and un-acked — a leak that could stall
        dependent downstream cgroups and skip their process-layer release.
        This shared helper releases every member cgroup, optionally writes a
        durable release_intent, issues a single group ack_release, then
        re-evaluates deferred downstream cgroups.

        Members whose _release_proc fails are parked in _pending_release for
        the background retry loop (fail-closed: they stay fenced).

        Returns (output_by_cgroup, primary_released).
        """
        member_cgroups = self._resolve_member_cgroups(members, primary_cgroup)
        member_policies = self._member_policies(members)
        if member_policies is None and proc_policy is not None:
            policy_hash = self._policy_hash(proc_policy)
            member_policies = {
                m: {"epoch_id": m, "cgroup_id": "", "proc_policy": proc_policy,
                    "policy_hash": policy_hash}
                for m in members
            }
        all_output: Dict[str, str] = {}
        if not hasattr(self, "_epoch_results"):
            self._epoch_results = {}
        primary_ok = False
        if member_cgroups is None:
            self._park_pending_group(group_id, members, graph_generation,
                                     [], member_policies,
                                     released_cgroups=set(),
                                     ack_pending=False,
                                     primary_cgroup=primary_cgroup,
                                     epoch_id=epoch_id or "")
            return all_output, False
        if member_policies is None:
            self._park_pending_group(group_id, members, graph_generation,
                                     member_cgroups, {},
                                     released_cgroups=set(),
                                     ack_pending=False,
                                     primary_cgroup=primary_cgroup,
                                     epoch_id=epoch_id or "")
            return all_output, False

        # Durable release_intent must be written BEFORE externally visible
        # release operations. Recovery can then resume unfinished members.
        if journal_release_intent:
            entry = {"cgroup": primary_cgroup, "group_id": group_id,
                     "members": members, "graph_generation": graph_generation,
                     "epoch": epoch_id}
            if journal_sid:
                entry["sid"] = journal_sid
            self._journal.append("release_intent", **entry)

        failed_members = []
        released_cgroups = set()
        for idx, mcg in enumerate(member_cgroups):
            member_policy = member_policies.get(members[idx], {}).get("proc_policy")
            ok, stdout = self._release_proc(mcg, skip_ack=True,
                                            proc_policy=member_policy)
            if ok:
                all_output[mcg] = stdout
                if idx < len(members):
                    self._epoch_results[members[idx]] = {
                        "epoch_id": members[idx],
                        "cgroup_id": mcg,
                        "stdout": stdout,
                        "released": True,
                        "group_id": group_id,
                    }
                if journal_release_intent:
                    self._journal.append("release_member_done", cgroup=mcg,
                                         group_id=group_id, epoch=epoch_id)
                released_cgroups.add(mcg)
                if mcg == primary_cgroup:
                    primary_ok = True
            else:
                failed_members.append(mcg)
                log.warning("  Release of member cgroup=%s failed -- deferred", mcg)

        if failed_members:
            log.warning("  group %d not acked; failed members remain pending: %s",
                        group_id, failed_members)
            self._park_pending_group(group_id, members, graph_generation,
                                     member_cgroups, member_policies,
                                     released_cgroups=released_cgroups,
                                     ack_pending=False,
                                     primary_cgroup=primary_cgroup,
                                     epoch_id=epoch_id or "")
            self._try_release_pending()
            return all_output, primary_ok

        # Single group ack_release for all members, only after every member
        # release succeeded and release_member_done was durable.
        if not self._fs_group_ack(group_id, primary_cgroup, epoch_id):
            self._park_pending_group(group_id, members, graph_generation,
                                     member_cgroups, member_policies,
                                     released_cgroups=set(member_cgroups),
                                     ack_pending=True,
                                     primary_cgroup=primary_cgroup,
                                     epoch_id=epoch_id or "")
            log.warning("  ack_release_group(%d) failed -- parked for retry",
                        group_id)
        else:
            self._journal.append("group_release_done", group_id=group_id,
                                 cgroup=primary_cgroup, epoch=epoch_id or "")
            with self._pending_group_lock:
                self._pending_groups.pop(group_id, None)
            self._drop_authorized_members(members)

        # This group may unblock deferred downstream cgroups.
        self._try_release_pending()
        return all_output, primary_ok

    def get_epoch_result(self, epoch_id: str) -> dict:
        if not hasattr(self, "_epoch_results"):
            self._epoch_results = {}
        res = self._epoch_results.get(epoch_id)
        if not res:
            return {"status": "ok", "ready": False, "epoch_id": epoch_id}
        out = dict(res)
        out["status"] = "ok"
        out["ready"] = True
        return out

    def resolve_epoch(self, epoch_id: str, cgroup_id: str,
                      allowed_ops: List[Dict] = None,
                      session_id: str = None,
                      proc_policy: Optional[Dict] = None) -> dict:
        """Group-level finalization state machine (Phase 3) — the SINGLE
        convergence point for commit / session_commit_epoch / submit_policy.

        Implements the resolution flow:
          1. prepare_resolution → group_id, members, graph_gen
          2. (caller has already frozen the primary cgroup)
          3. TOCTOU check by begin_finalize (graph_generation must match)
          6. begin_finalize(group_id, graph_gen)
          7. poll get_finalize_status until finalized/failed
          8-12. release ALL members (process commit + output + resume)
         10. write durable release_intent to journal (session-scoped only)
         13. group ack_release

        ``proc_policy`` (P0-5): optional fine-grained process-layer policy
        forwarded to every member's continue_by_cgroup; None = allow-all.

        On any failure: returns error (caller handles rollback).
        Group members whose release fails are parked for retry.
        """
        log.info("RESOLVE_EPOCH epoch=%s cgroup=%s rules=%d session=%s",
                 epoch_id or "<active>", cgroup_id,
                 len(allowed_ops or []), session_id or "<none>")

        # Steps 1, 3, 6-7: group-level FS finalization.
        fs_result = self._fs_group_finalize(epoch_id, cgroup_id,
                                            proc_policy=proc_policy)
        if fs_result.get("status") != "ok":
            return fs_result
        if fs_result.get("state") != "finalized":
            return {"status": "error", "decision": "authorized_pending",
                    "message": "file layer not finalized",
                    "finalize_err": fs_result.get("finalize_err", "")}

        group_id = fs_result["group_id"]
        members = fs_result["members"]
        graph_gen = fs_result["graph_generation"]

        # Steps 8-13: release ALL members + journal + group ack (P0-7).
        # journal release_intent only for session-scoped resolves.
        all_output, primary_ok = self._release_group_members(
            group_id, members, graph_gen, cgroup_id,
            proc_policy=proc_policy,
            journal_release_intent=bool(session_id),
            journal_sid=session_id,
            epoch_id=epoch_id or "")

        primary_output = all_output.get(cgroup_id, "")
        return {"status": "ok", "decision": "finalized",
                "group_id": group_id, "members": members,
                "graph_generation": graph_gen,
                "stdout": primary_output, "released": primary_ok}

    def _finalize_retry_loop(self) -> None:
        """Background loop: periodically retry finalization for deferred
        cgroups and release them once ShadowFS reports Finalized. This turns a
        transient promotion failure into a self-healing wait instead of a
        permanent stall, while never releasing before Finalized. It also
        retries ack-only for cgroups already released but not yet acked.
        """
        while not self._retry_stop.wait(self._retry_interval):
            with self._pending_lock:
                pending = list(self._pending_release)
            with self._pending_ack_lock:
                acks = list(self._pending_ack)
            with self._pending_group_lock:
                groups = list(self._pending_groups.values())
            if not pending and not acks and not groups:
                continue
            with self._release_lock:
                # Retry group-level releases before legacy single-cgroup queues.
                self._retry_pending_groups()
                for cg in pending:
                    self._fs_retry_finalize(cg)
                    if self._fs_can_release(cg):
                        log.info("  finalize-retry: cgroup=%s reached Finalized "
                                 "-- releasing", cg)
                        ok, _ = self._release_proc(cg)
                        if ok:
                            with self._pending_lock:
                                self._pending_release.discard(cg)
                        else:
                            log.warning("  finalize-retry: release of cgroup=%s "
                                        "failed -- keeping pending for retry", cg)
                # Retry ONLY the ack for already-released cgroups.
                self._retry_pending_acks()

    def _retry_pending_groups(self) -> None:
        """Retry group-level release/ack without degrading to single-epoch APIs.
        Must be called with self._release_lock held.
        """
        with self._pending_group_lock:
            groups = [dict(g) for g in self._pending_groups.values()]
        for g in groups:
            gid = g["group_id"]
            members = g.get("members", [])
            member_cgroups = g.get("member_cgroups", [])
            policies = g.get("policies", {}) or {}
            released = set(g.get("released_cgroups", set()))
            epoch_id = g.get("epoch_id", "")
            primary = g.get("primary_cgroup", "")
            all_done = True
            for idx, mcg in enumerate(member_cgroups):
                if mcg in released:
                    continue
                member_policy = None
                if idx < len(members):
                    member_policy = policies.get(members[idx], {}).get("proc_policy")
                ok, _ = self._release_proc(mcg, skip_ack=True,
                                           proc_policy=member_policy)
                if ok:
                    released.add(mcg)
                    self._journal.append("release_member_done", cgroup=mcg,
                                         group_id=gid, epoch=epoch_id)
                else:
                    all_done = False
            if not all_done:
                with self._pending_group_lock:
                    if gid in self._pending_groups:
                        self._pending_groups[gid]["released_cgroups"] = released
                continue
            if self._fs_group_ack(gid, primary, epoch_id):
                self._journal.append("group_release_done", group_id=gid,
                                     cgroup=primary, epoch=epoch_id)
                with self._pending_group_lock:
                    self._pending_groups.pop(gid, None)
                self._drop_authorized_members(members)
            else:
                with self._pending_group_lock:
                    if gid in self._pending_groups:
                        self._pending_groups[gid]["released_cgroups"] = released
                        self._pending_groups[gid]["ack_pending"] = True

    def _retry_pending_acks(self) -> None:
        """Retry ONLY the ShadowFS ack_release for cgroups whose external
        effects were already released (processes resumed AND output delivered)
        but whose ack did not land. NEVER re-resumes processes or re-flushes
        output. Must be called with self._release_lock held.
        """
        with self._pending_ack_lock:
            acks = list(self._pending_ack)
        for cg, ep in acks:
            if self._fs_ack_release(cg, ep or None):
                with self._pending_ack_lock:
                    self._pending_ack.discard((cg, ep))
                log.info("  ack-retry: cgroup=%s epoch=%s acked -- ShadowFS record dropped",
                         cg, ep or "<active>")

    def _release_proc(self, cgroup_id: str,
                      skip_ack: bool = False,
                      proc_policy: Optional[Dict] = None) -> Tuple[bool, str]:
        """
        Resume ShadowProc's frozen processes for a cgroup (letting their
        held IPC / network / exit operations proceed), flush the cgroup's
        buffered stdout to the caller, and finally ACK the release to ShadowFS
        so it can drop the finalized agent's terminal record.

        ``proc_policy`` (P0-5): an optional fine-grained process-layer policy
        dict (see PolicyIR.to_proc_policy) forwarded to ShadowProc's
        continue_by_cgroup. When None, the cgroup is released allow-all
        (legacy full-release semantics). When present, ShadowProc installs
        the policy atomically and switches to MODE_ENFORCED *before* any
        process is resumed (fail-closed: a policy-install failure leaves the
        processes frozen).

        MUST only be called for a cgroup ShadowFS has confirmed Finalized
        (see _fs_can_release).

        Ordering is chosen so an output-read failure fails CLOSED before any
        process is resumed:
          1. query frozen processes
          2. PRE-READ the buffered output (without deleting it)
          3. discard baselines (commit_by_cgroup) -- FS is already finalized
          4. resume the processes (continue_by_cgroup, full release)
          5. consume (delete) the output buffer
          6. ack the release to ShadowFS

        Returns (ok, stdout). If the process query/resume, the output PRE-READ,
        or the baseline discard (commit_by_cgroup) fails, returns (False, "")
        WITHOUT resuming, WITHOUT consuming the output buffer, and WITHOUT
        acking -- the caller keeps the cgroup fenced and parked for retry.

        Once processes are resumed AND the output consumed, the external
        effects are OUT: this returns (True, stdout) even if the final
        ack_release fails. A failed ack does NOT re-fence -- the cgroup is
        parked in _pending_ack for an ACK-ONLY retry (never re-resumed).
        """
        # Step 1: query frozen processes. A failed/unreachable query means we
        # cannot know the process state -- do not proceed.
        try:
            frozen_resp = self.proc_client.request({
                "action": "list_frozen",
                "cgroup_id": cgroup_id,
            })
        except Exception as e:  # noqa: BLE001 - fail closed
            log.error("  list_frozen(%s) unreachable: %s -- NOT releasing/acking",
                      cgroup_id, e)
            return False, ""
        if not isinstance(frozen_resp, dict) or frozen_resp.get("status") != "ok":
            log.error("  list_frozen(%s) failed: %r -- NOT releasing/acking",
                      cgroup_id, frozen_resp)
            return False, ""

        # Step 2: PRE-READ the buffered output WITHOUT consuming it. Doing this
        # BEFORE resuming means a read failure fails closed with the processes
        # still frozen -- no external effect has escaped.
        read_ok, buffered = self._peek_output(cgroup_id)
        if not read_ok:
            log.error("  Output pre-read failed for cgroup=%s -- NOT resuming/"
                      "acking (fail closed; buffer preserved)", cgroup_id)
            return False, ""

        # Step 3: discard baselines (commit_by_cgroup) BEFORE full-releasing. FS
        # is already finalized so the file epoch is canonical; this discards the
        # frozen process baselines so they can't linger. Failure is fail-closed:
        # do NOT resume / consume / ack.
        try:
            commit_resp = self.proc_client.request({
                "action": "commit_by_cgroup",
                "cgroup_id": cgroup_id,
            })
        except Exception as e:  # noqa: BLE001 - fail closed
            log.error("  commit_by_cgroup(%s) unreachable: %s -- NOT releasing/"
                      "acking (processes stay frozen)", cgroup_id, e)
            return False, ""
        if not isinstance(commit_resp, dict) or commit_resp.get("status") != "ok":
            log.error("  commit_by_cgroup(%s) failed: %r -- NOT releasing/acking "
                      "(processes stay frozen; will retry)", cgroup_id, commit_resp)
            return False, ""

        # Step 4: resume the frozen processes (if any). A resume failure leaves
        # them frozen, so we must NOT consume the output or ack.
        frozen = frozen_resp.get("frozen") or []
        if frozen:
            log.info("  Releasing %d frozen process(es) for cgroup=%s",
                     len(frozen), cgroup_id)
            try:
                resume_req = {
                    "action": "continue_by_cgroup",
                    "cgroup_id": cgroup_id,
                }
                # Forward the fine-grained policy so ShadowProc enforces it
                # instead of the default allow-all (P0-5).
                if proc_policy is not None:
                    resume_req["policy"] = proc_policy
                resume_resp = self.proc_client.request(resume_req)
            except Exception as e:  # noqa: BLE001 - fail closed
                log.error("  Resume(%s) unreachable: %s -- NOT acking "
                          "(processes stay frozen; will retry)", cgroup_id, e)
                return False, ""
            if not isinstance(resume_resp, dict) or resume_resp.get("status") != "ok":
                log.error("  Resume failed for cgroup=%s: %r -- NOT acking "
                          "(processes stay frozen; will retry)",
                          cgroup_id, resume_resp)
                return False, ""
            log.info("  Resumed PIDs: %s", resume_resp.get("pids", []))

        # Step 5: processes are resumed -- now it is safe to consume (delete)
        # the buffered stdout we already read.
        self._consume_output(cgroup_id)
        if buffered:
            log.info("  Releasing %d bytes of buffered stdout for cgroup=%s",
                     len(buffered), cgroup_id)

        # Step 6: external effects are OUT -- ack so ShadowFS drops the record.
        # A failed ack does NOT re-fence (effects already released); park it
        # for an ack-only retry instead. When skip_ack is set (group-level
        # release), the caller performs a single group ack_release_group after
        # all members are released.
        if skip_ack:
            return True, buffered
        if not self._fs_ack_release(cgroup_id):
            with self._pending_ack_lock:
                self._pending_ack.add((cgroup_id, ""))
            log.warning("  ack_release(%s) failed -- external effects already "
                        "released; parked for ack-only retry", cgroup_id)
        return True, buffered

    def _try_release_pending(self) -> None:
        """
        Re-evaluate every deferred cgroup and release those that have since
        reached Finalized. Committing/finalizing one cgroup can unblock
        previously-deferred downstream cgroups, so this is called after every
        commit (and periodically by the background retry loop). It first asks
        ShadowFS to retry_finalize each pending cgroup so a transient promotion
        failure does not wedge it, then releases only those now Finalized.
        """
        with self._release_lock:
            with self._pending_lock:
                pending = list(self._pending_release)
            for cg in pending:
                self._fs_retry_finalize(cg)
                if self._fs_can_release(cg):
                    log.info("  Upstream now finalized \u2014 releasing deferred "
                             "cgroup=%s", cg)
                    ok, _ = self._release_proc(cg)
                    if ok:
                        with self._pending_lock:
                            self._pending_release.discard(cg)
                    else:
                        log.warning("  Release of deferred cgroup=%s failed -- "
                                    "keeping pending for retry", cg)
            # Also finish group-level retries and ack-only retries.
            self._retry_pending_groups()
            self._retry_pending_acks()

    def commit(self, cgroup_id: str) -> dict:
        """
        Commit (authorize) a cgroup's session and release it iff it finalizes.

        Result semantics (fs_resp["decision"]):
          - "finalized":         ShadowFS promoted all file state and every
                                 upstream is finalized. Processes resumed,
                                 network un-fenced, stdout flushed, release
                                 acked. fs_resp["released"]=True.
          - "authorized_pending": policy approved but promotion and/or upstream
                                 finalization is not complete (or a promotion
                                 failed). The cgroup stays FENCED: processes
                                 frozen, network fenced, stdout buffered. It is
                                 parked for the background finalize-retry loop.
                                 fs_resp["released"]=False, "deferred"=True.

        NOTE: this NEVER runs a rollback. A commit whose promotion partially
        failed must not be rolled back (some paths may already be promoted);
        the safe action is to stay fenced and retry finalization.
        """
        log.info("COMMIT cgroup=%s", cgroup_id)

        with self._release_lock:
            # Step 1: GROUP-LEVEL file finalization (Phase 3).
            fs_result = self._fs_group_finalize(None, cgroup_id,
                                                proc_policy=self._allow_all_proc_policy())
            if fs_result.get("status") != "ok":
                log.error("  ShadowFS group finalize failed: %s",
                          fs_result.get("message"))
                with self._pending_lock:
                    self._pending_release.add(cgroup_id)
                return {"status": "error", "decision": "authorized_pending",
                        "released": False, "deferred": True,
                        "message": fs_result.get("message", ""), "stdout": ""}
            if fs_result.get("state") != "finalized":
                self._park_pending_group(fs_result.get("group_id", 0),
                                         fs_result.get("members", []),
                                         fs_result.get("graph_generation", 0),
                                         fs_result.get("member_cgroups", []),
                                         fs_result.get("member_policies", {}),
                                         released_cgroups=set(),
                                         ack_pending=False,
                                         primary_cgroup=cgroup_id,
                                         epoch_id="")
                log.info("  cgroup=%s authorized but NOT finalized -- keeping "
                         "processes frozen, network fenced, stdout buffered "
                         "(background retry will finalize)", cgroup_id)
                return {"status": "ok", "decision": "authorized_pending",
                        "released": False, "deferred": True,
                        "message": fs_result.get("finalize_err", ""),
                        "stdout": ""}
            log.info("  ShadowFS group %d finalized: %d members",
                     fs_result["group_id"], len(fs_result["members"]))

            # Step 2: Release ALL group members + group ack (P0-7). The group
            # finalization already confirmed Finalized; _release_group_members
            # resumes every SCC member (not just the primary cgroup), issues
            # the group ack, and re-evaluates deferred downstream cgroups.
            all_output, released_ok = self._release_group_members(
                fs_result["group_id"], fs_result["members"],
                fs_result["graph_generation"], cgroup_id,
                journal_release_intent=False)
            stdout = all_output.get(cgroup_id, "")
            if released_ok:
                with self._pending_lock:
                    self._pending_release.discard(cgroup_id)
                result = {"status": "ok", "decision": "finalized",
                          "released": True, "stdout": stdout,
                          "group_id": fs_result["group_id"],
                          "members": fs_result["members"]}
            else:
                self._park_pending_group(fs_result.get("group_id", 0),
                                         fs_result.get("members", []),
                                         fs_result.get("graph_generation", 0),
                                         fs_result.get("member_cgroups", []),
                                         fs_result.get("member_policies", {}),
                                         released_cgroups=set(),
                                         ack_pending=False,
                                         primary_cgroup=cgroup_id,
                                         epoch_id="")
                log.warning("  cgroup=%s finalized but process/output release "
                            "failed -- keeping fenced, deferred for retry",
                            cgroup_id)
                result = {"status": "ok", "decision": "authorized_pending",
                          "released": False, "deferred": True, "stdout": ""}

        return result

    def _rollback_proc(self, cgroup_id: str) -> dict:
        """
        Roll back ShadowProc's process layer for a cgroup.

        Long-lived speculative sessions are rolled back LOSSLESSLY: discard the
        candidate (and its epoch descendants) and RESUME the pristine baseline
        via reject_by_cgroup, so the session's shell survives with its identity,
        session and parent lineage intact. Only NON-versioned frozen processes
        (e.g. one-shot audited processes with no active epoch) are killed.

        This replaces the old kill-everything path, which would have destroyed a
        long-lived session's shell along with its speculative work.

        Returns {"resumed": [...baseline pids...], "killed": [...pids...]}.
        """
        resumed: List[int] = []
        killed: List[int] = []

        # Step 1: Reject any active speculative epochs — discard the candidate,
        # resume the pristine baseline. Lossless; the canonical pid is unchanged.
        reject_resp = self.proc_client.request({
            "action": "reject_by_cgroup",
            "cgroup_id": cgroup_id,
        })
        if reject_resp.get("status") == "ok":
            resumed = reject_resp.get("pids", []) or []
            if resumed:
                log.info("  Restored %d baseline(s) in cgroup %s: %s",
                         len(resumed), cgroup_id, resumed)
        else:
            log.warning("  reject_by_cgroup failed for %s: %s",
                        cgroup_id, reject_resp.get("message"))

        # Step 2: Kill any remaining NON-versioned frozen processes. The
        # just-resumed baselines were removed from ShadowProc's frozen set by the
        # reject, so they are not affected here.
        kill_resp = self.proc_client.request({
            "action": "kill_by_cgroup",
            "cgroup_id": cgroup_id,
        })
        if kill_resp.get("status") == "ok":
            killed = kill_resp.get("pids", []) or []
            if killed:
                log.info("  Killed %d non-versioned process(es) in cgroup %s: %s",
                         len(killed), cgroup_id, killed)

        return {"resumed": resumed, "killed": killed}

    def _fail_closed(self, cgroup_id: str, state, reason: str,
                     total_events: int = 0, stop_observe: bool = False) -> dict:
        """Abort an in-flight commit and drive the workload into a CONTAINED state.

        Called when a security-critical commit step fails (freeze, whitelist
        install, or ShadowFS commit). Rather than releasing processes against an
        un-frozen / un-enforced / un-committed state (fail OPEN), we discard the
        speculative work and keep the workload contained (fail CLOSED): stop
        observation (if still running), roll back the filesystem, roll back /
        kill the process layer for every affected cgroup, discard buffered
        stdout, and drop any deferred releases.

        Returns an error dict with decision="fail_closed".
        """
        log.error("  FAIL-CLOSED: %s (cgroup=%s) - containing workload",
                  reason, cgroup_id)

        # Stop observation if it is still running (the freeze-failure path aborts
        # before Step 2 has stopped it).
        if stop_observe and state is not None:
            try:
                self.observe_client.request({
                    "action": "stop_observe",
                    "cgroup_id": state["cgroup_inode"],
                })
            except Exception as e:  # noqa: BLE001 - best-effort containment
                log.warning("  fail-closed: stop_observe failed: %s", e)

        # Remove any runtime whitelist that may have been installed before a
        # later commit step failed. Leaving it in the same cgroup would let a
        # future retry inherit stale policy.
        if state is not None and self.observe_client:
            try:
                self.observe_client.request({
                    "action": "remove_whitelist",
                    "cgroup_id": state["cgroup_inode"],
                })
            except Exception as e:  # noqa: BLE001 - best-effort containment
                log.warning("  fail-closed: remove_whitelist failed: %s", e)

        # Roll back the filesystem (discard speculative changes).
        fs_resp = self.fs_client.request({
            "action": "rollback",
            "cgroup_id": cgroup_id,
        })
        affected = []
        if fs_resp.get("status") == "ok":
            affected = fs_resp.get("affected", []) or []
            log.info("  fail-closed: ShadowFS rollback ok, affected: %s", affected)
        else:
            log.error("  fail-closed: ShadowFS rollback FAILED: %s",
                      fs_resp.get("message"))

        # Roll back / kill the process layer for all affected cgroups.
        total_killed: List[int] = []
        total_resumed: List[int] = []
        kill_cgroups = affected if affected else [cgroup_id]
        for cg in kill_cgroups:
            res = self._rollback_proc(cg)
            total_resumed.extend(res["resumed"])
            total_killed.extend(res["killed"])

        # Discard buffered stdout + drop deferred releases for the undone cgroups.
        for cg in kill_cgroups:
            self._discard_output(cg)
        with self._pending_lock:
            for cg in kill_cgroups:
                self._pending_release.discard(cg)

        # Cleanup observation state.
        self._observe_state.pop(cgroup_id, None)

        return {
            "status": "error",
            "decision": "fail_closed",
            "reason": reason,
            "total_events": total_events,
            "killed_pids": total_killed,
            "resumed_pids": total_resumed,
        }

    def rollback(self, cgroup_id: str) -> dict:
        """
        Rollback changes for a cgroup (with cascade).

        Flow:
        1. Tell ShadowFS to rollback (returns affected cgroup list).
        2. For each affected cgroup, kill any frozen processes in ShadowProc.

        Args:
            cgroup_id: The cgroup identifier (path from /proc/<pid>/cgroup)
        """
        log.info("ROLLBACK cgroup=%s", cgroup_id)

        # Step 1: Rollback in ShadowFS (cascade)
        fs_resp = self.fs_client.request({
            "action": "rollback",
            "cgroup_id": cgroup_id,
        })
        if fs_resp["status"] != "ok":
            log.error("  ShadowFS rollback failed: %s", fs_resp.get("message"))
            return fs_resp

        affected = fs_resp.get("affected", [])
        log.info("  ShadowFS rollback successful, affected cgroups: %s", affected)

        # Step 2: Roll back the process layer for all affected cgroups. Each
        # long-lived speculative session is restored to its pristine baseline
        # (lossless); only non-versioned frozen processes are killed.
        total_killed = []
        total_resumed = []
        for affected_cgroup in affected:
            res = self._rollback_proc(affected_cgroup)
            total_resumed.extend(res["resumed"])
            total_killed.extend(res["killed"])

        if total_resumed:
            log.info("  Total baselines restored: %d", len(total_resumed))
        if total_killed:
            log.info("  Total killed processes: %d", len(total_killed))

        # Discard buffered stdout for all affected cgroups.
        for affected_cgroup in affected:
            self._discard_output(affected_cgroup)
        self._discard_output(cgroup_id)

        # Drop any deferred releases for cgroups undone by this cascade:
        # their processes were rolled back, so there is nothing to release.
        with self._pending_lock:
            for affected_cgroup in affected:
                self._pending_release.discard(affected_cgroup)
            self._pending_release.discard(cgroup_id)

        return {"status": "ok", "affected": affected,
                "killed_pids": total_killed, "resumed_pids": total_resumed}

    def list_agents(self) -> List[str]:
        """List all active ShadowFS agents."""
        resp = self.fs_client.request({"action": "list_agents"})
        return resp.get("agents", [])

    def list_frozen(self, cgroup_id: Optional[str] = None) -> List[dict]:
        """List frozen processes, optionally filtered by cgroup."""
        if cgroup_id:
            resp = self.proc_client.request({
                "action": "list_frozen",
                "cgroup_id": cgroup_id,
            })
        else:
            resp = self.proc_client.request({"action": "list_all_frozen"})
        return resp.get("frozen", [])

    def get_affected(self, cgroup_id: str) -> List[str]:
        """Get cgroups that would be affected by a rollback (dry-run)."""
        resp = self.fs_client.request({
            "action": "rollback_affected",
            "cgroup_id": cgroup_id,
        })
        return resp.get("affected", [])

    def list_completed(self, cgroup_id: Optional[str] = None) -> List[dict]:
        """
        List processes that have completed execution and are being held
        (frozen at exit_group syscall, awaiting commit/rollback decision).

        Args:
            cgroup_id: Optional cgroup filter
        """
        req = {"action": "list_completed"}
        if cgroup_id:
            req["cgroup_id"] = cgroup_id
        resp = self.proc_client.request(req)
        return resp.get("frozen", [])

    # ──────────────────────────────────────────────────────────────────────
    # Speculative bash sessions (ShadowProc process epoch + ShadowFS file epoch)
    # ──────────────────────────────────────────────────────────────────────

    def _get_proxy(self) -> SessionProxy:
        """Lazily construct the SessionProxy (needs root + cgroup_exec)."""
        if self._proxy is None:
            self._proxy = SessionProxy(
                self._shadowproc_sock, verbose=True,
                shadowfs_mount=self._shadowfs_mount,
                backing_dir=self._backing_dir,
            )
        return self._proxy

    def session_open(self, cgroup_name: Optional[str] = None) -> dict:
        """
        Open a long-lived bash session inside a fresh monitored cgroup.

        The session is a stable handle: speculative epochs swap the underlying
        pid between a frozen baseline and a running candidate, but the caller
        only ever sees the session_id. File writes the session makes into the
        ShadowFS mount are attributed to its cgroup_id, so ShadowFS epoch
        commit/rollback lines up with the process-layer epoch.
        """
        proxy = self._get_proxy()
        sid = proxy.open_session(cgroup_name)
        cgroup_id = proxy.sessions[sid].cgroup_id
        with self._sessions_lock:
            self._sessions[sid] = cgroup_id
        self._journal.append("open", sid=sid, cgroup=cgroup_id)
        log.info("SESSION_OPEN sid=%s cgroup=%s", sid, cgroup_id)
        return {"status": "ok", "session_id": sid, "cgroup_id": cgroup_id}

    def session_run(self, session_id: str, command: str) -> dict:
        """Feed one command to the session's current live shell.

        Output is commit-gated. OUTSIDE an epoch the command is canonical and
        its stdout is returned immediately. INSIDE an active epoch the output is
        SPECULATIVE: it is held pending (never returned to the caller before
        finalization, so a non-rollbackable caller can't act on unwound state).
        The committed transcript is released by session_commit_epoch.
        """
        proxy = self._get_proxy()
        try:
            out = proxy.run(session_id, command)
        except KeyError:
            return {"status": "error", "message": f"unknown session {session_id}"}
        if out is None:
            # Speculative epoch active: do not release speculative output.
            return {"status": "pending", "output": None}
        return {"status": "ok", "output": out}

    def _session_cgroup(self, session_id: str) -> Optional[str]:
        with self._sessions_lock:
            return self._sessions.get(session_id)

    def _session_epoch(self, session_id: str) -> Optional[str]:
        with self._sessions_lock:
            return self._session_epochs.get(session_id)

    def session_begin_epoch(self, session_id: str) -> dict:
        """
        Open a unified speculative epoch for the session.

        Order matters: mark the ShadowFS epoch boundary FIRST (so every file
        write the candidate makes carries a seq past the marker), THEN fork the
        ShadowProc candidate and resume it as the live shell.
        """
        cgroup_id = self._session_cgroup(session_id)
        if not cgroup_id:
            return {"status": "error", "message": f"unknown session {session_id}"}
        # The orchestrator (not ShadowFS) mints the EpochID: the epoch -- not
        # the cgroup -- is the ShadowFS unit of versioning/finalization, and
        # every later commit/rollback/can_release call routes by this id.
        epoch_id = f"ep-{uuid.uuid4().hex[:12]}"
        log.info("SESSION_BEGIN_EPOCH sid=%s cgroup=%s epoch=%s",
                 session_id, cgroup_id, epoch_id)
        # Step 1: ShadowFS epoch registration (epoch_id -> cgroup attribution).
        fs_resp = self.fs_client.request({
            "action": "begin_epoch",
            "epoch_id": epoch_id,
            "cgroup_id": cgroup_id,
            "session_id": session_id,
        })
        if fs_resp.get("status") != "ok":
            log.error("  ShadowFS begin_epoch failed: %s", fs_resp.get("message"))
            return fs_resp
        with self._sessions_lock:
            self._session_epochs[session_id] = epoch_id
        # Step 2: ShadowProc baseline/candidate fork.
        try:
            self._get_proxy().begin_epoch(session_id)
        except NotAdmissibleError as e:
            # The baseline process is not snapshot-safe (multi-threaded, has
            # children, writable MAP_SHARED, pending signals, or non-regular
            # fds).  Degrade to non-speculative mode: unwind the FS epoch and
            # return an error so the caller runs commands directly.
            self.fs_client.request({"action": "rollback_epoch",
                                    "epoch_id": epoch_id,
                                    "cgroup_id": cgroup_id})
            with self._sessions_lock:
                self._session_epochs.pop(session_id, None)
            log.warning("  begin_epoch not admissible: %s -- degrading to "
                        "non-speculative mode", e)
            return {"status": "error", "reason": "not_admissible",
                    "message": str(e)}
        except Exception as e:  # noqa: BLE001
            # Best-effort unwind of the FS epoch so the agent is not left
            # with a dangling open epoch.
            self.fs_client.request({"action": "rollback_epoch",
                                    "epoch_id": epoch_id,
                                    "cgroup_id": cgroup_id})
            with self._sessions_lock:
                self._session_epochs.pop(session_id, None)
            log.error("  begin_epoch (process layer) failed: %s", e)
            return {"status": "error", "message": str(e)}
        return {"status": "ok", "cgroup_id": cgroup_id, "epoch_id": epoch_id}

    def session_commit_epoch(self, session_id: str) -> dict:
        """
        Accept the current epoch: keep the candidate as canonical (ShadowProc)
        AND durably PROMOTE the epoch's file changes (ShadowFS). The session
        lives on.

        This drives the FULL finalization path -- FS "commit" (authorize +
        promote to orig), a fail-closed can_release gate, the destructive
        process commit, and the release ack -- NOT the marker-only
        "commit_epoch" control op. The old convenience path only closed the
        epoch marker while the files stayed un-promoted in the overlay, yet it
        destroyed the baseline and released output: a later whole-agent
        rollback could then undo "committed" files with no baseline left.
        """
        cgroup_id = self._session_cgroup(session_id)
        if not cgroup_id:
            return {"status": "error", "message": f"unknown session {session_id}"}
        # Route by the session's own epoch_id when we minted one; fall back to
        # cgroup-only routing (ShadowFS resolves the active epoch) for sessions
        # opened before the epoch model.
        epoch_id = self._session_epoch(session_id)
        log.info("SESSION_COMMIT_EPOCH sid=%s cgroup=%s epoch=%s",
                 session_id, cgroup_id, epoch_id or "<active>")
        proxy = self._get_proxy()
        # Journal the intent BEFORE touching either layer, so recovery knows a
        # commit was in progress for this session even if we crash immediately.
        self._journal.append("commit_intent", sid=session_id, cgroup=cgroup_id,
                             epoch=epoch_id or "")
        # FS-FIRST finalization. Phase 1 is REVERSIBLE: quiesce the candidate to
        # a stopped boundary WITHOUT discarding the baseline, so if the file
        # layer cannot finalize we can still roll the epoch back losslessly.
        try:
            proxy.quiesce_for_commit(session_id)
        except Exception as e:  # noqa: BLE001
            log.error("  quiesce_for_commit (process layer) failed: %s", e)
            return {"status": "error", "message": str(e)}
        with self._release_lock:
            # Step 1: GROUP-LEVEL file finalization -- prepare_resolution →
            # begin_finalize → poll get_finalize_status. This replaces the
            # single-epoch "commit" + "can_release" with the group-aware
            # finalization flow (Phase 3).
            fs_result = self._fs_group_finalize(epoch_id, cgroup_id,
                                                proc_policy=self._allow_all_proc_policy())
            if fs_result.get("status") != "ok":
                log.error("  ShadowFS group finalize failed: %s -- baseline "
                          "preserved", fs_result.get("message"))
                return fs_result
            if fs_result.get("state") != "finalized":
                self._park_pending_group(fs_result.get("group_id", 0),
                                         fs_result.get("members", []),
                                         fs_result.get("graph_generation", 0),
                                         fs_result.get("member_cgroups", []),
                                         fs_result.get("member_policies", {}),
                                         released_cgroups=set(),
                                         ack_pending=False,
                                         primary_cgroup=cgroup_id,
                                         epoch_id=epoch_id or "")
                log.error("  cgroup=%s authorized but NOT finalized -- baseline "
                          "preserved (epoch stays fenced; retry the commit)",
                          cgroup_id)
                return {"status": "error", "decision": "authorized_pending",
                        "message": "file layer not finalized; epoch kept "
                                   "intact for retry",
                        "finalize_err": fs_result.get("finalize_err", "")}
            # DECISION POINT: the file layer finalized durably, so the
            # canonical outcome is now COMMITTED. Snapshot the committed
            # transcript into the journal BEFORE any externally-visible process
            # release, so recovery can deterministically resume the release.
            committed_output = proxy.peek_epoch_output(session_id)
            member_policies = self._member_policies(fs_result["members"])
            self._journal.append("fs_committed", sid=session_id, cgroup=cgroup_id,
                                 output=committed_output,
                                 group_id=fs_result["group_id"],
                                 members=fs_result["members"],
                                 graph_generation=fs_result["graph_generation"],
                                 epoch=epoch_id or "",
                                 member_policies=member_policies or {})

            member_cgroups = self._resolve_member_cgroups(
                fs_result["members"], cgroup_id)
            if member_cgroups is None:
                log.error("  cannot resolve all release-group members -- NOT "
                          "releasing/acking session commit")
                return {"status": "error", "decision": "authorized_pending",
                        "message": "cannot resolve all release-group members",
                        "released": False}

            # Durable release_intent must precede every externally-visible
            # process/output release, including the session primary.
            self._journal.append("release_intent",
                                sid=session_id, cgroup=cgroup_id,
                                group_id=fs_result["group_id"],
                                members=fs_result["members"],
                                graph_generation=fs_result["graph_generation"],
                                epoch=epoch_id or "")

            # Release sibling members first. If any sibling cannot be released,
            # keep the primary session fenced and do NOT ack the group.
            sibling_failed = False
            for idx, mcg in enumerate(member_cgroups):
                if mcg == cgroup_id:
                    continue
                member_policy = None
                if member_policies is not None and idx < len(fs_result["members"]):
                    member_policy = member_policies.get(
                        fs_result["members"][idx], {}).get("proc_policy")
                ok, _ = self._release_proc(mcg, skip_ack=True,
                                           proc_policy=member_policy)
                if ok:
                    self._journal.append("release_member_done", cgroup=mcg,
                                         group_id=fs_result["group_id"],
                                         epoch=epoch_id or "")
                else:
                    sibling_failed = True
                    self._park_pending_group(fs_result["group_id"],
                                             fs_result["members"],
                                             fs_result["graph_generation"],
                                             member_cgroups, member_policies,
                                             released_cgroups=set(member_cgroups[:idx]),
                                             ack_pending=False,
                                             primary_cgroup=cgroup_id,
                                             epoch_id=epoch_id or "")
                    log.warning("  Release of sibling member cgroup=%s failed "
                                "-- deferred; group not acked", mcg)
            if sibling_failed:
                return {"status": "error", "decision": "authorized_pending",
                        "message": "one or more sibling releases failed",
                        "released": False}

            # All siblings are out (or none exist). Release the primary session
            # via the SessionProxy-specific commit path, then mark it done.
            try:
                proxy.finalize_commit(session_id)
            except Exception as e:  # noqa: BLE001
                # Outcome is already durably COMMITTED and release_intent is
                # durable: recovery/retry must finish the primary release before
                # group ack.
                log.error("  finalize_commit (process layer) failed: %s", e)
                return {"status": "error", "message": str(e),
                        "released": False}
            self._journal.append("release_member_done", cgroup=cgroup_id,
                                 group_id=fs_result["group_id"],
                                 epoch=epoch_id or "")

            # External effects for every member are out -- only now may ShadowFS
            # drop the group's terminal records.
            acked = self._fs_group_ack(fs_result["group_id"], cgroup_id,
                                       epoch_id or "")
            if not acked:
                self._park_pending_group(fs_result["group_id"],
                                         fs_result["members"],
                                         fs_result["graph_generation"],
                                         member_cgroups, member_policies,
                                         released_cgroups=set(member_cgroups),
                                         ack_pending=True,
                                         primary_cgroup=cgroup_id,
                                         epoch_id=epoch_id or "")
                log.warning("  ack_release_group(%d) failed -- parked for "
                            "group ack retry", fs_result["group_id"])
                return {"status": "ok", "output": committed_output,
                        "released": True, "ack_pending": True}
        self._journal.append("commit_done", sid=session_id, cgroup=cgroup_id)
        self._journal.append("group_release_done", group_id=fs_result["group_id"],
                             cgroup=cgroup_id, epoch=epoch_id or "")
        self._drop_authorized_members(fs_result["members"])
        with self._sessions_lock:
            self._session_epochs.pop(session_id, None)
        self._recovered_outputs.pop(session_id, None)
        return {"status": "ok", "output": proxy.get_output(session_id),
                "released": True}

    def session_rollback_epoch(self, session_id: str) -> dict:
        """
        Roll back the current epoch losslessly: undo the epoch's file changes
        (ShadowFS), then discard the candidate and resume the pristine baseline
        (ShadowProc). To the session it is as if the epoch never ran.

        ORDER MATTERS: ShadowFS is rolled back FIRST. If ShadowFS refuses (e.g.
        the epoch's promotion has already started, so its published files can
        no longer be undone), we must NOT roll back the process/network layer
        either -- otherwise the process version would be reverted while the
        file state stayed published, leaving the two layers inconsistent.
        """
        cgroup_id = self._session_cgroup(session_id)
        if not cgroup_id:
            return {"status": "error", "message": f"unknown session {session_id}"}
        epoch_id = self._session_epoch(session_id)
        log.info("SESSION_ROLLBACK_EPOCH sid=%s cgroup=%s epoch=%s",
                 session_id, cgroup_id, epoch_id or "<active>")

        # Step 1: roll back the file layer FIRST and gate on its success.
        try:
            rb_req = {"action": "rollback_epoch", "cgroup_id": cgroup_id}
            if epoch_id:
                rb_req["epoch_id"] = epoch_id
            fs_resp = self.fs_client.request(rb_req)
        except Exception as e:  # noqa: BLE001 - fail closed: do not touch procs
            log.error("  ShadowFS rollback_epoch unreachable: %s -- "
                      "NOT rolling back the process layer", e)
            return {"status": "error", "message": str(e)}
        if fs_resp.get("status") != "ok":
            # Refused/failed: the file state cannot be undone, so leave the
            # process/network layer as-is (still fenced) and surface the error.
            log.error("  ShadowFS rollback_epoch refused/failed: %s -- "
                      "NOT rolling back the process layer", fs_resp.get("message"))
            return fs_resp

        # Step 2: file layer undone -> now roll back the process layer.
        proxy = self._get_proxy()
        try:
            proxy.reject(session_id)
        except Exception as e:  # noqa: BLE001
            log.error("  rollback_epoch (process layer) failed after FS undo: %s", e)
            return {"status": "error", "message": str(e)}
        self._journal.append("rollback", sid=session_id, cgroup=cgroup_id)
        with self._sessions_lock:
            self._session_epochs.pop(session_id, None)
        self._recovered_outputs.pop(session_id, None)
        return {"status": "ok"}

    def session_get_output(self, session_id: str) -> dict:
        """Return the session's committed (commit-gated) transcript.

        Falls back to the journal-recovered committed transcript when the live
        session did not survive a crash but its epoch was durably committed, so
        the caller still gets the deterministic committed result.
        """
        proxy = self._get_proxy()
        try:
            return {"status": "ok", "output": proxy.get_output(session_id)}
        except KeyError:
            if session_id in self._recovered_outputs:
                return {"status": "ok",
                        "output": self._recovered_outputs[session_id],
                        "recovered": True}
            return {"status": "error", "message": f"unknown session {session_id}"}

    def session_close(self, session_id: str) -> dict:
        """Tear down the session (kills its cgroup, releases the FIFO/cgroup)."""
        proxy = self._get_proxy()
        proxy.close_session(session_id)
        with self._sessions_lock:
            self._sessions.pop(session_id, None)
            self._session_epochs.pop(session_id, None)
        self._recovered_outputs.pop(session_id, None)
        self._journal.append("close", sid=session_id)
        log.info("SESSION_CLOSE sid=%s", session_id)
        return {"status": "ok"}

    # ──────────────────────────────────────────────────────────────────────
    # ShadowObserve integration
    # ──────────────────────────────────────────────────────────────────────

    def start_observe(self, cgroup_id: str, cgroup_inode: int,
                      log_path: Optional[str] = None,
                      epoch_id: Optional[str] = None) -> dict:
        """
        Start observing a cgroup via ShadowObserve.

        Args:
            cgroup_id: The cgroup identifier (e.g., "/shadow-demo")
            cgroup_inode: The cgroup directory inode number (uint64)
            log_path: Path for JSONL event log (auto-generated if None)
            epoch_id: Optional epoch identifier written to the log header
        """
        if not self.observe_client:
            return {"status": "error", "message": "ShadowObserve not configured"}

        if log_path is None:
            fd, log_path = tempfile.mkstemp(
                prefix=f"observ_{cgroup_id.strip('/').replace('/', '_')}_",
                suffix=".jsonl",
            )
            os.close(fd)  # mkstemp returns (fd, path); we only need the path

        log.info("START_OBSERVE cgroup=%s inode=%d log=%s epoch=%s",
                 cgroup_id, cgroup_inode, log_path, epoch_id or "<none>")

        req = {
            "action": "start_observe",
            "cgroup_id": cgroup_inode,
            "log_path": log_path,
        }
        if epoch_id:
            req["epoch_id"] = epoch_id
        resp = self.observe_client.request(req)

        if resp.get("status") == "ok":
            self._observe_state[cgroup_id] = {
                "log_path": log_path,
                "cgroup_inode": cgroup_inode,
            }
            log.info("  Observation started: %s", log_path)
        else:
            log.error("  start_observe failed: %s", resp.get("message"))

        return resp

    def stop_observe(self, cgroup_id: str) -> dict:
        """
        Stop observing a cgroup.

        Args:
            cgroup_id: The cgroup identifier
        """
        if not self.observe_client:
            return {"status": "error", "message": "ShadowObserve not configured"}

        state = self._observe_state.get(cgroup_id)
        if not state:
            return {"status": "error", "message": f"No active observation for {cgroup_id}"}

        resp = self.observe_client.request({
            "action": "stop_observe",
            "cgroup_id": state["cgroup_inode"],
        })

        if resp.get("status") == "ok":
            log.info("STOP_OBSERVE cgroup=%s", cgroup_id)
        return resp

    def submit_policy(self, cgroup_id: str, allowed_ops: List[Dict]) -> dict:
        """
        Submit an allowed operations policy for a cgroup.

        This triggers the core orchestration flow:
        1. Freeze all processes in the cgroup (ShadowProc)
        2. Stop observation (ShadowObserve)
        3. Audit recorded events against allowed_ops
        4. If audit passes: install whitelist eBPF + commit files + resume processes
        5. If audit fails: rollback files + kill processes

        Args:
            cgroup_id: The cgroup identifier (e.g., "/shadow-demo")
            allowed_ops: List of allowed operation dicts, each with:
                - event_type: str ("OPEN", "CREATE", "DELETE", etc.) or "*" for any
                - action: "allow" or "deny"
                - path_pattern: str (prefix match, e.g., "/tmp/")

        Returns:
            dict with status="committed" or status="rolled_back"
        """
        if not self.observe_client:
            return {"status": "error", "message": "ShadowObserve not configured"}

        state = self._observe_state.get(cgroup_id)
        if not state:
            return {"status": "error",
                    "message": f"No active observation for {cgroup_id}. "
                               f"Call start_observe first."}

        log.info("SUBMIT_POLICY cgroup=%s rules=%d", cgroup_id, len(allowed_ops))

        # ── Step 1: Freeze all processes in the cgroup ──
        log.info("  Step 1: Freezing processes...")
        freeze_resp = self.proc_client.request({
            "action": "freeze_by_cgroup",
            "cgroup_id": cgroup_id,
        })
        if freeze_resp.get("status") != "ok":
            # FAIL CLOSED: without a successful freeze there is no quiescent
            # snapshot to audit, and letting the workload keep running (then
            # committing/releasing it) would let unaudited, irreversible effects
            # escape. Abort and contain instead of continuing.
            return self._fail_closed(
                cgroup_id, state,
                f"freeze_by_cgroup failed: {freeze_resp.get('message')}",
                stop_observe=True,
            )
        frozen_pids = freeze_resp.get("pids", [])
        log.info("  Froze %d processes: %s", len(frozen_pids), frozen_pids)

        # ── Step 2: Stop observation (drains tail events, then seals log) ──
        log.info("  Step 2: Stopping observation...")
        stop_resp = self.observe_client.request({
            "action": "stop_observe",
            "cgroup_id": state["cgroup_inode"],
        })
        # FAIL CLOSED on an incomplete log. The paper guarantees an incomplete
        # audit log implies rollback: if stop failed, events were dropped
        # (ring-buffer overflow), the log write failed, or the ring could not be
        # drained, then the recorded log is NOT a faithful record of what the
        # frozen workload did -- auditing it could pass unaudited effects. The
        # `complete` field defaults to False when absent (unknown => fail closed).
        # path_errors counts events whose canonical path could not be built
        # (too deep / oversized component): their resource identity is unknown,
        # so they cannot be audited against any path-scoped rule.
        if (stop_resp.get("status") != "ok"
                or not stop_resp.get("complete", False)
                or stop_resp.get("dropped_events", 0) > 0
                or stop_resp.get("path_errors", 0) > 0
                or stop_resp.get("write_error", False)
                or stop_resp.get("drain_error", False)):
            return self._fail_closed(
                cgroup_id, state,
                "observation log incomplete at stop "
                f"(complete={stop_resp.get('complete')}, "
                f"dropped={stop_resp.get('dropped_events')}, "
                f"path_errors={stop_resp.get('path_errors')}, "
                f"write_error={stop_resp.get('write_error')}, "
                f"drain_error={stop_resp.get('drain_error')}, "
                f"status={stop_resp.get('status')})",
            )

        # ── Step 3: Audit recorded events against policy ──
        log.info("  Step 3: Auditing events...")
        # FAIL CLOSED on a malformed policy: an unknown event_type must not be
        # silently widened to ANY. Contain the cgroup instead of auditing
        # against a permissive rule set.
        try:
            ir = PolicyIR.from_allowed_ops(allowed_ops)
            audit_rules = ir.to_audit_rules()
        except ValueError as e:
            return self._fail_closed(
                cgroup_id, state,
                f"invalid policy (audit rules): {e}",
            )
        audit_resp = self.observe_client.request({
            "action": "audit",
            "log_path": state["log_path"],
            "rules": audit_rules,
        })

        if audit_resp.get("status") != "ok":
            log.error("  Audit request failed: %s", audit_resp.get("message"))
            return {"status": "error", "message": "audit failed",
                    "detail": audit_resp.get("message")}

        # FAIL CLOSED if the audit could not fully parse the log. An unparsable
        # record is an unknown event that may hide a violation; skipping it (the
        # old behaviour) would let it silently pass. `complete` defaults to
        # False when absent so an older daemon also fails closed.
        if (not audit_resp.get("complete", False)
                or audit_resp.get("parse_errors", 0) > 0):
            return self._fail_closed(
                cgroup_id, state,
                "audit log integrity failure "
                f"(complete={audit_resp.get('complete')}, "
                f"parse_errors={audit_resp.get('parse_errors')})",
                total_events=audit_resp.get("total_events", 0),
            )

        total_violations = audit_resp.get("total_violations", 0)
        total_events = audit_resp.get("total_events", 0)
        log.info("  Audit result: %d events, %d violations",
                 total_events, total_violations)

        # ── Step 4: Decision based on audit ──
        if total_violations == 0:
            # AUDIT PASSED: install whitelist → commit → resume
            log.info("  Step 4: Audit PASSED - committing...")

            # Install whitelist eBPF filter
            # FAIL CLOSED on a malformed policy: an unknown event_type must not
            # be silently widened to the 0xFFFF wildcard, which would admit
            # every event once the workload is released.
            try:
                ir = PolicyIR.from_allowed_ops(allowed_ops, state["cgroup_inode"])
                whitelist_ops = ir.to_bpf_whitelist()
            except ValueError as e:
                return self._fail_closed(
                    cgroup_id, state,
                    f"invalid policy (whitelist): {e}",
                    total_events=total_events,
                )
            wl_resp = self.observe_client.request({
                "action": "install_whitelist",
                "cgroup_id": state["cgroup_inode"],
                "allowed_ops": whitelist_ops,
            })
            if wl_resp.get("status") == "ok":
                log.info("  Whitelist installed: %s rules",
                         wl_resp.get("rules_added"))
            else:
                # FAIL CLOSED: the whitelist is the enforcement filter that
                # governs the process once released. Releasing it without the
                # filter installed would run the workload unconstrained, so
                # abort the commit and contain instead of only warning.
                return self._fail_closed(
                    cgroup_id, state,
                    f"whitelist install failed: {wl_resp.get('message')}",
                    total_events=total_events,
                )

            # Compile the fine-grained process-layer policy (P0-5) that will
            # govern the workload once released. Fail CLOSED on a malformed
            # policy: releasing under a partial policy could admit unaudited
            # effects. `ir` was built above for the whitelist; reuse it.
            try:
                proc_policy = ir.to_proc_policy()
            except ValueError as e:
                return self._fail_closed(
                    cgroup_id, state,
                    f"invalid policy (proc_policy): {e}",
                    total_events=total_events,
                )

            # Group-level filesystem finalization (Phase 3).
            buffered = ""
            fs_result = self._fs_group_finalize(None, cgroup_id,
                                                proc_policy=proc_policy)
            if fs_result.get("status") != "ok":
                # FAIL CLOSED: if the filesystem finalization failed, the
                # on-disk state is not the audited state. Releasing the frozen
                # processes to run against it would be fail-open, so abort and
                # contain: roll back the filesystem and the process layer.
                return self._fail_closed(
                    cgroup_id, state,
                    f"ShadowFS group finalize failed: {fs_result.get('message')}",
                    total_events=total_events,
                )
            if fs_result.get("state") != "finalized":
                self._park_pending_group(fs_result.get("group_id", 0),
                                         fs_result.get("members", []),
                                         fs_result.get("graph_generation", 0),
                                         fs_result.get("member_cgroups", []),
                                         fs_result.get("member_policies", {}),
                                         released_cgroups=set(),
                                         ack_pending=False,
                                         primary_cgroup=cgroup_id,
                                         epoch_id="")
                log.info("  cgroup=%s independently authorized but SCC is not "
                         "ready to finalize (%s); keeping policy cached and "
                         "workload fenced", cgroup_id,
                         fs_result.get("finalize_err", ""))
                return {
                    "status": "ok",
                    "decision": "authorized_pending",
                    "total_events": total_events,
                    "total_violations": 0,
                    "stdout": "",
                    "released": False,
                    "deferred": True,
                    "group_id": fs_result.get("group_id"),
                    "members": fs_result.get("members", []),
                    "missing_members": fs_result.get("missing_members", []),
                }
            log.info("  ShadowFS group %d finalized: %d members",
                     fs_result["group_id"], len(fs_result["members"]))

            # Release ALL group members + group ack (P0-7). The fine-grained
            # proc_policy (P0-5) is forwarded to every member's
            # continue_by_cgroup so ShadowProc enforces it instead of
            # allow-all. _release_group_members also writes the durable
            # release_intent and re-evaluates deferred downstream cgroups.
            all_output, released = self._release_group_members(
                fs_result["group_id"], fs_result["members"],
                fs_result["graph_generation"], cgroup_id,
                proc_policy=proc_policy,
                journal_release_intent=True)
            buffered = all_output.get(cgroup_id, "")
            if not released:
                buffered = ""
                self._park_pending_group(fs_result.get("group_id", 0),
                                         fs_result.get("members", []),
                                         fs_result.get("graph_generation", 0),
                                         fs_result.get("member_cgroups", []),
                                         fs_result.get("member_policies", {}),
                                         released_cgroups=set(),
                                         ack_pending=False,
                                         primary_cgroup=cgroup_id,
                                         epoch_id="")
                log.warning("  cgroup=%s finalized but process/output release "
                            "failed -- keeping fenced, deferred for retry",
                            cgroup_id)

            # Cleanup observation state
            del self._observe_state[cgroup_id]

            return {
                "status": "ok",
                "decision": "committed",
                "total_events": total_events,
                "total_violations": 0,
                "stdout": buffered,
                "released": released,
            }
        else:
            # AUDIT FAILED: rollback → kill
            log.info("  Step 4: Audit FAILED (%d violations) - rolling back...",
                     total_violations)

            violations = audit_resp.get("violations", [])
            for v in violations[:5]:  # Log first 5
                log.info("    VIOLATION: %s", v.get("description", str(v)))

            # Rollback filesystem
            fs_resp = self.fs_client.request({
                "action": "rollback",
                "cgroup_id": cgroup_id,
            })
            affected = []
            affected_epochs = []
            if fs_resp.get("status") == "ok":
                affected = fs_resp.get("affected", [])
                affected_epochs = fs_resp.get("affected_epochs", [])
                log.info("  ShadowFS rollback successful, affected: %s", affected)
            else:
                log.error("  ShadowFS rollback failed: %s", fs_resp.get("message"))

            # Roll back the process layer (all affected cgroups). Long-lived
            # speculative sessions are restored to their pristine baseline
            # (lossless); only non-versioned frozen processes are killed.
            total_killed = []
            total_resumed = []
            kill_cgroups = affected if affected else [cgroup_id]
            for cg in kill_cgroups:
                res = self._rollback_proc(cg)
                total_resumed.extend(res["resumed"])
                total_killed.extend(res["killed"])

            if total_resumed:
                log.info("  Restored baselines: %s", total_resumed)
            if total_killed:
                log.info("  Killed PIDs: %s", total_killed)

            # Discard buffered stdout for all affected cgroups
            for cg in kill_cgroups:
                self._discard_output(cg)
            self._drop_authorized_members(affected_epochs)

            # Drop any deferred releases for the undone cgroups.
            with self._pending_lock:
                for cg in kill_cgroups:
                    self._pending_release.discard(cg)

            # Cleanup observation state
            del self._observe_state[cgroup_id]

            return {
                "status": "ok",
                "decision": "rolled_back",
                "total_events": total_events,
                "total_violations": total_violations,
                "violations": violations,
                "killed_pids": total_killed,
                "resumed_pids": total_resumed,
            }


# ──────────────────────────────────────────────────────────────────────────────
# Standalone server mode: expose the orchestrator's API via its own Unix socket
# ──────────────────────────────────────────────────────────────────────────────

class OrchestratorServer:
    """
    Exposes the ShadowOrchestrator API over a Unix socket.

    Protocol: JSON-line request/response (same pattern as ShadowFS/ShadowProc).

    Supported actions:
        commit, rollback, add_cgroup, list_agents, list_frozen, get_affected,
        start_observe, stop_observe, submit_policy,
        session_open, session_run, session_begin_epoch, session_commit_epoch,
        session_rollback_epoch, session_get_output, session_close
    """

    def __init__(self, orchestrator: ShadowOrchestrator, listen_path: str):
        self.orch = orchestrator
        self.listen_path = listen_path
        self._running = True

    def serve(self):
        """Run the server (blocking)."""
        if os.path.exists(self.listen_path):
            os.remove(self.listen_path)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.listen_path)
        server.listen(16)
        server.settimeout(1.0)
        log.info("Orchestrator API listening on %s", self.listen_path)

        while self._running:
            try:
                conn, _ = server.accept()
                t = threading.Thread(target=self._handle_conn, args=(conn,),
                                     daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

        server.close()
        if os.path.exists(self.listen_path):
            os.remove(self.listen_path)

    def stop(self):
        self._running = False

    def _handle_conn(self, conn: socket.socket):
        try:
            f = conn.makefile("rw", buffering=1)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError as e:
                    resp = {"status": "error", "message": f"invalid JSON: {e}"}
                    f.write(json.dumps(resp) + "\n")
                    f.flush()
                    continue

                resp = self._dispatch(req)
                f.write(json.dumps(resp) + "\n")
                f.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()

    def _dispatch(self, req: dict) -> dict:
        action = req.get("action", "")
        cgroup_id = req.get("cgroup_id", "")
        cgroup_path = req.get("cgroup_path", "")

        try:
            if action == "commit":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                return self.orch.commit(cgroup_id)

            elif action == "rollback":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                return self.orch.rollback(cgroup_id)

            elif action == "add_cgroup":
                if not cgroup_path:
                    return {"status": "error", "message": "cgroup_path required"}
                return self.orch.add_cgroup(cgroup_path)

            elif action == "register_output":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                output_file = req.get("output_file", "")
                if not output_file:
                    return {"status": "error", "message": "output_file required"}
                return self.orch.register_output(cgroup_id, output_file)

            elif action == "get_output":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                return self.orch.get_buffered_output(cgroup_id)

            elif action == "list_agents":
                agents = self.orch.list_agents()
                return {"status": "ok", "agents": agents}

            elif action == "list_frozen":
                frozen = self.orch.list_frozen(cgroup_id or None)
                return {"status": "ok", "frozen": frozen}

            elif action == "list_completed":
                completed = self.orch.list_completed(cgroup_id or None)
                return {"status": "ok", "completed": completed}

            elif action == "get_affected":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                affected = self.orch.get_affected(cgroup_id)
                return {"status": "ok", "affected": affected}

            elif action == "get_epoch_result":
                epoch_id = req.get("epoch_id", "")
                if not epoch_id:
                    return {"status": "error", "message": "epoch_id required"}
                return self.orch.get_epoch_result(epoch_id)

            elif action == "start_observe":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                cgroup_inode = req.get("cgroup_inode", 0)
                if not cgroup_inode:
                    return {"status": "error", "message": "cgroup_inode required"}
                log_path = req.get("log_path", None)
                epoch_id = req.get("epoch_id", None)
                return self.orch.start_observe(cgroup_id, int(cgroup_inode), log_path, epoch_id)

            elif action == "stop_observe":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                return self.orch.stop_observe(cgroup_id)

            elif action == "submit_policy":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                allowed_ops = req.get("allowed_ops", [])
                if not allowed_ops:
                    return {"status": "error", "message": "allowed_ops required"}
                return self.orch.submit_policy(cgroup_id, allowed_ops)

            elif action == "session_open":
                cgroup_name = req.get("cgroup_name") or None
                return self.orch.session_open(cgroup_name)

            elif action == "session_run":
                session_id = req.get("session_id", "")
                command = req.get("command", "")
                if not session_id:
                    return {"status": "error", "message": "session_id required"}
                if not command:
                    return {"status": "error", "message": "command required"}
                return self.orch.session_run(session_id, command)

            elif action == "session_begin_epoch":
                session_id = req.get("session_id", "")
                if not session_id:
                    return {"status": "error", "message": "session_id required"}
                return self.orch.session_begin_epoch(session_id)

            elif action == "session_commit_epoch":
                session_id = req.get("session_id", "")
                if not session_id:
                    return {"status": "error", "message": "session_id required"}
                return self.orch.session_commit_epoch(session_id)

            elif action == "session_rollback_epoch":
                session_id = req.get("session_id", "")
                if not session_id:
                    return {"status": "error", "message": "session_id required"}
                return self.orch.session_rollback_epoch(session_id)

            elif action == "session_get_output":
                session_id = req.get("session_id", "")
                if not session_id:
                    return {"status": "error", "message": "session_id required"}
                return self.orch.session_get_output(session_id)

            elif action == "session_close":
                session_id = req.get("session_id", "")
                if not session_id:
                    return {"status": "error", "message": "session_id required"}
                return self.orch.session_close(session_id)

            else:
                return {"status": "error", "message": f"unknown action: {action}"}

        except Exception as e:
            log.exception("Error handling request: %s", req)
            return {"status": "error", "message": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="ShadowOrchestrator - coordinate ShadowFS, ShadowProc, and ShadowObserve"
    )
    parser.add_argument("--shadowfs-sock", required=True,
                        help="Unix socket path to ShadowFS")
    parser.add_argument("--shadowproc-sock", required=True,
                        help="Unix socket path to ShadowProc")
    parser.add_argument("--shadowobserve-sock", default=None,
                        help="Unix socket path to ShadowObserve (optional)")
    parser.add_argument("--listen", required=True,
                        help="Unix socket path for orchestrator API")
    parser.add_argument("--shadowfs-mount", default=None,
                        help="Path where ShadowFS FUSE is mounted (for domain isolation). "
                             "If set, each candidate bash runs inside a mount namespace "
                             "with read-only root and this mount preserved.")
    parser.add_argument("--backing-dir", default=None,
                        help="ShadowFS backing directory to block (staging/lower). "
                             "May be a colon-separated list. Prevents direct access bypassing ShadowFS.")
    args = parser.parse_args()

    # Parse colon-separated backing_dir list.
    backing_dir = args.backing_dir.split(":") if args.backing_dir else None

    orch = ShadowOrchestrator(args.shadowfs_sock, args.shadowproc_sock,
                              args.shadowobserve_sock,
                              shadowfs_mount=args.shadowfs_mount,
                              backing_dir=backing_dir)
    server = OrchestratorServer(orch, args.listen)

    def sig_handler(signum, frame):
        log.info("Shutting down...")
        server.stop()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        server.serve()
    finally:
        orch.close()
        log.info("Orchestrator stopped.")


if __name__ == "__main__":
    main()
