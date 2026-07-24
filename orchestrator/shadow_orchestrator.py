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
import socket
import os
import sys
import argparse
import logging
import threading
import signal
import tempfile
import time
from typing import Optional, List, Dict, Any, Tuple

from session_proxy import SessionProxy

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
                 shadowobserve_sock: Optional[str] = None):
        self.fs_client = SocketClient(shadowfs_sock)
        self.proc_client = SocketClient(shadowproc_sock)
        self.observe_client = None
        self.fs_client.connect()
        self.proc_client.connect()

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

        # Track stdout buffer files: cgroup_id → output_file_path
        # Populated via register_output(); flushed on commit; discarded on rollback.
        self._output_buffers: Dict[str, str] = {}

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
        self._retry_thread.start()

        # ── Speculative bash-session support ──
        # A SessionProxy drives long-lived bash sessions and their ShadowProc
        # baseline/candidate epochs (process layer). The orchestrator layers
        # ShadowFS epoch commit/rollback on top so a session's file changes and
        # process state for one epoch are committed/rolled back together.
        # Created lazily (needs root + cgroup_exec) on first session_open.
        self._shadowproc_sock = shadowproc_sock
        self._proxy: Optional[SessionProxy] = None
        self._sessions: Dict[str, str] = {}  # session_id → cgroup_id
        self._sessions_lock = threading.Lock()

    def close(self):
        """Close connections to all services."""
        self._retry_stop.set()
        self.fs_client.close()
        self.proc_client.close()
        if self.observe_client:
            self.observe_client.close()

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

    def _fs_can_release(self, cgroup_id: str) -> bool:
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
            resp = self.fs_client.request({
                "action": "can_release",
                "cgroup_id": cgroup_id,
            })
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

    def _fs_retry_finalize(self, cgroup_id: str) -> dict:
        """Ask ShadowFS to re-run promotion/finalization for a stuck agent.
        Returns the response dict (or an error dict on failure). Idempotent.
        """
        try:
            return self.fs_client.request({
                "action": "retry_finalize",
                "cgroup_id": cgroup_id,
            })
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

    def _fs_ack_release(self, cgroup_id: str) -> bool:
        """Tell ShadowFS the external effects for a Finalized agent have been
        released, so it may drop the terminal record. AckRelease is idempotent
        on the ShadowFS side (unknown agent -> ok), so retrying is safe.

        Returns True iff ShadowFS acknowledged (status==ok). On a socket error
        or a non-ok response returns False so the caller can park the cgroup
        for an ack-only retry (a failed ack would otherwise leave a permanent
        Finalized record in ShadowFS).
        """
        try:
            resp = self.fs_client.request({
                "action": "ack_release",
                "cgroup_id": cgroup_id,
            })
        except Exception as e:  # noqa: BLE001
            log.warning("  ack_release(%s) failed: %s", cgroup_id, e)
            return False
        if not isinstance(resp, dict) or resp.get("status") != "ok":
            log.debug("  ack_release(%s): %s", cgroup_id,
                      resp.get("message") if isinstance(resp, dict) else resp)
            return False
        return True

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
            if not pending and not acks:
                continue
            with self._release_lock:
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

    def _retry_pending_acks(self) -> None:
        """Retry ONLY the ShadowFS ack_release for cgroups whose external
        effects were already released (processes resumed AND output delivered)
        but whose ack did not land. NEVER re-resumes processes or re-flushes
        output. Must be called with self._release_lock held.
        """
        with self._pending_ack_lock:
            acks = list(self._pending_ack)
        for cg in acks:
            if self._fs_ack_release(cg):
                with self._pending_ack_lock:
                    self._pending_ack.discard(cg)
                log.info("  ack-retry: cgroup=%s acked -- ShadowFS record dropped",
                         cg)

    def _release_proc(self, cgroup_id: str) -> Tuple[bool, str]:
        """
        Resume ShadowProc's frozen processes for a cgroup (letting their
        held IPC / network / exit operations proceed), flush the cgroup's
        buffered stdout to the caller, and finally ACK the release to ShadowFS
        so it can drop the finalized agent's terminal record.

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
                resume_resp = self.proc_client.request({
                    "action": "continue_by_cgroup",
                    "cgroup_id": cgroup_id,
                })
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
        # for an ack-only retry instead.
        if not self._fs_ack_release(cgroup_id):
            with self._pending_ack_lock:
                self._pending_ack.add(cgroup_id)
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
            # Also finish any ack-only retries (never re-resumes processes).
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
            # Step 1: Authorize + attempt finalization in ShadowFS.
            try:
                fs_resp = self.fs_client.request({
                    "action": "commit",
                    "cgroup_id": cgroup_id,
                })
            except Exception as e:  # noqa: BLE001 - fail closed: keep fenced
                log.error("  ShadowFS commit unreachable: %s -- keeping fenced", e)
                with self._pending_lock:
                    self._pending_release.add(cgroup_id)
                return {"status": "error", "decision": "authorized_pending",
                        "released": False, "deferred": True,
                        "message": str(e), "stdout": ""}
            if fs_resp.get("status") != "ok":
                log.error("  ShadowFS commit failed: %s", fs_resp.get("message"))
                return fs_resp
            log.info("  ShadowFS commit: state=%s releasable=%s%s",
                     fs_resp.get("state"), fs_resp.get("releasable"),
                     (" finalize_err=" + fs_resp["finalize_err"])
                     if fs_resp.get("finalize_err") else "")

            # Step 2: Release ONLY if the agent reached Finalized. The gate is
            # re-queried (fail-closed) rather than trusting the commit echo.
            if self._fs_can_release(cgroup_id):
                released_ok, stdout = self._release_proc(cgroup_id)
                if released_ok:
                    fs_resp["decision"] = "finalized"
                    fs_resp["stdout"] = stdout
                    fs_resp["released"] = True
                    with self._pending_lock:
                        self._pending_release.discard(cgroup_id)
                else:
                    # ShadowFS finalized the agent, but ShadowProc could not be
                    # queried/resumed or the output could not be read. Nothing
                    # was acked and the output buffer is intact; keep the cgroup
                    # fenced and parked so the retry loop finishes the release.
                    with self._pending_lock:
                        self._pending_release.add(cgroup_id)
                    log.warning("  cgroup=%s finalized but process/output release "
                                "failed -- keeping fenced, deferred for retry",
                                cgroup_id)
                    fs_resp["decision"] = "authorized_pending"
                    fs_resp["stdout"] = ""
                    fs_resp["released"] = False
                    fs_resp["deferred"] = True
            else:
                with self._pending_lock:
                    self._pending_release.add(cgroup_id)
                log.info("  cgroup=%s authorized but NOT finalized -- keeping "
                         "processes frozen, network fenced, stdout buffered "
                         "(background retry will finalize)", cgroup_id)
                fs_resp["decision"] = "authorized_pending"
                fs_resp["stdout"] = ""
                fs_resp["released"] = False
                fs_resp["deferred"] = True

            # Step 3: This commit may have unblocked deferred downstream cgroups.
            self._try_release_pending()

        return fs_resp

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
            self._proxy = SessionProxy(self._shadowproc_sock, verbose=True)
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
        log.info("SESSION_BEGIN_EPOCH sid=%s cgroup=%s", session_id, cgroup_id)
        # Step 1: ShadowFS epoch marker.
        fs_resp = self.fs_client.request({
            "action": "begin_epoch",
            "cgroup_id": cgroup_id,
        })
        if fs_resp.get("status") != "ok":
            log.error("  ShadowFS begin_epoch failed: %s", fs_resp.get("message"))
            return fs_resp
        # Step 2: ShadowProc baseline/candidate fork.
        try:
            self._get_proxy().begin_epoch(session_id)
        except Exception as e:  # noqa: BLE001
            # Best-effort unwind of the FS marker so the agent is not left
            # with a dangling open epoch.
            self.fs_client.request({"action": "rollback_epoch",
                                    "cgroup_id": cgroup_id})
            log.error("  begin_epoch (process layer) failed: %s", e)
            return {"status": "error", "message": str(e)}
        return {"status": "ok", "cgroup_id": cgroup_id}

    def session_commit_epoch(self, session_id: str) -> dict:
        """
        Accept the current epoch: keep the candidate as canonical (ShadowProc)
        AND accept the epoch's file changes (ShadowFS). The session lives on.
        """
        cgroup_id = self._session_cgroup(session_id)
        if not cgroup_id:
            return {"status": "error", "message": f"unknown session {session_id}"}
        log.info("SESSION_COMMIT_EPOCH sid=%s cgroup=%s", session_id, cgroup_id)
        proxy = self._get_proxy()
        # FS-FIRST finalization. Phase 1 is REVERSIBLE: quiesce the candidate to
        # a stopped boundary WITHOUT discarding the baseline, so if the file
        # layer cannot finalize we can still roll the epoch back losslessly.
        try:
            proxy.quiesce_for_commit(session_id)
        except Exception as e:  # noqa: BLE001
            log.error("  quiesce_for_commit (process layer) failed: %s", e)
            return {"status": "error", "message": str(e)}
        # Gate on the file layer: only proceed to the destructive process commit
        # once ShadowFS has finalized the epoch's file changes.
        fs_resp = self.fs_client.request({
            "action": "commit_epoch",
            "cgroup_id": cgroup_id,
        })
        if fs_resp.get("status") != "ok":
            # FS did NOT finalize: do NOT discard the baseline. The epoch stays
            # intact (candidate still frozen) so it can be rolled back later.
            log.error("  ShadowFS commit_epoch failed: %s -- baseline preserved",
                      fs_resp.get("message"))
            return fs_resp
        # FS finalized: perform the DESTRUCTIVE process commit (discard baseline,
        # keep candidate canonical) and release the buffered speculative output.
        try:
            proxy.finalize_commit(session_id)
        except Exception as e:  # noqa: BLE001
            log.error("  finalize_commit (process layer) failed: %s", e)
            return {"status": "error", "message": str(e)}
        return {"status": "ok", "output": proxy.get_output(session_id)}

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
        log.info("SESSION_ROLLBACK_EPOCH sid=%s cgroup=%s", session_id, cgroup_id)

        # Step 1: roll back the file layer FIRST and gate on its success.
        try:
            fs_resp = self.fs_client.request({
                "action": "rollback_epoch",
                "cgroup_id": cgroup_id,
            })
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
        return {"status": "ok"}

    def session_get_output(self, session_id: str) -> dict:
        """Return the session's committed (commit-gated) transcript."""
        proxy = self._get_proxy()
        try:
            return {"status": "ok", "output": proxy.get_output(session_id)}
        except KeyError:
            return {"status": "error", "message": f"unknown session {session_id}"}

    def session_close(self, session_id: str) -> dict:
        """Tear down the session (kills its cgroup, releases the FIFO/cgroup)."""
        proxy = self._get_proxy()
        proxy.close_session(session_id)
        with self._sessions_lock:
            self._sessions.pop(session_id, None)
        log.info("SESSION_CLOSE sid=%s", session_id)
        return {"status": "ok"}

    # ──────────────────────────────────────────────────────────────────────
    # ShadowObserve integration
    # ──────────────────────────────────────────────────────────────────────

    def start_observe(self, cgroup_id: str, cgroup_inode: int,
                      log_path: Optional[str] = None) -> dict:
        """
        Start observing a cgroup via ShadowObserve.

        Args:
            cgroup_id: The cgroup identifier (e.g., "/shadow-demo")
            cgroup_inode: The cgroup directory inode number (uint64)
            log_path: Path for JSONL event log (auto-generated if None)
        """
        if not self.observe_client:
            return {"status": "error", "message": "ShadowObserve not configured"}

        if log_path is None:
            log_path = tempfile.mkstemp(
                prefix=f"observ_{cgroup_id.strip('/').replace('/', '_')}_",
                suffix=".jsonl"
            )

        log.info("START_OBSERVE cgroup=%s inode=%d log=%s",
                 cgroup_id, cgroup_inode, log_path)

        resp = self.observe_client.request({
            "action": "start_observe",
            "cgroup_id": cgroup_inode,
            "log_path": log_path,
        })

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
        if (stop_resp.get("status") != "ok"
                or not stop_resp.get("complete", False)
                or stop_resp.get("dropped_events", 0) > 0
                or stop_resp.get("write_error", False)
                or stop_resp.get("drain_error", False)):
            return self._fail_closed(
                cgroup_id, state,
                "observation log incomplete at stop "
                f"(complete={stop_resp.get('complete')}, "
                f"dropped={stop_resp.get('dropped_events')}, "
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
            audit_rules = self._convert_policy_to_audit_rules(allowed_ops)
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
                whitelist_ops = self._convert_policy_to_whitelist(
                    allowed_ops, state["cgroup_inode"])
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

            # Commit filesystem changes
            buffered = ""
            fs_resp = self.fs_client.request({
                "action": "commit",
                "cgroup_id": cgroup_id,
            })
            if fs_resp.get("status") != "ok":
                # FAIL CLOSED: if the filesystem changes did not commit, the
                # on-disk state is not the audited state. Releasing the frozen
                # processes to run against it would be fail-open, so abort and
                # contain: roll back the filesystem and the process layer.
                return self._fail_closed(
                    cgroup_id, state,
                    f"ShadowFS commit failed: {fs_resp.get('message')}",
                    total_events=total_events,
                )
            log.info("  ShadowFS commit successful")

            # Release frozen processes only when all upstream dependencies
            # are committed; otherwise defer until a later upstream commit
            # unblocks this cgroup (keeps IPC / stdout held).
            released = False
            if self._fs_can_release(cgroup_id):
                released, buffered = self._release_proc(cgroup_id)
                if not released:
                    # Finalized in ShadowFS but ShadowProc query/resume or the
                    # output read failed: nothing acked, buffer preserved. Keep
                    # the cgroup fenced and parked so the retry loop finishes.
                    buffered = ""
                    with self._pending_lock:
                        self._pending_release.add(cgroup_id)
                    log.warning("  cgroup=%s finalized but process/output release "
                                "failed -- keeping fenced, deferred for retry",
                                cgroup_id)
            else:
                with self._pending_lock:
                    self._pending_release.add(cgroup_id)
                log.info("  Deferring release of cgroup=%s: upstream "
                         "dependencies not fully committed yet", cgroup_id)

            # Cleanup observation state
            del self._observe_state[cgroup_id]

            # This commit may unblock previously-deferred downstream cgroups.
            self._try_release_pending()

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
            if fs_resp.get("status") == "ok":
                affected = fs_resp.get("affected", [])
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

    @staticmethod
    def _normalize_fs_prefix(pattern: str) -> str:
        """Normalize a policy path prefix to the canonical form used by both the
        audit engine and the BPF enforcer.

        The enforcer probes prefixes of the resolved absolute path at '/'
        boundaries (see bpf/cri.bpf.h), so an installed key / audit pattern must
        match those candidates byte-for-byte. We strip trailing slashes (a lone
        "/" is left as the root marker) so "/tmp/" and "/tmp" both become
        "/tmp". Empty patterns (match-any) are preserved. Relative patterns are
        left unchanged; since canonical paths are absolute they simply will not
        match (fail-closed).
        """
        if not pattern:
            return ""
        p = pattern
        while len(p) > 1 and p.endswith("/"):
            p = p[:-1]
        return p

    @staticmethod
    def _convert_policy_to_audit_rules(allowed_ops: List[Dict]) -> List[Dict]:
        """
        Convert user-facing policy format to ShadowObserve audit rules.

        Allowed ops format:
            [{"event_type": "CREATE", "action": "allow", "path_pattern": "/tmp/"}]

        Audit rules format:
            [{"event_type": 2, "action": "allow", "path_pattern": "/tmp/"}]

        Fails CLOSED: an unrecognized event_type raises ValueError instead of
        defaulting to ANY (-1), so a typo can never widen a rule to match every
        event. The only wildcards are the explicit "*"/"ANY".
        """
        EVENT_TYPE_MAP = {
            "OPEN": 1, "CREATE": 2, "DELETE": 3, "RENAME": 4,
            "CHMOD": 5, "CHOWN": 6, "MKDIR": 7, "RMDIR": 8,
            "LINK": 9, "SYMLINK": 10, "TRUNCATE": 11,
            "EXEC": 100, "FORK": 101, "EXIT": 102, "KILL": 103,
            "SETUID": 106, "CAPSET": 107, "EXEC_PRIV": 108,
            "*": -1, "ANY": -1,
        }
        rules = []
        for op in allowed_ops:
            event_str = op.get("event_type", "*").upper()
            if event_str not in EVENT_TYPE_MAP:
                raise ValueError(f"unknown policy event_type: {event_str}")
            event_num = EVENT_TYPE_MAP[event_str]
            rules.append({
                "event_type": event_num,
                "action": op.get("action", "allow"),
                "path_pattern": ShadowOrchestrator._normalize_fs_prefix(
                    op.get("path_pattern", "")),
            })
        return rules

    @staticmethod
    def _convert_policy_to_whitelist(allowed_ops: List[Dict],
                                     cgroup_inode: int) -> List[Dict]:
        """
        Convert allowed_ops to whitelist format for eBPF enforcer.

        Whitelist format:
            [{"event_type": 2, "path_prefix": "/tmp/"}]

        Fails CLOSED: an unrecognized event_type raises ValueError instead of
        defaulting to the 0xFFFF wildcard, so a typo can never install a rule
        that admits every event. The only wildcards are the explicit "*"/"ANY".
        """
        EVENT_TYPE_MAP = {
            "OPEN": 1, "CREATE": 2, "DELETE": 3, "RENAME": 4,
            "CHMOD": 5, "CHOWN": 6, "MKDIR": 7, "RMDIR": 8,
            "LINK": 9, "SYMLINK": 10, "TRUNCATE": 11,
            "EXEC": 100, "FORK": 101, "EXIT": 102, "KILL": 103,
            "SETUID": 106, "CAPSET": 107, "EXEC_PRIV": 108,
            "*": 0xFFFF, "ANY": 0xFFFF,
        }
        whitelist = []
        for op in allowed_ops:
            if op.get("action", "allow").lower() != "allow":
                continue
            event_str = op.get("event_type", "*").upper()
            if event_str not in EVENT_TYPE_MAP:
                raise ValueError(f"unknown policy event_type: {event_str}")
            event_num = EVENT_TYPE_MAP[event_str]
            whitelist.append({
                "event_type": event_num,
                "path_prefix": ShadowOrchestrator._normalize_fs_prefix(
                    op.get("path_pattern", "")),
            })
        return whitelist


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

            elif action == "start_observe":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                cgroup_inode = req.get("cgroup_inode", 0)
                if not cgroup_inode:
                    return {"status": "error", "message": "cgroup_inode required"}
                log_path = req.get("log_path", None)
                return self.orch.start_observe(cgroup_id, int(cgroup_inode), log_path)

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
    args = parser.parse_args()

    orch = ShadowOrchestrator(args.shadowfs_sock, args.shadowproc_sock,
                              args.shadowobserve_sock)
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
