#!/usr/bin/env python3
"""
Experiment 2: Historical Audit and Future Execution Consistency

This experiment measures the SYSTEM, not a model of it. Every lifecycle step
goes through the real ShadowOrchestrator session API (framework.orch.OrchClient):

    session_open -> session_begin_epoch -> session_run -> session_resolve_epoch

so the full pipeline actually runs:

    freeze -> drain -> seal -> batch audit -> promote/rollback -> release

`session_resolve_epoch(decision="allow", allowed_ops=...)` compiles ONE PolicyIR
that the orchestrator uses BOTH to audit the sealed ShadowObserve trace
(retrospective) AND to install the prospective ShadowProc policy. The experiment
never builds an ``audit_trail`` by hand and never calls ShadowFS commit/rollback
directly -- it only reads the orchestrator's reply and checks external state.

Outcome classification (framework.errors): a lifecycle failure (orchestrator
unreachable, epoch open, seal/audit fail-closed, observer not wired, fence never
happened) is an INFRA_ERROR and makes the run exit non-zero. It is never a pass.

Design notes that follow from the observer/audit implementation:
  * ShadowObserve records FILESYSTEM and process-LIFECYCLE events (FORK=101,
    EXIT=102). Lifecycle events sit outside the (class<<8|op) space, so ONLY a
    wildcard allow rule covers them.
  * Network operations are NOT recorded by the observer; they are enforced
    prospectively by ShadowProc. So "allow the file history, deny the future
    connect" is expressible from one policy only if the audited trace carries no
    lifecycle events -- hence the fork-free tool command below (bash builtins +
    ``/dev/tcp``), which produces FILESYSTEM events only.

Usage:
    SHADOW_RUN_RQ2_EXPERIMENTS=1 python3 exp2_audit_consistency.py --repeats 10
"""

import argparse
import os
import socket
import sys
import tempfile
import threading
import time

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
from framework.paths import (
    fuse_path, harness_path, ensure_fuse_dirs, is_fuse_mounted,
    SHADOWFS_MNT, SHADOWFS_ORIG,
)

RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ2_EXPERIMENTS") == "1"

# FILESYSTEM operations (policy/effect_schema.json legacy_event_map). Note the
# read op is named "OPEN" in the schema (OPEN -> FILESYSTEM/READ); "READ" is
# NOT a valid policy event_type and fails compilation. A fork-free command only
# produces these, so allowing all of them (path "/") passes the audit while
# still leaving NETWORK default-denied prospectively.
FS_OPS = ("OPEN", "WRITE", "CREATE", "DELETE", "RENAME", "LINK", "SYMLINK",
          "TRUNCATE", "CHMOD", "CHOWN", "MKDIR", "RMDIR")


def allow_all_fs():
    """allowed_ops that permit every filesystem op at any path (no network)."""
    return [{"event_type": op, "action": "allow", "path_pattern": "/"}
            for op in FS_OPS]


def wildcard_allow():
    """allowed_ops that permit everything (covers FORK/EXIT lifecycle events)."""
    return [{"event_type": "*", "action": "allow", "path_pattern": "/"}]


class TcpReceiver:
    """External ground-truth receiver: did the denied connect ever arrive?

    Listens on an ephemeral 127.0.0.1 port BEFORE the session attempts its
    connect, so an allowed connect would be observed here. A denied (EPERM)
    connect never reaches it.
    """

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self.connections = 0
        self.bytes_received = 0
        self._stop = False
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            conn.settimeout(0.2)
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    self.bytes_received += len(data)
            except OSError:
                pass
            finally:
                conn.close()

    def stop(self):
        self._stop = True
        if self._thread:
            self._thread.join(timeout=1.0)
        try:
            self._sock.close()
        except OSError:
            pass


class Experiment2:
    """Audit-consistency experiment driven entirely by the session API."""

    def __init__(self, repeats: int = 10):
        self.repeats = repeats
        self.run_id = str(int(time.time() * 1000))[-8:]
        self.orch = OrchClient()
        self.metrics = MetricsCollector("exp2_audit_consistency")
        self._open_sessions = []
        self._agent_seq = 0

    # ── setup / teardown ────────────────────────────────────────────────

    def setup(self):
        if os.geteuid() != 0:
            raise InfrastructureError(
                "privileges", "Experiment 2 requires root privileges")
        # The orchestrator is the system under test: if it is not reachable the
        # experiment cannot run at all (never a silent pass).
        self.orch.require_listening()
        # ShadowObserve must be reachable, otherwise the retrospective audit has
        # nothing to seal and every audit-gated trial would be meaningless.
        try:
            observe = ShadowObserveClient()
            observe.connect()
            observe.close()
        except (FileNotFoundError, ConnectionError, OSError) as exc:
            raise InfrastructureError(
                "shadowobserve_socket",
                "ShadowObserve is not reachable; retrospective audit cannot run",
                exc)
        if not is_fuse_mounted():
            raise InfrastructureError(
                "fuse_mount",
                f"ShadowFS FUSE is not mounted at {SHADOWFS_MNT}; file "
                f"operations would bypass ShadowFS")
        ensure_fuse_dirs("exp2")
        self.metrics.metadata.update({
            "orch_sock": orch_sock_path(),
            "shadowfs_mount": SHADOWFS_MNT,
            "backing_store": SHADOWFS_ORIG,
            "repeats": self.repeats,
            "run_id": self.run_id,
        })
        print(f"[exp2] orchestrator={orch_sock_path()} mount={SHADOWFS_MNT}")

    def teardown(self):
        for sid in list(self._open_sessions):
            try:
                self.orch.session_close(sid)
            except Exception as exc:  # noqa: BLE001 - teardown is best effort
                print(f"[exp2] WARNING: session_close({sid}) failed: {exc}")
        self._open_sessions.clear()

    # ── session helpers ─────────────────────────────────────────────────

    def _next_agent(self, tag: str) -> str:
        self._agent_seq += 1
        return f"exp2-{tag}-{self.run_id}-{self._agent_seq}"

    def _open_session(self, tag: str):
        """Open a persistent session and remember it for teardown."""
        agent = self._next_agent(tag)
        resp = self.orch.session_open(agent_id=agent,
                                      cgroup_name=f"exp2-{tag}-{self.run_id}-"
                                                  f"{self._agent_seq}")
        sid = resp.get("session_id")
        cg = resp.get("cgroup_id")
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
            print(f"[exp2] WARNING: session_close({sid}) failed: {exc}")
        finally:
            if sid in self._open_sessions:
                self._open_sessions.remove(sid)

    def _resolve(self, sid: str, agent: str, decision: str,
                 allowed_ops=None):
        """Raw resolve reply (never raises on status!=ok): the audit-gated tests
        must inspect ``status``/``resolved``/``audit`` to classify the outcome
        instead of letting a fail-closed error look like a system rejection."""
        return self.orch.request(
            "session_resolve_epoch", timeout=180.0,
            session_id=sid, agent_id=agent, decision=decision,
            allowed_ops=allowed_ops)

    @staticmethod
    def _audit_performed(reply: dict) -> bool:
        audit = reply.get("audit") or {}
        return bool(audit.get("audited"))

    def _wait_fenced(self, cgroup_id: str, timeout: float = 10.0):
        """Poll ShadowProc (via the orchestrator) until a process is fenced."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            frozen = self.orch.list_frozen(cgroup_id)
            if frozen:
                return frozen
            time.sleep(0.05)
        return []

    @staticmethod
    def _backing(rel: str) -> str:
        return harness_path(rel)

    # ── Test 1: allowed historical write is audited and committed ────────

    def test_historical_write_allowed(self):
        """A write the policy allows must pass the sealed-trace audit and be
        promoted to the backing store on commit."""
        for i in range(self.repeats):
            rel = f"exp2/allow-{self.run_id}-{i}.txt"
            target = fuse_path(rel)
            backing = self._backing(rel)
            if os.path.exists(backing):
                os.unlink(backing)
            sid = cg = None
            with self.metrics.open_trial(
                    f"hist-write-allowed-{i}", scenario="allow_history") as t:
                try:
                    sid, cg, agent = self._open_session("allow")
                    self._begin_epoch(sid, agent)
                    # Fork-free write through FUSE (bash builtin + redirect).
                    self.orch.session_run(
                        sid, f"printf 'EXP2DATA' > {target}", timeout=30.0)
                    reply = self._resolve(sid, agent, "allow", wildcard_allow())

                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="resolve_fail_closed")
                        continue
                    if not self._audit_performed(reply):
                        t.infra_error(
                            "orchestrator did not audit a sealed trace "
                            "(ShadowObserve not wired into the session path)",
                            stage="audit_not_performed")
                        continue
                    resolved = reply.get("resolved", "allow")
                    violations = (reply.get("audit") or {}).get("violations") or []
                    committed = os.path.exists(backing)
                    t.check("allowed_write_committed",
                            resolved == "allow" and committed and not violations,
                            f"resolved={resolved} committed={committed} "
                            f"violations={len(violations)}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 2 (problem 3): disallowed historical write is rejected ──────

    def test_historical_write_rejected(self):
        """A write the policy does NOT allow must be caught by the sealed-trace
        audit, and the orchestrator must reject (roll back) the epoch on its own
        so the backing store is unchanged."""
        for i in range(self.repeats):
            rel = f"exp2/reject-{self.run_id}-{i}.txt"
            target = fuse_path(rel)
            backing = self._backing(rel)
            if os.path.exists(backing):
                os.unlink(backing)
            # Wildcard allow covers incidental/lifecycle events; the explicit
            # WRITE deny on the target makes "the policy does not allow this
            # write" true and produces exactly one audited violation.
            ops = wildcard_allow() + [
                {"event_type": "WRITE", "action": "deny", "path_pattern": target}]
            sid = None
            with self.metrics.open_trial(
                    f"hist-write-rejected-{i}", scenario="reject_history") as t:
                try:
                    sid, cg, agent = self._open_session("reject")
                    self._begin_epoch(sid, agent)
                    self.orch.session_run(
                        sid, f"printf 'EXP2DATA' > {target}", timeout=30.0)
                    reply = self._resolve(sid, agent, "allow", ops)

                    if reply.get("status") != "ok":
                        # Fail-closed (could not seal/parse the trace) is an
                        # infrastructure problem, not a clean policy catch.
                        t.infra_error(reply.get("message", reply),
                                      stage="resolve_fail_closed")
                        continue
                    if not self._audit_performed(reply):
                        t.infra_error(
                            "orchestrator did not audit a sealed trace "
                            "(ShadowObserve not wired into the session path)",
                            stage="audit_not_performed")
                        continue
                    rejected = (reply.get("resolved") == "deny"
                                or reply.get("audit_rejected") is True)
                    violations = (reply.get("audit") or {}).get("violations") or []
                    unchanged = not os.path.exists(backing)
                    # Property: the system itself refused the disallowed write.
                    t.check("disallowed_write_rejected", rejected and bool(violations),
                            f"resolved={reply.get('resolved')} "
                            f"audit_rejected={reply.get('audit_rejected')} "
                            f"violations={len(violations)}")
                    t.check("backing_store_unchanged", unchanged,
                            f"backing exists={os.path.exists(backing)}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 3 (problem 4): allow file history + deny future connect ─────

    def test_allow_history_deny_future(self):
        """One tool command: write a local file, then connect a network
        endpoint. The connect is fenced; we resolve with a policy that allows the
        file write but NOT the endpoint. The historical write must pass the
        audit, the restarted connect must be denied, and the external receiver
        must see nothing -- all from the SAME policy."""
        for i in range(self.repeats):
            rel = f"exp2/future-{self.run_id}-{i}.txt"
            target = fuse_path(rel)
            backing = self._backing(rel)
            if os.path.exists(backing):
                os.unlink(backing)
            receiver = TcpReceiver()
            receiver.start()
            sid = None
            with self.metrics.open_trial(
                    f"allow-hist-deny-future-{i}",
                    scenario="allow_history_deny_future") as t:
                try:
                    sid, cg, agent = self._open_session("future")
                    self._begin_epoch(sid, agent)

                    # Single fork-free tool command: file write, then connect.
                    # The connect blocks (fenced) so session_run must run in a
                    # worker thread while the main thread resolves the epoch.
                    cmd = (f"printf 'EXP2DATA' > {target}; "
                           f"exec 3<>/dev/tcp/127.0.0.1/{receiver.port} "
                           f"&& echo CONNECT_OK || echo CONNECT_DENIED")
                    box = {}

                    def worker():
                        try:
                            box["reply"] = self.orch.session_run(
                                sid, cmd, timeout=60.0)
                        except Exception as exc:  # noqa: BLE001
                            box["error"] = exc

                    th = threading.Thread(target=worker, daemon=True)
                    th.start()

                    frozen = self._wait_fenced(cg, timeout=10.0)
                    if not frozen:
                        th.join(timeout=5.0)
                        t.infra_error(
                            "network connect was never fenced; cannot exercise "
                            "the prospective-deny restart path",
                            stage="fence_not_observed")
                        continue

                    # Same policy: allow all filesystem ops (audit passes),
                    # allow NO network op (connect denied on restart).
                    reply = self._resolve(sid, agent, "allow", allow_all_fs())
                    th.join(timeout=60.0)

                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="resolve_fail_closed")
                        continue
                    if not self._audit_performed(reply):
                        t.infra_error(
                            "orchestrator did not audit a sealed trace "
                            "(ShadowObserve not wired into the session path)",
                            stage="audit_not_performed")
                        continue
                    if "error" in box:
                        t.infra_error(box["error"], stage="session_run")
                        continue

                    output = (box.get("reply") or {}).get("output", "")
                    violations = (reply.get("audit") or {}).get("violations") or []
                    history_ok = (reply.get("resolved") == "allow"
                                  and not violations
                                  and os.path.exists(backing))
                    connect_denied = ("CONNECT_DENIED" in output
                                      and "CONNECT_OK" not in output)
                    receiver_clean = receiver.connections == 0

                    t.check("history_passed_audit", history_ok,
                            f"resolved={reply.get('resolved')} "
                            f"violations={len(violations)} "
                            f"backing={os.path.exists(backing)}")
                    t.check("future_connect_denied", connect_denied,
                            f"output={output.strip()[:120]!r}")
                    t.check("receiver_saw_no_connection", receiver_clean,
                            f"connections={receiver.connections} "
                            f"bytes={receiver.bytes_received}")
                finally:
                    receiver.stop()
                    if sid:
                        self._close_session(sid)

    # ── Test 4: pure future-connect denial on restart ───────────────────

    def test_future_connect_denied_restart(self):
        """A fenced connect, resolved with a policy that omits NETWORK, must
        return EPERM on restart and never reach the receiver."""
        for i in range(self.repeats):
            receiver = TcpReceiver()
            receiver.start()
            sid = None
            with self.metrics.open_trial(
                    f"future-connect-denied-{i}",
                    scenario="deny_future_connect") as t:
                try:
                    sid, cg, agent = self._open_session("denyconnect")
                    self._begin_epoch(sid, agent)
                    cmd = (f"exec 3<>/dev/tcp/127.0.0.1/{receiver.port} "
                           f"&& echo CONNECT_OK || echo CONNECT_DENIED")
                    box = {}

                    def worker():
                        try:
                            box["reply"] = self.orch.session_run(
                                sid, cmd, timeout=60.0)
                        except Exception as exc:  # noqa: BLE001
                            box["error"] = exc

                    th = threading.Thread(target=worker, daemon=True)
                    th.start()
                    frozen = self._wait_fenced(cg, timeout=10.0)
                    if not frozen:
                        th.join(timeout=5.0)
                        t.infra_error(
                            "network connect was never fenced",
                            stage="fence_not_observed")
                        continue
                    # Allow only filesystem ops -> NETWORK stays default-deny.
                    reply = self._resolve(sid, agent, "allow", allow_all_fs())
                    th.join(timeout=60.0)
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="resolve_fail_closed")
                        continue
                    if "error" in box:
                        t.infra_error(box["error"], stage="session_run")
                        continue
                    output = (box.get("reply") or {}).get("output", "")
                    t.check("future_connect_denied",
                            "CONNECT_DENIED" in output
                            and "CONNECT_OK" not in output,
                            f"output={output.strip()[:120]!r}")
                    t.check("receiver_saw_no_connection",
                            receiver.connections == 0,
                            f"connections={receiver.connections}")
                finally:
                    receiver.stop()
                    if sid:
                        self._close_session(sid)

    # ── Test 5: dual-path rename fully undone by rollback ───────────────

    def test_dual_path_rename_rollback(self):
        """rename touches BOTH source and destination. Rolling the epoch back
        (decision=deny) must restore the source and remove the destination,
        proving ShadowFS recorded both paths."""
        for i in range(self.repeats):
            src_rel = f"exp2/rename-src-{self.run_id}-{i}.txt"
            dst_rel = f"exp2/rename-dst-{self.run_id}-{i}.txt"
            src_backing, dst_backing = self._backing(src_rel), self._backing(dst_rel)
            os.makedirs(os.path.dirname(src_backing), exist_ok=True)
            with open(src_backing, "w") as f:
                f.write("rename test data")
            if os.path.exists(dst_backing):
                os.unlink(dst_backing)
            sid = None
            with self.metrics.open_trial(
                    f"dual-path-rename-{i}", scenario="dual_path_rename") as t:
                try:
                    sid, cg, agent = self._open_session("rename")
                    self._begin_epoch(sid, agent)
                    # mv is an external command (forks) -- fine here because the
                    # rollback is driven by decision=deny, not by the audit.
                    self.orch.session_run(
                        sid, f"mv {fuse_path(src_rel)} {fuse_path(dst_rel)}",
                        timeout=30.0)
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)  # let the FUSE cache expire
                    src_restored = os.path.exists(src_backing)
                    dst_removed = not os.path.exists(dst_backing)
                    t.check("dual_path_rollback_complete",
                            src_restored and dst_removed,
                            f"src_restored={src_restored} dst_removed={dst_removed}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── Test 6: dual-path hard link fully undone by rollback ────────────

    def test_dual_path_hardlink_rollback(self):
        """A hard link adds a directory entry AND bumps nlink. Rollback must
        remove the new link and restore the original nlink."""
        for i in range(self.repeats):
            src_rel = f"exp2/link-src-{self.run_id}-{i}.txt"
            dst_rel = f"exp2/link-dst-{self.run_id}-{i}.txt"
            src_backing, dst_backing = self._backing(src_rel), self._backing(dst_rel)
            os.makedirs(os.path.dirname(src_backing), exist_ok=True)
            with open(src_backing, "w") as f:
                f.write("hardlink test data")
            if os.path.exists(dst_backing):
                os.unlink(dst_backing)
            nlink_before = os.stat(src_backing).st_nlink
            sid = None
            with self.metrics.open_trial(
                    f"dual-path-hardlink-{i}", scenario="dual_path_hardlink") as t:
                try:
                    sid, cg, agent = self._open_session("hardlink")
                    self._begin_epoch(sid, agent)
                    self.orch.session_run(
                        sid, f"ln {fuse_path(src_rel)} {fuse_path(dst_rel)}",
                        timeout=30.0)
                    reply = self._resolve(sid, agent, "deny")
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)
                    nlink_after = (os.stat(src_backing).st_nlink
                                   if os.path.exists(src_backing) else 0)
                    dst_removed = not os.path.exists(dst_backing)
                    t.check("dual_path_rollback_complete",
                            nlink_after == nlink_before and dst_removed,
                            f"nlink {nlink_before}->{nlink_after} "
                            f"dst_removed={dst_removed}")
                finally:
                    if sid:
                        self._close_session(sid)

    # ── driver ──────────────────────────────────────────────────────────

    def run(self):
        self.setup()
        print(f"\n{'=' * 70}")
        print("  EXPERIMENT 2: Audit Consistency (real orchestrator sessions)")
        print(f"  Repeats: {self.repeats}")
        print(f"{'=' * 70}\n")

        tests = [
            ("Allowed historical write committed", self.test_historical_write_allowed),
            ("Disallowed historical write rejected", self.test_historical_write_rejected),
            ("Allow file history + deny future connect", self.test_allow_history_deny_future),
            ("Future connect denied on restart", self.test_future_connect_denied_restart),
            ("Dual-path rename rollback", self.test_dual_path_rename_rollback),
            ("Dual-path hard link rollback", self.test_dual_path_hardlink_rollback),
        ]
        try:
            for idx, (label, fn) in enumerate(tests, 1):
                print(f"  [{idx}/{len(tests)}] {label} ...", flush=True)
                fn()
        except KeyboardInterrupt:
            print("\n[exp2] Interrupted")
        finally:
            self.metrics.finish()
            self.teardown()

        self.metrics.print_report()
        return self.metrics


def main():
    parser = argparse.ArgumentParser(
        description="RQ2 Experiment 2: Audit Consistency")
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output-dir", type=str, default="./results")
    args = parser.parse_args()

    if not RUN_EXPERIMENTS:
        print("ERROR: Set SHADOW_RUN_RQ2_EXPERIMENTS=1")
        sys.exit(1)

    exp = Experiment2(repeats=args.repeats)
    try:
        metrics = exp.run()
    except InfrastructureError as exc:
        print(f"\n[exp2] FATAL INFRASTRUCTURE ERROR: {exc}")
        sys.exit(2)
    metrics.save_report(args.output_dir)
    sys.exit(metrics.exit_code)


if __name__ == "__main__":
    main()
