#!/usr/bin/env python3
"""
Session Proxy for ShadowProc — Frozen Baseline + Speculative Clone.

The Session Proxy gives an agent a *stable* handle (a `session_id`) to a
long-lived shell, and hides the fact that speculative execution keeps swapping
the underlying pid between a frozen "baseline" and a running "candidate".

Mechanism (all delegated to the ShadowProc daemon over its Unix socket):

  open_session()      launch a real bash inside a monitored cgroup, driven by a
                      FIFO. The live shell idles blocked in read() on the FIFO —
                      this is the natural per-epoch snapshot boundary.

  begin_epoch(sid)    freeze the live shell at its read() boundary, then
                      begin_speculative: the ORIGINAL becomes the pristine
                      *baseline* (never runs the epoch's commands) and a COW
                      *candidate* is forked and resumed. The candidate is now the
                      live shell; the proxy tracks the pid swap internally.

  run(sid, cmd)       feed a command to the current live shell (the candidate,
                      during an epoch) and capture its stdout.

  commit(sid)         accept the candidate as canonical and discard the baseline.
                      The candidate keeps running; session_id is unchanged.

  reject(sid)         discard the candidate and resume the pristine baseline —
                      the ORIGINAL process, lineage intact, which never ran the
                      epoch's commands. Rollback is lossless; session_id is
                      unchanged.

The agent only ever sees `session_id`. It never learns, or needs, a pid.

Requires: root, Linux >= 5.15 with BPF LSM, cgroup v2, and a running ShadowProc
daemon whose socket this proxy connects to. `cgroup_exec` (from
demo/test_programs) is used to place bash into the cgroup atomically.
"""

import argparse
import itertools
import json
import os
import signal
import socket
import sys
import time
import uuid


# ──────────────────────────── ShadowProc client ────────────────────────────
class ShadowProcClient:
    """Thin newline-delimited-JSON client for the ShadowProc Unix socket."""

    def __init__(self, sock_path):
        self.sock_path = sock_path

    def call(self, action, **fields):
        """Send one request, return the parsed response dict.

        Raises RuntimeError if the daemon reports status == "error".
        """
        req = {"action": action}
        req.update({k: v for k, v in fields.items() if v is not None})
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.sock_path)
        try:
            f = s.makefile("rw", buffering=1)
            f.write(json.dumps(req) + "\n")
            f.flush()
            line = f.readline()
        finally:
            s.close()
        if not line:
            raise RuntimeError(f"{action}: empty response from ShadowProc")
        resp = json.loads(line)
        if resp.get("status") == "error":
            raise RuntimeError(f"{action}: {resp.get('message')}")
        return resp


# ──────────────────────────── Session state ────────────────────────────────
class _Session:
    def __init__(self, session_id, cgroup_name, cgroup_root):
        self.id = session_id
        self.cgroup_name = cgroup_name
        self.cgroup_id = "/" + cgroup_name                     # ShadowProc form
        self.cgroup_path = os.path.join(cgroup_root, cgroup_name)
        self.fifo_path = f"/tmp/shadow-session-{session_id}.fifo"
        self.log_path = f"/tmp/shadow-session-{session_id}.log"
        self.fifo_wfd = None        # held-open write end (keeps FIFO from EOF)
        self.live_pid = None        # current canonical pid (agent never sees it)
        self.epoch = None           # {"baseline": pid, "candidate": pid} or None
        # Commit-gated output. `committed_output` is the durable transcript that
        # is safe to release externally (get_output). `epoch_buffer` holds the
        # SPECULATIVE output produced during the current epoch; it is merged
        # into committed_output on commit and dropped on reject.
        self.committed_output = []
        self.epoch_buffer = []


# ──────────────────────────── The proxy ────────────────────────────────────
class SessionProxy:
    def __init__(self, sock_path, cgroup_root="/sys/fs/cgroup",
                 cgroup_exec=None, verbose=True):
        self.client = ShadowProcClient(sock_path)
        self.cgroup_root = cgroup_root
        self.cgroup_exec = cgroup_exec or self._default_cgroup_exec()
        self.verbose = verbose
        self.sessions = {}
        self._sentinel_ids = itertools.count(1)

    # ---- infra helpers -----------------------------------------------------
    @staticmethod
    def _default_cgroup_exec():
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(here)
        return os.path.join(root, "demo", "test_programs", "cgroup_exec")

    def _log(self, msg):
        if self.verbose:
            print(f"  [proxy] {msg}", flush=True)

    @staticmethod
    def _proc_state(pid):
        try:
            with open(f"/proc/{pid}/status") as fh:
                for ln in fh:
                    if ln.startswith("State:"):
                        return ln.split()[1]
        except OSError:
            return None
        return None

    def _wait_state_T(self, pid, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc_state(pid) == "T":
                return True
            time.sleep(0.05)
        return False

    @staticmethod
    def _reap(pid, timeout=2.0):
        """Reap a child the daemon killed, so it doesn't linger as a zombie.

        The daemon SIGKILLs the process but is NOT its parent (candidates are
        CLONE_PARENT siblings of the shell, i.e. children of this launcher), so
        only we can reap it. The candidate now exits with SIGCHLD, so a normal
        waitpid() can collect it. Poll briefly because the target may not have
        become a zombie yet at the instant we're called (the daemon's SIGKILL is
        asynchronous).
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                wpid, _ = os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                return  # already reaped, or not our child
            if wpid == pid:
                return  # reaped
            time.sleep(0.02)

    def _loglines(self, sess):
        try:
            with open(sess.log_path, "r", errors="replace") as fh:
                return fh.read().splitlines()
        except OSError:
            return []

    def _feed(self, sess, line):
        os.write(sess.fifo_wfd, (line + "\n").encode())

    # ---- session lifecycle -------------------------------------------------
    def open_session(self, cgroup_name=None):
        """Launch a bash session inside a fresh monitored cgroup. Returns sid."""
        sid = uuid.uuid4().hex[:8]
        cgroup_name = cgroup_name or f"shadow-session-{sid}"
        sess = _Session(sid, cgroup_name, self.cgroup_root)

        os.makedirs(sess.cgroup_path, exist_ok=True)
        # Register the cgroup with ShadowProc's eBPF (monitored). bash can start
        # here because the mmap hook exempts its read-only loader mappings.
        self.client.call("add_cgroup", cgroup_path=sess.cgroup_path)

        # Fresh FIFO + log. Hold the FIFO open O_RDWR so the shell never sees
        # EOF and our writes never block.
        for p in (sess.fifo_path, sess.log_path):
            try:
                os.remove(p)
            except OSError:
                pass
        os.mkfifo(sess.fifo_path)
        # O_CLOEXEC so the held write end does not leak into bash across exec().
        sess.fifo_wfd = os.open(sess.fifo_path, os.O_RDWR | os.O_CLOEXEC)

        # Launch bash via cgroup_exec, which writes its own pid into cgroup.procs
        # and then exec()s bash — so the returned pid IS the bash. These fds are
        # dup2'd onto 0/1/2 in the child (which clears CLOEXEC on 0/1/2), so only
        # the stray originals close on exec.
        stdin_fd = os.open(sess.fifo_path, os.O_RDONLY | os.O_CLOEXEC)   # won't block: writer open
        log_fd = os.open(sess.log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o644)
        pid = os.fork()
        if pid == 0:  # child
            try:
                os.dup2(stdin_fd, 0)
                os.dup2(log_fd, 1)
                os.dup2(log_fd, 2)
                os.execv(self.cgroup_exec,
                         [self.cgroup_exec, os.path.join(sess.cgroup_path, "cgroup.procs"),
                          "bash", "--norc"])
            except Exception:  # noqa: BLE001 — child must not return
                os._exit(127)
        os.close(stdin_fd)
        os.close(log_fd)

        sess.live_pid = pid
        time.sleep(0.5)
        if self._proc_state(pid) is None:
            raise RuntimeError("bash failed to start in cgroup")

        self.sessions[sid] = sess
        self._log(f"session {sid}: bash live (pid {pid}) in cgroup {sess.cgroup_id}")
        return sid

    def close_session(self, sid):
        sess = self.sessions.pop(sid, None)
        if not sess:
            return
        # Kill everything left in the cgroup (live shell, any candidate/baseline).
        try:
            with open(os.path.join(sess.cgroup_path, "cgroup.procs")) as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln.isdigit():
                        try:
                            os.kill(int(ln), 9)
                        except OSError:
                            pass
                        self._reap(int(ln))
        except OSError:
            pass
        if sess.fifo_wfd is not None:
            try:
                os.close(sess.fifo_wfd)
            except OSError:
                pass
        # Release the eBPF cgroup slot so the daemon can reclaim it. Without this
        # every session permanently consumes one of the 64 cgroup_map slots.
        try:
            self.client.call("remove_cgroup", cgroup_path=sess.cgroup_path)
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass
        for p in (sess.fifo_path, sess.log_path):
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(sess.cgroup_path)
        except OSError:
            pass
        self._log(f"session {sid}: closed")

    # ---- command execution -------------------------------------------------
    def run(self, sid, command, timeout=10.0):
        """Feed one command to the current live shell and return its stdout.

        Works both between epochs (on the committed shell) and inside an epoch
        (on the speculative candidate) — the caller doesn't need to care which.

        Output is commit-gated: the speculating agent still receives this
        command's stdout directly (it needs the candidate's result to decide
        what to do next), but the externally-releasable transcript is only
        updated when the output is canonical. Output produced INSIDE an epoch is
        held in the epoch buffer and released to the committed transcript on
        commit / discarded on reject; output produced outside an epoch is
        committed immediately. See get_output().
        """
        sess = self.sessions[sid]
        sentinel = f"__SHADOW_DONE_{next(self._sentinel_ids)}__"
        n0 = len(self._loglines(sess))
        self._feed(sess, command)
        self._feed(sess, f"echo {sentinel}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            lines = self._loglines(sess)
            if sentinel in lines[n0:]:
                idx = lines.index(sentinel, n0)
                out = "\n".join(lines[n0:idx])
                if sess.epoch is not None:
                    sess.epoch_buffer.append(out)   # speculative: hold pending commit
                else:
                    sess.committed_output.append(out)  # canonical: release now
                return out
            time.sleep(0.05)
        raise TimeoutError(f"command timed out: {command!r}")

    def get_output(self, sid):
        """Return the session's COMMITTED transcript (commit-gated).

        This is the only output safe to release externally: it contains output
        from committed epochs and non-speculative commands, but NEVER output
        from an epoch that is still in flight or was rejected. It mirrors the
        orchestrator's commit-gated output buffer, applied per speculative epoch.
        """
        sess = self.sessions[sid]
        return "\n".join(sess.committed_output)

    # ---- speculative epoch -------------------------------------------------
    def begin_epoch(self, sid, retries=3):
        """Freeze the live shell as baseline and fork+resume a speculative
        candidate. After this returns, run()/commit()/reject() act on the epoch.
        """
        sess = self.sessions[sid]
        if sess.epoch is not None:
            raise RuntimeError("an epoch is already active for this session")

        last_err = None
        for attempt in range(1, retries + 1):
            try:
                # Freeze the live shell at its idle read() boundary.
                self.client.call("freeze_by_cgroup", cgroup_id=sess.cgroup_id)
                if not self._wait_state_T(sess.live_pid):
                    raise RuntimeError("live shell never reached stopped state")
                time.sleep(0.15)
                # Freeze original as baseline; fork the speculative candidate.
                resp = self.client.call("begin_speculative", pid=sess.live_pid)
                pids = resp.get("pids") or []
                if not pids:
                    raise RuntimeError("begin_speculative returned no candidate pid")
                candidate = pids[0]
                baseline = sess.live_pid
                # Resume the candidate — it becomes the live shell.
                self.client.call("resume_pid", pid=candidate)
                time.sleep(0.3)
                sess.epoch = {"baseline": baseline, "candidate": candidate}
                sess.live_pid = candidate
                self._log(f"session {sid}: epoch begun — baseline(frozen)={baseline} "
                          f"candidate(live)={candidate}")
                return
            except (RuntimeError, TimeoutError) as e:
                last_err = e
                self._log(f"session {sid}: begin_epoch attempt {attempt} failed: {e}")
                time.sleep(0.3)
        raise RuntimeError(f"begin_epoch failed after {retries} attempts: {last_err}")

    def commit(self, sid):
        """Accept the candidate as canonical; discard the frozen baseline."""
        sess = self.sessions[sid]
        if sess.epoch is None:
            raise RuntimeError("no active epoch to commit")
        candidate = sess.epoch["candidate"]
        baseline = sess.epoch["baseline"]
        # Quiesce the candidate to a stopped read()-boundary first (the proven
        # commit flow acts on a frozen candidate, then continues it).
        self._quiesce_epoch(sess)
        self.client.call("commit_pid", pid=candidate)
        self._reap(baseline)
        # The candidate is still frozen at its boundary — resume it as canonical.
        self.client.call("continue_pid", pid=candidate)
        sess.live_pid = candidate            # unchanged: candidate stays live
        sess.epoch = None
        # Release the speculative transcript: the epoch's output is now canonical.
        sess.committed_output.extend(sess.epoch_buffer)
        sess.epoch_buffer = []
        time.sleep(0.2)                      # let it settle back into read()
        self._log(f"session {sid}: COMMIT — candidate {candidate} is now canonical "
                  f"(baseline {baseline} discarded)")

    def reject(self, sid):
        """Discard the candidate; resume the pristine baseline (lossless)."""
        sess = self.sessions[sid]
        if sess.epoch is None:
            raise RuntimeError("no active epoch to reject")
        candidate = sess.epoch["candidate"]
        baseline = sess.epoch["baseline"]
        # Quiesce the candidate to a stopped read()-boundary first: this mirrors
        # the proven rollback flow (the candidate is frozen before it is
        # discarded), and avoids killing it while it is actively blocked in the
        # pipe read() it shares (COW) with the baseline.
        self._quiesce_epoch(sess)
        resp = self.client.call("reject_pid", pid=baseline)
        self._reap(candidate)
        # pids[0] is the canonical pid from now on (the resumed baseline).
        pids = resp.get("pids") or [baseline]
        sess.live_pid = pids[0]
        sess.epoch = None
        # Discard the speculative transcript: from the baseline's point of view
        # the epoch never happened, so its output is never released.
        sess.epoch_buffer = []
        time.sleep(0.2)                      # let the baseline settle back into read()
        self._log(f"session {sid}: REJECT — discarded candidate {candidate}, "
                  f"resumed pristine baseline {sess.live_pid}")

    def _quiesce_epoch(self, sess):
        """Bring the speculative candidate to a stopped read()-boundary (state T).

        Both the proven reject (Scenario 8) and commit (Scenario 12) flows make
        the commit/reject decision on a *stopped* candidate. freeze_by_cgroup
        stops the candidate (and skips the frozen baseline, which is a tracked
        versioning baseline).
        """
        candidate = sess.epoch["candidate"]
        try:
            self.client.call("freeze_by_cgroup", cgroup_id=sess.cgroup_id)
        except RuntimeError:
            pass
        if not self._wait_state_T(candidate, timeout=3.0):
            # Fallback: stop the candidate directly.
            try:
                os.kill(candidate, signal.SIGSTOP)
            except OSError:
                pass
            self._wait_state_T(candidate, timeout=1.0)
        time.sleep(0.1)


# ──────────────────────────── Self-contained demo ──────────────────────────
def _demo(proxy):
    """Prove the session_id abstraction: the agent mutates state speculatively,
    then either COMMITs (state persists) or REJECTs (state is losslessly
    restored) — all without ever touching a pid.
    """
    ok = True
    sid = proxy.open_session()
    try:
        proxy.run(sid, "export SHADOW_VAR=ORIGINAL")
        base = proxy.run(sid, "echo VAL=$SHADOW_VAR")
        print(f"  baseline state:        {base}")

        # ── Epoch 1: speculative mutation → REJECT (expect lossless rollback) ──
        print("\n  ── Epoch 1: mutate speculatively, then REJECT ──")
        proxy.begin_epoch(sid)
        proxy.run(sid, "export SHADOW_VAR=MODIFIED_BY_AGENT")
        in_epoch = proxy.run(sid, "echo VAL=$SHADOW_VAR")
        print(f"  inside epoch (candidate): {in_epoch}")
        proxy.reject(sid)
        after_reject = proxy.run(sid, "echo VAL=$SHADOW_VAR")
        print(f"  after REJECT:          {after_reject}")
        ok &= (in_epoch.strip() == "VAL=MODIFIED_BY_AGENT"
               and after_reject.strip() == "VAL=ORIGINAL")

        # ── Epoch 2: speculative mutation → COMMIT (expect state persists) ──
        print("\n  ── Epoch 2: mutate speculatively, then COMMIT ──")
        proxy.begin_epoch(sid)
        proxy.run(sid, "export SHADOW_VAR=COMMITTED_VALUE")
        proxy.commit(sid)
        after_commit = proxy.run(sid, "echo VAL=$SHADOW_VAR")
        print(f"  after COMMIT:          {after_commit}")
        ok &= (after_commit.strip() == "VAL=COMMITTED_VALUE")

        # ── Commit-gated output: the released transcript must contain the
        #    COMMITTED epoch's output but NEVER the REJECTED epoch's output ──
        transcript = proxy.get_output(sid)
        gate_ok = ("MODIFIED_BY_AGENT" not in transcript
                   and "VAL=COMMITTED_VALUE" in transcript)
        print(f"\n  committed transcript gate: "
              f"{'OK' if gate_ok else 'FAILED'} "
              f"(rejected output absent, committed output present)")
        ok &= gate_ok

        print()
        if ok:
            print("  \033[1;32m✓ SESSION PROXY OK: reject was lossless, commit persisted "
                  "— agent used only session_id\033[0m")
        else:
            print("  \033[1;31m✗ SESSION PROXY CHECK FAILED\033[0m")
    finally:
        proxy.close_session(sid)
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="ShadowProc Session Proxy")
    ap.add_argument("--sock", required=True, help="ShadowProc Unix socket path")
    ap.add_argument("--cgroup-root", default="/sys/fs/cgroup")
    ap.add_argument("--cgroup-exec", default=None,
                    help="path to cgroup_exec helper (default: demo/test_programs/cgroup_exec)")
    ap.add_argument("--demo", action="store_true", help="run the built-in commit/reject demo")
    args = ap.parse_args(argv)

    proxy = SessionProxy(args.sock, cgroup_root=args.cgroup_root,
                         cgroup_exec=args.cgroup_exec)
    if args.demo:
        return _demo(proxy)
    ap.error("nothing to do: pass --demo (this module is primarily a library)")


if __name__ == "__main__":
    sys.exit(main())
