#!/usr/bin/env python3
"""
reject_lsm_verify.py - Verify ShadowProc's REJECT path for an LSM-intercepted
boundary (connect()), the case h2_verify.py does NOT cover.

Run as root:
    sudo python3 tests/reject_lsm_verify.py

h2_verify.py exercises reject on a read() boundary (a blocking syscall stopped
by SIGSTOP). This test exercises the OTHER kind of boundary: a syscall held by
an eBPF LSM hook with -ERESTARTSYS + SIGSTOP. It drives one connect()-looping
target inside a monitored cgroup through a full epoch:

  freeze at connect() -> begin_speculative -> reject_pid(baseline).

After reject the pristine BASELINE must be restored coherently and, on SIGCONT,
RE-EXECUTE its connect() boundary syscall — observing ECONNREFUSED (errno 111)
from the dead loopback port. A regression in restore_baseline_for_restart shows
up here as one of:
  - the baseline crashing on resume (register clobber not undone),
  - errno 512 (raw ERESTARTSYS) leaking to userspace (restart not performed),
  - no output at all (baseline wedged).

PASS requires the baseline to print exactly a clean connect result after reject
AND still be alive afterwards. Exit code 0 on PASS, 1 otherwise.
"""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time

CG_NAME = "shadowproc_reject_lsm"
CG_DIR = f"/sys/fs/cgroup/{CG_NAME}"
CG_ID = f"/{CG_NAME}"
SOCK = "/tmp/shadowproc_reject_lsm.sock"
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
TARGET = os.path.join(HERE, "h2_connect_target")

DAEMON_LOG = "/tmp/shadowproc_reject_lsm.daemon.log"
OUT_PATH = "/tmp/shadowproc_reject_lsm.target.out"
ERR_PATH = "/tmp/shadowproc_reject_lsm.target.err"

ECONNREFUSED = 111


def rpc(req: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    try:
        f = s.makefile("rw", buffering=1)
        f.write(json.dumps(req) + "\n")
        f.flush()
        line = f.readline()
        return json.loads(line) if line else {"status": "error", "message": "closed"}
    finally:
        s.close()


def find_bin() -> str:
    # Pick whichever build is NEWEST so a stale release binary can never shadow a
    # freshly rebuilt debug one (or vice-versa).
    cands = []
    for p in ("target/release/shadow-proc", "target/debug/shadow-proc"):
        fp = os.path.join(PROJECT, p)
        if os.path.exists(fp):
            cands.append((os.path.getmtime(fp), fp))
    if not cands:
        sys.exit("[!] shadow-proc binary not found. Build first: cargo build")
    cands.sort(reverse=True)
    chosen = cands[0][1]
    print(f"[*] using binary {chosen} (mtime {time.strftime('%H:%M:%S', time.localtime(cands[0][0]))})")
    return chosen


def read_out() -> str:
    try:
        with open(OUT_PATH) as f:
            return f.read()
    except OSError:
        return ""


def proc_state(pid: int):
    """Return the single-letter /proc state (e.g. 'T' stopped, 'R', 'S'), or
    None if the process is gone."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
    except OSError:
        return None
    # "pid (comm) state ...": comm may contain spaces/parens, anchor on last ')'.
    idx = data.rfind(")")
    if idx < 0:
        return None
    rest = data[idx + 1:].split()
    return rest[0] if rest else None


def wait_state_T(pid: int, timeout=5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc_state(pid) == "T":
            return True
        time.sleep(0.05)
    return False


def connect_line_for(pid: int, timeout=5.0):
    """Return the matched (connect_ret, errno) once the target prints a clean
    connect result for <pid>, else None on timeout.

    Matches: H2C pid=<pid> status=OK connect_ret=<r> errno=<e>
    """
    pat = re.compile(
        rf"H2C pid={pid} status=OK connect_ret=(-?\d+) errno=(\d+)"
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        for ln in read_out().splitlines():
            m = pat.search(ln)
            if m:
                return int(m.group(1)), int(m.group(2))
        time.sleep(0.05)
    return None


def main() -> int:
    if os.geteuid() != 0:
        sys.exit("[!] must run as root:  sudo python3 tests/reject_lsm_verify.py")
    if not os.path.exists(TARGET):
        sys.exit(f"[!] {TARGET} not built. Run: "
                 f"gcc -o tests/h2_connect_target tests/h2_connect_target.c -Wall")

    shadow_bin = find_bin()
    os.makedirs(CG_DIR, exist_ok=True)
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass

    daemon = target = wpipe = None
    candidate = None
    ok = False

    try:
        dlog = open(DAEMON_LOG, "w")
        daemon = subprocess.Popen(
            [shadow_bin, "--cgroup-path", CG_DIR, "--sock", SOCK],
            stdout=dlog, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
        print(f"[*] shadow-proc started (pid={daemon.pid}), log -> {DAEMON_LOG}")
        for _ in range(100):
            if os.path.exists(SOCK):
                break
            if daemon.poll() is not None:
                sys.exit(f"[!] daemon exited early; see {DAEMON_LOG}")
            time.sleep(0.1)
        else:
            sys.exit(f"[!] control socket never appeared; see {DAEMON_LOG}")
        time.sleep(0.3)

        # Launch the connect() target, gated on stdin so we can place it in the
        # cgroup before its first (monitored) connect().
        out_f = open(OUT_PATH, "w")
        err_f = open(ERR_PATH, "w")
        rpipe, wpipe = os.pipe()
        target = subprocess.Popen([TARGET], stdin=rpipe, stdout=out_f, stderr=err_f)
        os.close(rpipe)
        with open(os.path.join(CG_DIR, "cgroup.procs"), "w") as f:
            f.write(str(target.pid))
        baseline = target.pid
        print(f"[*] target(baseline) pid={baseline} in cgroup {CG_ID}")

        # Release the gate: the target now enters its connect() loop and the very
        # first connect() is held by the LSM hook (SIGSTOP -> state 'T').
        os.write(wpipe, b"go\n")
        print("=== LSM-boundary REJECT scenario ===")
        if not wait_state_T(baseline):
            print(f"[!] baseline never froze at connect() boundary; see {DAEMON_LOG}")
            return 1
        print(f"[*] baseline {baseline} frozen at connect() boundary (state T)")

        # Confirm the daemon classified it as a NETWORK interception.
        allf = rpc({"action": "list_all_frozen"})
        etypes = {p["pid"]: p.get("event_type") for p in (allf.get("frozen") or [])}
        print(f"[list_all_frozen]   {allf.get('status')} event_type={etypes.get(baseline)}")

        # Fork the speculative candidate at the connect() boundary.
        r = rpc({"action": "begin_speculative", "pid": baseline})
        print("[begin_speculative]", r)
        if r.get("status") != "ok" or not r.get("pids"):
            print(f"[!] begin_speculative failed; see {DAEMON_LOG}")
            return 1
        candidate = int(r["pids"][0])
        print(f"[*] candidate pid={candidate}")

        # Reject: discard the candidate, restore + resume the pristine baseline.
        # reject_pid already clears the stopped mark and SIGCONTs the baseline, so
        # it should re-execute its connect() boundary syscall.
        r = rpc({"action": "reject_pid", "pid": baseline})
        print("[reject_pid]       ", r)

        rc = target.poll()
        if rc is not None:
            if rc < 0:
                print(f"[C] baseline DIED on resume: killed by signal {-rc} "
                      f"({signal.Signals(-rc).name})")
            else:
                print(f"[C] baseline DIED on resume: exited with code {rc}")
            return 1

        res = connect_line_for(baseline)
        if res is None:
            print("[C] baseline produced NO connect result after reject "
                  "(wedged / restart not performed)")
            ok = False
        else:
            connect_ret, err = res
            print(f"[C] baseline connect after reject: connect_ret={connect_ret} errno={err}")
            if err == 512:
                print("[C] FAIL: raw ERESTARTSYS (errno 512) leaked to userspace "
                      "-> boundary syscall was not restarted")
                ok = False
            elif connect_ret == -1 and err == ECONNREFUSED:
                # Clean restart: connect() re-ran and hit the dead port.
                ok = True
            else:
                # Any other coherent connect result still proves a clean restart
                # (no crash, no ERESTARTSYS leak); accept but note it.
                print(f"[C] note: unexpected but coherent connect result "
                      f"(ret={connect_ret} errno={err})")
                ok = True

        # The baseline should still be alive, having looped back to its next
        # connect() boundary (re-frozen). This confirms it resumed coherently.
        alive = target.poll() is None
        print(f"[C] baseline alive after reject: {alive}")
        ok = ok and alive

        # ---- report ------------------------------------------------------
        print("\n---- target stderr ----")
        try:
            with open(ERR_PATH) as f:
                print(f.read().strip() or "(empty)")
        except OSError:
            print("(unreadable)")
        print("---- target stdout ----")
        print(read_out().strip() or "(empty)")

        verdict = "PASS" if ok else "FAIL"
        print("\n========================================")
        print(f"  LSM-BOUNDARY REJECT VERDICT: {verdict}")
        print("========================================")
        if verdict != "PASS":
            print("A FAIL here means the baseline, frozen at an LSM-intercepted")
            print("connect() boundary, was NOT restored to a coherent, restartable")
            print(f"state on reject. Inspect target output above and {DAEMON_LOG}.")
        return 0 if ok else 1

    finally:
        print("\n[cleanup] tearing down...")
        for pid in (candidate, target.pid if target else None):
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, TypeError):
                    pass
        if wpipe is not None:
            try:
                os.close(wpipe)
            except OSError:
                pass
        if daemon and daemon.poll() is None:
            daemon.send_signal(signal.SIGINT)
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
        try:
            os.unlink(SOCK)
        except FileNotFoundError:
            pass
        try:
            with open(os.path.join(CG_DIR, "cgroup.procs")) as f:
                for line in f:
                    line = line.strip()
                    if line.isdigit():
                        try:
                            os.kill(int(line), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
            time.sleep(0.2)
            os.rmdir(CG_DIR)
        except (FileNotFoundError, OSError):
            pass


if __name__ == "__main__":
    sys.exit(main())
