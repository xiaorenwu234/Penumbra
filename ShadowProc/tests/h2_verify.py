#!/usr/bin/env python3
"""
h2_verify.py - Automated verification of ShadowProc syscall-restart coherence
for BOTH sides of a speculative epoch.

Run as root:
    sudo python3 tests/h2_verify.py

It runs one looping boundary target (tests/h2_target) inside a monitored cgroup
and drives a full epoch through the daemon's control socket, checking two things
that the earlier candidate-only test missed:

  Scenario A - CANDIDATE restart:
      freeze -> begin_speculative -> resume candidate -> feed a line.
      The candidate (a fresh clone) must RESTART its read() and echo the line.

  Scenario B - BASELINE restart (the REJECT path):
      quiesce candidate -> reject_pid(baseline) -> feed a line.
      The pristine baseline, resumed from a job-control stop, must RESTART its
      read() and echo the line. This is the path that wedges if the baseline's
      interrupted syscall is not explicitly rewound after the clone injection.

PASS requires BOTH scenarios to succeed. Exit code 0 on PASS, 1 otherwise.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time

CG_NAME = "shadowproc_h2"
CG_DIR = f"/sys/fs/cgroup/{CG_NAME}"
CG_ID = f"/{CG_NAME}"
SOCK = "/tmp/shadowproc_h2.sock"
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
TARGET = os.path.join(HERE, "h2_target")

CAND_LINE = "CANDIDATE_EPOCH_LINE"
BASE_LINE = "BASELINE_REJECT_LINE"

DAEMON_LOG = "/tmp/shadowproc_h2.daemon.log"
OUT_PATH = "/tmp/shadowproc_h2.target.out"
ERR_PATH = "/tmp/shadowproc_h2.target.err"


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
    with open(OUT_PATH) as f:
        return f.read()


def line_ok(pid: int, line: str, timeout=4.0) -> bool:
    """True once a single stdout line reports pid=<pid> status=OK data=[<line>].
    Checked field-by-field so the intervening 'read_ret=N ' token cannot break
    the match."""
    deadline = time.time() + timeout
    needle_pid = f"pid={pid}"
    needle_data = f"data=[{line}]"
    while time.time() < deadline:
        for ln in read_out().splitlines():
            if needle_pid in ln and "status=OK" in ln and needle_data in ln:
                return True
        time.sleep(0.05)
    return False


def main() -> int:
    if os.geteuid() != 0:
        sys.exit("[!] must run as root:  sudo python3 tests/h2_verify.py")
    if not os.path.exists(TARGET):
        sys.exit(f"[!] {TARGET} not built. Run: gcc -o tests/h2_target tests/h2_target.c -Wall")

    shadow_bin = find_bin()
    os.makedirs(CG_DIR, exist_ok=True)
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass

    daemon = target = wpipe = None
    candidate = None
    a_ok = b_ok = False

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

        # launch the looping boundary target with a controlled stdin pipe
        out_f = open(OUT_PATH, "w")
        err_f = open(ERR_PATH, "w")
        rpipe, wpipe = os.pipe()
        target = subprocess.Popen([TARGET], stdin=rpipe, stdout=out_f, stderr=err_f)
        os.close(rpipe)
        with open(os.path.join(CG_DIR, "cgroup.procs"), "w") as f:
            f.write(str(target.pid))
        baseline = target.pid
        print(f"[*] target(baseline) pid={baseline} in cgroup {CG_ID}")
        time.sleep(0.6)

        # ---- Scenario A: candidate restart -------------------------------
        print("\n=== Scenario A: CANDIDATE restart ===")
        print("[freeze_by_cgroup] ", rpc({"action": "freeze_by_cgroup", "cgroup_id": CG_ID}))
        r = rpc({"action": "begin_speculative", "pid": baseline})
        print("[begin_speculative]", r)
        if r.get("status") != "ok" or not r.get("pids"):
            print(f"[!] begin_speculative failed; see {DAEMON_LOG}")
            return 1
        candidate = int(r["pids"][0])
        print(f"[*] candidate pid={candidate}")
        print("[resume candidate] ", rpc({"action": "resume_pid", "pid": candidate}))
        os.write(wpipe, (CAND_LINE + "\n").encode())
        a_ok = line_ok(candidate, CAND_LINE)
        print(f"[A] candidate restart: {'PASS' if a_ok else 'FAIL'}")

        # ---- Scenario B: baseline restart via REJECT ---------------------
        print("\n=== Scenario B: BASELINE restart (reject path) ===")
        # quiesce the candidate to a stopped boundary, then reject
        print("[freeze_by_cgroup] ", rpc({"action": "freeze_by_cgroup", "cgroup_id": CG_ID}))
        time.sleep(0.2)
        r = rpc({"action": "reject_pid", "pid": baseline})
        print("[reject_pid]       ", r)
        # reject_pid already SIGCONTs the baseline; check whether it survived
        # the resume before feeding it a line.
        rc = target.poll()
        if rc is not None:
            if rc < 0:
                print(f"[B] baseline DIED on resume: killed by signal {-rc} "
                      f"({signal.Signals(-rc).name})")
            else:
                print(f"[B] baseline DIED on resume: exited with code {rc}")
        else:
            print("[B] baseline alive after resume; feeding line")
        try:
            os.write(wpipe, (BASE_LINE + "\n").encode())
        except BrokenPipeError:
            print("[B] write failed: BrokenPipe (baseline read end already gone)")
        b_ok = line_ok(baseline, BASE_LINE)
        print(f"[B] baseline restart: {'PASS' if b_ok else 'FAIL'}")

        # ---- report ------------------------------------------------------
        print("\n---- target stderr ----")
        with open(ERR_PATH) as f:
            print(f.read().strip() or "(empty)")
        print("---- target stdout ----")
        print(read_out().strip() or "(empty)")

        verdict = "PASS" if (a_ok and b_ok) else "FAIL"
        print("\n========================================")
        print(f"  SYSCALL-RESTART VERDICT: {verdict}")
        print(f"    A candidate restart : {'PASS' if a_ok else 'FAIL'}")
        print(f"    B baseline restart  : {'PASS' if b_ok else 'FAIL'}")
        print("========================================")
        if verdict != "PASS":
            print("A FAIL here means the resumed process did NOT restart its boundary")
            print("read() (ERESTARTSYS / bad return leaked to userspace).")
            print(f"Inspect target stdout above and {DAEMON_LOG}.")
        return 0 if verdict == "PASS" else 1

    finally:
        print("\n[cleanup] tearing down...")
        for pid in (candidate, baseline if target else None):
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
