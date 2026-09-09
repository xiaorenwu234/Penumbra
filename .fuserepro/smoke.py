#!/usr/bin/env python3
"""Smoke test: can we mount ShadowFS unprivileged inside this sandbox and do
one full begin -> write -> read -> rollback round trip through it?

Everything lives under the workspace: /tmp is root-owned 0700 here, and the
sandbox only permits writes inside the workspace.
"""
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MNT = os.path.join(HERE, "mnt")
ORIG = os.path.join(HERE, "orig")
STAGING = os.path.join(HERE, "staging")
SOCK = os.path.join(HERE, "sf.sock")
LOG = os.path.join(HERE, "sf.log")
BIN = os.path.join(HERE, "shadowfs")


def own_cgroup():
    """The cgroup v2 path of this process, in the form ShadowFS compares."""
    with open("/proc/self/cgroup") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) == 3 and parts[0] == "0":
                return parts[2]
    return ""


def mounted():
    with open("/proc/mounts") as f:
        return any(MNT in line for line in f)


def rpc(conn, **req):
    conn.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = conn.recv(65536)
        if not chunk:
            raise RuntimeError(f"socket closed, partial={buf!r}")
        buf += chunk
    return json.loads(buf.decode())


def main():
    print(f"[smoke] own cgroup: {own_cgroup()!r}")

    for p in (SOCK, LOG):
        if os.path.exists(p):
            os.remove(p)

    proc = subprocess.Popen(
        [BIN, "-staging", STAGING, "-sock", SOCK, MNT, ORIG],
        stdout=open(LOG, "ab"), stderr=subprocess.STDOUT,
    )
    print(f"[smoke] shadowfs pid={proc.pid}")

    try:
        for _ in range(100):
            if mounted() and os.path.exists(SOCK):
                break
            if proc.poll() is not None:
                print(f"[smoke] FAILED: daemon exited rc={proc.returncode}")
                print(open(LOG, errors="replace").read()[-3000:])
                return 1
            time.sleep(0.1)
        else:
            print(f"[smoke] FAILED: mount never appeared")
            print(open(LOG, errors="replace").read()[-3000:])
            return 1

        print(f"[smoke] mount OK, socket OK")

        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(SOCK)
        conn.settimeout(20)

        # FUSE attribution works by matching the caller's cgroup against the
        # cgroup_id registered here, so it has to be OUR real cgroup.
        cg = own_cgroup()
        print(f"[smoke] using cgroup_id={cg!r}")

        r = rpc(conn, action="begin_epoch", epoch_id="ep-smoke-1",
                cgroup_id=cg, session_id="smoke")
        print(f"[smoke] begin_epoch -> {r}")
        assert r.get("status") == "ok", r

        # Only NOW is the mount usable: an unattributed caller gets EIO by
        # design (fail-closed), so any FUSE access before begin_epoch fails.
        print(f"[smoke] ls mnt -> {sorted(os.listdir(MNT))}")

        # A write through the mount, attributed to ep-smoke-1 via our cgroup.
        t0 = time.monotonic()
        with open(os.path.join(MNT, "ind_0.dat"), "w") as f:
            f.write("speculative payload\n")
        print(f"[smoke] fuse write OK in {(time.monotonic()-t0)*1e3:.2f}ms")

        t0 = time.monotonic()
        with open(os.path.join(MNT, "shared.dat")) as f:
            data = f.read()
        print(f"[smoke] fuse read OK in {(time.monotonic()-t0)*1e3:.2f}ms "
              f"-> {data!r}")

        r = rpc(conn, action="graph_stats")
        print(f"[smoke] graph_stats -> {json.dumps(r)[:300]}")

        t0 = time.monotonic()
        r = rpc(conn, action="rollback_epoch", epoch_id="ep-smoke-1")
        print(f"[smoke] rollback -> {r} in {(time.monotonic()-t0)*1e3:.2f}ms")
        assert r.get("status") == "ok", r

        with open(os.path.join(MNT, "ind_0.dat")) as f:
            after = f.read()
        print(f"[smoke] after rollback ind_0.dat -> {after!r} "
              f"(expect the base content back)")
        conn.close()
        print("[smoke] PASS")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
        print(f"[smoke] cleaned up, daemon rc={proc.returncode}")
        if mounted():
            print("[smoke] WARNING: still mounted")


if __name__ == "__main__":
    sys.exit(main())
