#!/usr/bin/env python3
"""Drive a real ShadowFS daemon the way the RQ3 rollback phase does, and catch
the wedge.

Shape being reproduced: one epoch writes an object, a second epoch reads it
while the first is still open (which is the only way ShadowFS records a
read-from edge), then the producer is rolled back so the rollback cascades
through the graph -- while other threads keep beginning and undoing epochs and
the checkpoint ticker keeps firing.

On a wedge the daemon is sent SIGQUIT, which makes the Go runtime dump every
goroutine stack to the log. That dump is the point of this script: it names the
exact line the daemon is stuck on instead of leaving us to reason about it.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MNT = os.path.join(HERE, "mnt")
ORIG = os.path.join(HERE, "orig")
STAGING = os.path.join(HERE, "staging")
SOCK = os.path.join(HERE, "sf.sock")
LOG = os.path.join(HERE, "sf.log")
BIN = os.path.join(HERE, "shadowfs")
DUMP = os.path.join(HERE, "wedge.txt")

ROUNDS = int(os.environ.get("ROUNDS", "40"))
CHURN = int(os.environ.get("CHURN", "4"))       # background begin/rollback threads
STALL_S = float(os.environ.get("STALL_S", "20"))  # no log growth => wedged


def own_cgroup():
    with open("/proc/self/cgroup") as f:
        for line in f:
            p = line.strip().split(":")
            if len(p) == 3 and p[0] == "0":
                return p[2]
    return ""


def mounted():
    with open("/proc/mounts") as f:
        return any(MNT in line for line in f)


class Conn:
    """One socket connection. RPCs are synchronous, so one per thread."""

    def __init__(self, timeout=STALL_S + 10):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(SOCK)
        self.s.settimeout(timeout)
        self.buf = b""

    def rpc(self, **req):
        self.s.sendall((json.dumps(req) + "\n").encode())
        while not self.buf.endswith(b"\n"):
            chunk = self.s.recv(65536)
            if not chunk:
                raise RuntimeError("socket closed by daemon")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line.decode())

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class Watchdog(threading.Thread):
    """Declare a wedge when the daemon stops logging while work is pending."""

    daemon = True

    def __init__(self, pid):
        super().__init__()
        self.pid = pid
        self.wedged = threading.Event()
        self.stop = threading.Event()
        self.last_size = -1
        self.last_change = time.monotonic()

    def run(self):
        while not self.stop.is_set():
            time.sleep(1)
            try:
                size = os.path.getsize(LOG)
            except OSError:
                continue
            if size != self.last_size:
                self.last_size = size
                self.last_change = time.monotonic()
            elif time.monotonic() - self.last_change > STALL_S:
                self.wedged.set()
                self.capture()
                return

    def capture(self):
        with open(DUMP, "w") as out:
            out.write(f"# watchdog: no log growth for {STALL_S}s, "
                      f"sending SIGQUIT to {self.pid}\n")
            out.flush()
            try:
                os.kill(self.pid, signal.SIGQUIT)
            except OSError as e:
                out.write(f"# kill failed: {e}\n")
            time.sleep(3)
            try:
                out.write(open(LOG, errors="replace").read())
            except OSError as e:
                out.write(f"# log read failed: {e}\n")
        print(f"[driver] WEDGE DETECTED -- goroutine dump in {DUMP}")


def fuse_write(rel, payload):
    with open(os.path.join(MNT, rel), "w") as f:
        f.write(payload)


def fuse_read(rel):
    try:
        with open(os.path.join(MNT, rel)) as f:
            return f.read()
    except OSError as e:
        return f"<{e.errno}>"


def churn_worker(idx, wd, errors):
    """Background pressure: begin and undo epochs, and stat the mount."""
    c = Conn()
    try:
        k = 0
        while not wd.wedged.is_set() and k < ROUNDS * 6:
            k += 1
            ep = f"ep-churn-{idx}-{k}"
            try:
                c.rpc(action="begin_epoch", epoch_id=ep,
                      cgroup_id=f"/churn-{idx}-{k}", session_id=f"churn{idx}")
                c.rpc(action="rollback_epoch", epoch_id=ep)
                c.rpc(action="graph_stats")
            except Exception as e:  # noqa: BLE001
                errors.append(f"churn{idx} k{k}: {e}")
                return
    finally:
        c.close()


def main():
    for p in (SOCK, LOG, DUMP):
        if os.path.exists(p):
            os.remove(p)

    cg = own_cgroup()
    proc = subprocess.Popen([BIN, "-staging", STAGING, "-sock", SOCK, MNT, ORIG],
                            stdout=open(LOG, "ab"), stderr=subprocess.STDOUT)
    print(f"[driver] shadowfs pid={proc.pid} cgroup={cg}")
    try:
        for _ in range(100):
            if mounted() and os.path.exists(SOCK):
                break
            if proc.poll() is not None:
                print(f"[driver] daemon died rc={proc.returncode}")
                print(open(LOG, errors="replace").read()[-2000:])
                return 1
            time.sleep(0.1)
        else:
            print("[driver] mount never appeared")
            return 1

        wd = Watchdog(proc.pid)
        wd.start()
        errors = []
        threads = [threading.Thread(target=churn_worker, args=(i, wd, errors),
                                    daemon=True) for i in range(CHURN)]
        for t in threads:
            t.start()

        c = Conn()
        t_start = time.monotonic()
        for r in range(ROUNDS):
            if wd.wedged.is_set():
                break
            producer = f"ep-prod-{r}"
            reader = f"ep-read-{r}"
            obj = f"obj_{r % 5}.dat"

            # Producer writes the object and stays OPEN.
            c.rpc(action="begin_epoch", epoch_id=producer, cgroup_id=cg,
                  session_id=f"s-prod-{r}")
            fuse_write(obj, f"producer {r}\n")

            # Reader is bound to the same cgroup now, so its read resolves to
            # the producer's still-live version and records a read-from edge.
            c.rpc(action="begin_epoch", epoch_id=reader, cgroup_id=cg,
                  session_id=f"s-read-{r}")
            got = fuse_read(obj)

            st = c.rpc(action="graph_stats", reset=False)
            g = st.get("graph", {})
            if r % 5 == 0:
                print(f"[driver] r={r} read={got!r} epochs={g.get('epochs')} "
                      f"edges={g.get('edges')} goroutines={g.get('goroutines')} "
                      f"elapsed={time.monotonic()-t_start:.1f}s")

            # Rolling back the producer must cascade into the reader.
            resp = c.rpc(action="rollback_epoch", epoch_id=producer)
            aff = resp.get("affected_epochs") or []
            if reader not in aff:
                errors.append(f"r={r}: cascade missed the reader: {resp}")
            # Undo the reader too so the graph does not grow without bound.
            c.rpc(action="rollback_epoch", epoch_id=reader)

        wd.stop.set()
        for t in threads:
            t.join(timeout=5)
        c.close()

        print(f"[driver] finished ROUNDS={ROUNDS} in "
              f"{time.monotonic()-t_start:.1f}s wedged={wd.wedged.is_set()}")
        if errors:
            print(f"[driver] {len(errors)} error(s), first 5:")
            for e in errors[:5]:
                print(f"    {e}")
        return 2 if wd.wedged.is_set() else (1 if errors else 0)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
        print(f"[driver] cleaned up rc={proc.returncode} mounted={mounted()}")


if __name__ == "__main__":
    sys.exit(main())
