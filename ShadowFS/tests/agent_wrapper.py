#!/usr/bin/env python3
"""Wrapper script executed inside an agent's cgroup via systemd-run.

Usage: python3 agent_wrapper.py <json_actions_file>
   or: echo '<json_actions>' | python3 agent_wrapper.py -

Actions format (JSON array):
  [{"op":"write","path":"/mnt/f.txt","content":"hello"},
   {"op":"read","path":"/mnt/f.txt"},
   {"op":"unlink","path":"/mnt/f.txt"},
   {"op":"mkdir","path":"/mnt/d"},
   {"op":"rmdir","path":"/mnt/d"},
   {"op":"rename","src":"/mnt/a","dst":"/mnt/b"},
   {"op":"list","path":"/mnt"},
   {"op":"exists","path":"/mnt/f.txt"},
   {"op":"open_w","path":"/mnt/f.txt","content":"data"},
   {"op":"stat","path":"/mnt/f.txt"},
   {"op":"rmtree","path":"/mnt/dir"},
   {"op":"noop"}]
"""
import sys, os, json, errno, shutil, time, fcntl, stat as statmod

def run_actions(actions):
    results = []
    for a in actions:
        op = a["op"]
        try:
            if op == "write":
                with open(a["path"], "w") as f:
                    f.write(a.get("content", ""))
                results.append({"op": op, "ok": True})
            elif op == "append":
                with open(a["path"], "a") as f:
                    f.write(a.get("content", ""))
                results.append({"op": op, "ok": True})
            elif op == "truncate":
                # truncate to a given size (creates if missing? require existing)
                with open(a["path"], "r+b") as f:
                    f.truncate(int(a.get("size", 0)))
                results.append({"op": op, "ok": True})
            elif op == "chmod":
                os.chmod(a["path"], int(a["mode"]))
                results.append({"op": op, "ok": True})
            elif op == "sleep":
                time.sleep(float(a.get("seconds", 0.0)))
                results.append({"op": op, "ok": True})
            elif op == "open_w":
                # Explicit O_WRONLY open + write + close
                fd = os.open(a["path"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
                os.write(fd, a.get("content", "").encode())
                os.close(fd)
                results.append({"op": op, "ok": True})
            elif op == "read":
                with open(a["path"], "r") as f:
                    results.append({"op": op, "ok": True, "content": f.read()})
            elif op == "read_bytes":
                with open(a["path"], "rb") as f:
                    results.append({"op": op, "ok": True, "content": f.read().decode("utf-8", errors="replace")})
            elif op == "unlink":
                os.unlink(a["path"])
                results.append({"op": op, "ok": True})
            elif op == "mkdir":
                os.mkdir(a["path"], a.get("mode", 0o755))
                results.append({"op": op, "ok": True})
            elif op == "rmdir":
                os.rmdir(a["path"])
                results.append({"op": op, "ok": True})
            elif op == "rmtree":
                # Equivalent to rm -rf: recursively delete dir and all contents
                shutil.rmtree(a["path"])
                results.append({"op": op, "ok": True})
            elif op == "rename":
                os.rename(a["src"], a["dst"])
                results.append({"op": op, "ok": True})
            elif op == "list":
                entries = os.listdir(a["path"])
                results.append({"op": op, "ok": True, "entries": sorted(entries)})
            elif op == "exists":
                results.append({"op": op, "ok": True, "exists": os.path.exists(a["path"])})
            elif op == "stat":
                st = os.stat(a["path"])
                results.append({"op": op, "ok": True, "size": st.st_size, "mode": oct(st.st_mode)})
            elif op == "lstat":
                st = os.lstat(a["path"])
                results.append({"op": op, "ok": True, "size": st.st_size, "mode": oct(st.st_mode)})
            elif op == "symlink":
                # Create a symlink at `path` pointing to `target` (no resolution).
                os.symlink(a["target"], a["path"])
                results.append({"op": op, "ok": True})
            elif op == "link":
                # Hard link: create `path` pointing at the same inode as `target`.
                os.link(a["target"], a["path"])
                results.append({"op": op, "ok": True})
            elif op == "mknod":
                # Special file. `kind` is one of fifo/char/block; `mode` is the
                # permission bits; `dev` is the device number (char/block).
                kind = a.get("kind", "fifo")
                perm = int(a.get("mode", 0o644))
                if kind == "fifo":
                    os.mkfifo(a["path"], perm)
                else:
                    ifmt = statmod.S_IFCHR if kind == "char" else statmod.S_IFBLK
                    os.mknod(a["path"], perm | ifmt, int(a.get("dev", 0)))
                results.append({"op": op, "ok": True})
            elif op == "setxattr":
                os.setxattr(a["path"], a["name"], a.get("value", "").encode())
                results.append({"op": op, "ok": True})
            elif op == "getxattr":
                val = os.getxattr(a["path"], a["name"])
                results.append({"op": op, "ok": True, "value": val.decode("utf-8", errors="replace")})
            elif op == "listxattr":
                results.append({"op": op, "ok": True, "names": sorted(os.listxattr(a["path"]))})
            elif op == "removexattr":
                os.removexattr(a["path"], a["name"])
                results.append({"op": op, "ok": True})
            elif op == "flock":
                # Acquire an advisory lock, optionally hold it, then release.
                # `kind` is sh/ex; `nb` requests non-blocking (LOCK_NB).
                lk = fcntl.LOCK_EX if a.get("kind", "ex") == "ex" else fcntl.LOCK_SH
                if a.get("nb"):
                    lk |= fcntl.LOCK_NB
                fd = os.open(a["path"], os.O_RDWR | os.O_CREAT, 0o644)
                try:
                    fcntl.flock(fd, lk)
                    time.sleep(float(a.get("hold", 0.0)))
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    results.append({"op": op, "ok": True})
                finally:
                    os.close(fd)
            elif op == "readlink":
                results.append({"op": op, "ok": True, "target": os.readlink(a["path"])})
            elif op == "raw_write":
                # Write content via low-level fd; lets caller verify
                # specific open flags work end-to-end.
                flags = int(a.get("flags", os.O_WRONLY | os.O_CREAT | os.O_TRUNC))
                fd = os.open(a["path"], flags, int(a.get("mode", 0o644)))
                try:
                    os.write(fd, a.get("content", "").encode())
                finally:
                    os.close(fd)
                results.append({"op": op, "ok": True})
            elif op == "noop":
                results.append({"op": op, "ok": True})
            else:
                results.append({"op": op, "ok": False, "error": f"unknown op: {op}"})
        except OSError as e:
            results.append({"op": op, "ok": False, "errno": e.errno, "error": str(e)})
    return results

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    if src == "-":
        data = json.load(sys.stdin)
    else:
        with open(src) as f:
            data = json.load(f)
    results = run_actions(data)
    print(json.dumps(results))
