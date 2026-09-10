#!/usr/bin/env python3
"""Probe process management and synchronization for RQ2 experiments.

Handles spawning C probe programs inside monitored cgroups, synchronizing
their execution via pipes (the SHADOW_GO_FD protocol), and collecting their
results (ret/errno output).
"""

import os
import re
import select
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# Directory containing compiled probe binaries
PROBES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "probes", "bin")


@dataclass
class ProbeResult:
    """Result from a probe execution."""
    probe_name: str
    returncode: int
    ret: int  # syscall return value
    errno: int  # errno after syscall
    stdout: str
    stderr: str
    timed_out: bool = False
    was_fenced: bool = False
    duration_ms: float = 0.0
    pid: int = 0  # PID of the probe process

    @property
    def succeeded(self) -> bool:
        """Syscall succeeded (ret >= 0 or ret == 0 depending on syscall)."""
        return self.ret == 0 and self.errno == 0

    @property
    def denied(self) -> bool:
        """Syscall was denied with EPERM."""
        return self.errno == 1  # EPERM = 1

    @property
    def enosys(self) -> bool:
        """Syscall not implemented (io_uring blocked, etc.)."""
        return self.errno == 38  # ENOSYS = 38


class ProbeRunner:
    """Manages probe process lifecycle and synchronization.

    Protocol (two-step handshake; see WAIT_GO() in probes/common.h):
      1. Create two pipes: go (harness->probe) and ready (probe->harness)
      2. Spawn probe with SHADOW_GO_FD and SHADOW_READY_FD in environment
      3. Probe performs its setup, then writes one byte to SHADOW_READY_FD
      4. Harness reads that byte, and only NOW places the PID into the
         monitored cgroup
      5. Harness writes a byte to the go pipe to signal "go"
      6. Probe executes its syscall and prints "ret=N errno=M"
      7. Collect output and exit status

    The ordering of steps 3 and 4 is the whole point. Joining the cgroup
    before the probe has finished its setup makes "was this setup syscall
    governed by the policy under test?" depend on a race, which is exactly how
    out_splice came to pass on repeat 0 and fail on repeats 1..9.

    Both environment variables are optional, so callers that spawn probes
    themselves (exp5's fork storm, orchestrator/test_kernel_effect_decisions.py)
    keep working unchanged -- they simply do not take part in the handshake.
    """

    # Hang guard for the setup announcement, not a throttle: a probe only runs
    # a handful of syscalls before announcing.
    READY_TIMEOUT = 10.0

    def __init__(self, probes_dir: str = None, timeout: float = 3.0):
        self.probes_dir = probes_dir or PROBES_DIR
        self.timeout = timeout
        self._children: List[subprocess.Popen] = []

    def get_probe_path(self, probe_name: str) -> str:
        """Get the full path to a compiled probe binary."""
        path = os.path.join(self.probes_dir, probe_name)
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Probe binary not found: {path}\n"
                f"Run 'make' in {os.path.dirname(self.probes_dir)} first.")
        return path

    def probe_available(self, probe_name: str) -> bool:
        """Check if a probe binary exists."""
        return os.path.exists(os.path.join(self.probes_dir, probe_name))

    def spawn(self, probe_name: str, cgroup_path: str,
              env_extra: Dict[str, str] = None,
              args: List[str] = None) -> Tuple[subprocess.Popen, int]:
        """Spawn a probe and place it in the cgroup. Returns (process, go_write_fd).

        The probe performs its setup, announces completion on SHADOW_READY_FD,
        then blocks reading SHADOW_GO_FD until the caller writes a byte. The
        cgroup is joined only after that announcement -- see the class docstring.
        """
        probe_path = self.get_probe_path(probe_name)
        read_fd, write_fd = os.pipe()
        ready_r, ready_w = os.pipe()

        env = dict(os.environ)
        env["SHADOW_GO_FD"] = str(read_fd)
        env["SHADOW_READY_FD"] = str(ready_w)
        if env_extra:
            env.update(env_extra)

        cmd = [probe_path] + (args or [])
        proc = subprocess.Popen(
            cmd,
            pass_fds=(read_fd, ready_w),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        os.close(read_fd)
        os.close(ready_w)
        self._children.append(proc)

        state = self._await_ready(ready_r, proc)
        os.close(ready_r)

        if state == "exited":
            # The probe already reported and exited (a setup syscall failed and
            # it called REPORT). Its ret/errno are on the stdout pipe for
            # wait_result(); joining a dead PID would only raise.
            return proc, write_fd
        if state == "timeout":
            # Never hang a whole run on one probe: fall back to joining anyway,
            # but say so loudly, since this trial's setup is race-dependent.
            print(f"[runner] WARNING: {probe_name} did not announce setup "
                  f"completion within {self.READY_TIMEOUT}s; joining the "
                  f"cgroup anyway, so this trial is race-dependent",
                  file=sys.stderr)

        # Place into cgroup
        procs_file = os.path.join(cgroup_path, "cgroup.procs")
        try:
            with open(procs_file, "w") as f:
                f.write(str(proc.pid))
        except OSError as e:
            # Probe died between announcing and being joined.
            print(f"[runner] WARNING: cannot place {probe_name} (pid "
                  f"{proc.pid}) into {procs_file}: {e}", file=sys.stderr)

        return proc, write_fd

    def _await_ready(self, ready_r: int, proc: subprocess.Popen) -> str:
        """Wait for the probe's "setup done" byte.

        Returns "ready" on handshake, "exited" if the probe finished without
        announcing (its ret/errno are already on stdout), or "timeout" if it is
        still alive but silent past READY_TIMEOUT.
        """
        deadline = time.time() + self.READY_TIMEOUT
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return "timeout"
            readable, _, _ = select.select([ready_r], [], [],
                                           min(remaining, 0.2))
            if readable:
                try:
                    # An empty read means the probe closed the fd without
                    # writing, i.e. it exited during setup.
                    return "ready" if os.read(ready_r, 1) else "exited"
                except OSError:
                    return "exited"
            if proc.poll() is not None:
                return "exited"

    def release(self, write_fd: int):
        """Signal the probe to execute its syscall."""
        try:
            os.write(write_fd, b"x")
        except BrokenPipeError:
            # Probe died before we could signal it (e.g., crashed on startup)
            pass
        except OSError:
            pass
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass

    def wait_result(self, proc: subprocess.Popen, probe_name: str = "",
                    timeout: float = None) -> ProbeResult:
        """Wait for probe completion and parse its output."""
        timeout = timeout or self.timeout
        t0 = time.time()
        timed_out = False

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate(timeout=2)

        duration_ms = (time.time() - t0) * 1000

        # Parse "ret=N errno=M" from stdout
        ret, errno_val = self._parse_output(stdout)

        return ProbeResult(
            probe_name=probe_name,
            returncode=proc.returncode if proc.returncode is not None else -9,
            ret=ret,
            errno=errno_val,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            duration_ms=duration_ms,
            pid=proc.pid,
        )

    def run_probe(self, probe_name: str, cgroup_path: str,
                  env_extra: Dict[str, str] = None,
                  args: List[str] = None,
                  release_immediately: bool = True) -> ProbeResult:
        """Full lifecycle: spawn, place in cgroup, release, wait, collect."""
        proc, write_fd = self.spawn(probe_name, cgroup_path, env_extra, args)
        if release_immediately:
            self.release(write_fd)
        else:
            # Caller must call release() manually; store fd
            return None  # type: ignore
        result = self.wait_result(proc, probe_name)
        # If probe died before producing output, mark as fenced/crashed
        if result.ret == -999 and result.returncode != 0:
            result.was_fenced = True
        return result

    def spawn_and_hold(self, probe_name: str, cgroup_path: str,
                       env_extra: Dict[str, str] = None,
                       args: List[str] = None) -> Tuple[subprocess.Popen, int]:
        """Spawn a probe but do NOT release it. Returns (proc, write_fd).

        Useful for testing fencing: the probe sits blocked in read() until
        the caller decides to release or kill it.
        """
        return self.spawn(probe_name, cgroup_path, env_extra, args)

    def check_fenced(self, proc: subprocess.Popen, cgroup_id: str,
                     proc_client, timeout: float = 3.0) -> Tuple[bool, List[Dict]]:
        """Check if the probe was fenced (frozen) by BPF.

        Polls ShadowProc's list_frozen for the cgroup until the probe appears
        or timeout expires.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            frozen = proc_client.list_frozen(cgroup_id)
            if frozen:
                return True, frozen
            if proc.poll() is not None:
                # Process exited without being fenced
                return False, []
            time.sleep(0.05)
        return False, []

    def _parse_output(self, stdout: str) -> Tuple[int, int]:
        """Parse 'ret=N errno=M' from probe stdout.

        Handles unsigned overflow: some probes print -1 as 4294967295
        (0xFFFFFFFF) due to unsigned printf formatting. Values >= 2^31
        are converted to signed 32-bit representation.
        """
        ret = -999
        errno_val = -999
        match = re.search(r"ret=(-?\d+)\s+errno=(\d+)", stdout)
        if match:
            ret = int(match.group(1))
            errno_val = int(match.group(2))
            # Convert unsigned 32-bit overflow to signed
            # (e.g., 4294967295 -> -1, 4294967294 -> -2)
            if ret >= 0x80000000:
                ret = ret - 0x100000000
        return ret, errno_val

    def cleanup(self):
        """Kill any remaining child processes."""
        for proc in self._children:
            if proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        self._children.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()


def list_available_probes(probes_dir: str = None) -> List[str]:
    """List all compiled probe binaries."""
    d = probes_dir or PROBES_DIR
    if not os.path.isdir(d):
        return []
    return sorted(f for f in os.listdir(d)
                  if os.path.isfile(os.path.join(d, f)) and
                  os.access(os.path.join(d, f), os.X_OK))
