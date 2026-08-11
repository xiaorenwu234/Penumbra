#!/usr/bin/env python3
"""Probe process management and synchronization for RQ2 experiments.

Handles spawning C probe programs inside monitored cgroups, synchronizing
their execution via pipes (the SHADOW_GO_FD protocol), and collecting their
results (ret/errno output).
"""

import os
import re
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

    Protocol (matches test_kernel_effect_decisions.py):
      1. Create a pipe (read_fd, write_fd)
      2. Spawn probe with SHADOW_GO_FD=read_fd in environment
      3. Place probe PID into the monitored cgroup
      4. Write a byte to write_fd to signal "go"
      5. Probe executes its syscall and prints "ret=N errno=M"
      6. Collect output and exit status
    """

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

        The probe blocks reading from SHADOW_GO_FD until the caller writes a byte.
        """
        probe_path = self.get_probe_path(probe_name)
        read_fd, write_fd = os.pipe()

        env = dict(os.environ)
        env["SHADOW_GO_FD"] = str(read_fd)
        if env_extra:
            env.update(env_extra)

        cmd = [probe_path] + (args or [])
        proc = subprocess.Popen(
            cmd,
            pass_fds=(read_fd,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        os.close(read_fd)
        self._children.append(proc)

        # Place into cgroup
        procs_file = os.path.join(cgroup_path, "cgroup.procs")
        with open(procs_file, "w") as f:
            f.write(str(proc.pid))

        return proc, write_fd

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
