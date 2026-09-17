#!/usr/bin/env python3
"""hs epoch engine for the RQ3 baseline experiment — binpash/hs.

hS ("dynamic-parallelizer", https://github.com/binpash/hs) executes shell
programs out of order: every command runs speculatively inside a try
sandbox under strace, and the scheduler commits or discards each sandbox
based on the traced filesystem dependencies. This engine maps one
Penumbra epoch onto ONE hs *command execution*, driving hs's own executor
path (nothing reimplemented):

Phase mapping (Penumbra → hs executor path):
  begin_epoch   → per-epoch sandbox/out/tmp dirs + the initial shell
                  environment snapshot (jit_runtime/pash_declare_vars.sh —
                  the same declare-p + fd_util -s the JIT runtime performs
                  before a command can run)
  session_run   → executor/run_command.sh, byte-for-byte the command the
                  hs executor launches for every node:
                      fd_util -f <env>.fds -p <outdir> \
                        bash deps/try/try -D <sandbox> -L <lower dirs> \
                        executor/template_script_to_execute.sh
                  which runs the command under
                      strace -y -f --seccomp-bpf --trace=fork,clone,%file
                  The trace is what hs's scheduler uses for dependency
                  analysis — it is a real, inseparable part of hs's
                  per-command cost.
  commit        → executor.commit_workspace:
                      try -i /run/mount commit <sandbox>
                  (hs's own commit entry point, ignore pattern included)
  rollback      → hs's delete_sandbox path: rm -rf <sandbox>/upperdir

Command output: fd_util's partial-restore files capture the command's
stdout/stderr into <outdir>/<fd> (merged, as hs's runtime reads them
back) — timed_run returns them as the epoch's output for verify_fn.

Not included (and why): hs's scheduler daemon, preprocessor and JIT
runtime schedule whole *scripts* (startup/preprocessing costs are
per-script, not per-command, so they cannot be charged to a single-epoch
measurement). The one scheduler callback run_command.sh makes
(pash_spec_communicate_scheduler_just_send — a blocking IPC round-trip in
hs) is stubbed to a no-op, exactly like the harness's other engines which
have no daemon either.

Measured pitfalls (mostly shared with try_engine — same try lineage):
  - As root, try's user namespace maps only uid 0 (--map-root-user), so
    sandboxed access to other-uid files (this RQ3 tree under /home/xht,
    mode 0750) fails with EACCES (command exit 126). Fix: the shared
    root-run unshare shim strips the userns flags — a real root needs no
    user namespace, mount isolation still comes from try's mount ns.
  - `try commit` must get an ABSOLUTE sandbox path (upstream fts chdir
    bug); every path built here is absolute.
  - fd_util -p <dir> realpath()s the dir at startup, so the out directory
    must exist before the run (created in begin_epoch).
  - try's overlay workdir contains a kernel-created 000-mode `work/`
    subdir; only root can remove leftovers without a chmod fixup (below).
"""

import os
import shlex
import shutil
import subprocess
import stat
import tempfile
from typing import List, Optional

from .baseline_engine import BaselineEngineError
from .timing import Timer
from .try_engine import is_overlay_whiteout, _ROOT_UNSHARE_SHIM

# Directory names inside the engine root
DIR_WORK = "work"            # live work tree = the tree the workloads use
DIR_ENV = "env"              # per-epoch environment snapshots
DIR_OUT = "out"              # fd_util partial-restore dirs (command output)
DIR_SANDBOXES = "sandboxes"  # per-command try sandbox dirs
DIR_TMP = "tmp"              # per-epoch TMPDIR for run_command.sh
DIR_TRACES = "traces"        # strace trace files
DIR_TOOLS = "tools"          # root-run shim dir (unshare wrapper)

_HERE = os.path.dirname(os.path.abspath(__file__))
_RQ3_DIR = os.path.dirname(_HERE)
# <RQ2> — the workspace that also holds the try-osdi26-ae clone
_RQ2_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_RQ3_DIR)))


# ─── Locating the hs installation (unit-testable without root) ──────────────

def hs_root_candidates() -> List[str]:
    """Where to look for the hs source tree, in priority order."""
    cands = []
    env_root = os.environ.get("HS_ROOT")
    if env_root:
        cands.append(env_root)
    cands.append(os.path.join(_RQ2_ROOT, "hs"))
    cands.append(os.path.join(_RQ3_DIR, "third_party", "hs"))
    return cands


def find_hs_root() -> Optional[str]:
    """Locate the hs installation (the tree holding executor/)."""
    for root in hs_root_candidates():
        if os.path.isfile(os.path.join(root, "executor",
                                       "run_command.sh")):
            return os.path.abspath(root)
    return None


def unwrap_command(argv: List[str]) -> str:
    """Flatten a command argv into hs's single CMD_STRING.

    The harness wraps every command as ["bash", "-c", script] (plus an
    optional leading taskset for the merged pin_once form). hs's
    CMD_STRING is the command *text* the JIT runtime executes, so the
    bash -c wrapper is unwrapped back to the script — one less bash
    fork than re-quoting the whole argv, and the exact text hs would
    have taken from the program skeleton.
    """
    if len(argv) >= 3 and argv[0] == "bash" and argv[1] == "-c":
        return argv[2]
    return " ".join(shlex.quote(a) for a in argv)


def upperdir_files(upperdir: str, ignore_prefixes=()) -> List[str]:
    """Files left in `upperdir` after a run (relative paths).

    NOTE on commit semantics: hs's commit path is `try commit`, whose
    try-commit runs with `-c` — *copy* files instead of moving them
    (hs branch; upstream moves). A successful hs commit therefore KEEPS
    every source file in the upperdir by design, so "upperdir drained"
    is NOT a valid commit check here (unlike try_engine). What is
    checked instead: the commit command's exit status and stderr, plus —
    in the smoke test — that every upper entry's content matches the
    live tree.

    Whiteout entries (deletion markers) are excluded: they carry no
    content to compare.
    """
    files = []
    if not os.path.isdir(upperdir):
        return files
    for dirpath, _dirnames, filenames in os.walk(upperdir):
        rel_dir = os.path.relpath(dirpath, upperdir)
        rel_dir = "" if rel_dir == "." else rel_dir
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.join(rel_dir, name) if rel_dir else name
            if any(rel == pre or rel.startswith(pre + "/")
                   for pre in ignore_prefixes):
                continue
            if is_overlay_whiteout(path):
                continue
            files.append(rel)
    return files


def _rmtree_with_chmod(path: str):
    """rmtree that survives kernel-created 000-mode workdirs (non-root).

    try's overlay workdir holds a 000-mode `work/` subdir; neither walk
    nor rmtree can descend into it before a chmod. Walk top-down and
    chmod every directory entry BEFORE descending into it (the standard
    trick — chmod from the parent works because the parent is already
    accessible), then remove the tree. Root runs never need this (DAC
    override), but engine smoke tests may run unprivileged.
    """
    if not os.path.exists(path):
        return
    for dirpath, dirnames, _filenames in os.walk(path):
        for name in dirnames:
            try:
                os.chmod(os.path.join(dirpath, name), 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


# ─── Engine ──────────────────────────────────────────────────────────────────

class HsEngine:
    """One isolated session backed by hs's per-command executor path.

    Lifecycle:
        setup()                    create the directory tree
        session_open()/close()     no-ops (hs has no persistent session)
        timed_begin_epoch()        epoch dirs + env snapshot           [timed]
        timed_run(...)             hs run_command.sh (fd_util+try+strace)[timed]
        timed_commit()             try -i /run/mount commit per sandbox [timed]
        timed_rollback()           delete each sandbox's upperdir       [timed]
        recover_failed_epoch()     untimed discard after a failure
        refresh()                  no-op (a fresh sandbox sees the live
                                   tree by construction)
        teardown()                 remove the whole directory tree
    """

    # hs's native model is one sandbox per command with the earlier
    # sandboxes chained in as extra lower layers (-L); the engine
    # implements that chain for multi-command epochs. Leaving this False
    # keeps the per-command granularity hs itself uses. (Workloads that
    # request an epoch-level pin — W9b's pin_once — are merged into one
    # `bash -c 'set -e; ...'` command by the harness regardless, matching
    # the Penumbra/CRIU measurement contract.)
    merge_epoch_commands = False

    # Reported in result params / comparison tables.
    engine_name = "hs"

    def __init__(self, root: str, verbose: bool = True,
                 hs_root: str = None):
        self.root = os.path.abspath(root)
        self.work = os.path.join(self.root, DIR_WORK)
        # hs sandboxes the live filesystem itself (try's overlays): the
        # backing store and the merged view the workloads talk to are the
        # same live path.
        self.lower = self.work
        self.mnt = self.work
        self.env_dir = os.path.join(self.root, DIR_ENV)
        self.out_root = os.path.join(self.root, DIR_OUT)
        self.sandboxes = os.path.join(self.root, DIR_SANDBOXES)
        self.tmp_root = os.path.join(self.root, DIR_TMP)
        self.traces = os.path.join(self.root, DIR_TRACES)
        self.tools = os.path.join(self.root, DIR_TOOLS)
        self.verbose = verbose
        self.hs_root = hs_root or find_hs_root()
        if not self.hs_root:
            raise BaselineEngineError(
                "hs installation not found (set HS_ROOT, or place it at "
                "<RQ2>/hs / third_party/hs) — see third_party/build_hs.sh")
        self.run_command_sh = os.path.join(
            self.hs_root, "executor", "run_command.sh")
        self.template_sh = os.path.join(
            self.hs_root, "executor", "template_script_to_execute.sh")
        self.fd_util = os.path.join(self.hs_root, "executor", "fd_util")
        self.declare_vars_sh = os.path.join(
            self.hs_root, "jit_runtime", "pash_declare_vars.sh")
        self.try_bin = os.path.join(self.hs_root, "deps", "try", "try")
        # Interface compat with the shared BaselineHarness: hs has no
        # process-state snapshot, so the session payload axis (W10) is a
        # no-op here — the value is accepted and ignored.
        self.sleeper_mem_bytes = 0
        self._epoch = None
        self._epoch_seq = 0

    def log(self, msg: str):
        if self.verbose:
            print(f"  [hs] {msg}", flush=True)

    # ─── lifecycle ────────────────────────────────────────────────────────

    def setup(self):
        """Create the engine directory tree and verify hs is built."""
        for d in (self.work, self.env_dir, self.out_root, self.sandboxes,
                  self.tmp_root, self.traces):
            os.makedirs(d, exist_ok=True)
        if os.geteuid() == 0:
            self._install_root_unshare_shim()
        missing = []
        for path, hint in (
                (self.run_command_sh, "hs source tree incomplete"),
                (self.template_sh, "hs source tree incomplete"),
                (self.declare_vars_sh, "hs source tree incomplete"),
                (self.try_bin, "init the submodule: git -c "
                 "http.sslVerify=false submodule update --init deps/try"),
                (self.fd_util, "build it: make -C <hs>/executor"),
        ):
            if not os.path.isfile(path):
                missing.append(f"{path} ({hint})")
        if missing:
            raise BaselineEngineError(
                "hs prerequisites missing:\n  - " + "\n  - ".join(missing))
        if not os.access(self.fd_util, os.X_OK):
            raise BaselineEngineError(
                f"{self.fd_util} is not executable — rebuild with "
                "make -C <hs>/executor")

    def _install_root_unshare_shim(self):
        """Install the root-run unshare wrapper into <root>/tools.

        Same root/userns pitfall and fix as TryEngine (see module
        docstring): as real root, --map-root-user maps only uid 0 and
        other-uid files become unreachable inside the sandbox.
        """
        real = shutil.which("unshare")
        if not real:
            raise BaselineEngineError(
                "unshare not found (required to run try)")
        os.makedirs(self.tools, exist_ok=True)
        shim = os.path.join(self.tools, "unshare")
        with open(shim, "w") as f:
            f.write(_ROOT_UNSHARE_SHIM.format(real_unshare=real))
        os.chmod(shim, 0o755)

    def _base_env(self) -> dict:
        """Environment for every hs subprocess (executor, try, utils).

        Mirrors the exports the hs entry script performs (PASH_SPEC_TOP,
        RUNTIME_DIR/RUNTIME_LIBRARY_DIR, LD_LIBRARY_PATH) plus the two
        stubbed functions the JIT runtime would normally receive from the
        hs shell: pash_redir_output (logging shim) and
        pash_spec_communicate_scheduler_just_send (the blocking IPC
        round-trip to the scheduler daemon — a no-op here; see module
        docstring). bash imports BASH_FUNC_* environment entries as shell
        functions in every descendant shell.
        """
        env = dict(os.environ)
        env["PASH_SPEC_TOP"] = self.hs_root
        env["RUNTIME_DIR"] = os.path.join(self.hs_root, "jit_runtime")
        env["RUNTIME_LIBRARY_DIR"] = os.path.join(self.hs_root, "executor")
        env["PASH_DEBUG_LEVEL"] = "0"
        env["PASH_REDIR"] = "&2"
        env["LD_LIBRARY_PATH"] = (
            env.get("LD_LIBRARY_PATH", "") + ":/usr/local/lib/")
        path_dirs = []
        if os.geteuid() == 0 and os.path.isdir(self.tools):
            # unshare shim first (root runs only; see _install_root_...)
            path_dirs.append(self.tools)
        utils_dir = os.path.join(self.hs_root, "deps", "try", "utils")
        if os.path.isdir(utils_dir):
            path_dirs.append(utils_dir)
        if path_dirs:
            env["PATH"] = os.pathsep.join(path_dirs
                                          + [env.get("PATH", "")])
        env["BASH_FUNC_pash_redir_output%%"] = "() { :; }"
        env["BASH_FUNC_pash_spec_communicate_scheduler_just_send%%"] = \
            "() { :; }"
        return env

    # ─── timed epoch phases ───────────────────────────────────────────────

    def timed_begin_epoch(self) -> int:
        """Set up one epoch: dirs + initial environment snapshot. [timed]"""
        with Timer() as t:
            seq = self._epoch_seq
            self._epoch_seq += 1
            tag = f"e{seq:06d}"
            sandbox = tempfile.mkdtemp(prefix=f"{tag}-", dir=self.sandboxes)
            outdir = tempfile.mkdtemp(prefix=f"{tag}-", dir=self.out_root)
            tmpdir = tempfile.mkdtemp(prefix=f"{tag}-", dir=self.tmp_root)
            env_file = os.path.join(self.env_dir, f"{tag}.pre.sh")
            post_env = os.path.join(self.env_dir, f"{tag}.post.sh")
            trace_file = os.path.join(self.traces, f"{tag}.trace")
            # Initial environment snapshot — hs's own script
            # (pash_declare_vars.sh): cd line + declare -p/-f + fd save.
            proc = subprocess.run(
                ["bash", self.declare_vars_sh, env_file],
                cwd=self.mnt, env=self._base_env(),
                capture_output=True, text=True, timeout=60)
            if proc.returncode != 0 or not os.path.isfile(
                    env_file + ".fds"):
                raise BaselineEngineError(
                    "environment snapshot failed "
                    f"(rc={proc.returncode}): "
                    f"{(proc.stderr or proc.stdout)[:200]!r}")
            self._epoch = {
                "seq": seq,
                "sandbox": sandbox,     # first command's sandbox (from begin)
                "outdir": outdir,
                "tmpdir": tmpdir,
                "env": env_file,
                "post_env": post_env,
                "trace": trace_file,
                "sandboxes": [],        # every sandbox used, in order
                "begun": True,
            }
        return t.elapsed_ns

    def timed_run(self, argv: List[str], timeout: float = 300.0):
        """Run one command through hs's executor path. [timed]

        Returns (returncode, output, elapsed_ns). The command's
        stdout/stderr are captured by fd_util into <outdir>/<fd> (that is
        how hs's runtime reads them back) and returned as `output`,
        merged with anything the run_command.sh layer itself printed —
        the same stdout+stderr contract the other engines use.
        """
        ep = self._epoch
        if ep is None or not ep.get("begun"):
            raise BaselineEngineError(
                "timed_run called without timed_begin_epoch")
        sandbox = ep["sandbox"]
        if sandbox is None:
            # >1 command in this epoch (non-merged mode): each command
            # gets its own sandbox, chained onto the earlier ones — the
            # hs -L model.
            sandbox = tempfile.mkdtemp(
                prefix=f"e{ep['seq']:06d}-x-", dir=self.sandboxes)
        else:
            ep["sandbox"] = None
        # hs -L: earlier sandboxes are extra LOWER layers, so this
        # command's speculation builds on theirs (their upperdirs).
        lower = ":".join(os.path.join(s, "upperdir")
                         for s in ep["sandboxes"])
        cmd_string = unwrap_command(argv)
        full = [
            "bash", self.run_command_sh,
            cmd_string, ep["trace"], ep["outdir"], ep["env"],
            sandbox, ep["tmpdir"], "standard", str(ep["seq"]),
            ep["post_env"], "1", lower,
        ]
        rc, layer_out = None, ""
        with Timer() as t:
            try:
                proc = subprocess.run(
                    full, cwd=self.mnt, env=self._base_env(),
                    capture_output=True, text=True, timeout=timeout)
                rc = proc.returncode
                layer_out = (proc.stdout or "") + (proc.stderr or "")
            except subprocess.TimeoutExpired:
                rc = 124
        ep["sandboxes"].append(sandbox)
        out = self._read_command_output(ep["outdir"]) + layer_out
        return rc, out, t.elapsed_ns

    def timed_commit(self) -> int:
        """Commit every sandbox via hs's commit_workspace, then discard
        them. [timed]

        hs commit = `try -i /run/mount commit <sandbox>`; the hs branch
        of try invokes try-commit with `-c` (COPY, not move), so the
        sandbox keeps its files afterwards — by design (they were serving
        as extra lower layers for later speculative commands). The
        authoritative success signals here are the command's exit status
        and its stderr ("couldn't commit ..." lines), NOT an upperdir
        drained check.
        """
        ep = self._require_epoch()
        with Timer() as t:
            for sandbox in ep["sandboxes"]:
                full = ["bash", self.try_bin, "-i", "/run/mount",
                        "commit", sandbox]
                proc = subprocess.run(
                    full, cwd=self.mnt, env=self._base_env(),
                    capture_output=True, text=True, timeout=300)
                err = (proc.stderr or "") + (proc.stdout or "")
                if proc.returncode != 0 or "couldn't commit" in err:
                    raise BaselineEngineError(
                        f"hs commit failed (rc={proc.returncode}): "
                        f"{err[:300]!r}")
            self._discard_epoch()
        return t.elapsed_ns

    def timed_rollback(self) -> int:
        """Discard every sandbox's upperdir (hs delete_sandbox) and drop
        the epoch dirs. [timed]

        Like TryEngine's rollback, the accounting includes dropping the
        speculative state entirely (upperdir removal is the timed part
        that matters; the rest of the sandbox scaffolding is cleaned in
        the same phase for symmetry with commit).
        """
        ep = self._require_epoch()
        with Timer() as t:
            for sandbox in ep["sandboxes"]:
                shutil.rmtree(os.path.join(sandbox, "upperdir"),
                              ignore_errors=True)
            self._discard_epoch()
        return t.elapsed_ns

    def recover_failed_epoch(self):
        """Untimed recovery after a failed run phase: drop everything."""
        try:
            self._discard_epoch()
        except OSError as e:
            self.log(f"recovery failed: {e}")

    # ─── helpers ──────────────────────────────────────────────────────────

    def _require_epoch(self) -> dict:
        ep = self._epoch
        if ep is None or not ep.get("sandboxes"):
            raise BaselineEngineError(
                "no epoch in flight (begin/run before commit/rollback)")
        return ep

    def _read_command_output(self, outdir: str) -> str:
        """fd_util's partial-restore files: <outdir>/<fd> per stream."""
        chunks = []
        try:
            names = sorted(os.listdir(outdir))
        except OSError:
            return ""
        for name in names:
            path = os.path.join(outdir, name)
            if os.path.isfile(path):
                try:
                    with open(path, "r", errors="replace") as f:
                        chunks.append(f.read())
                except OSError:
                    pass
        return "".join(chunks)

    def _discard_epoch(self):
        """Drop the epoch's sandbox/out/tmp dirs (env/trace files stay
        for post-mortem inspection; they are tiny)."""
        ep = self._epoch
        self._epoch = None
        if not ep:
            return
        for sandbox in ep["sandboxes"]:
            _rmtree_with_chmod(sandbox)
        for key in ("outdir", "tmpdir"):
            path = ep.get(key)
            if path:
                _rmtree_with_chmod(path)

    # ─── interface-compat shims (no persistent session in hs) ─────────────

    def session_open(self):
        pass

    def session_close(self):
        pass

    def refresh(self):
        """No-op: each epoch's sandbox sees the current live tree."""
        pass

    def teardown(self):
        """Remove everything this engine ever created."""
        self._discard_epoch()
        for d in (self.env_dir, self.out_root, self.sandboxes,
                  self.tmp_root, self.traces, self.tools):
            shutil.rmtree(d, ignore_errors=True)


# ─── Smoke test (fully functional unprivileged; root = production mode) ─────

def smoke_test(root: str, verbose: bool = True) -> bool:
    """End-to-end check of the hs engine: run/rollback/commit paths.

    Verifies the mechanisms the RQ3 measurement relies on: sandbox
    isolation of the live tree, output capture via fd_util, rollback
    cleanliness, commit application (create + delete incl. whiteouts),
    and sandbox cleanup. Returns True when all checks pass.
    """
    engine = HsEngine(root, verbose=verbose)
    engine.setup()
    live = engine.mnt
    checks = []

    def add(name, ok, detail=""):
        checks.append((name, ok, detail))

    try:
        # ── epoch 1: run is isolated, rollback keeps live clean ──
        engine.timed_begin_epoch()
        marker = "HS-SMOKE-OK"
        spec_file = os.path.join(live, "hs-smoke-created.txt")
        rc, out, ns = engine.timed_run(
            ["bash", "-c", f"echo {marker}; printf x > {spec_file}"])
        add("run through hs executor", rc == 0,
            f"rc={rc} {ns / 1e6:.1f} ms")
        add("command output captured (fd_util outdir)", marker in out,
            f"out={out[:60]!r}")
        # strace -o <trace> writes inside the sandbox view: the trace
        # lands in the sandbox's own upperdir (chroot path mapping).
        trace_in_sandbox = os.path.join(
            engine._epoch["sandboxes"][0], "upperdir",
            engine._epoch["trace"].lstrip("/"))
        add("strace trace produced", os.path.isfile(trace_in_sandbox))
        add("live tree isolated", not os.path.exists(spec_file))
        ns = engine.timed_rollback()
        add("rollback keeps live clean", not os.path.exists(spec_file),
            f"{ns / 1e6:.1f} ms")
        add("sandbox dirs cleaned up",
            not os.listdir(engine.sandboxes))

        # ── epoch 2: commit applies a create to the live tree ──
        engine.timed_begin_epoch()
        rc, out, ns = engine.timed_run(
            ["bash", "-c", f"echo {marker}2; printf y > {spec_file}"])
        add("second run ok", rc == 0 and marker + "2" in out)
        # hs commit copies (try-commit -c): grab the sandbox copy first —
        # after the commit the live tree must hold the same content.
        sandbox = engine._epoch["sandboxes"][0]
        upper_copy = os.path.join(sandbox, "upperdir",
                                  spec_file.lstrip("/"))
        upper_content = None
        if os.path.isfile(upper_copy):
            with open(upper_copy) as f:
                upper_content = f.read()
        ns = engine.timed_commit()
        live_content = None
        if os.path.isfile(spec_file):
            with open(spec_file) as f:
                live_content = f.read()
        add("commit applies effect to live tree",
            os.path.exists(spec_file), f"{ns / 1e6:.1f} ms")
        add("live content matches the sandbox copy (copy semantics)",
            upper_content == "y" and live_content == upper_content,
            f"upper={upper_content!r} live={live_content!r}")

        # ── epoch 3: commit propagates a deletion (whiteout) ──
        engine.timed_begin_epoch()
        rc, _out, _ns = engine.timed_run(
            ["bash", "-c", f"rm -f {spec_file}"])
        add("rm inside sandbox ok", rc == 0)
        add("live file still present before commit",
            os.path.exists(spec_file))
        engine.timed_commit()
        add("commit propagates deletion", not os.path.exists(spec_file))

        # ── epoch 4: rollback leaves the committed state intact ──
        engine.timed_begin_epoch()
        rc, _out, _ns = engine.timed_run(
            ["bash", "-c", f"printf z > {spec_file}"])
        engine.timed_rollback()
        add("rollback discards spec write", not os.path.exists(spec_file))
    finally:
        engine.teardown()

    print("=" * 62)
    print("  HS ENGINE SMOKE TEST (binpash/hs executor path)")
    print("=" * 62)
    for name, ok, detail in checks:
        flag = "PASS" if ok else "FAIL"
        line = f"  [{flag}] {name}"
        if detail:
            line += f" — {detail}"
        print(line)
    ok_all = all(ok for _n, ok, _d in checks)
    print("=" * 62)
    print("  SMOKE TEST PASSED" if ok_all else "  SMOKE TEST FAILED")
    print("=" * 62)
    return ok_all
