#!/usr/bin/env bash
#
# session_integrated_demo.sh — ShadowFS + ShadowProc + Orchestrator, together.
#
# This is the demo the other scripts were missing: a long-lived bash SESSION on
# which an agent performs speculative tool operations, where BOTH the process
# state (env vars, via ShadowProc baseline/candidate) AND the filesystem
# (files written into the ShadowFS mount) are committed / rolled back together,
# per epoch, coordinated by the Orchestrator.
#
#   Epoch 1  →  mutate env + write a file  →  ROLLBACK  →  both are undone
#               (as if the tool never ran; the session keeps living)
#   Epoch 2  →  mutate env + write a file  →  COMMIT    →  both persist
#
# Requires: root, cgroup v2, BPF LSM (same preconditions as run_demo.sh).
set -u

# ──────────────────────────── Paths ────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_DIR="$SCRIPT_DIR"

SHADOWFS_BIN="$PROJECT_ROOT/ShadowFS/shadowfs"
SHADOWPROC_BIN="$PROJECT_ROOT/ShadowProc/target/release/shadow-proc"
ORCH_SCRIPT="$PROJECT_ROOT/orchestrator/shadow_orchestrator.py"
ORCH_CLIENT="$DEMO_DIR/orch_client.py"
CGROUP_EXEC="$DEMO_DIR/test_programs/cgroup_exec"

# The ONE real path: ShadowFS is mounted OVER it in place (see run_demo.sh).
ORIG_DIR="/tmp/shadow-sess-orig"          # data + agent path + mountpoint
LOWER_DIR="/tmp/.shadow-sess-lower"       # hidden private bind (same data)
STAGING_DIR="/tmp/.shadow-sess-staging"   # overlay layer for uncommitted writes

SHADOWFS_SOCK="/tmp/shadow-sess-fs.sock"
SHADOWPROC_SOCK="/tmp/shadow-sess-proc.sock"
ORCH_SOCK="/tmp/shadow-sess-orch.sock"

SHADOWFS_PID=""
SHADOWPROC_PID=""
ORCH_PID=""
SESSION_CG=""     # session cgroup path, for teardown

# ──────────────────────────── Colors ───────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
banner()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; }
section() { echo -e "\n${BOLD}${BLUE}▶ $1${NC}"; }
info()    { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
step()    { echo -e "  ${CYAN}→${NC} $1"; }
fail()    { echo -e "  ${RED}✗${NC} $1"; }

# ──────────────────────────── Orchestrator client helpers ──────────────────
orch()  { python3 "$ORCH_CLIENT" "$ORCH_SOCK" "$@"; }
# Extract a top-level JSON field from stdin (usage: ... | jf field_name).
jf()    { python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))"; }

# ──────────────────────────── Cleanup ──────────────────────────────────────
# Count the mounts stacked at a path, WITHOUT touching the filesystem.
# `mountpoint -q` is unusable for ShadowFS: it needs a successful stat(), but a
# fail-closed ShadowFS mount returns EIO to any cgroup with no active epoch --
# including this shell. The probe then fails, cleanup skips the unmount, and the
# stale mount survives into the next run, where it makes the whole setup die with
# EIO. /proc/self/mountinfo is pure kernel bookkeeping and always readable.
# mountinfo field 5 is the mount point.
_mount_layers() { awk -v t="$1" '$5 == t { n++ } END { print n+0 }' /proc/self/mountinfo; }

# Unmount EVERY layer stacked at a path. Layers accumulate because the FUSE
# mount over $ORIG_DIR is shared, so it propagates onto the $LOWER_DIR bind --
# one extra layer per run if cleanup only ever removes one.
_force_unmount() {
    local path="$1" label="$2" n
    n=$(_mount_layers "$path")
    [[ "$n" -eq 0 ]] && return 0
    step "Unmounting $label ($n layer(s) at $path)"
    while [[ "$n" -gt 0 ]]; do
        fusermount3 -u "$path" 2>/dev/null \
            || umount "$path" 2>/dev/null \
            || umount -l "$path" 2>/dev/null \
            || break
        local left; left=$(_mount_layers "$path")
        [[ "$left" -ge "$n" ]] && break   # no progress: stop rather than spin
        n="$left"
    done
    n=$(_mount_layers "$path")
    [[ "$n" -eq 0 ]] || info "WARNING: $n mount layer(s) still at $path"
}

cleanup() {
    banner
    section "Cleaning up..."

    # Kill anything left in the session cgroup.
    if [[ -n "$SESSION_CG" && -f "$SESSION_CG/cgroup.procs" ]]; then
        while read -r p; do kill -9 "$p" 2>/dev/null || true; done < "$SESSION_CG/cgroup.procs"
    fi

    for name in ORCH SHADOWFS SHADOWPROC; do
        pidvar="${name}_PID"; pid="${!pidvar}"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            step "Stopping $name (PID $pid)"
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    # Also reap a ShadowFS left over from an EARLIER run: its mount is what makes
    # this run's setup fail, and $SHADOWFS_PID is empty when we did not start it.
    pkill -f "shadowfs .*$ORIG_DIR" 2>/dev/null || true

    # FUSE first (it sits on top), then every layer at the backing bind.
    _force_unmount "$ORIG_DIR"  "ShadowFS mount"
    _force_unmount "$LOWER_DIR" "backing bind"

    [[ -n "$SESSION_CG" && -d "$SESSION_CG" ]] && rmdir "$SESSION_CG" 2>/dev/null || true

    rm -rf "$LOWER_DIR" "$ORIG_DIR" "$STAGING_DIR" 2>/dev/null || true
    rm -f "$SHADOWFS_SOCK" "$SHADOWPROC_SOCK" "$ORCH_SOCK"
    info "Cleanup complete."
}
trap cleanup EXIT

# ──────────────────────────── Toolchain PATH ───────────────────────────────
# sudo resets PATH and drops the invoking user's per-user toolchains
# (rustup installs cargo into ~/.cargo/bin). Recover them so preflight/build
# find cargo/go even under sudo.
fixup_path() {
    local home=""
    if [[ -n "${SUDO_USER:-}" ]]; then
        home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi
    for d in "$home/.cargo/bin" "$HOME/.cargo/bin" "$home/go/bin" \
             "/usr/local/go/bin" "/usr/local/bin"; do
        [[ -n "$d" && -d "$d" && ":$PATH:" != *":$d:"* ]] && PATH="$d:$PATH"
    done
    export PATH
    # Inherit the invoking user's rustup/cargo config; otherwise rustup under
    # sudo has no default toolchain configured and cargo refuses to run.
    if [[ -n "$home" ]]; then
        [[ -d "$home/.rustup" ]] && export RUSTUP_HOME="$home/.rustup"
        [[ -d "$home/.cargo" ]] && export CARGO_HOME="$home/.cargo"
    fi
}

# ──────────────────────────── Preflight ────────────────────────────────────
preflight() {
    section "Preflight checks"
    if [[ $EUID -ne 0 ]]; then fail "Must run as root (sudo)"; exit 1; fi
    info "Running as root"
    if ! mount | grep -q "cgroup2"; then fail "cgroup v2 not mounted"; exit 1; fi
    info "cgroup v2 available"
    if cat /sys/kernel/security/lsm 2>/dev/null | grep -q bpf; then
        info "BPF LSM enabled"
    else
        warn "BPF LSM may not be enabled — ShadowProc might fail"
    fi
    for tool in go cargo gcc python3 fusermount3; do
        command -v "$tool" &>/dev/null || { fail "$tool not found in PATH"; exit 1; }
    done
    info "Toolchain present (go, cargo, gcc, python3, fusermount3)"
}

# ──────────────────────────── Build ────────────────────────────────────────
build() {
    section "Building components"
    step "Compiling cgroup_exec helper..."
    gcc -o "$CGROUP_EXEC" "$DEMO_DIR/test_programs/cgroup_exec.c" -Wall
    info "cgroup_exec built"
    step "Building ShadowFS..."
    (cd "$PROJECT_ROOT/ShadowFS" && go build -o shadowfs .)
    info "ShadowFS built"
    step "Building ShadowProc (release)..."
    # Do not let the pipe swallow cargo's exit code: a failed build used to print
    # "ShadowProc built" while the demo silently ran a stale binary.
    if ! (cd "$PROJECT_ROOT/ShadowProc" && cargo build --release 2>&1 | tail -2; exit "${PIPESTATUS[0]}"); then
        fail "ShadowProc build failed"
        exit 1
    fi
    info "ShadowProc built"
}

# ──────────────────────────── Setup ────────────────────────────────────────
setup_stack() {
    section "Setting up environment"

    # A previous run may have left a stale ShadowFS mount here. It is fail-closed,
    # so every access from this shell returns EIO -- rm/mkdir/redirect all fail and
    # the setup below dies. Clear it BEFORE touching the paths.
    pkill -f "shadowfs .*$ORIG_DIR" 2>/dev/null || true
    _force_unmount "$ORIG_DIR"  "stale ShadowFS mount"
    _force_unmount "$LOWER_DIR" "stale backing bind"

    rm -rf "$ORIG_DIR" "$STAGING_DIR"
    mkdir -p "$ORIG_DIR" "$STAGING_DIR" "$LOWER_DIR"

    echo "production-data" > "$ORIG_DIR/original.txt"
    info "Seeded production data at $ORIG_DIR (original.txt)"

    mount --bind "$ORIG_DIR" "$LOWER_DIR"
    # Stop mount propagation between the two. Without this the FUSE mount that
    # ShadowFS puts over $ORIG_DIR (which inherits `shared` from /tmp) propagates
    # onto this bind, so $LOWER_DIR ends up with a stacked fuse.rawBridge layer --
    # one more on every run. Make BOTH sides private, and do not swallow the
    # error: if propagation is not cut, the backing store silently becomes the
    # FUSE mount instead of the real directory, which invalidates every
    # host-side check in this demo.
    mount --make-private "$LOWER_DIR" \
        || { fail "cannot make $LOWER_DIR private (mount propagation would \
 corrupt the backing store)"; exit 1; }
    mount --make-private "$ORIG_DIR" 2>/dev/null || true
    info "Exposed same data to ShadowFS lower layer via private bind (no copy)"

    step "Starting ShadowFS (mounted over $ORIG_DIR)..."
    "$SHADOWFS_BIN" -staging "$STAGING_DIR" -sock "$SHADOWFS_SOCK" \
        -allow-other "$ORIG_DIR" "$LOWER_DIR" &
    SHADOWFS_PID=$!
    sleep 1
    kill -0 "$SHADOWFS_PID" 2>/dev/null || { fail "ShadowFS failed to start"; exit 1; }
    info "ShadowFS running (PID $SHADOWFS_PID)"

    step "Starting ShadowProc..."
    "$SHADOWPROC_BIN" --sock "$SHADOWPROC_SOCK" </dev/null &
    SHADOWPROC_PID=$!
    sleep 2
    kill -0 "$SHADOWPROC_PID" 2>/dev/null || { fail "ShadowProc failed to start"; exit 1; }
    info "ShadowProc running (PID $SHADOWPROC_PID)"

    step "Starting Orchestrator..."
    # SHADOW_AGENT_WAIT_TIMEOUT is read by the orchestrator at startup, NOT by the
    # client, so it has to be set here. Kept short so the agent-barrier section's
    # "blocked" case fails fast instead of sitting on the 30s default.
    SHADOW_AGENT_WAIT_TIMEOUT=2 python3 "$ORCH_SCRIPT" --shadowfs-sock "$SHADOWFS_SOCK" \
        --shadowproc-sock "$SHADOWPROC_SOCK" --listen "$ORCH_SOCK" \
        --shadowfs-mount "$ORIG_DIR" \
        --backing-dir "$STAGING_DIR:$LOWER_DIR" &
    ORCH_PID=$!
    sleep 1
    kill -0 "$ORCH_PID" 2>/dev/null || { fail "Orchestrator failed to start"; exit 1; }
    info "Orchestrator running (PID $ORCH_PID), socket=$ORCH_SOCK"
}

# ──────────────────────────── Scenario ─────────────────────────────────────
# Assertion bookkeeping.
PASS=true
check() {  # check "label" "actual" "expected"
    if [[ "$2" == "$3" ]]; then
        info "$1: $2 (expected $3)"
    else
        fail "$1: got '$2', expected '$3'"; PASS=false
    fi
}

scenario() {
    banner
    section "Unified session epoch: process state + filesystem, committed/rolled-back together"

    # ── Open the session ──
    step "Opening bash session..."
    local resp SID CG
    resp=$(orch session_open)
    SID=$(echo "$resp" | jf session_id)
    CG=$(echo "$resp" | jf cgroup_id)
    [[ -n "$SID" ]] || { fail "session_open failed: $resp"; PASS=false; return; }
    SESSION_CG="/sys/fs/cgroup${CG}"
    info "session_id=$SID  cgroup_id=$CG"

    # ── Baseline state ──
    # ShadowFS is fail-closed: it attributes every access by cgroup and denies
    # anything coming from a cgroup with no ACTIVE epoch. Two consequences the
    # checks below must respect:
    #   1. A write to the mount from OUTSIDE an epoch never lands. So keep.txt is
    #      seeded inside a committed setup epoch -- the same thing the replay
    #      harness does via its dedicated setup epoch.
    #   2. THIS SHELL cannot read the mount either: the demo runs in the user's
    #      login cgroup, which never has an epoch, so `[ -f $ORIG_DIR/x ]` always
    #      reports absent regardless of the real state. Host-side verification
    #      therefore reads $LOWER_DIR (a plain bind of the backing store, no
    #      FUSE in the way) -- which is exactly where ShadowFS promotes on commit.
    step "Seeding baseline: SHADOW_VAR=ORIGINAL + a persistent file keep.txt"
    orch session_run session_id="$SID" 'command=export SHADOW_VAR=ORIGINAL' >/dev/null
    orch session_begin_epoch session_id="$SID" >/dev/null
    orch session_run session_id="$SID" "command=echo baseline > $ORIG_DIR/keep.txt" >/dev/null
    sleep 0.3
    orch session_commit_epoch session_id="$SID" >/dev/null
    sleep 0.4
    local base
    base=$(orch session_run session_id="$SID" 'command=echo VAL=$SHADOW_VAR' | jf output)
    info "baseline env: $base ; keep.txt in backing store: $([[ -f $LOWER_DIR/keep.txt ]] && echo yes || echo no)"

    # ── Epoch 1: mutate speculatively, then ROLLBACK (expect lossless undo) ──
    banner
    section "Epoch 1 — mutate env + write file, then ROLLBACK"
    orch session_begin_epoch session_id="$SID" >/dev/null
    orch session_run session_id="$SID" 'command=export SHADOW_VAR=MODIFIED_BY_AGENT' >/dev/null
    orch session_run session_id="$SID" "command=echo speculative > $ORIG_DIR/epoch1.txt" >/dev/null
    sleep 0.3
    # In-epoch output is SPECULATIVE but is released to the caller IMMEDIATELY
    # (optimistic release): the agent's context is internal state and may advance
    # before finalization, while externally-visible effects stay gated by the
    # epoch. So session_run returns status=ok with the speculative value, and the
    # rollback below is what makes that value non-canonical again.
    # The file-layer write is likewise visible in the mount immediately.
    local e1_status e1_env e1_file
    e1_status=$(orch session_run session_id="$SID" 'command=echo VAL=$SHADOW_VAR' | jf status)
    e1_env=$(orch session_run session_id="$SID" 'command=echo VAL=$SHADOW_VAR' | jf output)
    # Ask the SESSION whether it sees its own speculative write: an uncommitted
    # write lives in the staging layer, so it is visible through the mount (to a
    # cgroup that has an epoch) but NOT yet in the backing store.
    e1_file=$(orch session_run session_id="$SID" \
        "command=test -f $ORIG_DIR/epoch1.txt && echo present || echo absent" | jf output)
    check "in-epoch output released" "$e1_status" "ok"
    check "in-epoch speculative value" "$e1_env" "VAL=MODIFIED_BY_AGENT"
    check "in-epoch file (session view)"  "$e1_file" "present"
    # Not yet promoted: the backing store must still be clean pre-commit.
    check "in-epoch file not yet in backing store" \
        "$([[ -f $LOWER_DIR/epoch1.txt ]] && echo present || echo absent)" "absent"

    step ">>> ROLLBACK epoch 1 (discard candidate + undo file writes)..."
    orch session_rollback_epoch session_id="$SID" >/dev/null
    sleep 0.4
    local r1_env r1_file
    r1_env=$(orch session_run session_id="$SID" 'command=echo VAL=$SHADOW_VAR' | jf output)
    # Backing store must be clean: the speculative write was never promoted.
    r1_file=$([[ -f "$LOWER_DIR/epoch1.txt" ]] && echo present || echo absent)
    check "after-rollback env"  "$r1_env"  "VAL=ORIGINAL"
    check "after-rollback file" "$r1_file" "absent"

    # ── Epoch 2: mutate speculatively, then COMMIT (expect both persist) ──
    banner
    section "Epoch 2 — mutate env + write file, then COMMIT"
    orch session_begin_epoch session_id="$SID" >/dev/null
    orch session_run session_id="$SID" 'command=export SHADOW_VAR=COMMITTED_VALUE' >/dev/null
    orch session_run session_id="$SID" "command=echo persisted > $ORIG_DIR/epoch2.txt" >/dev/null
    sleep 0.3
    step ">>> COMMIT epoch 2 (keep candidate canonical + accept file writes)..."
    orch session_commit_epoch session_id="$SID" >/dev/null
    sleep 0.4
    local c2_env c2_file
    c2_env=$(orch session_run session_id="$SID" 'command=echo VAL=$SHADOW_VAR' | jf output)
    # Commit promotes into the backing store, so the host can now see it.
    c2_file=$([[ -f "$LOWER_DIR/epoch2.txt" ]] && echo present || echo absent)
    check "after-commit env"  "$c2_env"  "VAL=COMMITTED_VALUE"
    check "after-commit file" "$c2_file" "present"

    # ── Baseline file untouched throughout ──
    local keep
    keep=$([[ -f "$LOWER_DIR/keep.txt" ]] && echo present || echo absent)
    check "baseline keep.txt intact" "$keep" "present"

    step "Closing session..."
    orch session_close session_id="$SID" >/dev/null
    SESSION_CG=""

    # ════════════════════════════════════════════════════════════
    # Per-agent barrier: same agent serialized across sessions,
    # different agent never blocks.
    # ════════════════════════════════════════════════════════════
    banner
    section "Agent barrier — same agent serialized, different agent free"

    # Open two sessions owned by the SAME agent.
    local resp_a1 resp_a2 SID_A1 SID_A2
    resp_a1=$(orch session_open agent_id=agent-alpha)
    SID_A1=$(echo "$resp_a1" | jf session_id)
    resp_a2=$(orch session_open agent_id=agent-alpha)
    SID_A2=$(echo "$resp_a2" | jf session_id)
    info "agent-alpha owns sessions $SID_A1 and $SID_A2"

    # Open one session owned by a DIFFERENT agent.
    local resp_b SID_B
    resp_b=$(orch session_open agent_id=agent-beta)
    SID_B=$(echo "$resp_b" | jf session_id)
    info "agent-beta owns session $SID_B"

    # Start an epoch on session A1. This claims agent-alpha's barrier slot.
    local begin_a1
    begin_a1=$(orch session_begin_epoch session_id="$SID_A1" agent_id=agent-alpha)
    check "epoch on A1 opens" "$(echo "$begin_a1" | jf status)" "ok"

    # Same agent's OTHER session (A2) should be BLOCKED: the barrier waits out
    # its timeout and then reports agent_busy. Note `jf` prints the PYTHON repr
    # of the parsed JSON value, so a JSON `true` comes back as `True`.
    local begin_a2
    begin_a2=$(orch session_begin_epoch session_id="$SID_A2" agent_id=agent-alpha 2>/dev/null)
    check "same-agent second session blocked" "$(echo "$begin_a2" | jf agent_busy)" "True"

    # Different agent (beta) must NOT be blocked.
    local begin_b
    begin_b=$(orch session_begin_epoch session_id="$SID_B" agent_id=agent-beta)
    check "different agent not blocked" "$(echo "$begin_b" | jf status)" "ok"

    # Commit A1's epoch -> frees agent-alpha's slot.
    orch session_commit_epoch session_id="$SID_A1" agent_id=agent-alpha >/dev/null
    sleep 0.3

    # Now A2 should succeed (slot freed).
    local begin_a2_retry
    begin_a2_retry=$(orch session_begin_epoch session_id="$SID_A2" agent_id=agent-alpha)
    check "same-agent proceeds after commit" "$(echo "$begin_a2_retry" | jf status)" "ok"

    # Cleanup: rollback/close all three.
    orch session_rollback_epoch session_id="$SID_A2" agent_id=agent-alpha >/dev/null 2>&1 || true
    orch session_rollback_epoch session_id="$SID_B" agent_id=agent-beta >/dev/null 2>&1 || true
    orch session_close session_id="$SID_A1" >/dev/null 2>&1 || true
    orch session_close session_id="$SID_A2" >/dev/null 2>&1 || true
    orch session_close session_id="$SID_B" >/dev/null 2>&1 || true
    info "agent barrier tests complete"

    banner
    if $PASS; then
        echo -e "  ${GREEN}${BOLD}✓ UNIFIED EPOCH DEMO PASSED${NC}"
        echo -e "  ${GREEN}  Epoch 1 rollback losslessly undid BOTH env and file; the session lived on.${NC}"
        echo -e "  ${GREEN}  Epoch 2 commit persisted BOTH env and file. Baseline was never disturbed.${NC}"
    else
        echo -e "  ${RED}${BOLD}✗ DEMO FAILED — see mismatches above${NC}"
    fi
}

# ──────────────────────────── Main ─────────────────────────────────────────
main() {
    banner
    echo -e "${BOLD}ShadowFS + ShadowProc + Orchestrator — unified session epoch demo${NC}"
    fixup_path
    preflight
    build
    setup_stack
    scenario
    $PASS
}
main "$@"
