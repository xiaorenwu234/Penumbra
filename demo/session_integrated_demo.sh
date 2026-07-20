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

    if mountpoint -q "$ORIG_DIR" 2>/dev/null; then
        step "Unmounting $ORIG_DIR"
        fusermount3 -u "$ORIG_DIR" 2>/dev/null || umount "$ORIG_DIR" 2>/dev/null || true
    fi
    if mountpoint -q "$LOWER_DIR" 2>/dev/null; then
        step "Unmounting backing bind $LOWER_DIR"
        umount "$LOWER_DIR" 2>/dev/null || umount -l "$LOWER_DIR" 2>/dev/null || true
    fi
    [[ -n "$SESSION_CG" && -d "$SESSION_CG" ]] && rmdir "$SESSION_CG" 2>/dev/null || true

    rm -rf "$LOWER_DIR" "$ORIG_DIR" "$STAGING_DIR"
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
    (cd "$PROJECT_ROOT/ShadowProc" && cargo build --release 2>&1 | tail -2)
    info "ShadowProc built"
}

# ──────────────────────────── Setup ────────────────────────────────────────
setup_stack() {
    section "Setting up environment"

    rm -rf "$ORIG_DIR" "$STAGING_DIR"
    mkdir -p "$ORIG_DIR" "$STAGING_DIR" "$LOWER_DIR"

    echo "production-data" > "$ORIG_DIR/original.txt"
    info "Seeded production data at $ORIG_DIR (original.txt)"

    mount --bind "$ORIG_DIR" "$LOWER_DIR"
    mount --make-private "$LOWER_DIR" 2>/dev/null || true
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
    python3 "$ORCH_SCRIPT" --shadowfs-sock "$SHADOWFS_SOCK" \
        --shadowproc-sock "$SHADOWPROC_SOCK" --listen "$ORCH_SOCK" &
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

    # ── Baseline state (outside any epoch) ──
    step "Seeding baseline: SHADOW_VAR=ORIGINAL + a persistent file keep.txt"
    orch session_run session_id="$SID" 'command=export SHADOW_VAR=ORIGINAL' >/dev/null
    orch session_run session_id="$SID" "command=echo baseline > $ORIG_DIR/keep.txt" >/dev/null
    sleep 0.3
    local base
    base=$(orch session_run session_id="$SID" 'command=echo VAL=$SHADOW_VAR' | jf output)
    info "baseline env: $base ; keep.txt present: $([[ -f $ORIG_DIR/keep.txt ]] && echo yes || echo no)"

    # ── Epoch 1: mutate speculatively, then ROLLBACK (expect lossless undo) ──
    banner
    section "Epoch 1 — mutate env + write file, then ROLLBACK"
    orch session_begin_epoch session_id="$SID" >/dev/null
    orch session_run session_id="$SID" 'command=export SHADOW_VAR=MODIFIED_BY_AGENT' >/dev/null
    orch session_run session_id="$SID" "command=echo speculative > $ORIG_DIR/epoch1.txt" >/dev/null
    sleep 0.3
    local e1_env e1_file
    e1_env=$(orch session_run session_id="$SID" 'command=echo VAL=$SHADOW_VAR' | jf output)
    e1_file=$([[ -f "$ORIG_DIR/epoch1.txt" ]] && echo present || echo absent)
    check "in-epoch env"   "$e1_env"  "VAL=MODIFIED_BY_AGENT"
    check "in-epoch file"  "$e1_file" "present"

    step ">>> ROLLBACK epoch 1 (discard candidate + undo file writes)..."
    orch session_rollback_epoch session_id="$SID" >/dev/null
    sleep 0.4
    local r1_env r1_file
    r1_env=$(orch session_run session_id="$SID" 'command=echo VAL=$SHADOW_VAR' | jf output)
    r1_file=$([[ -f "$ORIG_DIR/epoch1.txt" ]] && echo present || echo absent)
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
    c2_file=$([[ -f "$ORIG_DIR/epoch2.txt" ]] && echo present || echo absent)
    check "after-commit env"  "$c2_env"  "VAL=COMMITTED_VALUE"
    check "after-commit file" "$c2_file" "present"

    # ── Baseline file untouched throughout ──
    local keep
    keep=$([[ -f "$ORIG_DIR/keep.txt" ]] && echo present || echo absent)
    check "baseline keep.txt intact" "$keep" "present"

    step "Closing session..."
    orch session_close session_id="$SID" >/dev/null
    SESSION_CG=""

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
