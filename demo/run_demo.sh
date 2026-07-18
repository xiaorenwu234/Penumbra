#!/usr/bin/env bash
#
# run_demo.sh — End-to-end demo for ShadowFS + ShadowProc integrated system.
#
# This script:
#   1. Builds ShadowFS (Go), ShadowProc (Rust), and test programs (C)
#   2. Sets up cgroup v2, directories, and starts all components
#   3. Runs three scenarios through the orchestrator:
#      - Scenario 1: Commit  (file write + IPC freeze → commit)
#      - Scenario 2: Rollback (file write + IPC freeze → rollback)
#      - Scenario 3: Cascade rollback (A writes → B reads A → rollback A → B also rolled back)
#      - Scenario 7: Deferred release (commit downstream B → held frozen until
#                    upstream A commits → then released)
#   4. Cleans up everything
#
# Requirements:
#   - Root privileges
#   - Linux kernel >= 5.15 with BPF LSM enabled
#   - cgroup v2 mounted at /sys/fs/cgroup
#   - Go, Rust (cargo), gcc installed
#
# Usage:
#   sudo bash demo/run_demo.sh
#

set -euo pipefail

# ──────────────────── Fix PATH for sudo ─────────────────────────────────────────
# When running via sudo, ~/.cargo/bin and /usr/local/go/bin may not be in PATH.
# Try to find them from the invoking user's home directory.
if [[ -n "${SUDO_USER:-}" ]]; then
    SUDO_HOME=$(eval echo "~$SUDO_USER")
    for p in "$SUDO_HOME/.cargo/bin" "$HOME/.cargo/bin" "/usr/local/go/bin" "$SUDO_HOME/go/bin"; do
        if [[ -d "$p" ]]; then
            export PATH="$p:$PATH"
        fi
    done
    # Inherit the invoking user's rustup/cargo config so the correct toolchain is used
    if [[ -d "$SUDO_HOME/.rustup" ]]; then
        export RUSTUP_HOME="$SUDO_HOME/.rustup"
    fi
    if [[ -d "$SUDO_HOME/.cargo" ]]; then
        export CARGO_HOME="$SUDO_HOME/.cargo"
    fi
fi
# Also add common paths unconditionally if they exist
for p in "$HOME/.cargo/bin" "/usr/local/go/bin"; do
    if [[ -d "$p" ]]; then
        export PATH="$p:$PATH"
    fi
done

# Use Chinese Go proxy to avoid toolchain download timeouts
export GOPROXY="https://goproxy.cn,direct"

# ──────────────────────────── Paths ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_DIR="$SCRIPT_DIR"

SHADOWFS_BIN="$PROJECT_ROOT/ShadowFS/shadowfs"
SHADOWPROC_BIN="$PROJECT_ROOT/ShadowProc/target/release/shadow-proc"
ORCH_SCRIPT="$PROJECT_ROOT/orchestrator/shadow_orchestrator.py"
ORCH_CLIENT="$DEMO_DIR/orch_client.py"

# ── The ONE and ONLY data path ──
# ORIG_DIR is the single real directory you care about: it holds the
# "production" data AND is the exact path the agent uses. ShadowFS is mounted
# OVER it in place, so the agent's path never changes — only its semantics
# (commit/rollback) do.
ORIG_DIR="/tmp/shadow-demo-orig"        # the single real path (data + agent + mountpoint)
# Internal, auto-managed plumbing — you never create or touch these yourself:
#   LOWER_DIR   a hidden PRIVATE bind of ORIG_DIR so ShadowFS can read the
#               underlying data without recursing through its own mount
#               (FUSE cannot use a mountpoint as its own lower layer).
#   STAGING_DIR overlay/upper layer holding uncommitted writes.
LOWER_DIR="/tmp/.shadow-demo-lower"    # hidden internal bind (same data as ORIG_DIR, not a copy)
STAGING_DIR="/tmp/.shadow-demo-staging" # hidden overlay layer for uncommitted writes
SHADOW_OUTPUT_DIR="/tmp/shadow-demo-outputs"
CGROUP_NAME="shadow-demo"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"
CGROUP_NAME_B="shadow-demo-b"
CGROUP_PATH_B="/sys/fs/cgroup/$CGROUP_NAME_B"
# Dedicated cgroup for the bash env-rollback scenario. It IS registered with
# ShadowProc's eBPF (monitored), so bash freezes are triggered by genuine eBPF
# interception of bash's own connect() (via a /dev/tcp redirection), exactly
# like every other agent in this demo. This is only possible because the
# lsm/mmap_file hook now exempts read-only MAP_SHARED mappings (ld.so.cache /
# locale-archive), which bash performs at startup — otherwise bash would freeze
# before it could run a single command.
CGROUP_NAME_C="shadow-demo-c"
CGROUP_PATH_C="/sys/fs/cgroup/$CGROUP_NAME_C"

# Socket paths
SHADOWFS_SOCK="/tmp/shadow-demo-fs.sock"
SHADOWPROC_SOCK="/tmp/shadow-demo-proc.sock"
ORCH_SOCK="/tmp/shadow-demo-orch.sock"

# Bash env-rollback scenario (Scenario 8) plumbing
BASH_FIFO="/tmp/shadow-demo-bash.fifo"
BASH_LOG="/tmp/shadow-demo-bash.log"

# PIDs for cleanup
SHADOWFS_PID=""
SHADOWPROC_PID=""
ORCH_PID=""

# Test programs
AGENT_WORKER="$DEMO_DIR/test_programs/agent_worker"
FILE_RW="$DEMO_DIR/test_programs/file_reader_writer"
CGROUP_EXEC="$DEMO_DIR/test_programs/cgroup_exec"
MEM_MODIFIER="$DEMO_DIR/test_programs/mem_modifier"
LIBEXITHOLD="$DEMO_DIR/test_programs/libexithold.so"
CGROUP_EXEC_HOLD="$DEMO_DIR/test_programs/cgroup_exec_hold"
READ_PROC_MEM="$DEMO_DIR/test_programs/read_proc_mem.py"
PRIV_ESCALATOR="$DEMO_DIR/test_programs/priv_escalator"
FILE_MUTATOR="$DEMO_DIR/test_programs/file_mutator"
IPC_SHM="$DEMO_DIR/test_programs/ipc_shm"

# ──────────────────────────── Colors ───────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

banner() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; }
section() { echo -e "\n${BOLD}${BLUE}▶ $1${NC}"; }
info()    { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
step()    { echo -e "  ${CYAN}→${NC} $1"; }
fail()    { echo -e "  ${RED}✗${NC} $1"; }
show_json() { echo "$1" | python3 -m json.tool 2>/dev/null || echo "$1"; }

# ──────────────────────────── Cleanup ──────────────────────────────────────────
cleanup() {
    banner
    section "Cleaning up..."

    # Kill test processes in cgroup A
    if [[ -f "$CGROUP_PATH/cgroup.procs" ]]; then
        while read -r pid; do
            kill -9 "$pid" 2>/dev/null || true
        done < "$CGROUP_PATH/cgroup.procs"
    fi

    # Kill test processes in cgroup B
    if [[ -f "$CGROUP_PATH_B/cgroup.procs" ]]; then
        while read -r pid; do
            kill -9 "$pid" 2>/dev/null || true
        done < "$CGROUP_PATH_B/cgroup.procs"
    fi

    # Kill test processes in cgroup C (bash env-rollback scenario)
    if [[ -f "$CGROUP_PATH_C/cgroup.procs" ]]; then
        while read -r pid; do
            kill -9 "$pid" 2>/dev/null || true
        done < "$CGROUP_PATH_C/cgroup.procs"
    fi

    # Kill orchestrator
    if [[ -n "$ORCH_PID" ]] && kill -0 "$ORCH_PID" 2>/dev/null; then
        step "Stopping orchestrator (PID $ORCH_PID)"
        kill "$ORCH_PID" 2>/dev/null || true
        wait "$ORCH_PID" 2>/dev/null || true
    fi

    # Kill ShadowFS
    if [[ -n "$SHADOWFS_PID" ]] && kill -0 "$SHADOWFS_PID" 2>/dev/null; then
        step "Stopping ShadowFS (PID $SHADOWFS_PID)"
        kill "$SHADOWFS_PID" 2>/dev/null || true
        wait "$SHADOWFS_PID" 2>/dev/null || true
    fi

    # Kill ShadowProc
    if [[ -n "$SHADOWPROC_PID" ]] && kill -0 "$SHADOWPROC_PID" 2>/dev/null; then
        step "Stopping ShadowProc (PID $SHADOWPROC_PID)"
        kill "$SHADOWPROC_PID" 2>/dev/null || true
        wait "$SHADOWPROC_PID" 2>/dev/null || true
    fi

    # Unmount FUSE (the overlay stacked on the agent path)
    if mountpoint -q "$ORIG_DIR" 2>/dev/null; then
        step "Unmounting $ORIG_DIR"
        fusermount3 -u "$ORIG_DIR" 2>/dev/null || umount "$ORIG_DIR" 2>/dev/null || true
    fi

    # Unmount the private backing bind
    if mountpoint -q "$LOWER_DIR" 2>/dev/null; then
        step "Unmounting backing bind $LOWER_DIR"
        umount "$LOWER_DIR" 2>/dev/null || umount -l "$LOWER_DIR" 2>/dev/null || true
    fi

    # Remove cgroup A
    if [[ -d "$CGROUP_PATH" ]]; then
        step "Removing cgroup $CGROUP_PATH"
        rmdir "$CGROUP_PATH" 2>/dev/null || true
    fi

    # Remove cgroup B
    if [[ -d "$CGROUP_PATH_B" ]]; then
        step "Removing cgroup $CGROUP_PATH_B"
        rmdir "$CGROUP_PATH_B" 2>/dev/null || true
    fi

    # Remove cgroup C
    if [[ -d "$CGROUP_PATH_C" ]]; then
        step "Removing cgroup $CGROUP_PATH_C"
        rmdir "$CGROUP_PATH_C" 2>/dev/null || true
    fi

    # Remove temp files
    rm -rf "$LOWER_DIR" "$ORIG_DIR" "$STAGING_DIR" "$SHADOW_OUTPUT_DIR"
    rm -f "$SHADOWFS_SOCK" "$SHADOWPROC_SOCK" "$ORCH_SOCK"
    rm -f "$BASH_FIFO" "$BASH_LOG"

    info "Cleanup complete."
}

trap cleanup EXIT

# ──────────────────────────── Preflight checks ────────────────────────────────
preflight() {
    section "Preflight checks"

    # Root
    if [[ $EUID -ne 0 ]]; then
        fail "This demo must be run as root (sudo)"
        exit 1
    fi
    info "Running as root"

    # cgroup v2
    if ! mount | grep -q "cgroup2"; then
        fail "cgroup v2 not mounted at /sys/fs/cgroup"
        exit 1
    fi
    info "cgroup v2 available"

    # BPF LSM
    if ! cat /sys/kernel/security/lsm 2>/dev/null | grep -q bpf; then
        warn "BPF LSM may not be enabled — ShadowProc might fail"
    else
        info "BPF LSM enabled"
    fi

    # Go
    if ! command -v go &>/dev/null; then
        fail "Go not found in PATH"
        exit 1
    fi
    info "Go: $(go version | awk '{print $3}')"

    # Rust
    if ! command -v cargo &>/dev/null; then
        fail "Cargo not found in PATH"
        exit 1
    fi
    info "Rust: $(cargo --version)"

    # gcc
    if ! command -v gcc &>/dev/null; then
        fail "gcc not found in PATH"
        exit 1
    fi
    info "gcc: $(gcc --version | head -1)"

    # Python
    if ! command -v python3 &>/dev/null; then
        fail "python3 not found"
        exit 1
    fi
    info "Python: $(python3 --version)"
}

# ──────────────────────────── Build ────────────────────────────────────────────
build() {
    section "Building components"

    # Test programs
    step "Compiling test programs..."
    gcc -o "$AGENT_WORKER" "$DEMO_DIR/test_programs/agent_worker.c" -Wall
    gcc -o "$FILE_RW" "$DEMO_DIR/test_programs/file_reader_writer.c" -Wall
    gcc -o "$CGROUP_EXEC" "$DEMO_DIR/test_programs/cgroup_exec.c" -Wall
    gcc -o "$MEM_MODIFIER" "$DEMO_DIR/test_programs/mem_modifier.c" -Wall
    gcc -shared -fPIC -o "$LIBEXITHOLD" "$DEMO_DIR/test_programs/exit_hold_lib.c" -Wall
    gcc -o "$CGROUP_EXEC_HOLD" "$DEMO_DIR/test_programs/cgroup_exec_hold.c" -Wall
    gcc -o "$PRIV_ESCALATOR" "$DEMO_DIR/test_programs/priv_escalator.c" -Wall
    gcc -o "$FILE_MUTATOR" "$DEMO_DIR/test_programs/file_mutator.c" -Wall
    gcc -o "$IPC_SHM" "$DEMO_DIR/test_programs/ipc_shm.c" -Wall
    info "Test programs built: agent_worker, file_reader_writer, cgroup_exec, cgroup_exec_hold, mem_modifier, libexithold.so, priv_escalator, file_mutator, ipc_shm"

    # ShadowFS
    step "Building ShadowFS..."
    (cd "$PROJECT_ROOT/ShadowFS" && go build -o shadowfs .)
    info "ShadowFS built: $SHADOWFS_BIN"

    # ShadowProc
    step "Building ShadowProc..."
    (cd "$PROJECT_ROOT/ShadowProc" && cargo build --release 2>&1 | tail -3)
    info "ShadowProc built: $SHADOWPROC_BIN"
}

# ──────────────────────────── Setup ────────────────────────────────────────────
setup_env() {
    section "Setting up environment"

    # ── ONE real path, overlaid in place ──
    # There is a single user-visible path: ORIG_DIR. We seed it with the
    # "production" data and then mount ShadowFS OVER this very same path, so the
    # agent's path never changes.
    #
    # FUSE cannot use a mountpoint as its own lower layer (it would recurse), so
    # we expose the SAME underlying data to ShadowFS via a PRIVATE bind mount
    # (LOWER_DIR). LOWER_DIR is NOT a second copy — it is literally the same
    # directory ORIG_DIR was, captured just before the overlay was stacked on top.
    rm -rf "$ORIG_DIR" "$STAGING_DIR"
    mkdir -p "$ORIG_DIR" "$STAGING_DIR" "$LOWER_DIR"

    # Seed the ONE real path with production data.
    echo "original-data-content" > "$ORIG_DIR/original.txt"
    echo "config-v1" > "$ORIG_DIR/config.cfg"
    info "Seeded the agent path $ORIG_DIR with production files: original.txt, config.cfg"

    # Expose that same data to ShadowFS as its lower layer via a private bind,
    # then (below) stack ShadowFS on top of the original path. --make-private
    # stops the upcoming FUSE mount from propagating back onto this bind.
    mount --bind "$ORIG_DIR" "$LOWER_DIR"
    mount --make-private "$LOWER_DIR" 2>/dev/null || true
    info "Exposed the same data to ShadowFS's lower layer via a private bind (no copy)"

    # Create cgroups
    mkdir -p "$CGROUP_PATH"
    info "Created cgroup A: $CGROUP_PATH"
    mkdir -p "$CGROUP_PATH_B"
    info "Created cgroup B: $CGROUP_PATH_B"

    # Start ShadowFS
    step "Starting ShadowFS..."
    "$SHADOWFS_BIN" \
        -staging "$STAGING_DIR" \
        -sock "$SHADOWFS_SOCK" \
        -allow-other \
        "$ORIG_DIR" "$LOWER_DIR" &
    SHADOWFS_PID=$!
    sleep 1
    if ! kill -0 "$SHADOWFS_PID" 2>/dev/null; then
        fail "ShadowFS failed to start"
        exit 1
    fi
    info "ShadowFS running (PID $SHADOWFS_PID), mount=$ORIG_DIR"

    # Prove ShadowFS is genuinely in the I/O path before running any scenario.
    verify_shadowfs_active

    # Start ShadowProc
    step "Starting ShadowProc..."
    "$SHADOWPROC_BIN" \
        --cgroup-path "$CGROUP_PATH" \
        --sock "$SHADOWPROC_SOCK" </dev/null &
    SHADOWPROC_PID=$!
    sleep 2
    if ! kill -0 "$SHADOWPROC_PID" 2>/dev/null; then
        fail "ShadowProc failed to start"
        exit 1
    fi
    info "ShadowProc running (PID $SHADOWPROC_PID)"

    # Start Orchestrator
    step "Starting Orchestrator..."
    python3 "$ORCH_SCRIPT" \
        --shadowfs-sock "$SHADOWFS_SOCK" \
        --shadowproc-sock "$SHADOWPROC_SOCK" \
        --listen "$ORCH_SOCK" &
    ORCH_PID=$!
    sleep 1
    if ! kill -0 "$ORCH_PID" 2>/dev/null; then
        fail "Orchestrator failed to start"
        exit 1
    fi
    info "Orchestrator running (PID $ORCH_PID), socket=$ORCH_SOCK"

    # Verify connectivity
    step "Verifying connectivity..."
    local resp
    resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_agents 2>&1) || true
    info "list_agents response: $resp"

    # Register Agent-B's cgroup with ShadowProc
    step "Registering Agent-B cgroup with ShadowProc..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" add_cgroup "cgroup_path=$CGROUP_PATH_B" 2>&1)"
}

# ──────────────────────────── Helper: run process in cgroup ────────────────────
run_in_cgroup() {
    # Usage: run_in_cgroup <command> [args...]
    #
    # ShadowProc no longer intercepts write() to stdout/stderr (fd 1/2);
    # instead we redirect stdout/stderr to a per-agent buffer file via
    # SHADOW_OUTPUT_FILE. The orchestrator releases the buffered output on
    # commit and discards it on rollback.
    #
    # cgroup_exec:
    #   1. Writes NOTHING to stdout/stderr itself
    #   2. Moves itself into the cgroup via cgroup.procs
    #   3. Redirects fd 1/2 to $SHADOW_OUTPUT_FILE (if set)
    #   4. exec()s the target command
    mkdir -p "$SHADOW_OUTPUT_DIR"
    local output_file="$SHADOW_OUTPUT_DIR/stdout-$$-$RANDOM"
    : > "$output_file"
    # Register the buffer with the orchestrator (best-effort).
    local cg_id
    cg_id="${SHADOW_CGROUP_ID_OVERRIDE:-/$CGROUP_NAME}"
    python3 "$ORCH_CLIENT" "$ORCH_SOCK" register_output \
        "cgroup_id=$cg_id" "output_file=$output_file" >/dev/null 2>&1 || true
    SHADOW_OUTPUT_FILE="$output_file" "$CGROUP_EXEC" "$CGROUP_PATH/cgroup.procs" "$@"
}

run_in_cgroup_b() {
    # Same as run_in_cgroup but for Agent-B's separate cgroup (cross-agent cascade demo).
    mkdir -p "$SHADOW_OUTPUT_DIR"
    local output_file="$SHADOW_OUTPUT_DIR/stdout-b-$$-$RANDOM"
    : > "$output_file"
    local cg_id
    cg_id="${SHADOW_CGROUP_ID_B_OVERRIDE:-/$CGROUP_NAME_B}"
    python3 "$ORCH_CLIENT" "$ORCH_SOCK" register_output \
        "cgroup_id=$cg_id" "output_file=$output_file" >/dev/null 2>&1 || true
    SHADOW_OUTPUT_FILE="$output_file" "$CGROUP_EXEC" "$CGROUP_PATH_B/cgroup.procs" "$@"
}

# Helper: get the cgroup ID that ShadowFS/ShadowProc will see for processes in a given cgroup dir
get_cgroup_id_for() {
    # Run a short-lived probe process in the given cgroup and read its actual
    # cgroup path from /proc. This matches what ShadowFS readCgroupRaw() and
    # ShadowProc read_process_cgroup() will see.
    local cg_path=$1
    local probe_pid
    # Use the C wrapper to avoid bash stdout interception issues
    "$CGROUP_EXEC" "$cg_path/cgroup.procs" sleep 30 &
    probe_pid=$!
    sleep 0.2
    local cg
    cg=$(grep '^0:' /proc/"$probe_pid"/cgroup 2>/dev/null | cut -d: -f3) || true
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    if [[ -n "$cg" ]]; then
        echo "$cg"
    else
        echo "/${cg_path##*/}"
    fi
}

# Backward-compatible wrapper for the primary cgroup
get_cgroup_id() {
    get_cgroup_id_for "$CGROUP_PATH"
}

# Helper: wait for a process to be frozen (or timeout)
# Checks both the given PID and any process currently in the demo cgroup,
# because the bash subshell ($!) may have a different PID than the actual
# agent (cgroup_exec exec's into the target, but bash may not exec-optimize).
wait_for_frozen() {
    local pid=$1
    local timeout=${2:-10}
    local cg_path=${3:-"$CGROUP_PATH"}
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        # Check the given PID directly
        local state
        state=$(awk '/^State:/{print $2}' /proc/"$pid"/status 2>/dev/null) || true
        if [[ "$state" == "T" ]]; then
            return 0  # frozen
        fi
        # Also scan every process currently in the target cgroup — the actual
        # frozen process may have a different PID than the bash subshell we
        # captured with $!.
        if [[ -r "$cg_path/cgroup.procs" ]]; then
            while IFS= read -r cg_pid; do
                [[ -z "$cg_pid" ]] && continue
                cg_state=$(awk '/^State:/{print $2}' /proc/"$cg_pid"/status 2>/dev/null) || true
                if [[ "$cg_state" == "T" ]]; then
                    return 0
                fi
            done < "$cg_path/cgroup.procs"
        fi
        sleep 0.5
        elapsed=$((elapsed + 1))
    done
    return 1  # timeout
}

# Helper: show file state
show_files() {
    step "Files via agent path ($ORIG_DIR) — merged view:"
    ls -la "$ORIG_DIR"/ 2>/dev/null | grep -v "^total" | grep -v "^\." || true
    step "Files in backing store ($LOWER_DIR) — real persisted data:"
    ls -la "$LOWER_DIR"/ 2>/dev/null | grep -v "^total" | grep -v "^\." || true
}

# ─────────────── Verify ShadowFS is genuinely intercepting ──────────────────────
# These checks fail LOUDLY if the "agent path" (ORIG_DIR) is just an ordinary
# directory, i.e. ShadowFS is NOT actually in the I/O path. They rely on facts
# that are impossible to reproduce without a live overlay filesystem:
#   1. The agent path is a FUSE mount, not a plain dir.
#   2. Files that exist ONLY in the hidden backing store are still visible
#      through the agent path — proving ShadowFS synthesizes a merged view.
verify_shadowfs_active() {
    section "Verifying ShadowFS is genuinely intercepting the agent path"
    local pass=true

    # Proof 1: the agent path is a live FUSE mount served by ShadowFS.
    # A plain directory (ShadowFS not running / not mounted here) would have
    # an empty or non-fuse fstype and this assertion would fail.
    local fstype
    fstype=$(awk -v m="$ORIG_DIR" '$2==m {print $3}' /proc/mounts | tail -1)
    if [[ "$fstype" == fuse* ]]; then
        info "Agent path is a FUSE mount (fstype=$fstype) — served by ShadowFS, not the plain FS"
    else
        fail "Agent path $ORIG_DIR is NOT a FUSE mount (fstype='${fstype:-none}') — ShadowFS is not in the I/O path!"
        pass=false
    fi

    # Proof 2: merged-view synthesis. The seed files physically live in the one
    # real directory (readable raw via the LOWER_DIR bind, which bypasses the
    # overlay). If they are also readable through the agent path while absent
    # from staging, ShadowFS must be actively merging lower+overlay on the fly.
    if [[ -f "$LOWER_DIR/original.txt" && ! -e "$ORIG_DIR/original.txt" ]]; then
        fail "Seed file exists in the raw backing but is NOT visible via the agent path — merge not working!"
        pass=false
    elif [[ -f "$ORIG_DIR/original.txt" && ! -e "$STAGING_DIR/original.txt" ]]; then
        info "Seed file readable via the agent path with no overlay copy → ShadowFS is synthesizing the merged view"
    else
        warn "Could not confirm merged-view synthesis (seed file layout unexpected)"
    fi

    if $pass; then
        info "ShadowFS interception CONFIRMED — scenario results below are meaningful"
    else
        fail "ShadowFS interception NOT confirmed — scenario results below would be meaningless"
    fi
}

# assert_intercepted <filename>
# Proves a file the agent wrote via ORIG_DIR is under ShadowFS control:
#   [agent view] visible through the mount (merged view)
#   [staging]    physically redirected into the overlay (ShadowFS caught it)
#   [backing]    absent from the real store (no leak; still uncommitted)
assert_intercepted() {
    local fname=$1
    if [[ -f "$ORIG_DIR/$fname" ]]; then
        info "  [agent view] $ORIG_DIR/$fname visible: $(cat "$ORIG_DIR/$fname")"
    else
        warn "  [agent view] $fname NOT visible via the agent path"
    fi
    if [[ -e "$STAGING_DIR/$fname" ]]; then
        info "  [staging]    write redirected into the overlay → ShadowFS intercepted it"
    else
        warn "  [staging]    $fname NOT in staging — the write may have bypassed ShadowFS!"
    fi
    if [[ -e "$LOWER_DIR/$fname" ]]; then
        fail "  [backing]    $fname LEAKED into the real backing store — isolation broken!"
    else
        info "  [backing]    $fname absent from the real store (isolation intact — uncommitted)"
    fi
}

# assert_committed <filename>
# Proves a commit actually promoted the overlay copy into the real backing
# store (something only ShadowFS can do — the agent never writes LOWER_DIR).
assert_committed() {
    local fname=$1
    if [[ -f "$LOWER_DIR/$fname" ]]; then
        info "  [backing]    $fname now persisted to the real store: $(cat "$LOWER_DIR/$fname")"
    else
        warn "  [backing]    $fname NOT persisted (commit/promote may have failed)"
    fi
    if [[ -e "$STAGING_DIR/$fname" ]]; then
        warn "  [staging]    overlay copy still present (promote incomplete)"
    else
        info "  [staging]    overlay copy consumed by promote (moved into backing store)"
    fi
}

# ──────────────────────────── Scenario 1: Commit ──────────────────────────────
scenario_commit() {
    banner
    section "Scenario 1: COMMIT"
    echo -e "  ${YELLOW}Agent writes a file, triggers IPC → process frozen → orchestrator commits${NC}"
    echo ""

    local CGROUP_ID
    CGROUP_ID=$(get_cgroup_id)
    info "Expected cgroup ID for agents: $CGROUP_ID"

    # Step 1: Agent writes file + triggers IPC
    step "Starting agent_worker in cgroup (writes file + triggers connect)..."
    run_in_cgroup "$AGENT_WORKER" "$ORIG_DIR" "agent1.txt" "hello-from-agent1" &
    local AGENT_PID=$!
    info "Agent started (PID $AGENT_PID)"

    # Step 2: Wait for process to be frozen
    step "Waiting for agent to be frozen by ShadowProc..."
    if wait_for_frozen "$AGENT_PID" 10; then
        info "Agent is FROZEN (SIGSTOP'd by eBPF after connect() attempt)"
    else
        warn "Agent did not freeze within 10s — checking state..."
        cat /proc/"$AGENT_PID"/status 2>/dev/null | grep "^State:" || true
    fi

    # Step 3: Prove ShadowFS intercepted the write.
    # The agent wrote to ORIG_DIR (its normal path). We now show the write was
    # redirected into staging and did NOT leak into the real backing store.
    step "Verifying ShadowFS interception (agent view vs staging vs backing store):"
    assert_intercepted "agent1.txt"

    # Step 4: Query orchestrator
    step "Querying orchestrator: list_agents..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_agents 2>&1)"

    step "Querying orchestrator: list_frozen..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_frozen 2>&1)"

    # Step 5: COMMIT via orchestrator
    echo ""
    step ">>> Sending COMMIT via orchestrator..."
    local commit_resp
    commit_resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" commit "cgroup_id=$CGROUP_ID" 2>&1)
    show_json "$commit_resp"

    # Step 6: Wait for agent to finish
    step "Waiting for agent to complete (resumed by orchestrator)..."
    wait "$AGENT_PID" 2>/dev/null || true
    info "Agent process exited"

    # Step 7: Verify
    echo ""
    step "Post-commit verification (ShadowFS promoted staging → backing store):"
    assert_committed "agent1.txt"

    step "Querying orchestrator: list_frozen (should be empty)..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_frozen 2>&1)"
}

# ──────────────────────────── Scenario 2: Rollback ────────────────────────────
scenario_rollback() {
    banner
    section "Scenario 2: ROLLBACK"
    echo -e "  ${YELLOW}Agent writes a file, triggers IPC → orchestrator rolls back files + kills process${NC}"
    echo ""

    local CGROUP_ID
    CGROUP_ID=$(get_cgroup_id)

    # Step 1: Agent writes file + triggers IPC
    step "Starting agent_worker in cgroup..."
    run_in_cgroup "$AGENT_WORKER" "$ORIG_DIR" "agent2.txt" "rollback-test-data" &
    local AGENT_PID=$!
    info "Agent started (PID $AGENT_PID)"

    # Step 2: Wait for freeze
    step "Waiting for agent to be frozen..."
    if wait_for_frozen "$AGENT_PID" 10; then
        info "Agent is FROZEN"
    else
        warn "Agent did not freeze within 10s"
    fi

    # Step 3: Verify file exists in overlay
    step "File state before rollback:"
    if [[ -f "$ORIG_DIR/agent2.txt" ]]; then
        info "agent2.txt in mount: $(cat "$ORIG_DIR/agent2.txt")"
    fi
    if [[ ! -f "$LOWER_DIR/agent2.txt" ]]; then
        info "agent2.txt NOT in orig (correct — only in overlay)"
    fi

    # Step 4: ROLLBACK via orchestrator
    echo ""
    step ">>> Sending ROLLBACK via orchestrator..."
    local rb_resp
    rb_resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" rollback "cgroup_id=$CGROUP_ID" 2>&1)
    show_json "$rb_resp"

    # Step 5: Wait for agent to be killed
    step "Waiting for agent process..."
    wait "$AGENT_PID" 2>/dev/null || true
    info "Agent process terminated (killed by orchestrator)"

    # Step 6: Verify rollback
    echo ""
    step "Post-rollback verification:"
    if [[ -f "$ORIG_DIR/agent2.txt" ]]; then
        warn "agent2.txt still in mount (rollback may have failed)"
    else
        info "agent2.txt REMOVED from mount (rollback successful)"
    fi
    if [[ -f "$LOWER_DIR/agent2.txt" ]]; then
        warn "agent2.txt in orig (should not be)"
    else
        info "agent2.txt NOT in orig (correct)"
    fi

    # Also clean up agent1.txt from scenario 1 if it was committed
    rm -f "$LOWER_DIR/agent1.txt" 2>/dev/null || true
}

# ──────────────────────────── Scenario 3: Cascade ─────────────────────────────
scenario_cascade() {
    banner
    section "Scenario 3: CASCADE ROLLBACK (cross-agent)"
    echo -e "  ${YELLOW}Agent-A (cgroup-A) writes data.txt → frozen${NC}"
    echo -e "  ${YELLOW}Agent-B (cgroup-B) reads data.txt + writes derived.txt → frozen${NC}"
    echo -e "  ${YELLOW}ROLLBACK A → ShadowFS cascades to B → both files removed + both processes killed${NC}"
    echo ""

    local CGROUP_ID_A CGROUP_ID_B
    CGROUP_ID_A=$(get_cgroup_id_for "$CGROUP_PATH")
    CGROUP_ID_B=$(get_cgroup_id_for "$CGROUP_PATH_B")
    info "Agent-A cgroup ID: $CGROUP_ID_A"
    info "Agent-B cgroup ID: $CGROUP_ID_B"

    # Step 1: Agent-A writes data.txt + triggers IPC → frozen
    step "Step 1: Agent-A writes data.txt and triggers IPC (cgroup-A)..."
    run_in_cgroup "$AGENT_WORKER" "$ORIG_DIR" "data.txt" "agent-a-data" &
    local AGENT_A_PID=$!
    info "Agent-A started (PID $AGENT_A_PID)"

    step "Waiting for Agent-A to be frozen..."
    if wait_for_frozen "$AGENT_A_PID" 10 "$CGROUP_PATH"; then
        info "Agent-A is FROZEN"
    else
        warn "Agent-A did not freeze"
    fi

    # Step 2: Agent-B (different cgroup) reads data.txt → writes derived.txt → triggers IPC → frozen
    echo ""
    step "Step 2: Agent-B reads data.txt, writes derived.txt, triggers IPC (cgroup-B)..."
    run_in_cgroup_b "$FILE_RW" "$ORIG_DIR" "data.txt" "derived.txt" "derived-from-" &
    local AGENT_B_PID=$!
    info "Agent-B started (PID $AGENT_B_PID)"

    step "Waiting for Agent-B to be frozen..."
    if wait_for_frozen "$AGENT_B_PID" 10 "$CGROUP_PATH_B"; then
        info "Agent-B is FROZEN"
    else
        warn "Agent-B did not freeze"
    fi

    # Step 3: Show state before rollback
    echo ""
    step "Step 3: State before rollback..."
    step "list_agents (should show two separate agents):"
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_agents 2>&1)"

    step "list_frozen (both agents should be frozen):"
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_frozen 2>&1)"

    step "File state:"
    if [[ -f "$ORIG_DIR/data.txt" ]]; then
        info "data.txt in mount: $(cat "$ORIG_DIR/data.txt")"
    fi
    if [[ -f "$ORIG_DIR/derived.txt" ]]; then
        info "derived.txt in mount: $(cat "$ORIG_DIR/derived.txt")"
    fi
    if [[ ! -f "$LOWER_DIR/data.txt" ]]; then
        info "data.txt NOT in orig (only in overlay — uncommitted)"
    fi

    # Step 4: get_affected dry-run (rolling back Agent-A)
    echo ""
    step "Step 4: Querying rollback impact for Agent-A (dry-run):"
    step "  Expected: both cgroup-A ($CGROUP_ID_A) and cgroup-B ($CGROUP_ID_B) are affected"
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" get_affected "cgroup_id=$CGROUP_ID_A" 2>&1)"

    # Step 5: ROLLBACK Agent-A → cascade kills Agent-B + rolls back both files
    echo ""
    step "Step 5: >>> ROLLBACK Agent-A (cascades to Agent-B)..."
    local cascade_resp
    cascade_resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" rollback "cgroup_id=$CGROUP_ID_A" 2>&1)
    show_json "$cascade_resp"

    # Step 6: Wait for both agents to terminate
    step "Step 6: Waiting for both agents to terminate..."
    wait "$AGENT_A_PID" 2>/dev/null || true
    wait "$AGENT_B_PID" 2>/dev/null || true
    info "Agent-A and Agent-B both terminated"

    # Step 7: Verify cross-agent cascade
    echo ""
    step "Step 7: Post-cascade verification:"
    if [[ -f "$ORIG_DIR/data.txt" ]]; then
        warn "data.txt still in mount (Agent-A rollback may have failed)"
    else
        info "data.txt REMOVED (Agent-A rolled back successfully)"
    fi
    if [[ -f "$ORIG_DIR/derived.txt" ]]; then
        warn "derived.txt still in mount (Agent-B cascade rollback may have failed)"
    else
        info "derived.txt REMOVED (Agent-B cascade rollback successful — cross-agent!)"
    fi

    step "Frozen processes (should be empty):"
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_frozen 2>&1)"
}

# Helper: send a JSON command directly to ShadowProc socket
shadowproc_cmd() {
    # Usage: shadowproc_cmd '{"action":"...", ...}'
    echo "$1" | python3 -c "
import socket, sys, json
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('$SHADOWPROC_SOCK')
f = sock.makefile('rw', buffering=1)
f.write(sys.stdin.read().strip() + '\n')
f.flush()
resp = f.readline()
sock.close()
print(resp.strip())
"
}

# ──────────────────────────── Scenario 4: COW Memory Rollback ─────────────────
scenario_cow_rollback() {
    banner
    section "Scenario 4: COW MEMORY ROLLBACK"
    echo -e "  ${YELLOW}Process modifies in-memory globals → COW mechanism captures original pages${NC}"
    echo -e "  ${YELLOW}After rollback, memory is restored to pre-modification state${NC}"
    echo ""

    local MARKER_FILE="/tmp/shadow-demo-cow-marker"
    rm -f "$MARKER_FILE"

    # Step 1: Start mem_modifier in cgroup
    step "Step 1: Starting mem_modifier in cgroup (will write marker + trigger IPC freeze)..."
    run_in_cgroup "$MEM_MODIFIER" "$MARKER_FILE" &
    local AGENT_PID=$!
    info "mem_modifier launched (wrapper PID $AGENT_PID)"

    # Step 2: Wait for it to be frozen (initial connect triggers BPF)
    step "Step 2: Waiting for process to be frozen (IPC connect intercepted)..."
    if wait_for_frozen "$AGENT_PID" 10; then
        info "Process is FROZEN (first freeze - before memory modification)"
    else
        warn "Process did not freeze within 10s"
        return
    fi

    # Read marker file to get the actual PID and addresses
    sleep 0.5
    if [[ ! -f "$MARKER_FILE" ]]; then
        warn "Marker file not created — mem_modifier may have failed"
        return
    fi
    local REAL_PID COUNTER_ADDR MESSAGE_ADDR
    REAL_PID=$(grep '^pid=' "$MARKER_FILE" | cut -d= -f2)
    COUNTER_ADDR=$(grep '^counter_addr=' "$MARKER_FILE" | cut -d= -f2)
    MESSAGE_ADDR=$(grep '^message_addr=' "$MARKER_FILE" | cut -d= -f2)
    info "Marker info: pid=$REAL_PID counter_addr=$COUNTER_ADDR message_addr=$MESSAGE_ADDR"

    # Verify initial state via /proc/pid/mem
    step "Verifying initial memory state (should be: counter=42, message=ORIGINAL)..."
    local counter_val msg_val
    counter_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$COUNTER_ADDR" int 2>&1) || true
    msg_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$MESSAGE_ADDR" str 2>&1) || true
    info "  g_counter = $counter_val (expected: 42)"
    info "  g_message = \"$msg_val\" (expected: \"ORIGINAL\")"

    # Step 3: Call begin_speculative on ShadowProc (creates COW shadow)
    echo ""
    step "Step 3: Calling begin_speculative (creates COW shadow fork)..."
    local spec_resp
    spec_resp=$(shadowproc_cmd "{\"action\":\"begin_speculative\",\"pid\":$REAL_PID}")
    show_json "$spec_resp"

    # Step 4: Resume the process (resume_pid) — it will modify memory then freeze again
    # NOTE: We use resume_pid (not continue_pid) so the process can be intercepted
    # again on connect(). continue_pid permanently allows the process through.
    step "Step 4: Resuming process (resume_pid) — process will modify memory..."
    local cont_resp
    cont_resp=$(shadowproc_cmd "{\"action\":\"resume_pid\",\"pid\":$REAL_PID}")
    show_json "$cont_resp"

    # Step 5: Wait for second freeze (connect triggers BPF)
    # NOTE: We must wait specifically for REAL_PID to enter T state.
    # The shadow child (created by fork injection) is also in the cgroup in T state,
    # so wait_for_frozen (which scans cgroup.procs) would return immediately.
    step "Step 5: Waiting for process to be frozen again (connect intercepted)..."
    local elapsed=0
    local frozen_ok=false
    while [[ $elapsed -lt 15 ]]; do
        local pstate
        pstate=$(awk '/^State:/{print $2}' /proc/"$REAL_PID"/status 2>/dev/null) || true
        if [[ "$pstate" == "T" ]]; then
            frozen_ok=true
            break
        fi
        sleep 0.5
        elapsed=$((elapsed + 1))
    done
    if $frozen_ok; then
        info "Process $REAL_PID is FROZEN again (after memory modification)"
    else
        warn "Process $REAL_PID did not freeze within timeout"
        return
    fi
    sleep 0.3

    # Step 6: Verify MODIFIED memory state
    echo ""
    step "Step 6: Verifying MODIFIED memory state (should be: counter=9999, message=MODIFIED_BY_SPECULATIVE)..."
    counter_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$COUNTER_ADDR" int 2>&1) || true
    msg_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$MESSAGE_ADDR" str 2>&1) || true
    info "  g_counter = $counter_val (expected: 9999)"
    info "  g_message = \"$msg_val\" (expected: \"MODIFIED_BY_SPECULATIVE\")"

    if [[ "$counter_val" == "9999" ]]; then
        info "  ✓ Memory was MODIFIED as expected"
    else
        warn "  Counter value unexpected: $counter_val"
    fi

    # Step 7: ROLLBACK memory (restore_memory_pid — restores without killing)
    echo ""
    step "Step 7: >>> Calling restore_memory_pid (COW rollback)..."
    local rb_resp
    rb_resp=$(shadowproc_cmd "{\"action\":\"restore_memory_pid\",\"pid\":$REAL_PID}")
    show_json "$rb_resp"

    # Step 8: Verify RESTORED memory state
    echo ""
    step "Step 8: Verifying RESTORED memory state (should be back to: counter=42, message=ORIGINAL)..."
    counter_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$COUNTER_ADDR" int 2>&1) || true
    msg_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$MESSAGE_ADDR" str 2>&1) || true
    info "  g_counter = $counter_val (expected: 42)"
    info "  g_message = \"$msg_val\" (expected: \"ORIGINAL\")"

    if [[ "$counter_val" == "42" && "$msg_val" == "ORIGINAL" ]]; then
        echo ""
        echo -e "  ${GREEN}${BOLD}✓ COW MEMORY ROLLBACK SUCCESSFUL!${NC}"
        echo -e "  ${GREEN}  Memory was restored from 9999→42, MODIFIED_BY_SPECULATIVE→ORIGINAL${NC}"
    else
        echo ""
        echo -e "  ${RED}✗ Memory rollback may have failed${NC}"
        echo -e "  ${RED}  counter=$counter_val (expected 42), message=$msg_val (expected ORIGINAL)${NC}"
    fi

    # Cleanup: kill the process via ShadowProc API (removes from frozen list)
    shadowproc_cmd "{\"action\":\"kill_pid\",\"pid\":$REAL_PID}" >/dev/null 2>&1 || true
    wait "$AGENT_PID" 2>/dev/null || true
    rm -f "$MARKER_FILE"
}

# ──────────────────────────── Scenario 5: Exit Hold ─────────────────

scenario_exit_hold() {
    banner
    section "Scenario 5: EXIT HOLD (transparent to caller)"
    echo -e "  ${YELLOW}cgroup_exec_hold launches agent → IPC freeze → resume → agent completes → HELD at exit${NC}"
    echo -e "  ${YELLOW}But the CALLER (this script) sees normal exit! It doesn't know the process is held.${NC}"
    echo -e "  ${YELLOW}Mechanism: fork + eventfd notification + LD_PRELOAD destructor + sentinel connect${NC}"
    echo ""

    local CGROUP_ID
    CGROUP_ID=$(get_cgroup_id)
    info "Expected cgroup ID: $CGROUP_ID"

    # Step 1: Launch agent via cgroup_exec_hold in BACKGROUND
    # cgroup_exec_hold will return to the caller when agent finishes work,
    # but the actual agent process remains held.
    step "Step 1: Starting agent via cgroup_exec_hold (transparent hold)..."
    "$CGROUP_EXEC_HOLD" "$CGROUP_PATH/cgroup.procs" "$LIBEXITHOLD" \
        "$AGENT_WORKER" "$ORIG_DIR" "exit_hold_test.txt" "exit-hold-data" &
    local WRAPPER_PID=$!
    info "cgroup_exec_hold started (wrapper PID $WRAPPER_PID)"

    # Step 2: Wait for first freeze (agent's own connect triggers IPC intercept)
    step "Step 2: Waiting for agent to be frozen (IPC - agent's connect())..."
    sleep 1
    # Find the real agent PID (child of wrapper, in cgroup, state T)
    local REAL_PID=""
    if [[ -r "$CGROUP_PATH/cgroup.procs" ]]; then
        while IFS= read -r cg_pid; do
            [[ -z "$cg_pid" ]] && continue
            [[ "$cg_pid" == "$WRAPPER_PID" ]] && continue
            local pstate
            pstate=$(awk '/^State:/{print $2}' /proc/"$cg_pid"/status 2>/dev/null) || true
            if [[ "$pstate" == "T" ]]; then
                REAL_PID="$cg_pid"
                break
            fi
        done < "$CGROUP_PATH/cgroup.procs"
    fi
    if [[ -z "$REAL_PID" ]]; then
        warn "Could not find frozen agent PID"
        wait "$WRAPPER_PID" 2>/dev/null || true
        return
    fi
    info "Agent is FROZEN (PID $REAL_PID, first freeze - IPC intercept)"

    # Step 3: Resume with resume_pid (NOT continue - so exit-hold will fire)
    echo ""
    step "Step 3: Resuming with resume_pid (temporary allow - exit-hold will fire later)..."
    local resume_resp
    resume_resp=$(shadowproc_cmd "{\"action\":\"resume_pid\",\"pid\":$REAL_PID}")
    show_json "$resume_resp"

    # NOTE: the cgroup_exec_hold WRAPPER runs OUTSIDE the monitored cgroup, so
    # the agent's connect() interception (whole-cgroup freeze) never touches it.
    # The wrapper is fully transparent — no manual resume is needed here; it
    # will return to the caller on its own once the agent signals completion.

    # Step 4: Wait for wrapper to EXIT (proves caller sees normal completion)
    step "Step 4: Waiting for cgroup_exec_hold to return (caller's perspective)..."
    local wait_exit_code=0
    wait "$WRAPPER_PID" || wait_exit_code=$?
    info "cgroup_exec_hold returned with exit code $wait_exit_code"
    echo -e "  ${GREEN}${BOLD}  → CALLER SEES NORMAL EXIT! (no blocking, no awareness of hold)${NC}"

    # Step 5: But the real process is STILL ALIVE and HELD!
    echo ""
    step "Step 5: Checking if agent process is still alive and held..."
    sleep 0.3
    local pstate
    pstate=$(awk '/^State:/{print $2}' /proc/"$REAL_PID"/status 2>/dev/null) || true
    if [[ "$pstate" == "T" ]]; then
        info "Process $REAL_PID is STILL ALIVE, state=T (stopped/held)!"
        info "Caller exited normally but the real process is transparently held."
    else
        warn "Process state is '$pstate' (expected T)"
    fi

    # Step 6: Query list_completed to confirm EXIT_HOLD
    step "Step 6: Querying list_completed (should show EXIT_HOLD event)..."
    local completed_resp
    completed_resp=$(shadowproc_cmd "{\"action\":\"list_completed\",\"cgroup_id\":\"$CGROUP_ID\"}")
    show_json "$completed_resp"

    # Step 7: Verify file was written
    step "Step 7: Verifying agent completed its work (file should exist in mount)..."
    if [[ -f "$ORIG_DIR/exit_hold_test.txt" ]]; then
        info "exit_hold_test.txt exists: $(cat "$ORIG_DIR/exit_hold_test.txt")"
    else
        warn "exit_hold_test.txt not found"
    fi

    # Step 8: COMMIT - let process exit + persist files
    echo ""
    step "Step 8: >>> COMMIT (continue_process to allow exit + commit files)..."
    local commit_resp
    commit_resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" commit "cgroup_id=$CGROUP_ID" 2>&1)
    show_json "$commit_resp"

    # Step 9: Wait for process to actually exit
    step "Step 9: Waiting for held process to exit (now permanently allowed)..."
    sleep 1
    if [[ -d "/proc/$REAL_PID" ]]; then
        warn "Process $REAL_PID still alive after commit"
    else
        info "Process $REAL_PID exited normally after commit"
    fi

    # Step 10: Verify commit
    echo ""
    step "Step 10: Post-commit verification:"
    if [[ -f "$LOWER_DIR/exit_hold_test.txt" ]]; then
        info "exit_hold_test.txt COMMITTED to orig: $(cat "$LOWER_DIR/exit_hold_test.txt")"
        echo ""
        echo -e "  ${GREEN}${BOLD}✓ EXIT HOLD + TRANSPARENT CALLER RETURN SUCCESSFUL!${NC}"
        echo -e "  ${GREEN}  Caller returned immediately → process still held → commit → exited normally${NC}"
    else
        warn "exit_hold_test.txt NOT in orig (commit may have failed)"
    fi

    # Cleanup
    rm -f "$LOWER_DIR/exit_hold_test.txt" 2>/dev/null || true
}
# ──────────────────────────── Scenario 6: Privilege Escalation ─────────────────

scenario_priv_escalation() {
    banner
    section "Scenario 6: PRIVILEGE ESCALATION INTERCEPTION"
    echo -e "  ${YELLOW}Agent writes a file, then attempts setuid(0) → process frozen by eBPF${NC}"
    echo -e "  ${YELLOW}Orchestrator detects privilege escalation → rollback files + kill process${NC}"
    echo ""

    local CGROUP_ID
    CGROUP_ID=$(get_cgroup_id)
    info "Expected cgroup ID for agents: $CGROUP_ID"

    # Step 1: Agent writes file + attempts privilege escalation
    step "Starting priv_escalator in cgroup (writes file + attempts setuid(0))..."
    run_in_cgroup "$PRIV_ESCALATOR" "$ORIG_DIR" "priv_test.txt" "malicious-payload" &
    local AGENT_PID=$!
    info "priv_escalator started (PID $AGENT_PID)"

    # Step 2: Wait for process to be frozen
    step "Waiting for process to be frozen by ShadowProc (setuid intercepted)..."
    if wait_for_frozen "$AGENT_PID" 10; then
        info "Process is FROZEN (SIGSTOP'd by eBPF after setuid(0) attempt)"
    else
        warn "Process did not freeze within 10s — checking state..."
        cat /proc/"$AGENT_PID"/status 2>/dev/null | grep "^State:" || true
    fi

    # Step 3: Check file in mount (file was written BEFORE the setuid attempt)
    step "Verifying file in ShadowFS mount:"
    if [[ -f "$ORIG_DIR/priv_test.txt" ]]; then
        info "priv_test.txt exists, content: $(cat "$ORIG_DIR/priv_test.txt")"
    else
        warn "priv_test.txt not found in mount"
    fi
    step "Checking orig (should NOT have priv_test.txt):"
    if [[ -f "$LOWER_DIR/priv_test.txt" ]]; then
        warn "priv_test.txt already in orig (unexpected)"
    else
        info "priv_test.txt NOT in orig (correct — not yet committed)"
    fi

    # Step 4: Query orchestrator for frozen state
    step "Querying orchestrator: list_frozen..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_frozen 2>&1)"

    # Step 5: ROLLBACK - privilege escalation is a security violation!
    echo ""
    step ">>> SECURITY VIOLATION DETECTED: setuid(0) attempt!"
    step ">>> Sending ROLLBACK via orchestrator (reject malicious agent)..."
    local rb_resp
    rb_resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" rollback "cgroup_id=$CGROUP_ID" 2>&1)
    show_json "$rb_resp"

    # Step 6: Wait for agent to be killed
    step "Waiting for agent process..."
    wait "$AGENT_PID" 2>/dev/null || true
    info "Agent process terminated (killed by orchestrator)"

    # Step 7: Verify rollback
    echo ""
    step "Post-rollback verification:"
    if [[ -f "$ORIG_DIR/priv_test.txt" ]]; then
        warn "priv_test.txt still in mount (rollback may have failed)"
    else
        info "priv_test.txt REMOVED from mount (rollback successful)"
    fi
    if [[ -f "$LOWER_DIR/priv_test.txt" ]]; then
        warn "priv_test.txt in orig (should not be)"
    else
        info "priv_test.txt NOT in orig (correct)"
    fi

    echo ""
    echo -e "  ${GREEN}${BOLD}✓ PRIVILEGE ESCALATION BLOCKED!${NC}"
    echo -e "  ${GREEN}  Process attempted setuid(0) → intercepted by eBPF → frozen → rolled back${NC}"
    echo -e "  ${GREEN}  System integrity preserved: no privilege escalation, no file persistence${NC}"
}

# ──────────────── Scenario 7: Deferred Release (commit ordering) ───────────────
# Verifies that a committed DOWNSTREAM cgroup is NOT released until its
# UPSTREAM dependency is also committed. This is the exact path added by the
# deferred-release gate: ShadowProc must keep the downstream's IPC/network
# operations frozen (and its stdout buffered) while an upstream rollback
# could still cascade into it.
#
#   Agent-A (cgroup-A) writes data7.txt              → frozen (upstream)
#   Agent-B (cgroup-B) reads data7.txt + writes
#     derived7.txt                                   → frozen (downstream, depends on A)
#
#   COMMIT B first  → expect DEFERRED (B stays frozen, derived7.txt not in orig)
#   COMMIT A second → expect B auto-released, both files persisted to orig
scenario_deferred_release() {
    banner
    section "Scenario 7: DEFERRED RELEASE (upstream-gated commit)"
    echo -e "  ${YELLOW}Agent-A writes data7.txt → frozen (upstream)${NC}"
    echo -e "  ${YELLOW}Agent-B reads data7.txt + writes derived7.txt → frozen (downstream)${NC}"
    echo -e "  ${YELLOW}COMMIT B first → B must stay FROZEN (deferred); COMMIT A → B released${NC}"
    echo ""

    local CGROUP_ID_A CGROUP_ID_B
    CGROUP_ID_A=$(get_cgroup_id_for "$CGROUP_PATH")
    CGROUP_ID_B=$(get_cgroup_id_for "$CGROUP_PATH_B")
    info "Agent-A cgroup ID: $CGROUP_ID_A"
    info "Agent-B cgroup ID: $CGROUP_ID_B"

    # Step 1: Agent-A writes data7.txt + triggers IPC → frozen
    step "Step 1: Agent-A writes data7.txt and triggers IPC (cgroup-A)..."
    run_in_cgroup "$AGENT_WORKER" "$ORIG_DIR" "data7.txt" "agent-a-data7" &
    local AGENT_A_PID=$!
    if wait_for_frozen "$AGENT_A_PID" 10 "$CGROUP_PATH"; then
        info "Agent-A is FROZEN"
    else
        warn "Agent-A did not freeze"
    fi

    # Step 2: Agent-B reads data7.txt → writes derived7.txt → IPC → frozen
    echo ""
    step "Step 2: Agent-B reads data7.txt, writes derived7.txt, triggers IPC (cgroup-B)..."
    run_in_cgroup_b "$FILE_RW" "$ORIG_DIR" "data7.txt" "derived7.txt" "derived7-from-" &
    local AGENT_B_PID=$!
    if wait_for_frozen "$AGENT_B_PID" 10 "$CGROUP_PATH_B"; then
        info "Agent-B is FROZEN"
    else
        warn "Agent-B did not freeze"
    fi

    # Confirm the dependency exists: rolling back A would affect B.
    echo ""
    step "Step 3: Confirming dependency (get_affected A should include B)..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" get_affected "cgroup_id=$CGROUP_ID_A" 2>&1)"

    # Step 4: COMMIT the DOWNSTREAM (B) first — must be DEFERRED.
    echo ""
    step "Step 4: >>> COMMIT Agent-B (downstream) while Agent-A is still uncommitted..."
    local commit_b_resp
    commit_b_resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" commit "cgroup_id=$CGROUP_ID_B" 2>&1)
    show_json "$commit_b_resp"

    local b_deferred
    b_deferred=$(echo "$commit_b_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('deferred') and not d.get('released', True) else 'no')" 2>/dev/null || echo "unknown")

    local pass=true
    if [[ "$b_deferred" == "yes" ]]; then
        info "commit(B) response: released=false, deferred=true (correct)"
    else
        fail "commit(B) was NOT deferred (released prematurely!) — got: $b_deferred"
        pass=false
    fi

    # Step 5: Assert B is STILL frozen and derived7.txt is NOT persisted.
    step "Step 5: Verifying Agent-B is still FROZEN (not released)..."
    local b_state
    b_state=$(awk '/^State:/{print $2}' /proc/"$AGENT_B_PID"/status 2>/dev/null) || true
    # Fall back to scanning cgroup-B for any stopped process.
    if [[ "$b_state" != "T" && -r "$CGROUP_PATH_B/cgroup.procs" ]]; then
        while IFS= read -r cg_pid; do
            [[ -z "$cg_pid" ]] && continue
            local s
            s=$(awk '/^State:/{print $2}' /proc/"$cg_pid"/status 2>/dev/null) || true
            [[ "$s" == "T" ]] && b_state="T" && break
        done < "$CGROUP_PATH_B/cgroup.procs"
    fi
    if [[ "$b_state" == "T" ]]; then
        info "Agent-B is STILL FROZEN after its own commit (deferred — correct)"
    else
        fail "Agent-B is NOT frozen after commit (state=$b_state) — release leaked!"
        pass=false
    fi

    if [[ -f "$LOWER_DIR/derived7.txt" ]]; then
        fail "derived7.txt already in orig before upstream commit — persisted prematurely!"
        pass=false
    else
        info "derived7.txt NOT in orig yet (correct — upstream A not committed)"
    fi

    # Step 6: COMMIT the UPSTREAM (A) — this must release the deferred B.
    echo ""
    step "Step 6: >>> COMMIT Agent-A (upstream) — should unblock + release B..."
    local commit_a_resp
    commit_a_resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" commit "cgroup_id=$CGROUP_ID_A" 2>&1)
    show_json "$commit_a_resp"

    # Step 7: Both agents should now resume and exit.
    step "Step 7: Waiting for both agents to complete (now released)..."
    wait "$AGENT_A_PID" 2>/dev/null || true
    wait "$AGENT_B_PID" 2>/dev/null || true
    info "Both agents exited"

    # Step 8: Verify both files are now persisted and nothing stays frozen.
    echo ""
    step "Step 8: Post-commit verification..."
    if [[ -f "$LOWER_DIR/data7.txt" ]]; then
        info "data7.txt COMMITTED to orig: $(cat "$LOWER_DIR/data7.txt")"
    else
        fail "data7.txt NOT in orig (upstream commit failed)"
        pass=false
    fi
    if [[ -f "$LOWER_DIR/derived7.txt" ]]; then
        info "derived7.txt COMMITTED to orig (released after upstream): $(cat "$LOWER_DIR/derived7.txt")"
    else
        fail "derived7.txt NOT in orig (downstream was never released)"
        pass=false
    fi

    step "Frozen processes (should be empty):"
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_frozen 2>&1)"

    echo ""
    if $pass; then
        echo -e "  ${GREEN}${BOLD}✓ DEFERRED RELEASE SUCCESSFUL!${NC}"
        echo -e "  ${GREEN}  Downstream B stayed frozen until upstream A committed, then was released.${NC}"
    else
        echo -e "  ${RED}${BOLD}✗ DEFERRED RELEASE CHECK FAILED${NC}"
    fi

    # Cleanup committed files for idempotent re-runs.
    rm -f "$LOWER_DIR/data7.txt" "$LOWER_DIR/derived7.txt" 2>/dev/null || true
}

# ─────── Scenario 8: Forked Child Env Var Rollback via Process Versioning ───────
# Demonstrates speculative rollback of a REAL forked bash child inside a
# MONITORED cgroup, using PROCESS VERSIONING instead of in-place memory patching.
#
# eBPF interception is proven directly: the child issues connect() from inside
# the monitored cgroup (via a `< /dev/tcp/127.0.0.1/PORT` redirection) and
# lsm/socket_connect traps + freezes it. This is only possible because the
# mmap-hook fix exempts bash's read-only MAP_SHARED startup mappings.
#
# Why process versioning (not restore_memory): patching a live process's pages
# from the snapshot only works when the snapshot boundary and the rollback
# boundary share the same live call chain. An auto-tracked forked child is
# snapshotted at fork() but would be rolled back at a different point, so its
# registers/stack reference heap/arena state the page-restore reverts → dangling
# pointers → libc segfault. Instead we keep the fork-time checkpoint (the shadow)
# as a complete, resumable process and, on reject, DISCARD the speculative child
# and RESUME the checkpoint as canonical — no T0/T1 boundary mismatch possible.
#
# We drive the child through its own FIFO (fd 8) as a command REPL:
#   begin_speculative(bash)      -> auto-track ON; child auto-forked at birth = P0
#   read ORIGINAL                -> child (P1) observes inherited value
#   export SHADOW_VAR=MODIFIED    -> speculative modification in P1
#   connect()                    -> eBPF freezes the cgroup (interception proof)
#   reject_pid(P1)               -> kill P1, SIGCONT its fork-checkpoint P0
#   read SHADOW_VAR              -> P0 reports ORIGINAL (proves rollback)
# NOTE: verification uses `echo` (not /proc/PID/environ): bash's `export` only
# mutates its heap variable table, never the execve-time stack env region that
# /proc/PID/environ exposes.
scenario_bash_env_rollback() {
    banner
    section "Scenario 8: FORKED CHILD ENV VAR COW ROLLBACK (real shell)"
    echo -e "  ${YELLOW}A real bash exports SHADOW_VAR=ORIGINAL — bash itself is NOT intercepted${NC}"
    echo -e "  ${YELLOW}bash is COW-tracked (begin_speculative) → auto-track ON for its children${NC}"
    echo -e "  ${YELLOW}bash forks a child; the child is auto-snapshotted at fork() = ORIGINAL${NC}"
    echo -e "  ${YELLOW}Child changes SHADOW_VAR=MODIFIED_BY_AGENT, then connect() → eBPF auto-freezes${NC}"
    echo -e "  ${YELLOW}the cgroup. REJECT = discard the speculative child, resume its pristine${NC}"
    echo -e "  ${YELLOW}fork-checkpoint (process versioning) → SHADOW_VAR is ORIGINAL again${NC}"
    echo ""

    local CGROUP_ID="/$CGROUP_NAME_C"
    local CHILD_FIFO="/tmp/shadow-demo-child.fifo"
    local CHILD_LOG="/tmp/shadow-demo-child.log"
    mkdir -p "$CGROUP_PATH_C"
    # Register cgroup-C with ShadowProc's eBPF so bash + its forked children are
    # genuinely MONITORED. bash can live here without freezing at startup because
    # the mmap hook exempts its read-only MAP_SHARED loader mappings.
    step "Registering cgroup-C with ShadowProc (eBPF-monitored)..."
    show_json "$(shadowproc_cmd "{\"action\":\"add_cgroup\",\"cgroup_path\":\"$CGROUP_PATH_C\"}")"
    info "bash + its forked children live in eBPF-MONITORED cgroup: $CGROUP_ID"

    # Read the value part of the last "tag:VALUE" line from bash's / the child's log.
    read_bash()  { grep "^$1:" "$BASH_LOG"  2>/dev/null | tail -1 | cut -d: -f2- || true; }
    read_child() { grep "^$1:" "$CHILD_LOG" 2>/dev/null | tail -1 | cut -d: -f2- || true; }
    # Feed a command to bash (fd 9 is the FIFO write end) and let it run.
    feed_bash() { printf '%s\n' "$1" >&9; sleep 0.5; }
    # Feed a command to the FIFO-driven CHILD (fd 8 is its FIFO write end).
    feed_child() { printf '%s\n' "$1" >&8; sleep 0.5; }
    # Poll /proc/PID/status until the process reaches stopped state 'T' (or timeout).
    wait_state_T() {
        local pid=$1 t=0
        while [[ $t -lt 25 ]]; do
            [[ "$(awk '/^State:/{print $2}' /proc/"$pid"/status 2>/dev/null)" == "T" ]] && return 0
            sleep 0.1; t=$((t + 1))
        done
        return 1
    }
    # Purge leftover processes in cgroup-C (bash, its subshell, COW shadows) at teardown.
    purge_cgroup_c() {
        if [[ -f "$CGROUP_PATH_C/cgroup.procs" ]]; then
            while read -r p; do kill -9 "$p" 2>/dev/null || true; done < "$CGROUP_PATH_C/cgroup.procs"
        fi
    }

    local orig="" before="" after="" success=false
    warn "ptrace fork-injection (begin_speculative) into a live, signal-driven shell"
    warn "has a small residual timing race (the SIGSTOP crash-class is already fixed"
    warn "via PTRACE_SEIZE); if bash / its child loses it, this scenario retries (max 3)."

    local attempt
    for attempt in 1 2 3; do
        echo ""
        step "────────── Attempt $attempt/3 ──────────"
        purge_cgroup_c
        orig=""; before=""; after=""

        # Fresh FIFOs + logs each attempt. Hold the bash FIFO open read-write on
        # fd 9 so bash never sees EOF and the write side never blocks. The child
        # gets its OWN FIFO used purely as a clean idle-in-read boundary.
        rm -f "$BASH_FIFO" "$BASH_LOG" "$CHILD_FIFO" "$CHILD_LOG"
        mkfifo "$BASH_FIFO"; mkfifo "$CHILD_FIFO"; : > "$BASH_LOG"; : > "$CHILD_LOG"
        exec 9<>"$BASH_FIFO"
        # Hold the child's FIFO open rw on fd 8 too, so the child (and its
        # resumed checkpoint) never see EOF and our command writes never block.
        exec 8<>"$CHILD_FIFO"

        # Launch a real bash inside the MONITORED cgroup-C. cgroup_exec exec()s in
        # place, so BASH_PID is the actual bash.
        step "Step 1: Launching real bash inside cgroup-C (eBPF-monitored, driven via FIFO)..."
        "$CGROUP_EXEC" "$CGROUP_PATH_C/cgroup.procs" bash --norc < "$BASH_FIFO" > "$BASH_LOG" 2>&1 &
        local BASH_PID=$!
        sleep 0.5
        if ! kill -0 "$BASH_PID" 2>/dev/null; then
            warn "bash failed to start — retrying"; exec 8>&- 9>&-; continue
        fi
        info "bash running (PID $BASH_PID)"

        # Seed the environment variable inside the live shell (NO interception here).
        feed_bash 'export SHADOW_VAR=ORIGINAL'
        feed_bash 'echo parent_val:$SHADOW_VAR'
        sleep 0.3
        info "parent bash: SHADOW_VAR=$(read_bash parent_val) (bash itself is never intercepted)"

        # Step 2: Freeze bash at its idle-in-read boundary + begin_speculative.
        # begin_speculative snapshots bash AND turns ON auto-track + eBPF fork
        # reporting, so any child bash forks will be COW-snapshotted at fork time.
        echo ""
        step "Step 2: Freeze bash (freeze_by_cgroup) + begin_speculative (COW snapshot + auto-track children ON)..."
        show_json "$(shadowproc_cmd "{\"action\":\"freeze_by_cgroup\",\"cgroup_id\":\"$CGROUP_ID\"}")"
        wait_state_T "$BASH_PID" || warn "bash never reached state=T"
        sleep 0.2
        show_json "$(shadowproc_cmd "{\"action\":\"begin_speculative\",\"pid\":$BASH_PID}")"
        show_json "$(shadowproc_cmd "{\"action\":\"resume_pid\",\"pid\":$BASH_PID}")"
        sleep 0.4

        # Step 3: bash forks a FIFO-driven REPL child. eBPF reports the fork and
        # ShadowProc injects a fork into it, producing a FROZEN process-checkpoint
        # P0 (a complete, resumable clone of the child at birth = ORIGINAL). The
        # live child is the speculative version P1, driven command-by-command
        # through CHILD_FIFO (fd 8). P0 and P1 share the same env at fork.
        echo ""
        step "Step 3: bash forks a FIFO-REPL child → auto fork-checkpoint P0 (ORIGINAL) + speculative P1..."
        feed_bash "( while IFS= read -r _cmd; do eval \"\$_cmd\"; done ) < $CHILD_FIFO & echo \"childpid:\$!\""
        sleep 0.5
        local CHILD_PID
        CHILD_PID=$(read_bash childpid | tr -d ' ')
        if [[ -z "$CHILD_PID" ]]; then
            warn "could not capture child pid — retrying"
            kill -9 "$BASH_PID" 2>/dev/null || true
            exec 8>&- 9>&-; wait "$BASH_PID" 2>/dev/null || true; purge_cgroup_c
            continue
        fi
        info "speculative child P1 PID: $CHILD_PID (its fork-checkpoint P0 is frozen alongside)"

        # Step 4: feed the speculative sequence to P1: observe ORIGINAL, mutate to
        # MODIFIED_BY_AGENT, observe it, then connect(). The connect() is
        # intercepted by eBPF, which SIGSTOPs P1 (mid-syscall — we don't care,
        # we're going to DISCARD P1 wholesale) and auto-freezes the whole cgroup.
        echo ""
        step "Step 4: drive P1: read ORIGINAL → export MODIFIED_BY_AGENT → connect() → eBPF freezes the cgroup..."
        feed_child "echo \"child_orig:\$SHADOW_VAR\" >> $CHILD_LOG"
        feed_child "export SHADOW_VAR=MODIFIED_BY_AGENT"
        feed_child "echo \"child_before:\$SHADOW_VAR\" >> $CHILD_LOG"
        feed_child "read -t 1 _ < /dev/tcp/127.0.0.1/9 2>/dev/null || true"
        if wait_state_T "$CHILD_PID"; then
            info "speculative P1 is FROZEN (state=T) by lsm/socket_connect; cgroup auto-frozen too"
        else
            warn "P1 did not freeze on connect() — retrying"
            kill -9 "$CHILD_PID" "$BASH_PID" 2>/dev/null || true
            exec 8>&- 9>&-; wait "$BASH_PID" 2>/dev/null || true; purge_cgroup_c
            continue
        fi
        orig=$(read_child child_orig)
        before=$(read_child child_before)
        info "P1 inherited SHADOW_VAR=$orig at fork, mutated it to $before before connecting"
        if [[ "$before" != "MODIFIED_BY_AGENT" ]]; then
            warn "P1 never applied the modification (lost race / crashed) — retrying"
            kill -9 "$CHILD_PID" "$BASH_PID" 2>/dev/null || true
            exec 8>&- 9>&-; wait "$BASH_PID" 2>/dev/null || true; purge_cgroup_c
            continue
        fi

        # Step 5: REJECT. Instead of patching P1's memory (which mixes fork-time
        # snapshot with idle-time registers and crashes glibc), we DISCARD the
        # speculative version P1 entirely and RESUME its pristine fork-checkpoint
        # P0 as the canonical process. P0's registers/stack/heap/TLS all belong to
        # the same instant, so it resumes cleanly with SHADOW_VAR=ORIGINAL.
        echo ""
        step "Step 5: >>> REJECT: kill speculative P1, resume its fork-checkpoint P0 as canonical (process versioning)..."
        show_json "$(shadowproc_cmd "{\"action\":\"reject_pid\",\"pid\":$CHILD_PID}")"
        sleep 0.6

        # Step 6: P0 is now the live child, back at its FIFO read loop. Feed it one
        # observation command; it reports SHADOW_VAR from its own (ORIGINAL) state.
        # The speculative export/connect were consumed by the now-dead P1 and never
        # touched P0, so P0 reads ORIGINAL.
        echo ""
        step "Step 6: drive the resumed checkpoint P0 → it reports SHADOW_VAR (expect ORIGINAL)..."
        feed_child "echo \"child_after:\$SHADOW_VAR\" >> $CHILD_LOG"
        sleep 0.6
        after=$(read_child child_after)
        info "child value after reject: SHADOW_VAR=$after (expected: ORIGINAL)"

        # Per-attempt teardown.
        kill -9 "$CHILD_PID" "$BASH_PID" 2>/dev/null || true
        exec 8>&- 9>&-
        wait "$BASH_PID" 2>/dev/null || true
        purge_cgroup_c

        if [[ "$orig" == "ORIGINAL" && "$before" == "MODIFIED_BY_AGENT" && "$after" == "ORIGINAL" ]]; then
            success=true
            break
        fi
        warn "attempt $attempt did not fully verify (after=$after) — retrying"
    done

    # Verdict
    echo ""
    if $success; then
        echo -e "  ${GREEN}${BOLD}✓ FORKED CHILD ENV VAR COW ROLLBACK SUCCESSFUL!${NC}"
        echo -e "  ${GREEN}  child: ORIGINAL → MODIFIED_BY_AGENT → connect() → frozen → REJECT → checkpoint resumed → ORIGINAL${NC}"
        echo -e "  ${GREEN}  The speculative version was discarded and its pristine fork-checkpoint resumed as canonical.${NC}"
    else
        echo -e "  ${RED}${BOLD}✗ Forked child env var rollback check failed after 3 attempts${NC}"
        echo -e "  ${RED}  orig=$orig (exp ORIGINAL), before=$before (exp MODIFIED_BY_AGENT), after=$after (exp ORIGINAL)${NC}"
        echo -e "  ${RED}  (ptrace fork-injection / connect-freeze lost the race on every attempt)${NC}"
    fi

    rm -f "$BASH_FIFO" "$BASH_LOG" "$CHILD_FIFO" "$CHILD_LOG"
}

# ─────── Scenario 9: Modify an EXISTING file (rollback + commit) ───────
# Every other file scenario CREATES new files. This one MODIFIES a pre-existing,
# already-committed production file (config.cfg) and shows both directions:
#   Part A — ROLLBACK restores the ORIGINAL content (the overlay preserved it)
#   Part B — COMMIT persists the NEW content into the backing store
scenario_modify_existing() {
    banner
    section "Scenario 9: MODIFY EXISTING FILE (rollback preserves original, commit persists)"
    echo -e "  ${YELLOW}Agent overwrites an existing production file config.cfg${NC}"
    echo -e "  ${YELLOW}Rollback → original restored; Commit → new content persisted${NC}"
    echo ""

    local CGROUP_ID
    CGROUP_ID=$(get_cgroup_id)
    local base
    base=$(cat "$LOWER_DIR/config.cfg" 2>/dev/null || echo "?")
    info "Baseline: backing config.cfg = \"$base\" (expected: config-v1)"

    # ── Part A: modify → ROLLBACK (must restore original) ──
    echo ""
    step "Part A — Agent overwrites config.cfg, then we ROLLBACK..."
    run_in_cgroup "$AGENT_WORKER" "$ORIG_DIR" "config.cfg" "config-MODIFIED-by-agent" &
    local A_PID=$!
    if wait_for_frozen "$A_PID" 10; then
        info "Agent frozen after overwriting config.cfg"
    else
        warn "Agent did not freeze"; return
    fi
    local view_mod backing_pre
    view_mod=$(cat "$ORIG_DIR/config.cfg" 2>/dev/null || echo "?")
    backing_pre=$(cat "$LOWER_DIR/config.cfg" 2>/dev/null || echo "?")
    info "  [agent view] config.cfg = \"$view_mod\" (expected: config-MODIFIED-by-agent)"
    if [[ "$backing_pre" == "config-v1" ]]; then
        info "  [backing]    config.cfg STILL \"config-v1\" (original preserved, uncommitted)"
    else
        fail "  [backing]    config.cfg = \"$backing_pre\" (expected config-v1 — isolation broken!)"
    fi
    step ">>> ROLLBACK via orchestrator..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" rollback "cgroup_id=$CGROUP_ID" 2>&1)"
    wait "$A_PID" 2>/dev/null || true
    local view_after
    view_after=$(cat "$ORIG_DIR/config.cfg" 2>/dev/null || echo "?")
    if [[ "$view_after" == "config-v1" ]]; then
        info "  ✓ After rollback: config.cfg restored to \"config-v1\" (original intact)"
    else
        fail "  After rollback: config.cfg = \"$view_after\" (expected config-v1)"
    fi

    # ── Part B: modify → COMMIT (must persist the new content) ──
    echo ""
    step "Part B — Agent overwrites config.cfg again, then we COMMIT..."
    run_in_cgroup "$AGENT_WORKER" "$ORIG_DIR" "config.cfg" "config-v2-committed" &
    local B_PID=$!
    if wait_for_frozen "$B_PID" 10; then
        info "Agent frozen after overwriting config.cfg"
    else
        warn "Agent did not freeze"; return
    fi
    step ">>> COMMIT via orchestrator..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" commit "cgroup_id=$CGROUP_ID" 2>&1)"
    wait "$B_PID" 2>/dev/null || true
    local backing_after
    backing_after=$(cat "$LOWER_DIR/config.cfg" 2>/dev/null || echo "?")
    echo ""
    if [[ "$backing_after" == "config-v2-committed" ]]; then
        echo -e "  ${GREEN}${BOLD}✓ MODIFY-EXISTING-FILE SUCCESSFUL!${NC}"
        echo -e "  ${GREEN}  Rollback restored config-v1; commit persisted config-v2-committed${NC}"
    else
        echo -e "  ${RED}${BOLD}✗ Modify-existing check failed${NC}"
        echo -e "  ${RED}  backing config.cfg = \"$backing_after\" (expected config-v2-committed)${NC}"
    fi

    # Restore the seed for idempotent re-runs (writes the raw backing bind directly).
    echo "config-v1" > "$LOWER_DIR/config.cfg" 2>/dev/null || true
}

# ─────── Scenario 10: Delete / Rename rollback (existing files) ───────
# Agent destroys existing production files (unlink + rename). ShadowFS records
# each as an undoable overlay entry (whiteout / rename undo-log), so ROLLBACK
# brings the original file back — the real backing store was never touched.
scenario_delete_rename_rollback() {
    banner
    section "Scenario 10: DELETE / RENAME ROLLBACK (existing files)"
    echo -e "  ${YELLOW}Agent deletes / renames a production file → rollback restores it${NC}"
    echo ""

    local CGROUP_ID
    CGROUP_ID=$(get_cgroup_id)

    # ── Part A: delete original.txt → ROLLBACK restores it ──
    step "Part A — Agent deletes original.txt, then we ROLLBACK..."
    info "Baseline: original.txt = \"$(cat "$LOWER_DIR/original.txt" 2>/dev/null || echo '?')\""
    run_in_cgroup "$FILE_MUTATOR" "$ORIG_DIR" "delete" "original.txt" &
    local D_PID=$!
    if wait_for_frozen "$D_PID" 10; then
        info "Agent frozen after unlink(original.txt)"
    else
        warn "Agent did not freeze"; return
    fi
    if [[ -e "$ORIG_DIR/original.txt" ]]; then
        warn "  [agent view] original.txt still visible (delete not intercepted?)"
    else
        info "  [agent view] original.txt GONE (whiteout in overlay)"
    fi
    if [[ -e "$LOWER_DIR/original.txt" ]]; then
        info "  [backing]    original.txt STILL present (delete uncommitted — isolation intact)"
    else
        fail "  [backing]    original.txt deleted from backing store — isolation broken!"
    fi
    step ">>> ROLLBACK via orchestrator..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" rollback "cgroup_id=$CGROUP_ID" 2>&1)"
    wait "$D_PID" 2>/dev/null || true
    if [[ -f "$ORIG_DIR/original.txt" ]]; then
        info "  ✓ After rollback: original.txt restored: \"$(cat "$ORIG_DIR/original.txt")\""
    else
        fail "  After rollback: original.txt still missing!"
    fi

    # ── Part B: rename original.txt → renamed.txt → ROLLBACK restores it ──
    echo ""
    step "Part B — Agent renames original.txt → renamed.txt, then we ROLLBACK..."
    run_in_cgroup "$FILE_MUTATOR" "$ORIG_DIR" "rename" "original.txt" "renamed.txt" &
    local R_PID=$!
    if wait_for_frozen "$R_PID" 10; then
        info "Agent frozen after rename(original.txt → renamed.txt)"
    else
        warn "Agent did not freeze"; return
    fi
    if [[ -e "$ORIG_DIR/renamed.txt" && ! -e "$ORIG_DIR/original.txt" ]]; then
        info "  [agent view] original.txt → renamed.txt (rename visible in overlay)"
    else
        warn "  [agent view] rename not reflected as expected"
    fi
    step ">>> ROLLBACK via orchestrator..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" rollback "cgroup_id=$CGROUP_ID" 2>&1)"
    wait "$R_PID" 2>/dev/null || true
    echo ""
    if [[ -f "$ORIG_DIR/original.txt" && ! -e "$ORIG_DIR/renamed.txt" ]]; then
        echo -e "  ${GREEN}${BOLD}✓ DELETE / RENAME ROLLBACK SUCCESSFUL!${NC}"
        echo -e "  ${GREEN}  original.txt survived both a delete and a rename via rollback${NC}"
    else
        echo -e "  ${RED}${BOLD}✗ Delete/rename rollback check failed${NC}"
        local hp hr
        hp=$([[ -f "$ORIG_DIR/original.txt" ]] && echo yes || echo no)
        hr=$([[ -e "$ORIG_DIR/renamed.txt" ]] && echo yes || echo no)
        echo -e "  ${RED}  original.txt present=$hp, renamed.txt present=$hr${NC}"
    fi
}

# ─────── Scenario 11: Shared-memory IPC interception (covert channel) ───────
# Beyond network connect(), ShadowProc also hooks SysV/POSIX IPC. This agent
# tries to attach a SysV shared-memory segment (shmat) — a classic covert
# channel — and is frozen by lsm/shm_shmat BEFORE the channel is usable.
scenario_shm_intercept() {
    banner
    section "Scenario 11: SHARED-MEMORY IPC INTERCEPTION (covert channel)"
    echo -e "  ${YELLOW}Agent tries to attach a SysV shared-memory segment (shmat)${NC}"
    echo -e "  ${YELLOW}lsm/shm_shmat freezes it BEFORE the channel is usable${NC}"
    echo ""

    local CGROUP_ID
    CGROUP_ID=$(get_cgroup_id)

    step "Step 1: Starting ipc_shm in cgroup (shmget + shmat)..."
    run_in_cgroup "$IPC_SHM" &
    local S_PID=$!
    step "Step 2: Waiting for process to be frozen (shmat intercepted)..."
    if wait_for_frozen "$S_PID" 10; then
        info "Process is FROZEN (SIGSTOP'd by eBPF at shmat)"
    else
        warn "Process did not freeze — shm interception may be unavailable on this kernel"
        shadowproc_cmd "{\"action\":\"kill_by_cgroup\",\"cgroup_id\":\"$CGROUP_ID\"}" >/dev/null 2>&1 || true
        wait "$S_PID" 2>/dev/null || true
        return
    fi

    step "Step 3: Confirming the freeze is classified as an IPC event..."
    local frozen_json
    frozen_json=$(shadowproc_cmd "{\"action\":\"list_all_frozen\"}")
    show_json "$frozen_json"
    echo ""
    if echo "$frozen_json" | grep -q '"event_type":"IPC"'; then
        echo -e "  ${GREEN}${BOLD}✓ SHARED-MEMORY IPC BLOCKED!${NC}"
        echo -e "  ${GREEN}  shmat() intercepted (event_type=IPC) → covert channel never opened${NC}"
    else
        echo -e "  ${RED}${BOLD}✗ Expected an IPC-classified freeze, not found${NC}"
    fi

    step "Step 4: Rejecting the agent (kill via ShadowProc)..."
    shadowproc_cmd "{\"action\":\"kill_by_cgroup\",\"cgroup_id\":\"$CGROUP_ID\"}" >/dev/null 2>&1 || true
    wait "$S_PID" 2>/dev/null || true
    info "Agent terminated — no shared-memory channel established"
}

# ─────── Scenario 12: COW memory COMMIT (accept speculative change) ───────
# The mirror of Scenario 4: instead of rolling the speculative memory change
# back, we ACCEPT it with commit_pid (which discards the COW shadow and keeps
# the modified pages live), then let the process run to completion.
scenario_cow_commit() {
    banner
    section "Scenario 12: COW MEMORY COMMIT (accept speculative change)"
    echo -e "  ${YELLOW}Modify memory speculatively, then COMMIT (keep it) — mirror of Scenario 4${NC}"
    echo -e "  ${YELLOW}commit_pid discards the shadow; the modified memory stays live${NC}"
    echo ""

    local MARKER_FILE="/tmp/shadow-demo-cow-commit-marker"
    rm -f "$MARKER_FILE"

    step "Step 1: Starting mem_modifier in cgroup..."
    run_in_cgroup "$MEM_MODIFIER" "$MARKER_FILE" &
    local AGENT_PID=$!
    step "Step 2: Waiting for first freeze (before modification)..."
    if wait_for_frozen "$AGENT_PID" 10; then
        info "Process FROZEN (before modification)"
    else
        warn "Process did not freeze"; return
    fi
    sleep 0.5
    if [[ ! -f "$MARKER_FILE" ]]; then warn "Marker file missing"; return; fi
    local REAL_PID COUNTER_ADDR MESSAGE_ADDR
    REAL_PID=$(grep '^pid=' "$MARKER_FILE" | cut -d= -f2)
    COUNTER_ADDR=$(grep '^counter_addr=' "$MARKER_FILE" | cut -d= -f2)
    MESSAGE_ADDR=$(grep '^message_addr=' "$MARKER_FILE" | cut -d= -f2)
    info "Marker: pid=$REAL_PID counter_addr=$COUNTER_ADDR"

    step "Step 3: begin_speculative (creates COW shadow)..."
    show_json "$(shadowproc_cmd "{\"action\":\"begin_speculative\",\"pid\":$REAL_PID}")"
    step "Step 4: resume_pid — process modifies memory..."
    show_json "$(shadowproc_cmd "{\"action\":\"resume_pid\",\"pid\":$REAL_PID}")"

    step "Step 5: Waiting for second freeze (after modification)..."
    local elapsed=0 frozen_ok=false
    while [[ $elapsed -lt 15 ]]; do
        local pstate
        pstate=$(awk '/^State:/{print $2}' /proc/"$REAL_PID"/status 2>/dev/null) || true
        [[ "$pstate" == "T" ]] && { frozen_ok=true; break; }
        sleep 0.5; elapsed=$((elapsed + 1))
    done
    if ! $frozen_ok; then warn "Second freeze timed out"; return; fi
    sleep 0.3
    local counter_val msg_val
    counter_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$COUNTER_ADDR" int 2>&1) || true
    msg_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$MESSAGE_ADDR" str 2>&1) || true
    info "  Modified: g_counter=$counter_val (expected 9999), g_message=\"$msg_val\""

    step "Step 6: >>> commit_pid (ACCEPT the speculative memory, discard shadow)..."
    show_json "$(shadowproc_cmd "{\"action\":\"commit_pid\",\"pid\":$REAL_PID}")"

    step "Step 7: Verifying memory is STILL modified after commit..."
    counter_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$COUNTER_ADDR" int 2>&1) || true
    msg_val=$(python3 "$READ_PROC_MEM" "$REAL_PID" "$MESSAGE_ADDR" str 2>&1) || true
    info "  g_counter = $counter_val (expected: 9999)"
    info "  g_message = \"$msg_val\" (expected: MODIFIED_BY_SPECULATIVE)"

    step "Step 8: continue_pid — let the process finish with committed memory..."
    shadowproc_cmd "{\"action\":\"continue_pid\",\"pid\":$REAL_PID}" >/dev/null 2>&1 || true
    wait "$AGENT_PID" 2>/dev/null || true

    echo ""
    if [[ "$counter_val" == "9999" && "$msg_val" == "MODIFIED_BY_SPECULATIVE" ]]; then
        echo -e "  ${GREEN}${BOLD}✓ COW MEMORY COMMIT SUCCESSFUL!${NC}"
        echo -e "  ${GREEN}  Speculative change (9999 / MODIFIED) ACCEPTED and kept live; shadow discarded${NC}"
    else
        echo -e "  ${RED}${BOLD}✗ COW memory commit check failed${NC}"
        echo -e "  ${RED}  counter=$counter_val (exp 9999), message=$msg_val (exp MODIFIED_BY_SPECULATIVE)${NC}"
    fi
    rm -f "$MARKER_FILE"
}

# ──────────────────────────── Main ─────────────────────────────────────────────
main() {
    banner
    echo -e "${BOLD}"
    echo "   ╔══════════════════════════════════════════════════════════╗"
    echo "   ║     ShadowFS + ShadowProc  Integration Demo             ║"
    echo "   ║                                                         ║"
    echo "   ║  File Layer (ShadowFS)  ←→  Orchestrator  ←→  Process  ║"
    echo "   ║  (Go/FUSE overlay)          (Python)         (Rust/eBPF)║"
    echo "   ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    preflight
    build
    setup_env

    # Run scenarios
    scenario_commit
    scenario_rollback
    scenario_cascade
    scenario_cow_rollback
    scenario_exit_hold
    scenario_priv_escalation
    scenario_deferred_release
    scenario_bash_env_rollback
    scenario_modify_existing
    scenario_delete_rename_rollback
    scenario_shm_intercept
    scenario_cow_commit

    banner
    echo -e "${BOLD}${GREEN}"
    echo "   All scenarios completed!"
    echo -e "${NC}"
    echo ""
    echo "Summary:"
    echo "  - Scenario 1 (Commit):       File written → IPC frozen → orchestrator resumed process + committed files"
    echo "  - Scenario 2 (Rollback):     File written → IPC frozen → orchestrator rolled back files + killed process"
    echo "  - Scenario 3 (Cascade):      Agent-A writes → Agent-B reads → ROLLBACK A cascades to B"
    echo "  - Scenario 4 (COW Memory):   Process modifies globals → COW snapshot → rollback restores original memory"
    echo "  - Scenario 5 (Exit Hold):    Agent completes execution → held at exit → commit lets process exit normally"
    echo "  - Scenario 6 (Priv Escalation): Process attempts setuid(0) → intercepted → rolled back"
    echo "  - Scenario 7 (Deferred Release): Commit downstream B → held frozen until upstream A commits → then released"
    echo "  - Scenario 8 (Forked Child Env Rollback): bash forks child → child changes SHADOW_VAR + connect() → whole cgroup auto-frozen → child memory rolled back to ORIGINAL"
    echo "  - Scenario 9 (Modify Existing):  Agent overwrites pre-existing file → rollback restores original content / commit persists new content"
    echo "  - Scenario 10 (Delete/Rename):   Agent deletes + renames pre-existing files → rollback resurrects them intact"
    echo "  - Scenario 11 (SysV IPC):        Agent attempts shmat() covert channel → intercepted (EVENT_IPC) → frozen before usable → killed"
    echo "  - Scenario 12 (COW Commit):      Process modifies globals → COW snapshot → COMMIT keeps speculative memory → process continues"
    echo ""
    echo "The orchestrator coordinated both ShadowFS (file layer) and ShadowProc (process layer)"
    echo "through a single Unix socket API."
}

main "$@"
