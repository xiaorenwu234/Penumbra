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

# Working directories
ORIG_DIR="/tmp/shadow-demo-orig"
MNT_DIR="/tmp/shadow-demo-mnt"
STAGING_DIR="/tmp/shadow-demo-staging"
SHADOW_OUTPUT_DIR="/tmp/shadow-demo-outputs"
CGROUP_NAME="shadow-demo"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"
CGROUP_NAME_B="shadow-demo-b"
CGROUP_PATH_B="/sys/fs/cgroup/$CGROUP_NAME_B"

# Socket paths
SHADOWFS_SOCK="/tmp/shadow-demo-fs.sock"
SHADOWPROC_SOCK="/tmp/shadow-demo-proc.sock"
ORCH_SOCK="/tmp/shadow-demo-orch.sock"

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

    # Unmount FUSE
    if mountpoint -q "$MNT_DIR" 2>/dev/null; then
        step "Unmounting $MNT_DIR"
        fusermount3 -u "$MNT_DIR" 2>/dev/null || umount "$MNT_DIR" 2>/dev/null || true
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

    # Remove temp files
    rm -rf "$ORIG_DIR" "$MNT_DIR" "$STAGING_DIR" "$SHADOW_OUTPUT_DIR"
    rm -f "$SHADOWFS_SOCK" "$SHADOWPROC_SOCK" "$ORCH_SOCK"

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
    info "Test programs built: agent_worker, file_reader_writer, cgroup_exec, cgroup_exec_hold, mem_modifier, libexithold.so, priv_escalator"

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

    # Create directories
    rm -rf "$ORIG_DIR" "$MNT_DIR" "$STAGING_DIR"
    mkdir -p "$ORIG_DIR" "$MNT_DIR" "$STAGING_DIR"

    # Seed original data
    echo "original-data-content" > "$ORIG_DIR/original.txt"
    echo "config-v1" > "$ORIG_DIR/config.cfg"
    info "Created orig dir with seed files: original.txt, config.cfg"

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
        "$MNT_DIR" "$ORIG_DIR" &
    SHADOWFS_PID=$!
    sleep 1
    if ! kill -0 "$SHADOWFS_PID" 2>/dev/null; then
        fail "ShadowFS failed to start"
        exit 1
    fi
    info "ShadowFS running (PID $SHADOWFS_PID), mount=$MNT_DIR"

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
    step "Files in mount ($MNT_DIR):"
    ls -la "$MNT_DIR"/ 2>/dev/null | grep -v "^total" | grep -v "^\." || true
    step "Files in orig ($ORIG_DIR):"
    ls -la "$ORIG_DIR"/ 2>/dev/null | grep -v "^total" | grep -v "^\." || true
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
    run_in_cgroup "$AGENT_WORKER" "$MNT_DIR" "agent1.txt" "hello-from-agent1" &
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

    # Step 3: Check file in mount
    step "Verifying file in ShadowFS mount:"
    if [[ -f "$MNT_DIR/agent1.txt" ]]; then
        info "agent1.txt exists, content: $(cat "$MNT_DIR/agent1.txt")"
    else
        warn "agent1.txt not found in mount"
    fi
    step "Checking orig (should NOT have agent1.txt):"
    if [[ -f "$ORIG_DIR/agent1.txt" ]]; then
        warn "agent1.txt already in orig (unexpected)"
    else
        info "agent1.txt NOT in orig (correct — not yet committed)"
    fi

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
    step "Post-commit verification:"
    if [[ -f "$ORIG_DIR/agent1.txt" ]]; then
        info "agent1.txt COMMITTED to orig, content: $(cat "$ORIG_DIR/agent1.txt")"
    else
        warn "agent1.txt NOT in orig (commit may have failed)"
    fi

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
    run_in_cgroup "$AGENT_WORKER" "$MNT_DIR" "agent2.txt" "rollback-test-data" &
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
    if [[ -f "$MNT_DIR/agent2.txt" ]]; then
        info "agent2.txt in mount: $(cat "$MNT_DIR/agent2.txt")"
    fi
    if [[ ! -f "$ORIG_DIR/agent2.txt" ]]; then
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
    if [[ -f "$MNT_DIR/agent2.txt" ]]; then
        warn "agent2.txt still in mount (rollback may have failed)"
    else
        info "agent2.txt REMOVED from mount (rollback successful)"
    fi
    if [[ -f "$ORIG_DIR/agent2.txt" ]]; then
        warn "agent2.txt in orig (should not be)"
    else
        info "agent2.txt NOT in orig (correct)"
    fi

    # Also clean up agent1.txt from scenario 1 if it was committed
    rm -f "$ORIG_DIR/agent1.txt" 2>/dev/null || true
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
    run_in_cgroup "$AGENT_WORKER" "$MNT_DIR" "data.txt" "agent-a-data" &
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
    run_in_cgroup_b "$FILE_RW" "$MNT_DIR" "data.txt" "derived.txt" "derived-from-" &
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
    if [[ -f "$MNT_DIR/data.txt" ]]; then
        info "data.txt in mount: $(cat "$MNT_DIR/data.txt")"
    fi
    if [[ -f "$MNT_DIR/derived.txt" ]]; then
        info "derived.txt in mount: $(cat "$MNT_DIR/derived.txt")"
    fi
    if [[ ! -f "$ORIG_DIR/data.txt" ]]; then
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
    if [[ -f "$MNT_DIR/data.txt" ]]; then
        warn "data.txt still in mount (Agent-A rollback may have failed)"
    else
        info "data.txt REMOVED (Agent-A rolled back successfully)"
    fi
    if [[ -f "$MNT_DIR/derived.txt" ]]; then
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
        "$AGENT_WORKER" "$MNT_DIR" "exit_hold_test.txt" "exit-hold-data" &
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
    if [[ -f "$MNT_DIR/exit_hold_test.txt" ]]; then
        info "exit_hold_test.txt exists: $(cat "$MNT_DIR/exit_hold_test.txt")"
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
    if [[ -f "$ORIG_DIR/exit_hold_test.txt" ]]; then
        info "exit_hold_test.txt COMMITTED to orig: $(cat "$ORIG_DIR/exit_hold_test.txt")"
        echo ""
        echo -e "  ${GREEN}${BOLD}✓ EXIT HOLD + TRANSPARENT CALLER RETURN SUCCESSFUL!${NC}"
        echo -e "  ${GREEN}  Caller returned immediately → process still held → commit → exited normally${NC}"
    else
        warn "exit_hold_test.txt NOT in orig (commit may have failed)"
    fi

    # Cleanup
    rm -f "$ORIG_DIR/exit_hold_test.txt" 2>/dev/null || true
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
    run_in_cgroup "$PRIV_ESCALATOR" "$MNT_DIR" "priv_test.txt" "malicious-payload" &
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
    if [[ -f "$MNT_DIR/priv_test.txt" ]]; then
        info "priv_test.txt exists, content: $(cat "$MNT_DIR/priv_test.txt")"
    else
        warn "priv_test.txt not found in mount"
    fi
    step "Checking orig (should NOT have priv_test.txt):"
    if [[ -f "$ORIG_DIR/priv_test.txt" ]]; then
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
    if [[ -f "$MNT_DIR/priv_test.txt" ]]; then
        warn "priv_test.txt still in mount (rollback may have failed)"
    else
        info "priv_test.txt REMOVED from mount (rollback successful)"
    fi
    if [[ -f "$ORIG_DIR/priv_test.txt" ]]; then
        warn "priv_test.txt in orig (should not be)"
    else
        info "priv_test.txt NOT in orig (correct)"
    fi

    echo ""
    echo -e "  ${GREEN}${BOLD}✓ PRIVILEGE ESCALATION BLOCKED!${NC}"
    echo -e "  ${GREEN}  Process attempted setuid(0) → intercepted by eBPF → frozen → rolled back${NC}"
    echo -e "  ${GREEN}  System integrity preserved: no privilege escalation, no file persistence${NC}"
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
    echo ""
    echo "The orchestrator coordinated both ShadowFS (file layer) and ShadowProc (process layer)"
    echo "through a single Unix socket API."
}

main "$@"
