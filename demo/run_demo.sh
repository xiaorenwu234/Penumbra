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
    rm -rf "$ORIG_DIR" "$MNT_DIR" "$STAGING_DIR"
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
    info "Test programs built: $AGENT_WORKER, $FILE_RW, $CGROUP_EXEC"

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
    # ShadowProc intercepts write() to stdout/stderr (fd 1/2) for all processes
    # in the monitored cgroup. Bash wrappers get frozen because bash internally
    # writes to stdout (job control, etc.) even after redirection.
    #
    # Fix: use a minimal C program (cgroup_exec) that:
    #   1. Writes NOTHING to stdout/stderr
    #   2. Moves itself into the cgroup via cgroup.procs
    #   3. exec()s the target command
    # This ensures no BPF interception before exec.
    "$CGROUP_EXEC" "$CGROUP_PATH/cgroup.procs" "$@"
}

run_in_cgroup_b() {
    # Same as run_in_cgroup but for Agent-B's separate cgroup (cross-agent cascade demo).
    "$CGROUP_EXEC" "$CGROUP_PATH_B/cgroup.procs" "$@"
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

    banner
    echo -e "${BOLD}${GREEN}"
    echo "   All scenarios completed!"
    echo -e "${NC}"
    echo ""
    echo "Summary:"
    echo "  - Scenario 1 (Commit):   File written → IPC frozen → orchestrator resumed process + committed files"
    echo "  - Scenario 2 (Rollback): File written → IPC frozen → orchestrator rolled back files + killed process"
    echo "  - Scenario 3 (Cascade):  Agent-A (cgroup-A) writes \u2192 frozen; Agent-B (cgroup-B) reads A's file \u2192 frozen; ROLLBACK A cascades to B \u2192 both files removed + both processes killed"
    echo ""
    echo "The orchestrator coordinated both ShadowFS (file layer) and ShadowProc (process layer)"
    echo "through a single Unix socket API."
}

main "$@"
