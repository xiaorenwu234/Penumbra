#!/usr/bin/env bash
#
# run_demo_full.sh — End-to-end demo for ShadowFS + ShadowProc + ShadowObserve.
#
# This script demonstrates the full three-component integration:
#   - Scenario A: Audit PASS → file operations within allowed policy → commit
#   - Scenario B: Audit FAIL → file operations violate policy → rollback
#
# The flow for each scenario:
#   1. start_observe: Begin eBPF event observation for a cgroup
#   2. Process runs: performs file operations in the cgroup
#   3. submit_policy: Orchestrator freezes → audits → commit/rollback
#
# Requirements:
#   - Root privileges
#   - Linux kernel >= 5.15 with BPF LSM enabled
#   - cgroup v2 mounted at /sys/fs/cgroup
#   - Go, Rust (cargo), gcc, cmake, clang installed
#
# Usage:
#   sudo bash demo/run_demo_full.sh
#

set -euo pipefail

# ──────────────────── Fix PATH for sudo ─────────────────────────────────────────
if [[ -n "${SUDO_USER:-}" ]]; then
    SUDO_HOME=$(eval echo "~$SUDO_USER")
    for p in "$SUDO_HOME/.cargo/bin" "$HOME/.cargo/bin" "/usr/local/go/bin" "$SUDO_HOME/go/bin"; do
        if [[ -d "$p" ]]; then
            export PATH="$p:$PATH"
        fi
    done
    if [[ -d "$SUDO_HOME/.rustup" ]]; then
        export RUSTUP_HOME="$SUDO_HOME/.rustup"
    fi
    if [[ -d "$SUDO_HOME/.cargo" ]]; then
        export CARGO_HOME="$SUDO_HOME/.cargo"
    fi
fi
for p in "$HOME/.cargo/bin" "/usr/local/go/bin"; do
    if [[ -d "$p" ]]; then
        export PATH="$p:$PATH"
    fi
done
export GOPROXY="https://goproxy.cn,direct"

# ──────────────────────────── Paths ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_DIR="$SCRIPT_DIR"

SHADOWFS_BIN="$PROJECT_ROOT/ShadowFS/shadowfs"
SHADOWPROC_BIN="$PROJECT_ROOT/ShadowProc/target/release/shadow-proc"
SHADOWOBSERVE_BIN="$PROJECT_ROOT/ShadowObserve/build/observ_daemon"
ORCH_SCRIPT="$PROJECT_ROOT/orchestrator/shadow_orchestrator.py"
ORCH_CLIENT="$DEMO_DIR/orch_client.py"

# Working directories
ORIG_DIR="/tmp/shadow-full-demo-orig"
MNT_DIR="/tmp/shadow-full-demo-mnt"
STAGING_DIR="/tmp/shadow-full-demo-staging"
CGROUP_NAME="shadow-full-demo"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"

# Socket paths
SHADOWFS_SOCK="/tmp/shadow-full-fs.sock"
SHADOWPROC_SOCK="/tmp/shadow-full-proc.sock"
SHADOWOBSERVE_SOCK="/tmp/shadow-full-observe.sock"
ORCH_SOCK="/tmp/shadow-full-orch.sock"

# PIDs for cleanup
SHADOWFS_PID=""
SHADOWPROC_PID=""
SHADOWOBSERVE_PID=""
ORCH_PID=""

# Test programs
AGENT_WORKER="$DEMO_DIR/test_programs/agent_worker"
CGROUP_EXEC="$DEMO_DIR/test_programs/cgroup_exec"

# ──────────────────────────── Colors ───────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

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

    # Kill test processes in cgroup
    if [[ -f "$CGROUP_PATH/cgroup.procs" ]]; then
        while read -r pid; do
            kill -9 "$pid" 2>/dev/null || true
        done < "$CGROUP_PATH/cgroup.procs"
    fi

    for PID_VAR in ORCH_PID SHADOWOBSERVE_PID SHADOWFS_PID SHADOWPROC_PID; do
        eval "PID_VAL=\$$PID_VAR"
        if [[ -n "$PID_VAL" ]] && kill -0 "$PID_VAL" 2>/dev/null; then
            step "Stopping $PID_VAR (PID $PID_VAL)"
            kill "$PID_VAL" 2>/dev/null || true
            wait "$PID_VAL" 2>/dev/null || true
        fi
    done

    if mountpoint -q "$MNT_DIR" 2>/dev/null; then
        step "Unmounting $MNT_DIR"
        fusermount3 -u "$MNT_DIR" 2>/dev/null || umount "$MNT_DIR" 2>/dev/null || true
    fi

    if [[ -d "$CGROUP_PATH" ]]; then
        step "Removing cgroup $CGROUP_PATH"
        rmdir "$CGROUP_PATH" 2>/dev/null || true
    fi

    rm -rf "$ORIG_DIR" "$MNT_DIR" "$STAGING_DIR"
    rm -f "$SHADOWFS_SOCK" "$SHADOWPROC_SOCK" "$SHADOWOBSERVE_SOCK" "$ORCH_SOCK"

    info "Cleanup complete."
}

trap cleanup EXIT

# ──────────────────────────── Build ────────────────────────────────────────────
build() {
    section "Building components"

    # Test programs
    step "Compiling test programs..."
    gcc -o "$AGENT_WORKER" "$DEMO_DIR/test_programs/agent_worker.c" -Wall
    gcc -o "$CGROUP_EXEC" "$DEMO_DIR/test_programs/cgroup_exec.c" -Wall
    info "Test programs built"

    # ShadowFS
    step "Building ShadowFS..."
    (cd "$PROJECT_ROOT/ShadowFS" && go build -o shadowfs .)
    info "ShadowFS built"

    # ShadowProc
    step "Building ShadowProc..."
    (cd "$PROJECT_ROOT/ShadowProc" && cargo build --release 2>&1 | tail -3)
    info "ShadowProc built"

    # ShadowObserve
    step "Building ShadowObserve..."
    mkdir -p "$PROJECT_ROOT/ShadowObserve/build"
    (cd "$PROJECT_ROOT/ShadowObserve/build" && cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3 && make -j$(nproc) 2>&1 | tail -5)
    info "ShadowObserve built"
}

# ──────────────────────────── Setup ────────────────────────────────────────────
setup_env() {
    section "Setting up environment"

    rm -rf "$ORIG_DIR" "$MNT_DIR" "$STAGING_DIR"
    mkdir -p "$ORIG_DIR" "$MNT_DIR" "$STAGING_DIR"

    echo "original-data" > "$ORIG_DIR/original.txt"
    info "Created orig dir with seed files"

    mkdir -p "$CGROUP_PATH"
    info "Created cgroup: $CGROUP_PATH"

    # Start ShadowFS
    step "Starting ShadowFS..."
    "$SHADOWFS_BIN" \
        -staging "$STAGING_DIR" \
        -sock "$SHADOWFS_SOCK" \
        -allow-other \
        "$MNT_DIR" "$ORIG_DIR" &
    SHADOWFS_PID=$!
    sleep 1
    info "ShadowFS running (PID $SHADOWFS_PID)"

    # Start ShadowProc
    step "Starting ShadowProc..."
    "$SHADOWPROC_BIN" \
        --cgroup-path "$CGROUP_PATH" \
        --sock "$SHADOWPROC_SOCK" </dev/null &
    SHADOWPROC_PID=$!
    sleep 2
    info "ShadowProc running (PID $SHADOWPROC_PID)"

    # Start ShadowObserve
    step "Starting ShadowObserve daemon..."
    "$SHADOWOBSERVE_BIN" --sock "$SHADOWOBSERVE_SOCK" &
    SHADOWOBSERVE_PID=$!
    sleep 1
    info "ShadowObserve running (PID $SHADOWOBSERVE_PID)"

    # Start Orchestrator (with ShadowObserve)
    step "Starting Orchestrator..."
    python3 "$ORCH_SCRIPT" \
        --shadowfs-sock "$SHADOWFS_SOCK" \
        --shadowproc-sock "$SHADOWPROC_SOCK" \
        --shadowobserve-sock "$SHADOWOBSERVE_SOCK" \
        --listen "$ORCH_SOCK" &
    ORCH_PID=$!
    sleep 1
    info "Orchestrator running (PID $ORCH_PID), socket=$ORCH_SOCK"

    # Verify connectivity
    step "Verifying connectivity..."
    show_json "$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" list_agents 2>&1)"
}

# ──────────────────────────── Helpers ──────────────────────────────────────────
SHADOW_OUTPUT_DIR="${SHADOW_OUTPUT_DIR:-/tmp/shadow-demo-full-outputs}"
run_in_cgroup() {
    mkdir -p "$SHADOW_OUTPUT_DIR"
    local output_file="$SHADOW_OUTPUT_DIR/stdout-$$-$RANDOM"
    : > "$output_file"
    local cg_id="${SHADOW_CGROUP_ID_OVERRIDE:-/$CGROUP_NAME}"
    python3 "$ORCH_CLIENT" "$ORCH_SOCK" register_output \
        "cgroup_id=$cg_id" "output_file=$output_file" >/dev/null 2>&1 || true
    SHADOW_OUTPUT_FILE="$output_file" "$CGROUP_EXEC" "$CGROUP_PATH/cgroup.procs" "$@"
}

get_cgroup_id() {
    local probe_pid
    "$CGROUP_EXEC" "$CGROUP_PATH/cgroup.procs" sleep 30 &
    probe_pid=$!
    sleep 0.2
    local cg
    cg=$(grep '^0:' /proc/"$probe_pid"/cgroup 2>/dev/null | cut -d: -f3) || true
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    if [[ -n "$cg" ]]; then
        echo "$cg"
    else
        echo "/$CGROUP_NAME"
    fi
}

get_cgroup_inode() {
    stat -c '%i' "$CGROUP_PATH"
}

# ──────────────────────────── Scenario A: Audit PASS ──────────────────────────
scenario_audit_pass() {
    banner
    section "Scenario A: AUDIT PASS (operations within policy → commit)"
    echo -e "  ${YELLOW}Flow: start_observe → agent writes file → submit_policy (allow) → commit${NC}"
    echo ""

    local CGROUP_ID CGROUP_INODE
    CGROUP_ID=$(get_cgroup_id)
    CGROUP_INODE=$(get_cgroup_inode)
    info "Cgroup ID: $CGROUP_ID, Inode: $CGROUP_INODE"

    # Step 1: Start observation
    step "Step 1: Starting observation..."
    local observe_resp
    observe_resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" start_observe \
        "cgroup_id=$CGROUP_ID" "cgroup_inode=$CGROUP_INODE" 2>&1)
    show_json "$observe_resp"

    # Step 2: Agent performs file operations (writes to mount)
    step "Step 2: Agent writing file in cgroup..."
    run_in_cgroup "$AGENT_WORKER" "$MNT_DIR" "allowed_file.txt" "hello-allowed" &
    local AGENT_PID=$!
    sleep 2

    # Verify file exists in mount
    if [[ -f "$MNT_DIR/allowed_file.txt" ]]; then
        info "allowed_file.txt in mount: $(cat "$MNT_DIR/allowed_file.txt")"
    fi

    # Step 3: Submit policy (allows the operations that were performed)
    echo ""
    step "Step 3: Submitting policy (ALLOW CREATE+OPEN on $MNT_DIR/)..."
    local policy_resp
    policy_resp=$(python3 -c "
import json, socket, sys
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('$ORCH_SOCK')
f = sock.makefile('rw', buffering=1)
req = {
    'action': 'submit_policy',
    'cgroup_id': '$CGROUP_ID',
    'allowed_ops': [
        {'event_type': '*', 'action': 'allow', 'path_pattern': '$MNT_DIR/'},
        {'event_type': '*', 'action': 'allow', 'path_pattern': '/tmp/'},
        {'event_type': 'FORK', 'action': 'allow', 'path_pattern': ''},
        {'event_type': 'EXEC', 'action': 'allow', 'path_pattern': ''},
        {'event_type': 'EXIT', 'action': 'allow', 'path_pattern': ''}
    ]
}
f.write(json.dumps(req) + '\n')
f.flush()
resp = f.readline()
sock.close()
print(resp.strip())
" 2>&1)
    show_json "$policy_resp"

    # Step 4: Verify result
    echo ""
    step "Step 4: Verification..."
    local decision
    decision=$(echo "$policy_resp" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','unknown'))" 2>/dev/null || echo "unknown")

    if [[ "$decision" == "committed" ]]; then
        info "Decision: COMMITTED (audit passed!)"
        if [[ -f "$ORIG_DIR/allowed_file.txt" ]]; then
            info "File committed to orig: $(cat "$ORIG_DIR/allowed_file.txt")"
        fi
    else
        warn "Unexpected decision: $decision"
    fi

    # Cleanup agent
    wait "$AGENT_PID" 2>/dev/null || true

    # Remove committed file for next scenario
    rm -f "$ORIG_DIR/allowed_file.txt" 2>/dev/null || true
}

# ──────────────────────────── Scenario B: Audit FAIL ──────────────────────────
scenario_audit_fail() {
    banner
    section "Scenario B: AUDIT FAIL (operations violate policy → rollback)"
    echo -e "  ${YELLOW}Flow: start_observe → agent writes file → submit_policy (deny) → rollback${NC}"
    echo ""

    local CGROUP_ID CGROUP_INODE
    CGROUP_ID=$(get_cgroup_id)
    CGROUP_INODE=$(get_cgroup_inode)
    info "Cgroup ID: $CGROUP_ID, Inode: $CGROUP_INODE"

    # Step 1: Start observation
    step "Step 1: Starting observation..."
    local observe_resp
    observe_resp=$(python3 "$ORCH_CLIENT" "$ORCH_SOCK" start_observe \
        "cgroup_id=$CGROUP_ID" "cgroup_inode=$CGROUP_INODE" 2>&1)
    show_json "$observe_resp"

    # Step 2: Agent writes to a restricted path
    step "Step 2: Agent writing file (will be denied by policy)..."
    run_in_cgroup "$AGENT_WORKER" "$MNT_DIR" "forbidden_file.txt" "should-be-rolled-back" &
    local AGENT_PID=$!
    sleep 2

    if [[ -f "$MNT_DIR/forbidden_file.txt" ]]; then
        info "forbidden_file.txt in mount (before audit): $(cat "$MNT_DIR/forbidden_file.txt")"
    fi

    # Step 3: Submit policy that DENIES the operation
    echo ""
    step "Step 3: Submitting policy (DENY all writes to $MNT_DIR/)..."
    local policy_resp
    policy_resp=$(python3 -c "
import json, socket, sys
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('$ORCH_SOCK')
f = sock.makefile('rw', buffering=1)
req = {
    'action': 'submit_policy',
    'cgroup_id': '$CGROUP_ID',
    'allowed_ops': [
        {'event_type': 'CREATE', 'action': 'deny', 'path_pattern': '$MNT_DIR/'},
        {'event_type': 'FORK', 'action': 'allow', 'path_pattern': ''},
        {'event_type': 'EXIT', 'action': 'allow', 'path_pattern': ''}
    ]
}
f.write(json.dumps(req) + '\n')
f.flush()
resp = f.readline()
sock.close()
print(resp.strip())
" 2>&1)
    show_json "$policy_resp"

    # Step 4: Verify result
    echo ""
    step "Step 4: Verification..."
    local decision
    decision=$(echo "$policy_resp" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','unknown'))" 2>/dev/null || echo "unknown")

    if [[ "$decision" == "rolled_back" ]]; then
        info "Decision: ROLLED BACK (audit failed!)"
        if [[ -f "$MNT_DIR/forbidden_file.txt" ]]; then
            warn "forbidden_file.txt still in mount (rollback may have failed)"
        else
            info "forbidden_file.txt REMOVED from mount (rollback successful)"
        fi
        if [[ -f "$ORIG_DIR/forbidden_file.txt" ]]; then
            warn "forbidden_file.txt in orig (should not be)"
        else
            info "forbidden_file.txt NOT in orig (correct)"
        fi
    else
        warn "Unexpected decision: $decision"
    fi

    # Cleanup agent
    wait "$AGENT_PID" 2>/dev/null || true
}

# ──────────────────────────── Main ─────────────────────────────────────────────
main() {
    banner
    echo -e "${BOLD}"
    echo "   ╔══════════════════════════════════════════════════════════╗"
    echo "   ║   ShadowFS + ShadowProc + ShadowObserve Full Demo       ║"
    echo "   ║                                                         ║"
    echo "   ║   File Layer   ←→  Orchestrator  ←→  Process Layer      ║"
    echo "   ║   (ShadowFS)        (Python)         (ShadowProc)       ║"
    echo "   ║                       ↕                                  ║"
    echo "   ║              Observation Layer (ShadowObserve)           ║"
    echo "   ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Root check
    if [[ $EUID -ne 0 ]]; then
        fail "This demo must be run as root (sudo)"
        exit 1
    fi

    build
    setup_env

    # Run scenarios
    scenario_audit_pass
    scenario_audit_fail

    banner
    echo -e "${BOLD}${GREEN}"
    echo "   All scenarios completed!"
    echo -e "${NC}"
    echo ""
    echo "Summary:"
    echo "  - Scenario A (Audit Pass):  Agent writes → policy allows → files committed + process resumed"
    echo "  - Scenario B (Audit Fail):  Agent writes → policy denies → files rolled back + process killed"
    echo ""
    echo "The orchestrator coordinated all three layers:"
    echo "  ShadowFS (file layer) + ShadowProc (process layer) + ShadowObserve (audit/enforcement)"
}

main "$@"
