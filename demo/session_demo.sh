#!/usr/bin/env bash
#
# session_demo.sh — Session Proxy demo for ShadowProc.
#
# Boots the minimal stack (just the ShadowProc daemon + one cgroup) and runs the
# Session Proxy's built-in commit/reject demo, which proves that a long-lived
# bash session can execute speculatively and then be COMMITted (state persists)
# or REJECTed (state losslessly restored) — with the agent using only a stable
# session_id and never touching a pid.
#
# Requirements: root; Linux >= 5.15 with BPF LSM; cgroup v2 at /sys/fs/cgroup;
# Rust (cargo) + gcc installed.
#
# Usage:  sudo bash demo/session_demo.sh
#
set -euo pipefail

# ──────────── Fix PATH for sudo (find cargo / rustup of the invoking user) ──────────
if [[ -n "${SUDO_USER:-}" ]]; then
    SUDO_HOME=$(eval echo "~$SUDO_USER")
    for p in "$SUDO_HOME/.cargo/bin" "$HOME/.cargo/bin"; do
        [[ -d "$p" ]] && export PATH="$p:$PATH"
    done
    [[ -d "$SUDO_HOME/.rustup" ]] && export RUSTUP_HOME="$SUDO_HOME/.rustup"
    [[ -d "$SUDO_HOME/.cargo" ]] && export CARGO_HOME="$SUDO_HOME/.cargo"
fi
[[ -d "$HOME/.cargo/bin" ]] && export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SHADOWPROC_BIN="$PROJECT_ROOT/ShadowProc/target/release/shadow-proc"
CGROUP_EXEC="$SCRIPT_DIR/test_programs/cgroup_exec"
PROXY="$PROJECT_ROOT/orchestrator/session_proxy.py"

CGROUP_NAME="shadow-session-boot"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"
SHADOWPROC_SOCK="/tmp/shadow-session-proc.sock"
SHADOWPROC_PID=""

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
step() { echo -e "  ${CYAN}→${NC} $1"; }
info() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }

cleanup() {
    echo ""
    step "Cleaning up..."
    # Kill any procs the daemon left in the boot cgroup.
    if [[ -f "$CGROUP_PATH/cgroup.procs" ]]; then
        while read -r p; do kill -9 "$p" 2>/dev/null || true; done < "$CGROUP_PATH/cgroup.procs"
    fi
    if [[ -n "$SHADOWPROC_PID" ]] && kill -0 "$SHADOWPROC_PID" 2>/dev/null; then
        kill "$SHADOWPROC_PID" 2>/dev/null || true
        wait "$SHADOWPROC_PID" 2>/dev/null || true
    fi
    rmdir "$CGROUP_PATH" 2>/dev/null || true
    rm -f "$SHADOWPROC_SOCK"
    info "Done."
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
    fail "This demo must be run as root (sudo)."
    exit 1
fi

echo -e "${BOLD}${CYAN}ShadowProc Session Proxy demo${NC}"

step "Building cgroup_exec helper..."
gcc -o "$CGROUP_EXEC" "$SCRIPT_DIR/test_programs/cgroup_exec.c" -Wall
info "cgroup_exec built"

step "Building ShadowProc (release)..."
(cd "$PROJECT_ROOT/ShadowProc" && cargo build --release 2>&1 | tail -3)
info "ShadowProc built"

step "Creating boot cgroup: $CGROUP_PATH"
mkdir -p "$CGROUP_PATH"

step "Starting ShadowProc daemon..."
"$SHADOWPROC_BIN" --cgroup-path "$CGROUP_PATH" --sock "$SHADOWPROC_SOCK" </dev/null &
SHADOWPROC_PID=$!
sleep 2
if ! kill -0 "$SHADOWPROC_PID" 2>/dev/null; then
    fail "ShadowProc daemon failed to start"
    exit 1
fi
info "ShadowProc running (PID $SHADOWPROC_PID), socket=$SHADOWPROC_SOCK"

echo ""
step "Running Session Proxy demo (agent uses session_id only)..."
echo ""
python3 "$PROXY" --sock "$SHADOWPROC_SOCK" --cgroup-exec "$CGROUP_EXEC" --demo
RC=$?

exit $RC
