#!/bin/bash
# run_test.sh - ShadowProc 完整测试脚本
# 用法: sudo ./tests/run_test.sh
#
# 此脚本会:
# 1. 创建测试用 cgroup
# 2. 编译测试目标程序
# 3. 启动 ShadowProc 监控
# 4. 在 cgroup 中运行目标程序
# 5. 观察拦截效果

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CGROUP_PATH="/sys/fs/cgroup/shadowproc_test"
TEST_BIN="$SCRIPT_DIR/test_target"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   ShadowProc Integration Test Script     ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
echo

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script must be run as root (need CAP_BPF + cgroup access)${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

# Step 1: 编译测试目标程序
echo -e "${YELLOW}[1/5] Compiling test target...${NC}"
gcc -o "$TEST_BIN" "$SCRIPT_DIR/test_target.c" -Wall
echo -e "${GREEN}  -> Compiled: $TEST_BIN${NC}"

# Step 2: 编译 ShadowProc (如果需要)
echo -e "${YELLOW}[2/5] Building ShadowProc...${NC}"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$PROJECT_DIR"
cargo build --release 2>&1 | tail -3
SHADOW_BIN="$PROJECT_DIR/target/release/shadow-proc"
if [ ! -f "$SHADOW_BIN" ]; then
    SHADOW_BIN="$PROJECT_DIR/target/debug/shadow-proc"
fi
echo -e "${GREEN}  -> Built: $SHADOW_BIN${NC}"

# Step 3: 创建 cgroup
echo -e "${YELLOW}[3/5] Setting up cgroup...${NC}"
if [ ! -d "$CGROUP_PATH" ]; then
    mkdir -p "$CGROUP_PATH"
    echo -e "${GREEN}  -> Created cgroup: $CGROUP_PATH${NC}"
else
    echo -e "${GREEN}  -> Cgroup already exists: $CGROUP_PATH${NC}"
fi

# 确保 cgroup 控制器可用
# 对于 cgroup v2, 需要启用相关子系统
echo "+memory +pids" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true

# Step 4: 启动 ShadowProc
echo -e "${YELLOW}[4/5] Starting ShadowProc monitor...${NC}"
echo -e "${BLUE}  -> Monitoring cgroup: $CGROUP_PATH${NC}"
echo

$SHADOW_BIN --cgroup-path "$CGROUP_PATH" &
SHADOW_PID=$!
sleep 1

# 检查是否成功启动
if ! kill -0 $SHADOW_PID 2>/dev/null; then
    echo -e "${RED}[ERROR] ShadowProc failed to start. Check dmesg for BPF errors.${NC}"
    exit 1
fi

echo -e "${GREEN}  -> ShadowProc running (PID: $SHADOW_PID)${NC}"
echo

# Step 5: 在 cgroup 中运行测试程序
echo -e "${YELLOW}[5/5] Launching test target in monitored cgroup...${NC}"
echo -e "${BLUE}  -> The test program will attempt stdout write (should be intercepted)${NC}"
echo

# 先启动进程，再将其移入 cgroup
"$TEST_BIN" 0 &
TARGET_PID=$!
# 立即 SIGSTOP 防止在加入 cgroup 前就跑完
kill -STOP $TARGET_PID
# 将其加入被监控的 cgroup
echo $TARGET_PID > "$CGROUP_PATH/cgroup.procs"
# 恢复进程，让 eBPF 来接管监控
kill -CONT $TARGET_PID

echo -e "${GREEN}  -> Test target launched (PID: $TARGET_PID)${NC}"
echo -e "${YELLOW}  -> Wait a moment, then check ShadowProc output above...${NC}"
echo

# 等待一段时间观察结果
sleep 3

echo
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}  Test Results:${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"

# 检查目标进程状态
if kill -0 $TARGET_PID 2>/dev/null; then
    STATE=$(cat /proc/$TARGET_PID/status 2>/dev/null | grep "State:" || echo "State: unknown")
    echo -e "${GREEN}  Target process still alive: $STATE${NC}"
    if echo "$STATE" | grep -q "stopped"; then
        echo -e "${GREEN}  SUCCESS! Process was intercepted and frozen!${NC}"
    fi
else
    echo -e "${YELLOW}  Target process has exited (may have completed before interception)${NC}"
fi

echo
echo -e "${YELLOW}Interactive commands available in ShadowProc:${NC}"
echo "  list          - Show frozen processes"
echo "  continue $TARGET_PID - Resume the frozen process"
echo "  discard $TARGET_PID  - Kill the frozen process"
echo "  quit          - Exit ShadowProc"
echo
echo -e "${YELLOW}Press Ctrl+C to stop this script, or interact with ShadowProc above.${NC}"
echo -e "${YELLOW}ShadowProc PID: $SHADOW_PID${NC}"

# 等待用户操作
wait $SHADOW_PID 2>/dev/null || true

# 清理
echo -e "\n${YELLOW}[Cleanup] Removing test cgroup...${NC}"
kill $TARGET_PID 2>/dev/null || true
rmdir "$CGROUP_PATH" 2>/dev/null || true
echo -e "${GREEN}[Done]${NC}"
