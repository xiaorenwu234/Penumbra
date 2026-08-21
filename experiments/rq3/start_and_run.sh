#!/bin/bash
# RQ3 性能实验启动脚本
# 启动 ShadowFS + ShadowProc + Orchestrator，然后运行 RQ3 实验
set -e

PROJ="/home/xht/桌面/penumbra-work/RQ2/speculative_shadow"
EXP_RQ3="$PROJ/experiments/rq3"

# Socket paths
SHADOWFS_SOCK="/tmp/shadowfs.sock"
SHADOWPROC_SOCK="/tmp/shadow_proc.sock"
ORCH_SOCK="/tmp/shadow-orch.sock"

# ShadowFS paths (与 RQ2 共用)
BASE_DIR="/tmp/shadow-rq2-test"
ORIG_DIR="$BASE_DIR/orig"
MNT_DIR="$BASE_DIR/mnt"
STAGING_DIR="$BASE_DIR/staging"

echo "══════════════════════════════════════════════════════════"
echo "  RQ3 Performance Experiment Launcher"
echo "══════════════════════════════════════════════════════════"

# ─── [1/7] 清理 ───────────────────────────────────────────────────────────────
echo "[1/7] 清理旧进程和挂载..."
pkill -9 -f shadow-proc 2>/dev/null || true
pkill -9 -f "shadowfs " 2>/dev/null || true
pkill -9 -f shadow_orchestrator 2>/dev/null || true
umount -l "$MNT_DIR" 2>/dev/null || true
sleep 1
rm -f "$SHADOWFS_SOCK" "$SHADOWPROC_SOCK" "$ORCH_SOCK"
# 清理旧 journal：orchestrator 启动时会把整个 journal 读入内存做崩溃恢复。
# 旧版记录的是每个 epoch 的全量 transcript（O(n²)），一次正式实验可达几十 GB，
# 不清理会导致重启时 load 慢甚至二次 OOM。实验环境每次全新启动，无跨启动
# 恢复需求，直接删除。
rm -f /tmp/shadow-orchestrator.journal /tmp/shadow-orchestrator.journal.tmp

# ─── [2/7] 准备目录 ───────────────────────────────────────────────────────────
echo "[2/7] 准备目录..."
rm -rf "$STAGING_DIR"
mkdir -p "$ORIG_DIR" "$STAGING_DIR" "$MNT_DIR"
mkdir -p /sys/fs/cgroup/shadow-rq2 2>/dev/null || true
# 创建 RQ3 工作目录
mkdir -p "$ORIG_DIR/rq3-work"

# ─── [3/7] 构建 benchmark ─────────────────────────────────────────────────────
echo "[3/7] 构建 benchmark 程序..."
make -C "$EXP_RQ3/benchmarks" all 2>&1 | tail -3
echo "  Done"

# ─── [4/7] 启动 ShadowFS ──────────────────────────────────────────────────────
echo "[4/7] 启动 ShadowFS..."
"$PROJ/ShadowFS/shadowfs" \
    -staging "$STAGING_DIR" \
    -sock "$SHADOWFS_SOCK" \
    -allow-other \
    "$MNT_DIR" \
    "$ORIG_DIR" \
    </dev/null >/var/tmp/shadowfs-rq3.log 2>&1 &
FS_PID=$!
sleep 2

if kill -0 $FS_PID 2>/dev/null; then
    echo "  ShadowFS PID=$FS_PID OK"
else
    echo "ERROR: ShadowFS 启动失败"
    cat /var/tmp/shadowfs-rq3.log
    exit 1
fi

# 验证 FUSE 挂载
if grep -q "$MNT_DIR" /proc/mounts 2>/dev/null; then
    echo "  FUSE 挂载: $MNT_DIR OK"
else
    echo "ERROR: FUSE 未挂载"
    exit 1
fi

# ─── [5/7] 启动 ShadowProc ────────────────────────────────────────────────────
echo "[5/7] 启动 ShadowProc..."
"$PROJ/ShadowProc/target/release/shadow-proc" \
    --sock "$SHADOWPROC_SOCK" \
    --cgroup-path /sys/fs/cgroup/shadow-rq2 \
    </dev/null >/var/tmp/shadowproc-rq3.log 2>&1 &
SP_PID=$!
sleep 3

if kill -0 $SP_PID 2>/dev/null; then
    echo "  ShadowProc PID=$SP_PID OK"
else
    echo "ERROR: ShadowProc 启动失败"
    cat /var/tmp/shadowproc-rq3.log
    exit 1
fi

# ─── [6/7] 启动 Orchestrator ──────────────────────────────────────────────────
echo "[6/7] 启动 Orchestrator..."
python3 "$PROJ/orchestrator/shadow_orchestrator.py" \
    --shadowfs-sock "$SHADOWFS_SOCK" \
    --shadowproc-sock "$SHADOWPROC_SOCK" \
    --listen "$ORCH_SOCK" \
    --shadowfs-mount "$MNT_DIR" \
    --backing-dir "$STAGING_DIR:$ORIG_DIR" \
    </dev/null >/var/tmp/orch-rq3.log 2>&1 &
ORCH_PID=$!
sleep 2

if kill -0 $ORCH_PID 2>/dev/null; then
    echo "  Orchestrator PID=$ORCH_PID OK"
else
    echo "ERROR: Orchestrator 启动失败"
    cat /var/tmp/orch-rq3.log
    exit 1
fi

# 等待 socket
for i in $(seq 1 10); do
    [ -S "$ORCH_SOCK" ] && break
    sleep 1
done
if [ ! -S "$ORCH_SOCK" ]; then
    echo "ERROR: Orchestrator socket 未创建"
    cat /var/tmp/orch-rq3.log
    exit 1
fi
echo "  Socket: $ORCH_SOCK OK"

# 连接测试
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$ORCH_SOCK')
f = s.makefile('rw')
f.write(json.dumps({'action': 'list_agents'}) + '\n')
f.flush()
resp = json.loads(f.readline())
assert resp.get('status') == 'ok', f'Orchestrator error: {resp}'
print('  Orchestrator 连接测试: OK')
s.close()
"

# ─── [7/7] 运行实验 ───────────────────────────────────────────────────────────
echo "[7/7] 运行 RQ3 实验..."
echo ""

cd "$EXP_RQ3"
export SHADOW_RUN_RQ3_EXPERIMENTS=1
export SHADOW_ORCH_SOCK="$ORCH_SOCK"
export SHADOWFS_MNT="$MNT_DIR"
export SHADOWFS_ORIG="$ORIG_DIR"
export SHADOWFS_STAGING="$STAGING_DIR"

# 解析参数
WORKLOAD="${1:-all}"
EXTRA_ARGS="${@:2}"

# 支持 "dep" 或 "dep-graph" 参数运行依赖图扩展性实验
if [ "$WORKLOAD" = "dep" ] || [ "$WORKLOAD" = "dep-graph" ]; then
    echo "运行依赖图扩展性实验..."
    python3 dep_graph_scalability.py $EXTRA_ARGS
else
    python3 run_all.py --workload "$WORKLOAD" --skip-build $EXTRA_ARGS
fi

EXIT_CODE=$?

# ─── 清理 ─────────────────────────────────────────────────────────────────────
echo ""
echo "清理守护进程..."
# 顺序：orchestrator → ShadowProc → ShadowFS（orchestrator 持有前两者的连接）
# 先 SIGTERM，等 2 秒，不死则 SIGKILL。避免 wait 无限阻塞。
for pid in $ORCH_PID $SP_PID $FS_PID; do
    kill "$pid" 2>/dev/null || true
done
sleep 2
for pid in $ORCH_PID $SP_PID $FS_PID; do
    kill -9 "$pid" 2>/dev/null || true
done
# 不 wait（进程可能已被 SIGKILL，wait 可能卡住）
umount -l "$MNT_DIR" 2>/dev/null || true
rm -f "$SHADOWFS_SOCK" "$SHADOWPROC_SOCK" "$ORCH_SOCK"

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  RQ3 实验完成 (exit=$EXIT_CODE)"
echo "  结果: $EXP_RQ3/results/"
echo "══════════════════════════════════════════════════════════"
exit $EXIT_CODE
