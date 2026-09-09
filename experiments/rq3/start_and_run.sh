#!/bin/bash
# RQ3 性能实验启动脚本
# 启动 ShadowFS + ShadowProc + Orchestrator，然后运行 RQ3 实验
#
# 用法: start_and_run.sh <workload> [该实验自己的参数...]
#   all        run_all.py 的全部负载（默认）
#   <name>     run_all.py 的单个负载
#   dep        实验 B：dep_graph_scalability.py（依赖图形状 scaling）
#   multi      实验 A：multi_agent_scaling.py（agent 数量 scaling）
#   scaling    实验 A + 实验 B，依次跑完
#   baseline   overlayfs + CRIU 对照实验（不需要守护进程）
#   summarize  只汇总 results/ 下已有的 JSON（不需要守护进程）
#
# 例：sudo ./start_and_run.sh scaling --quick
set -e

PROJ="/home/xht/桌面/penumbra-work/RQ2/speculative_shadow"
EXP_RQ3="$PROJ/experiments/rq3"

# Socket paths
SHADOWFS_SOCK="/tmp/shadowfs.sock"
SHADOWPROC_SOCK="/tmp/shadow_proc.sock"
ORCH_SOCK="/tmp/shadow-orch.sock"

# 守护进程 pidfile。framework/resources.py 按 env → pidfile → /proc cmdline
# 的顺序发现 PID；实验进程本身拿到的是 env，pidfile 是给「守护进程还在、实验
# 另开一个终端跑」的情况留的，也是 pkill 之外唯一可靠的回收依据。
FS_PIDFILE="/var/tmp/shadowfs-rq3.pid"
SP_PIDFILE="/var/tmp/shadowproc-rq3.pid"
ORCH_PIDFILE="/var/tmp/orch-rq3.pid"

# ShadowFS paths (与 RQ2 共用)
BASE_DIR="/tmp/shadow-rq2-test"
ORIG_DIR="$BASE_DIR/orig"
MNT_DIR="$BASE_DIR/mnt"
STAGING_DIR="$BASE_DIR/staging"

echo "══════════════════════════════════════════════════════════"
echo "  RQ3 Performance Experiment Launcher"
echo "══════════════════════════════════════════════════════════"

# 解析参数
WORKLOAD="${1:-all}"
EXTRA_ARGS="${@:2}"

# ─── summarize 分支：只读 results/ 下已有的 JSON ──────────────────────────────
# 汇总不需要守护进程，也不应该因为 /tmp 里还挂着一个 FUSE 就跑不起来。
if [ "$WORKLOAD" = "summarize" ]; then
    cd "$EXP_RQ3"
    python3 summarize_scaling.py $EXTRA_ARGS
    exit $?
fi

# ─── baseline 分支：overlayfs + CRIU 对照实验 ─────────────────────────────────
# 不需要 ShadowFS/ShadowProc/Orchestrator，完全独立运行；负载与 Penumbra 实验
# 完全相同（共享 workloads.py），结果写入 results/rq3_baseline.json。
if [ "$WORKLOAD" = "baseline" ]; then
    echo "运行 overlayfs + CRIU 基线实验（无需守护进程）..."
    echo ""

    # 检查 CRIU：Ubuntu 24.04 (noble) 软件源中没有 criu 包，需要源码构建。
    # 优先 PATH / third_party 构建产物；都没有则自动触发构建（需 root）。
    # 注意源码构建布局：二进制在 criu-<ver>/criu/criu（嵌套子目录）。
    if ! command -v criu >/dev/null 2>&1 \
            && [ ! -x "$EXP_RQ3/third_party/criu-4.2.1/criu/criu" ]; then
        echo "[baseline] 未找到 CRIU，从源码构建（一次性，需要几分钟）..."
        bash "$EXP_RQ3/third_party/build_criu.sh" || {
            echo "ERROR: CRIU 构建失败，请检查上方日志"
            exit 1
        }
    fi

    cd "$EXP_RQ3"
    export SHADOW_RUN_RQ3_EXPERIMENTS=1
    python3 run_baseline.py $EXTRA_ARGS
    EXIT_CODE=$?

    echo ""
    echo "══════════════════════════════════════════════════════════"
    echo "  RQ3 baseline 实验完成 (exit=$EXIT_CODE)"
    echo "  结果: $EXP_RQ3/results/rq3_baseline.json"
    echo "══════════════════════════════════════════════════════════"
    exit $EXIT_CODE
fi

# ─── [1/7] 清理 ───────────────────────────────────────────────────────────────
echo "[1/7] 清理旧进程和挂载..."
pkill -9 -f shadow-proc 2>/dev/null || true
pkill -9 -f "shadowfs " 2>/dev/null || true
pkill -9 -f shadow_orchestrator 2>/dev/null || true
umount -l "$MNT_DIR" 2>/dev/null || true
sleep 1
rm -f "$SHADOWFS_SOCK" "$SHADOWPROC_SOCK" "$ORCH_SOCK"
rm -f "$FS_PIDFILE" "$SP_PIDFILE" "$ORCH_PIDFILE"
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
    echo "$FS_PID" > "$FS_PIDFILE"
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
    echo "$SP_PID" > "$SP_PIDFILE"
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
    echo "$ORCH_PID" > "$ORCH_PIDFILE"
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
# framework/resources.py 的第一发现路径。直接给 PID，避免它去扫 /proc 时
# 把上一轮没清干净的同类进程当成当前守护进程。
export SHADOW_FS_PID="$FS_PID"
export SHADOW_PROC_PID="$SP_PID"
export SHADOW_ORCH_PID="$ORCH_PID"

run_dep_graph() {
    echo "运行实验 B：依赖图形状 scaling (dep_graph_scalability.py)..."
    python3 dep_graph_scalability.py $EXTRA_ARGS
}

run_multi_agent() {
    echo "运行实验 A：multi-agent scaling (multi_agent_scaling.py)..."
    python3 multi_agent_scaling.py $EXTRA_ARGS
}

EXIT_CODE=0
case "$WORKLOAD" in
    dep|dep-graph)
        run_dep_graph || EXIT_CODE=$?
        ;;
    multi|multi-agent)
        run_multi_agent || EXIT_CODE=$?
        ;;
    scaling)
        # 两个实验共用同一批守护进程，但各自写自己的 results JSON。
        # A 先跑：它的 agent 数轴短，能在 B 的一小时长跑之前先暴露环境问题。
        run_multi_agent || EXIT_CODE=$?
        if [ "$EXIT_CODE" -eq 0 ]; then
            run_dep_graph || EXIT_CODE=$?
        else
            echo "实验 A 失败 (exit=$EXIT_CODE)，跳过实验 B"
        fi
        ;;
    *)
        python3 run_all.py --workload "$WORKLOAD" --skip-build $EXTRA_ARGS \
            || EXIT_CODE=$?
        ;;
esac

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
rm -f "$FS_PIDFILE" "$SP_PIDFILE" "$ORCH_PIDFILE"

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  RQ3 实验完成 (exit=$EXIT_CODE)"
echo "  结果: $EXP_RQ3/results/"
echo "══════════════════════════════════════════════════════════"
exit $EXIT_CODE
