#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# RQ2 实验统一启动入口
#
# 该脚本负责：
#   1. 清理旧进程 / 挂载 / socket
#   2. 准备 backing store 与 FUSE 挂载目录
#   3. 启动四个组件（ShadowFS / ShadowProc / ShadowObserve / Orchestrator）
#      —— 任一组件未存活、socket 未连接、FUSE 未挂载 => 立即 exit 1（不再 warning）
#   4. 依次运行 exp1-5，结果写入时间戳目录，全过程写入时间戳日志
#
# 用法：
#   sudo ./start_and_run.sh [--basic-repeats N] [--dependency-repeats N]
#                           [--fault-repeats N] [--restart-repeats N]
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── 路径：一律从脚本位置推导，禁止硬编码绝对路径 ──────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(cd "$SCRIPT_DIR/../.." && pwd)"          # .../speculative_shadow
EXP="$PROJ/experiments/rq2"

# ── 组件二进制 / socket / 目录 ────────────────────────────────────────────
SHADOWFS_BIN="$PROJ/ShadowFS/shadowfs"
SHADOWPROC_BIN="$PROJ/ShadowProc/target/release/shadow-proc"
OBSERVE_BIN="$PROJ/ShadowObserve/build/observ_daemon"
ORCH_PY="$PROJ/orchestrator/shadow_orchestrator.py"

BASE="/tmp/shadow-rq2-test"
MNT="$BASE/mnt"
ORIG="$BASE/orig"
STAGING="$BASE/staging"
CGROOT="/sys/fs/cgroup/shadow-rq2"

PROC_SOCK="/tmp/shadow_proc.sock"
FS_SOCK="/tmp/shadowfs.sock"
OBSERVE_SOCK="/tmp/shadow_observe.sock"
ORCH_SOCK="/tmp/shadow-orch.sock"

# ── 默认实验参数（可被命令行覆盖）────────────────────────────────────────
BASIC_REPEATS=10          # exp1 (effect coverage), exp2 (audit consistency)
DEPENDENCY_REPEATS=5      # exp4 (dependency propagation)
FAULT_REPEATS=150         # exp5 (fail-closed / concurrency) trials per fault
RESTART_REPEATS=5         # exp3 (rollback / process-recovery correctness)

usage() {
    cat <<EOF
用法: sudo $0 [选项]
  --basic-repeats N       exp1/exp2 每个测试点重复次数 (默认 $BASIC_REPEATS)
  --dependency-repeats N  exp4 依赖传播重复次数 (默认 $DEPENDENCY_REPEATS)
  --fault-repeats N       exp5 每类故障试验次数 (默认 $FAULT_REPEATS)
  --restart-repeats N     exp3 回滚/恢复重复次数 (默认 $RESTART_REPEATS)
  -h, --help              显示本帮助
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --basic-repeats)      BASIC_REPEATS="${2:?}";      shift 2 ;;
        --dependency-repeats) DEPENDENCY_REPEATS="${2:?}"; shift 2 ;;
        --fault-repeats)      FAULT_REPEATS="${2:?}";      shift 2 ;;
        --restart-repeats)    RESTART_REPEATS="${2:?}";    shift 2 ;;
        -h|--help)            usage; exit 0 ;;
        *) echo "ERROR: 未知参数 '$1'" >&2; usage; exit 1 ;;
    esac
done

# ── 时间戳结果目录 / 日志文件 ─────────────────────────────────────────────
TS="$(date +%Y%m%d-%H%M%S)"
RESULTS_DIR="$EXP/results/rq2-final-$TS"
LOG_DIR="$EXP/logs"
LOG_FILE="$LOG_DIR/rq2-final-$TS.log"
mkdir -p "$RESULTS_DIR" "$LOG_DIR"

# 全过程同时输出到控制台与日志文件
exec > >(tee -a "$LOG_FILE") 2>&1

# ── 辅助函数 ──────────────────────────────────────────────────────────────
die() { echo "ERROR: $*" >&2; exit 1; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "必须以 root 运行（BPF / cgroup / FUSE 需要特权）：请使用 sudo"
    fi
}

# 等待一个 unix socket 出现（最多 timeout 秒）
wait_socket() {
    local sock="$1" timeout="$2" i
    for ((i = 1; i <= timeout; i++)); do
        if [ -S "$sock" ]; then return 0; fi
        sleep 1
    done
    return 1
}

# 验证进程存活
require_alive() {
    local pid="$1" name="$2" log="$3"
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "  --- $name 日志 (末尾) ---" >&2
        tail -n 40 "$log" >&2 2>/dev/null || true
        die "$name 启动失败 (pid=$pid 未存活)"
    fi
    echo "  $name PID=$pid 存活 OK"
}

# 连接测试：$1=socket $2=JSON 请求(可为空) $3=组件名
# 空请求 => 只验证 connect() 成功；非空 => 额外验证一次 status==ok 往返
sock_check() {
    local sock="$1" req="$2" name="$3" rc=0
    python3 - "$sock" "$req" "$name" <<'PY' || rc=$?
import socket, json, sys
sock, req, name = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock)
except Exception as e:
    print(f"    connect({name}) 失败: {e}"); sys.exit(1)
if req:
    try:
        f = s.makefile('rw')
        f.write(req + "\n"); f.flush()
        line = f.readline()
        if not line:
            print(f"    {name} 往返失败: 连接被关闭"); sys.exit(1)
        resp = json.loads(line)
        if resp.get("status") != "ok":
            print(f"    {name} 往返失败: {resp}"); sys.exit(1)
    except Exception as e:
        print(f"    {name} 往返失败: {e}"); sys.exit(1)
s.close()
print(f"  {name} socket 连接 OK" + ("（往返 status=ok）" if req else ""))
PY
    if [ "$rc" -ne 0 ]; then
        die "$name socket 连接测试失败 ($sock)"
    fi
}

# 运行单个实验：$1=exp 编号 $2=repeats $3=trials
# exit 2 (INFRA) => 组件异常，立即终止；exit 1 (violation) => 记录并继续
OVERALL_EXIT=0
run_exp() {
    local n="$1" repeats="$2" trials="$3" rc=0
    echo ""
    echo ">>> 运行 exp$n (repeats=$repeats trials=$trials) -> $RESULTS_DIR"
    python3 run_all.py --skip-build --exp "$n" \
        --repeats "$repeats" --trials "$trials" \
        --output-dir "$RESULTS_DIR" || rc=$?
    if [ "$rc" -eq 2 ]; then
        echo "ERROR: exp$n 报告 INFRASTRUCTURE ERROR (exit 2)：组件未正常运行，结果无效" >&2
        exit 2
    elif [ "$rc" -ne 0 ]; then
        echo "  exp$n 检测到 safety violations (exit $rc)"
        OVERALL_EXIT="$rc"
    fi
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
echo "======================================================================"
echo "  RQ2 实验统一入口  ($TS)"
echo "  PROJ=$PROJ"
echo "  结果目录: $RESULTS_DIR"
echo "  日志文件: $LOG_FILE"
echo "  参数: basic=$BASIC_REPEATS dependency=$DEPENDENCY_REPEATS" \
     "fault=$FAULT_REPEATS restart=$RESTART_REPEATS"
echo "======================================================================"

require_root

# ── [1/7] 清理旧进程和挂载 ────────────────────────────────────────────────
echo "[1/7] 清理旧进程和挂载..."
pkill -9 -f observ_daemon        2>/dev/null || true   # 二进制名，不是 shadow-observe
pkill -9 -f shadow_orchestrator  2>/dev/null || true
pkill -9 -f shadow-proc          2>/dev/null || true
pkill -9 -f shadowfs             2>/dev/null || true
umount -l "$MNT"                 2>/dev/null || true
sleep 1
rm -f "$PROC_SOCK" "$FS_SOCK" "$OBSERVE_SOCK" "$ORCH_SOCK"

# ── [2/7] 准备目录与 backing store ───────────────────────────────────────
echo "[2/7] 准备目录..."
rm -rf "$STAGING" "$ORIG"
mkdir -p "$ORIG" "$STAGING" "$MNT"
mkdir -p "$CGROOT" 2>/dev/null || true
echo "test-content" > "$ORIG/test.txt"
mkdir -p "$ORIG"/{exp1,exp2,exp3,exp4,exp5}

# ── [3/7] 校验/构建组件二进制（缺失即 fatal）────────────────────────────
echo "[3/7] 校验组件二进制..."
[ -x "$SHADOWFS_BIN" ]   || die "ShadowFS 二进制不存在或不可执行: $SHADOWFS_BIN (请先 make)"
[ -x "$SHADOWPROC_BIN" ] || die "ShadowProc 二进制不存在或不可执行: $SHADOWPROC_BIN (请先 cargo build --release)"
[ -f "$ORCH_PY" ]        || die "Orchestrator 脚本不存在: $ORCH_PY"

if [ ! -x "$OBSERVE_BIN" ]; then
    echo "  ShadowObserve 未构建，开始构建..."
    ( cd "$PROJ/ShadowObserve" && mkdir -p build && cd build \
      && cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null \
      && make -j"$(nproc)" observ_daemon >/dev/null ) \
      || die "ShadowObserve 构建失败（audit 验证是 exp1 的强制依赖）"
fi
[ -x "$OBSERVE_BIN" ] || die "ShadowObserve 构建后仍不可执行: $OBSERVE_BIN"
echo "  所有组件二进制就绪 OK"

# ── [4/7] 启动 ShadowFS + ShadowProc + ShadowObserve ─────────────────────
echo "[4/7] 启动核心守护进程..."

"$SHADOWFS_BIN" \
    -staging "$STAGING" \
    -sock "$FS_SOCK" \
    -allow-other \
    "$MNT" \
    "$ORIG" \
    </dev/null >/var/tmp/shadowfs.log 2>&1 &
FS_PID=$!
sleep 2
require_alive "$FS_PID" "ShadowFS" /var/tmp/shadowfs.log

"$SHADOWPROC_BIN" \
    --sock "$PROC_SOCK" \
    --cgroup-path "$CGROOT" \
    </dev/null >/var/tmp/shadowproc.log 2>&1 &
SP_PID=$!
sleep 3
require_alive "$SP_PID" "ShadowProc" /var/tmp/shadowproc.log

"$OBSERVE_BIN" \
    --sock "$OBSERVE_SOCK" \
    </dev/null >/var/tmp/shadowobserve.log 2>&1 &
OBSERVE_PID=$!
sleep 2
require_alive "$OBSERVE_PID" "ShadowObserve" /var/tmp/shadowobserve.log

# ── socket 就绪 + 连接测试（四个组件全部必须成功）────────────────────────
echo "  等待 socket 就绪..."
wait_socket "$FS_SOCK"      15 || { tail -n 40 /var/tmp/shadowfs.log >&2 || true;      die "ShadowFS socket 未创建: $FS_SOCK"; }
wait_socket "$PROC_SOCK"    15 || { tail -n 40 /var/tmp/shadowproc.log >&2 || true;    die "ShadowProc socket 未创建: $PROC_SOCK"; }
wait_socket "$OBSERVE_SOCK" 15 || { tail -n 40 /var/tmp/shadowobserve.log >&2 || true; die "ShadowObserve socket 未创建: $OBSERVE_SOCK"; }

sock_check "$FS_SOCK"      '{"action":"list_agents"}'      "ShadowFS"
sock_check "$PROC_SOCK"    '{"action":"list_all_frozen"}'  "ShadowProc"
sock_check "$OBSERVE_SOCK" ''                              "ShadowObserve"

# ── FUSE 挂载必须出现在 /proc/mounts ─────────────────────────────────────
echo "  验证 FUSE 挂载..."
if ! grep -q " $MNT " /proc/mounts 2>/dev/null; then
    tail -n 40 /var/tmp/shadowfs.log >&2 || true
    die "ShadowFS FUSE 未挂载于 $MNT (/proc/mounts 中未找到)"
fi
echo "  FUSE 挂载点 $MNT OK"

# ── [5/7] 启动 Orchestrator ──────────────────────────────────────────────
echo "[5/7] 启动 Orchestrator..."
python3 "$ORCH_PY" \
    --shadowfs-sock "$FS_SOCK" \
    --shadowproc-sock "$PROC_SOCK" \
    --shadowobserve-sock "$OBSERVE_SOCK" \
    --shadowfs-mount "$MNT" \
    --backing-dir "$ORIG:$STAGING" \
    --listen "$ORCH_SOCK" \
    </dev/null >/var/tmp/shadow-orchestrator.log 2>&1 &
ORCH_PID=$!
sleep 3
require_alive "$ORCH_PID" "Orchestrator" /var/tmp/shadow-orchestrator.log

wait_socket "$ORCH_SOCK" 15 || { tail -n 40 /var/tmp/shadow-orchestrator.log >&2 || true; die "Orchestrator socket 未创建: $ORCH_SOCK"; }
sock_check "$ORCH_SOCK" '{"action":"epoch_states"}' "Orchestrator"

# ── 导出实验运行所需环境变量 ─────────────────────────────────────────────
export SHADOW_RUN_RQ2_EXPERIMENTS=1
export SHADOWPROC_SOCK="$PROC_SOCK"
export SHADOWFS_SOCK="$FS_SOCK"
export SHADOWOBSERVE_SOCK="$OBSERVE_SOCK"
export PENUMBRA_ORCH_SOCK="$ORCH_SOCK"
export SHADOW_ORCH_SOCK="$ORCH_SOCK"
export SHADOWFS_MNT="$MNT"
export SHADOWFS_ORIG="$ORIG"
export SHADOWFS_STAGING="$STAGING"

echo "[6/7] 所有组件已就绪，开始运行实验..."
cd "$EXP"

# Phase A: exp1-4（BPF map 逐渐累积）
run_exp 1 "$BASIC_REPEATS"      "$FAULT_REPEATS"
run_exp 2 "$BASIC_REPEATS"      "$FAULT_REPEATS"
run_exp 3 "$RESTART_REPEATS"    "$FAULT_REPEATS"
run_exp 4 "$DEPENDENCY_REPEATS" "$FAULT_REPEATS"

# ── Phase B: 重启 ShadowProc 以获得干净的 BPF map（exp5 需要满容量）──────
echo ""
echo "######################################################################"
echo "  重启 ShadowProc（为 exp5 提供干净的 BPF map）"
echo "######################################################################"
kill -9 "$SP_PID" 2>/dev/null || true
sleep 1
rm -f "$PROC_SOCK"
mkdir -p "$CGROOT" 2>/dev/null || true
"$SHADOWPROC_BIN" \
    --sock "$PROC_SOCK" \
    --cgroup-path "$CGROOT" \
    </dev/null >/var/tmp/shadowproc.log 2>&1 &
SP_PID=$!
sleep 3
require_alive "$SP_PID" "ShadowProc(restarted)" /var/tmp/shadowproc.log
wait_socket "$PROC_SOCK" 15 || { tail -n 40 /var/tmp/shadowproc.log >&2 || true; die "ShadowProc 重启后 socket 未创建"; }
sock_check "$PROC_SOCK" '{"action":"list_all_frozen"}' "ShadowProc(restarted)"

# ── Phase C: exp5（干净 BPF map）─────────────────────────────────────────
run_exp 5 "$BASIC_REPEATS" "$FAULT_REPEATS"

# ── [7/7] 汇总 ───────────────────────────────────────────────────────────
echo ""
echo "[7/7] === 实验完成 ==="
echo "结果目录: $RESULTS_DIR"
echo "日志文件: $LOG_FILE"
echo "组合结果: $RESULTS_DIR/combined_results.json"
if [ "$OVERALL_EXIT" -ne 0 ]; then
    echo "警告: 至少一个实验检测到 safety violations (exit=$OVERALL_EXIT)"
fi
exit "$OVERALL_EXIT"
