#!/bin/bash
# RQ3 三系统串行实验运行器：Penumbra → try → hs
#
# 三段严格串行（性能测量不能共享机器）：
#   [1/3] Penumbra 全量（run_all.py，W1-W10）        -> results/rq3.json
#   [2/3] try 主基线（run_baseline.py --engine try） -> results/rq3_baseline_try.json
#   [3/3] hs 对照（run_baseline.py --engine hs）     -> results/rq3_baseline_hs.json
#
# 顺序理由：Penumbra 先跑，后两段结束时 run_baseline.py 能读到 rq3.json 并
# 在日志末尾打印并排对比表；try 先于 hs，优先保证主基线数据。
# overlayfs+CRIU 兜底版不在此脚本内，单独跑：
#   sudo ./experiments/rq3/start_and_run.sh baseline-criu
#
# 用法（需要 sudo —— mount / 守护进程管理；三段都以 root 运行）：
#   cd <repo>/speculative_shadow
#   sudo bash -c 'nohup ./experiments/rq3/run_three.sh >/dev/null 2>&1 & echo "started pid=$!"'
#
# 跟随进度：
#   tail -f experiments/rq3/logs/latest_penumbra.log   # 第 1 段
#   tail -f experiments/rq3/logs/latest_baseline.log   # 第 2 段（baseline = try 主基线）
#   tail -f experiments/rq3/logs/latest_hs.log         # 第 3 段
#
# 额外参数原样透传给每一段，例如冒烟（小规模快速过一遍三段链路）：
#   sudo ./experiments/rq3/run_three.sh --quick
#   sudo ./experiments/rq3/run_three.sh --workload 1,2 --quick
#
# 单段失败不中断后续段（三段相互独立）；三段退出码在末尾汇总，任一失败时
# 脚本以非零退出。

set -u

PROJ="/home/xht/桌面/penumbra-work/RQ2/speculative_shadow"
cd "$PROJ" || { echo "cannot cd to $PROJ" >&2; exit 1; }

# 透传给每一段的额外参数（--quick / --workload ... / --output-dir ...）。
EXTRA="$*"

LOGDIR="$PROJ/experiments/rq3/logs"
mkdir -p "$LOGDIR"

# 防重入（重复启动会互相踩踏 FUSE 挂载与 cgroup）。
PIDFILE="$LOGDIR/run_three.pid"
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[run_three] already running (pid $(cat "$PIDFILE")), refusing" >&2
    exit 1
fi
echo $$ > "$PIDFILE"
trap 'rm -f "$PIDFILE"' EXIT

STAMP="$(date +%Y%m%d_%H%M%S)"
PEN_LOG="$LOGDIR/rq3_penumbra_${STAMP}.log"
TRY_LOG="$LOGDIR/rq3_try_${STAMP}.log"
HS_LOG="$LOGDIR/rq3_hs_${STAMP}.log"
# 固定软链接便于 tail -f（latest_baseline.log = try 主基线）。
ln -sfn "$(basename "$PEN_LOG")" "$LOGDIR/latest_penumbra.log"
ln -sfn "$(basename "$TRY_LOG")" "$LOGDIR/latest_baseline.log"
ln -sfn "$(basename "$HS_LOG")" "$LOGDIR/latest_hs.log"

echo "[run_three] start  $(date '+%F %H:%M:%S')  args=${EXTRA:-<none>}"
echo "[run_three] Penumbra log: $PEN_LOG"
echo "[run_three] try log:      $TRY_LOG"
echo "[run_three] hs log:       $HS_LOG"

# ─── [1/3] Penumbra 全量 ───────────────────────────────────────────────
{
    echo "=== [1/3] Penumbra 全量 (W1-W10) — $(date '+%F %H:%M:%S') ==="
    ./experiments/rq3/start_and_run.sh all $EXTRA
    PEN_RC=$?
    echo ""
    echo "=== [1/3] Penumbra exit=$PEN_RC — $(date '+%F %H:%M:%S') ==="
} >> "$PEN_LOG" 2>&1
chmod a+r "$PEN_LOG"
echo "[run_three] [1/3] Penumbra exit=$PEN_RC (log: $PEN_LOG)"

# ─── [2/3] try 主基线 ──────────────────────────────────────────────────
{
    echo "=== [2/3] try 基线 (W1-W10) — $(date '+%F %H:%M:%S') ==="
    ./experiments/rq3/start_and_run.sh baseline $EXTRA
    TRY_RC=$?
    echo ""
    echo "=== [2/3] try exit=$TRY_RC — $(date '+%F %H:%M:%S') ==="
} >> "$TRY_LOG" 2>&1
chmod a+r "$TRY_LOG"
echo "[run_three] [2/3] try exit=$TRY_RC (log: $TRY_LOG)"

# ─── [3/3] hs 对照 ─────────────────────────────────────────────────────
{
    echo "=== [3/3] hs 基线 (W1-W10) — $(date '+%F %H:%M:%S') ==="
    ./experiments/rq3/start_and_run.sh baseline-hs $EXTRA
    HS_RC=$?
    echo ""
    echo "=== [3/3] hs exit=$HS_RC — $(date '+%F %H:%M:%S') ==="
} >> "$HS_LOG" 2>&1
chmod a+r "$HS_LOG"
echo "[run_three] [3/3] hs exit=$HS_RC (log: $HS_LOG)"

# ─── 汇总 ──────────────────────────────────────────────────────────────
SUMMARY="$LOGDIR/run_three_${STAMP}.summary"
{
    echo "RQ3 三系统串行实验 — 结束 $(date '+%F %H:%M:%S')"
    echo "  [1/3] Penumbra (all):      exit=$PEN_RC  log=$PEN_LOG"
    echo "  [2/3] try  (baseline):     exit=$TRY_RC  log=$TRY_LOG"
    echo "  [3/3] hs   (baseline-hs):  exit=$HS_RC  log=$HS_LOG"
    echo "  结果: experiments/rq3/results/rq3.json"
    echo "        experiments/rq3/results/rq3_baseline_try.json"
    echo "        experiments/rq3/results/rq3_baseline_hs.json"
} | tee "$SUMMARY"
chmod a+r "$SUMMARY"

if [ "$PEN_RC" -eq 0 ] && [ "$TRY_RC" -eq 0 ] && [ "$HS_RC" -eq 0 ]; then
    exit 0
fi
exit 1
