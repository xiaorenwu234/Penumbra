#!/bin/bash
# RQ3 back-to-back experiment runner: full Penumbra suite (W1-W10), then
# the overlayfs+CRIU baseline (same workloads). Logs go to separate files
# under experiments/rq3/logs/.
#
# Usage (sudo required — mount/criu/daemon management):
#   cd <repo>/speculative_shadow
#   sudo bash -c 'nohup ./experiments/rq3/run_both.sh >/dev/null 2>&1 & echo "started pid=$!"'
#
# Then follow progress:
#   tail -f experiments/rq3/logs/latest_penumbra.log    # phase 1
#   tail -f experiments/rq3/logs/latest_baseline.log    # phase 2
#
# Ordering: Penumbra FIRST so results/rq3.json exists when the baseline
# finishes — run_baseline.py then prints the side-by-side comparison table
# as its final output. The two runs are strictly serial (performance
# measurements must not share the machine).
#
# A failed first phase does NOT abort the second (they are independent);
# exit codes for both are reported at the end and the script exits
# non-zero if either failed.

set -u

PROJ="/home/xht/桌面/penumbra-work/RQ2/speculative_shadow"
cd "$PROJ" || { echo "cannot cd to $PROJ" >&2; exit 1; }

LOGDIR="$PROJ/experiments/rq3/logs"
mkdir -p "$LOGDIR"

# Guard against double-launch (would corrupt both experiments' data).
PIDFILE="$LOGDIR/run_both.pid"
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[run_both] already running (pid $(cat "$PIDFILE")), refusing" >&2
    exit 1
fi
echo $$ > "$PIDFILE"
trap 'rm -f "$PIDFILE"' EXIT

STAMP="$(date +%Y%m%d_%H%M%S)"
PEN_LOG="$LOGDIR/rq3_penumbra_${STAMP}.log"
BASE_LOG="$LOGDIR/rq3_baseline_${STAMP}.log"
# Stable names for tail -f convenience.
ln -sfn "$(basename "$PEN_LOG")" "$LOGDIR/latest_penumbra.log"
ln -sfn "$(basename "$BASE_LOG")" "$LOGDIR/latest_baseline.log"

echo "[run_both] start  $(date '+%F %H:%M:%S')"
echo "[run_both] Penumbra log: $PEN_LOG"
echo "[run_both] Baseline log: $BASE_LOG"

# ─── [1/2] Penumbra full suite ─────────────────────────────────────────
{
    echo "=== [1/2] Penumbra full suite (W1-W10) — $(date '+%F %H:%M:%S') ==="
    ./experiments/rq3/start_and_run.sh all
    PEN_RC=$?
    echo ""
    echo "=== Penumbra exit=$PEN_RC — $(date '+%F %H:%M:%S') ==="
} >> "$PEN_LOG" 2>&1
chmod a+r "$PEN_LOG"
echo "[run_both] Penumbra exit=$PEN_RC (log: $PEN_LOG)"

# ─── [2/2] overlayfs+CRIU baseline ─────────────────────────────────────
{
    echo "=== [2/2] overlayfs+CRIU baseline (W1-W10) — $(date '+%F %H:%M:%S') ==="
    ./experiments/rq3/start_and_run.sh baseline
    BASE_RC=$?
    echo ""
    echo "=== Baseline exit=$BASE_RC — $(date '+%F %H:%M:%S') ==="
} >> "$BASE_LOG" 2>&1
chmod a+r "$BASE_LOG"
echo "[run_both] Baseline exit=$BASE_RC (log: $BASE_LOG)"

# ─── Summary ────────────────────────────────────────────────────────────
SUMMARY="$LOGDIR/run_both_${STAMP}.summary"
{
    echo "RQ3 back-to-back run — finished $(date '+%F %H:%M:%S')"
    echo "  Penumbra (all):  exit=$PEN_RC  log=$PEN_LOG"
    echo "  Baseline (all):  exit=$BASE_RC  log=$BASE_LOG"
    echo "  Results: experiments/rq3/results/rq3.json + rq3_baseline.json"
} | tee "$SUMMARY"
chmod a+r "$SUMMARY"

if [ "$PEN_RC" -eq 0 ] && [ "$BASE_RC" -eq 0 ]; then
    exit 0
fi
exit 1
