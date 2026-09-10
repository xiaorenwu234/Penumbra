#!/bin/bash
# 完整 RQ3 套件串行跑：
#   开销轴  all      -> results/rq3.json (+ rq3.txt)         [需守护进程]
#   开销轴  baseline -> results/rq3_baseline.json            [无需守护进程; 末尾打印并排对比表]
#   扩展轴  scaling  -> results/multi_agent_scaling.json + dep_graph_scalability.json  [需守护进程; 含实验B长跑]
#   汇总    summarize-> results/scaling_*.csv                 [无需守护进程]
#
# 必须串行：三段都共用同一个 FUSE 挂载点与 shadow-* cgroup，并发会互相踩踏；
# 跑之前请让机器空闲。每段各自起停守护进程（start_and_run.sh 的 [1/7] 自带清理）。
#
# 后台运行（本脚本不以 set -e 中断，单段失败也继续跑完其余段并汇总 exit）：
#   cd /home/xht/桌面/penumbra-work/RQ2/speculative_shadow/experiments/rq3
#   sudo nohup ./run_full_rq3.sh > /var/tmp/rq3-full.log 2>&1 &
#
# 冒烟版（每段加 --quick，几分钟过一遍链路）：
#   sudo nohup ./run_full_rq3.sh --quick > /var/tmp/rq3-full.log 2>&1 &

cd "$(dirname "$0")" || exit 1

# 透传给每个实验段的额外参数（例如 --quick）。留空 = 完整正式跑。
EXTRA="$*"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

run_phase() {
    local mode="$1"
    echo ""
    echo "############################################################"
    echo "# [$(ts)] START  mode=$mode  args=${EXTRA:-<none>}"
    echo "############################################################"
    # 逐段独立进程；不用 set -e，捕获 exit 后继续。
    ./start_and_run.sh "$mode" $EXTRA
    local rc=$?
    echo "# [$(ts)] END    mode=$mode  exit=$rc"
    return $rc
}

overall=0
echo "=================================================================="
echo "[$(ts)] RQ3 FULL SUITE start (args=${EXTRA:-<none>})"
echo "=================================================================="

run_phase all       || overall=1
run_phase baseline  || overall=1
run_phase scaling   || overall=1

echo ""
echo "# [$(ts)] START  summarize"
./start_and_run.sh summarize || overall=1
echo "# [$(ts)] END    summarize"

echo ""
echo "=================================================================="
echo "[$(ts)] RQ3 FULL SUITE done  overall_exit=$overall"
echo "  结果目录: $(pwd)/results/"
echo "  守护进程日志: /var/tmp/{shadowfs,shadowproc,orch}-rq3.log"
echo "=================================================================="
exit $overall
