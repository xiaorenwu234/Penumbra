#!/bin/bash
# 构建 hs（binpash/hs dynamic-parallelizer，RQ3 对照基线）。
#   bash experiments/rq3/third_party/build_hs.sh      （无需 root）
#
# HsEngine 只使用 hs 的"执行器路径"（executor/run_command.sh +
# deps/try 子模块 + jit_runtime/pash_declare_vars.sh），因此本脚本只做：
#   1. 定位 hs 源树
#   2. 初始化 deps/try 子模块（binpash/try 的 hs 分支——带 -i/-L 扩展）
#   3. gcc 编译 executor（fd_util、set-diff）与 deps/try/utils
#      （try-commit、try-summary）
#
# 完整 hs 系统（scheduler/preprocessor/JIT runtime 跑整个脚本）另外需要
# Python 依赖（python_pkgs venv + requirements.txt）——HsEngine 不需要，
# 故默认跳过；如需完整系统请手工：
#   python3 -m venv <hs>/python_pkgs && <hs>/python_pkgs/bin/pip install \
#       -i https://pypi.org/simple --trusted-host pypi.org \
#       --trusted-host files.pythonhosted.org -r <hs>/requirements.txt
#   （本机 pip 全局配置指向不可用的镜像源，必须显式 -i + --trusted-host）
#
# 源码搜索顺序（与 framework/hs_engine.py 的运行时查找一致）：
#   1. $HS_ROOT
#   2. <RQ2>/hs               （用户克隆的默认位置）
#   3. <rq3>/third_party/hs
#
# 产物（原地构建）：
#   <hs>/executor/fd_util、<hs>/executor/set-diff
#   <hs>/deps/try/try（chmod +x）、<hs>/deps/try/utils/try-commit、
#   <hs>/deps/try/utils/try-summary

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
RQ2_ROOT="$(cd "$DIR/../../../.." && pwd)"

# ─── [1/4] 定位 hs 源码根 ─────────────────────────────────────────────────────
ENV_HS_ROOT="${HS_ROOT:-}"
HS_ROOT=""
for cand in "$ENV_HS_ROOT" "$RQ2_ROOT/hs" "$DIR/hs"; do
    if [ -n "$cand" ] && [ -f "$cand/executor/run_command.sh" ]; then
        HS_ROOT="$cand"
        break
    fi
done

if [ -z "$HS_ROOT" ]; then
    echo "ERROR: 找不到 hs 源码（需要 executor/run_command.sh）。请任选其一："
    echo "  - 设置 HS_ROOT=/path/to/hs 后重跑"
    echo "  - 把源码放到 $RQ2_ROOT/hs"
    echo "  - 把源码放到 $DIR/hs"
    exit 1
fi
echo "[build-hs] [1/4] 源码: $HS_ROOT"

# ─── [2/4] deps/try 子模块（binpash/try 的 hs 分支）───────────────────────────
echo "[build-hs] [2/4] 检查 deps/try 子模块 ..."
if [ ! -f "$HS_ROOT/deps/try/try" ]; then
    echo "[build-hs]   deps/try 为空，初始化子模块（binpash/try @ hs 分支）..."
    # 本机 CA 配置缺失，git 默认 TLS 校验会失败；该子模块是公开仓库，
    # 显式关闭校验（与上游 .gitmodules 的 branch=hs 对应）。
    ( cd "$HS_ROOT" && git -c http.sslVerify=false submodule update --init deps/try ) || {
        echo "ERROR: 子模块初始化失败（需要可访问 github.com/binpash/try）"
        echo "  也可手工克隆： git -c http.sslVerify=false clone -b hs \\"
        echo "      https://github.com/binpash/try.git $HS_ROOT/deps/try"
        exit 1
    }
fi
if [ ! -f "$HS_ROOT/deps/try/try" ]; then
    echo "ERROR: deps/try/try 仍不存在，请检查子模块状态"
    exit 1
fi
echo "[build-hs]   deps/try ok: $HS_ROOT/deps/try/try"

# ─── [3/4] 编译 C 工具 ───────────────────────────────────────────────────────
echo "[build-hs] [3/4] 编译 fd_util / set-diff / try utils ..."
command -v gcc >/dev/null 2>&1 || { echo "ERROR: 缺 gcc（apt install build-essential）"; exit 1; }
command -v make >/dev/null 2>&1 || { echo "ERROR: 缺 make"; exit 1; }
# 运行期依赖：run_command.sh/try 内部使用
for p in mktemp find sort df grep unshare strace nc; do
    command -v "$p" >/dev/null 2>&1 || { echo "ERROR: 缺 $p"; exit 1; }
done
make -C "$HS_ROOT/executor" >/dev/null
make -C "$HS_ROOT/deps/try/utils" >/dev/null
chmod +x "$HS_ROOT/deps/try/try" "$HS_ROOT/executor/run_command.sh" \
         "$HS_ROOT/jit_runtime/pash_declare_vars.sh" 2>/dev/null || true

# ─── [4/4] 校验 ───────────────────────────────────────────────────────────────
echo "[build-hs] [4/4] 校验产物 ..."
for f in executor/fd_util executor/run_command.sh \
         executor/template_script_to_execute.sh \
         jit_runtime/pash_declare_vars.sh \
         deps/try/try deps/try/utils/try-commit deps/try/utils/try-summary; do
    if [ ! -e "$HS_ROOT/$f" ]; then
        echo "ERROR: 产物缺失: $HS_ROOT/$f"
        exit 1
    fi
done
if [ ! -x "$HS_ROOT/executor/fd_util" ]; then
    echo "ERROR: fd_util 不可执行"
    exit 1
fi

echo ""
echo "[build-hs] 完成。"
echo "  hs        : $HS_ROOT"
echo "  fd_util   : $HS_ROOT/executor/fd_util"
echo "  内置 try  : $HS_ROOT/deps/try/try"
echo ""
echo "  快速自检   : sudo python3 run_baseline.py --smoke --engine hs"
echo ""
echo "  注: hs 的内置 try 分支 commit 走 try-commit -c（复制而非移动），"
echo "      commit 后沙箱 upperdir 按设计保留——HsEngine 以此为准校验。"
