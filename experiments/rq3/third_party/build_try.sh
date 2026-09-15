#!/bin/bash
# 构建 try（OSDI'26 论文代码，RQ3 主 baseline）。
#   bash experiments/rq3/third_party/build_try.sh      （无需 root）
#
# try 顶层是一个纯 POSIX sh 脚本，无需 autoconf/configure；只有两个可选的
# C 加速工具（try-commit / try-summary）需要 gcc。这里直接用 gcc 编译
# （与论文 AE 的 benchmarks/micro_benchmarks/scripts/setup.sh 相同做法，
#  绕开生成 Makefile 的流程）。缺了这两个工具 try 会退回纯 shell 实现——
# 语义正确但慢一个量级（per-file `mv` + `getfattr`），性能实验必须用 C 版。
#
# 源码搜索顺序（与 framework/try_engine.py 的运行时查找一致）：
#   1. $TRY_SRC
#   2. <RQ2>/try-osdi26-ae               （用户克隆的默认位置）
#   3. <rq3>/third_party/try-osdi26-ae   （自包含位置；不存在且没有解压后
#                                         的目录时，从本目录的 tar.gz 解压）
#
# 产物（原地构建）：
#   <try_root>/try                       （chmod +x）
#   <try_root>/utils/try-commit
#   <try_root>/utils/try-summary
# 运行时由 framework/try_engine.py 自动发现（也支持 TRY_BIN/TRY_UTILS_DIR
# 环境变量覆盖）。

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
RQ2_ROOT="$(cd "$DIR/../../../.." && pwd)"

# ─── [1/4] 定位 try 源码根 ────────────────────────────────────────────────────
TRY_ROOT=""
for cand in "${TRY_SRC:-}" "$RQ2_ROOT/try-osdi26-ae" \
            "$DIR/try-osdi26-ae"; do
    if [ -n "$cand" ] && [ -f "$cand/try" ]; then
        TRY_ROOT="$cand"
        break
    fi
done

if [ -z "$TRY_ROOT" ]; then
    TARBALL="$DIR/try-osdi26-ae.tar.gz"
    if [ -s "$TARBALL" ]; then
        echo "[build-try] [1/4] 解压 $TARBALL ..."
        tar xzf "$TARBALL" -C "$DIR"
        # tar 内可能带一层目录或直接展开，两种布局都兼容
        for cand in "$DIR/try-osdi26-ae" "$DIR/try"; do
            if [ -f "$cand/try" ]; then
                TRY_ROOT="$cand"
                break
            fi
        done
    fi
fi

if [ -z "$TRY_ROOT" ]; then
    echo "ERROR: 找不到 try 源码。请任选其一："
    echo "  - 设置 TRY_SRC=/path/to/try-osdi26-ae 后重跑"
    echo "  - 把源码放到 $RQ2_ROOT/try-osdi26-ae"
    echo "  - 把源码放到 $DIR/try-osdi26-ae（或放 tar.gz 到 $DIR）"
    exit 1
fi
echo "[build-try] [1/4] 源码: $TRY_ROOT"

# ─── [2/4] 依赖检查 ───────────────────────────────────────────────────────────
echo "[build-try] [2/4] 检查依赖 ..."
command -v gcc >/dev/null 2>&1 || { echo "ERROR: 缺 gcc（apt install build-essential）"; exit 1; }
command -v getfattr >/dev/null 2>&1 || { echo "ERROR: 缺 getfattr（apt install attr）"; exit 1; }
# 运行时依赖（try 脚本内部使用）：unshare/overlayfs 内核支持
for p in mktemp find sort df grep unshare; do
    command -v "$p" >/dev/null 2>&1 || { echo "ERROR: 缺 $p"; exit 1; }
done
modprobe overlay 2>/dev/null || true
lsmod | grep -q '^overlay' || echo "  警告: 未检测到 overlay 模块（若内核内置则正常）"

# ─── [3/4] 编译 C 工具 ────────────────────────────────────────────────────────
echo "[build-try] [3/4] 编译 try-commit / try-summary ..."
cd "$TRY_ROOT"
gcc -g -Wall -O2 -I utils -c utils/ignores.c      -o utils/ignores.o
gcc -g -Wall -O2 -I utils -c utils/try-summary.c  -o utils/try-summary.o
gcc -g -Wall -O2 -I utils -c utils/try-commit.c   -o utils/try-commit.o
gcc -g -Wall -O2 -o utils/try-summary utils/ignores.o utils/try-summary.o
gcc -g -Wall -O2 -o utils/try-commit  utils/ignores.o utils/try-commit.o

# ─── [4/4] 校验 ───────────────────────────────────────────────────────────────
echo "[build-try] [4/4] 校验产物 ..."
chmod +x "$TRY_ROOT/try"
for f in try utils/try-commit utils/try-summary; do
    if [ ! -x "$TRY_ROOT/$f" ]; then
        echo "ERROR: 产物缺失/不可执行: $TRY_ROOT/$f"
        exit 1
    fi
done

echo ""
echo "[build-try] 完成。"
echo "  try        : $TRY_ROOT/try"
echo "  try-commit : $TRY_ROOT/utils/try-commit"
echo "  快速自检   : bash $DIR/smoke_try.sh"
echo ""
echo "  注: RQ3 的 TryEngine 会为每次 commit 传绝对路径——上游 try-commit"
echo "      的 fts 遍历会 chdir，相对路径会导致 rename ENOENT（实测）。"
