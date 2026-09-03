#!/bin/bash
# 从源码构建 CRIU（以 root 运行一次）：
#   sudo bash experiments/rq3/third_party/build_criu.sh
#
# 为什么不用 apt：Ubuntu 24.04 (noble) 的软件源中没有 criu 包
# （jammy 22.04 有 3.16，noble 被跳过，26.04 才回归），Linux Mint 22.3
# 基于 noble，因此只能源码构建。CRIU 4.2.1 对 6.x 内核支持良好。
#
# 产物：experiments/rq3/third_party/criu-4.2.1/criu/criu（嵌套 criu/ 子目录）
# 运行时由 framework/baseline_engine.py 自动发现（也支持 CRIU_BIN 覆盖）。
# 依赖代理时先在当前 shell 执行 vpn（export http_proxy/https_proxy）。

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/criu-4.2.1"
TARBALL="$DIR/criu-4.2.1.tar.gz"

echo "[build-criu] [1/3] 安装构建依赖 ..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential protobuf-compiler protobuf-c-compiler \
    libprotobuf-c-dev \
    libnl-3-dev libnl-route-3-dev libcap-dev libbsd-dev \
    uuid-dev \
    pkg-config zlib1g-dev

# CRIU 依赖链（按报错顺序累积的坑）：
#   - protobuf-compiler 提供 protoc 本体（CRIU 的 images/Makefile 直接调
#     protoc；protoc-gen-c 插件才在 protobuf-c-compiler 包）
#   - uuid-dev 提供 -luuid（criu/Makefile.packages 的 check-packages 会
#     用 try-cc 链接 -lprotobuf-c -lnl-3 ... -luuid，缺则 Compilation aborted）
#   - libbsd-dev/libnl-route-3-dev 为可选功能，但建议一并安装
command -v protoc >/dev/null 2>&1 || {
    echo "ERROR: protoc 仍不可用，请检查上方 apt-get 输出"
    exit 1
}
command -v protoc-gen-c >/dev/null 2>&1 || {
    echo "ERROR: protoc-gen-c 仍不可用，请检查上方 apt-get 输出"
    exit 1
}
[ -f /usr/include/uuid/uuid.h ] || {
    echo "ERROR: uuid-dev 安装失败（缺 /usr/include/uuid/uuid.h）"
    exit 1
}

echo "[build-criu] [2/3] 准备源码 ..."
if [ ! -d "$SRC" ]; then
    if [ ! -s "$TARBALL" ]; then
        echo "  下载 v4.2.1 源码 ..."
        curl -fL --retry 3 --retry-delay 2 -o "$TARBALL" \
            "https://codeload.github.com/checkpoint-restore/criu/tar.gz/refs/tags/v4.2.1"
    fi
    tar xzf "$TARBALL" -C "$DIR"
else
    echo "  已存在: $SRC"
fi

echo "[build-criu] [3/3] 构建（$(nproc) 线程）..."
# 只构建 criu 主二进制目标：实验只需要它；默认 all 目标还会构建
# pycriu（Python 绑定）等多余产物，且对非 root 重跑有权限问题。
make -C "$SRC" -j"$(nproc)" criu

BIN="$SRC/criu/criu"
if [ ! -x "$BIN" ]; then
    echo "ERROR: 构建产物 $BIN 不存在"
    exit 1
fi

echo ""
"$BIN" --version
echo ""
echo "[build-criu] 完成。二进制: $BIN"
echo "[build-criu] 建议 root 下运行 '$BIN check' 验证内核特性支持。"
