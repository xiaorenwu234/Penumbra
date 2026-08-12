#!/bin/bash
# RQ2 实验启动脚本
set -e

PROJ="/home/xht/桌面/penumbra-work/RQ2/speculative_shadow"
EXP="$PROJ/experiments"

echo "[1/6] 清理旧进程和挂载..."
pkill -9 -f shadow-proc 2>/dev/null || true
pkill -9 -f shadowfs 2>/dev/null || true
pkill -9 -f shadow-observe 2>/dev/null || true
umount -l /tmp/shadow-rq2-test/mnt 2>/dev/null || true
sleep 1
rm -f /tmp/shadow_proc.sock /tmp/shadowfs.sock /tmp/shadow_observe.sock

echo "[2/6] 准备目录..."
# 清理旧的 staging/WAL 数据，避免历史 epoch 状态干扰新运行
rm -rf /tmp/shadow-rq2-test/staging
rm -rf /tmp/shadow-rq2-test/orig
rm -f "$EXP/results/combined_results.json"
mkdir -p /tmp/shadow-rq2-test/{orig,staging,mnt}
mkdir -p /sys/fs/cgroup/shadow-rq2 2>/dev/null || true
echo "test-content" > /tmp/shadow-rq2-test/orig/test.txt
# 在 backing store 中预创建实验目录（FUSE 挂载后通过 mnt/ 可见）
mkdir -p /tmp/shadow-rq2-test/orig/{exp1,exp2,exp3,exp4,exp5}

# 构建 ShadowObserve (如果尚未构建)
if [ ! -x "$PROJ/ShadowObserve/build/observ_daemon" ]; then
    echo "  构建 ShadowObserve..."
    cd "$PROJ/ShadowObserve"
    mkdir -p build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
    make -j$(nproc) observ_daemon >/dev/null 2>&1 || echo "  WARNING: ShadowObserve 构建失败"
    cd "$EXP"
fi

echo "[3/6] 启动 ShadowFS..."
"$PROJ/ShadowFS/shadowfs" \
    -staging /tmp/shadow-rq2-test/staging \
    -sock /tmp/shadowfs.sock \
    -allow-other \
    /tmp/shadow-rq2-test/mnt \
    /tmp/shadow-rq2-test/orig \
    </dev/null >/var/tmp/shadowfs.log 2>&1 &
FS_PID=$!
sleep 2

echo "[4/6] 启动 ShadowProc..."
"$PROJ/ShadowProc/target/release/shadow-proc" \
    --sock /tmp/shadow_proc.sock \
    --cgroup-path /sys/fs/cgroup/shadow-rq2 \
    </dev/null >/var/tmp/shadowproc.log 2>&1 &
SP_PID=$!
sleep 3

# 验证
if ! kill -0 $SP_PID 2>/dev/null; then
    echo "ERROR: ShadowProc 启动失败"; cat /var/tmp/shadowproc.log; exit 1
fi
echo "  ShadowProc PID=$SP_PID OK"

if kill -0 $FS_PID 2>/dev/null; then
    echo "  ShadowFS PID=$FS_PID OK"
else
    echo "  WARNING: ShadowFS 未运行 (filesystem 测试将受限)"
fi

# 启动 ShadowObserve (如果二进制存在)
OBSERVE_PID=""
if [ -x "$PROJ/ShadowObserve/build/observ_daemon" ]; then
    echo "  启动 ShadowObserve..."
    "$PROJ/ShadowObserve/build/observ_daemon" \
        --sock /tmp/shadow_observe.sock \
        </dev/null >/var/tmp/shadowobserve.log 2>&1 &
    OBSERVE_PID=$!
    sleep 1
    if kill -0 $OBSERVE_PID 2>/dev/null; then
        echo "  ShadowObserve PID=$OBSERVE_PID OK"
        export SHADOWOBSERVE_SOCK=/tmp/shadow_observe.sock
    else
        echo "  WARNING: ShadowObserve 启动失败 (audit 测试将受限)"
    fi
else
    echo "  WARNING: ShadowObserve 二进制不存在，audit 测试将被 skip"
fi

# 连接测试
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/tmp/shadow_proc.sock')
f = s.makefile('rw')
f.write(json.dumps({'action': 'list_all_frozen'}) + '\n')
f.flush()
resp = json.loads(f.readline())
assert resp['status'] == 'ok', f'ShadowProc error: {resp}'
print('  ShadowProc 连接测试: OK')
s.close()
"

# 验证 FUSE 挂载
echo "[5/6] 验证 FUSE 挂载..."
if grep -q "/tmp/shadow-rq2-test/mnt" /proc/mounts 2>/dev/null; then
    echo "  FUSE 挂载点: /tmp/shadow-rq2-test/mnt OK"
    # 测试写入
    if touch /tmp/shadow-rq2-test/mnt/.fuse_test 2>/dev/null; then
        rm -f /tmp/shadow-rq2-test/mnt/.fuse_test
        echo "  FUSE 写入测试: OK"
    else
        echo "  WARNING: FUSE 写入失败 (可能需要 epoch 归属)"
    fi
else
    echo "  WARNING: FUSE 未挂载，文件测试将使用 backing store"
fi

echo "[6/6] 运行实验..."
cd "$EXP"
export SHADOW_RUN_RQ2_EXPERIMENTS=1
export SHADOWPROC_SOCK=/tmp/shadow_proc.sock
export SHADOWFS_SOCK=/tmp/shadowfs.sock
export SHADOWFS_MNT=/tmp/shadow-rq2-test/mnt
export SHADOWFS_ORIG=/tmp/shadow-rq2-test/orig
export SHADOWFS_STAGING=/tmp/shadow-rq2-test/staging

REPEATS="${1:-2}"
TRIALS="${2:-100}"

# Phase A: Run exp1-4 (BPF map accumulates entries)
python3 run_all.py --repeats "$REPEATS" --trials "$TRIALS" --skip-build --exp 1 --output-dir ./results
python3 run_all.py --repeats "$REPEATS" --trials "$TRIALS" --skip-build --exp 2 --output-dir ./results
python3 run_all.py --repeats "$REPEATS" --trials "$TRIALS" --skip-build --exp 3 --output-dir ./results
python3 run_all.py --repeats "$REPEATS" --trials "$TRIALS" --skip-build --exp 4 --output-dir ./results

# Phase B: Restart ShadowProc to get fresh BPF maps for exp5
echo ""
echo "######################################################################"
echo "  RESTARTING ShadowProc (fresh BPF maps for Exp5)"
echo "######################################################################"
kill -9 $SP_PID 2>/dev/null || true
sleep 1
rm -f /tmp/shadow_proc.sock
# Ensure cgroup path exists for the restarted daemon
mkdir -p /sys/fs/cgroup/shadow-rq2 2>/dev/null || true
"$PROJ/ShadowProc/target/release/shadow-proc" \
    --sock /tmp/shadow_proc.sock \
    --cgroup-path /sys/fs/cgroup/shadow-rq2 \
    </dev/null >/var/tmp/shadowproc.log 2>&1 &
SP_PID=$!
sleep 3
if ! kill -0 $SP_PID 2>/dev/null; then
    echo "ERROR: ShadowProc restart failed"; cat /var/tmp/shadowproc.log; exit 1
fi
# Wait for socket to appear (up to 10 seconds)
for i in $(seq 1 10); do
    if [ -S /tmp/shadow_proc.sock ]; then
        break
    fi
    sleep 1
done
if [ ! -S /tmp/shadow_proc.sock ]; then
    echo "ERROR: ShadowProc socket not created after restart"
    cat /var/tmp/shadowproc.log
    exit 1
fi
echo "  ShadowProc restarted PID=$SP_PID OK (socket ready)"

# Phase C: Run exp5 with fresh BPF maps
python3 run_all.py --repeats "$REPEATS" --trials "$TRIALS" --skip-build --exp 5 --output-dir ./results

echo ""
echo "=== 实验完成 ==="
echo "结果保存在: $EXP/results/"
