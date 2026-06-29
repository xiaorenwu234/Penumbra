#!/bin/bash
# manual_test.sh - 手动分步测试 ShadowProc
# 用法: 打开两个终端，按步骤执行
#
# 此脚本只输出步骤指引，不自动执行全部操作

cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║         ShadowProc 手动测试指南 (需要两个终端)               ║
╚══════════════════════════════════════════════════════════════╝

======== 终端 1: 启动 ShadowProc ========

# Step 1: 创建测试 cgroup
sudo mkdir -p /sys/fs/cgroup/shadowproc_test

# Step 2: 编译并启动 ShadowProc
cd /home/xht/Desktop/ShadowProc
export PATH="$HOME/.cargo/bin:$PATH"
cargo build
sudo ./target/debug/shadow-proc --cgroup-path /sys/fs/cgroup/shadowproc_test

# ShadowProc 会显示交互式提示符: shadow-proc>


======== 终端 2: 运行测试程序 ========

# Step 3: 编译测试程序
cd /home/xht/Desktop/ShadowProc/tests
gcc -o test_target test_target.c

# Step 4: 将 shell 加入监控 cgroup，然后运行测试
#   方法 A: 用 cgexec (如果安装了 cgroup-tools)
sudo cgexec -g :shadowproc_test ./test_target 0

#   方法 B: 手动操作
echo $$ | sudo tee /sys/fs/cgroup/shadowproc_test/cgroup.procs
./test_target 0

# 预期结果：测试程序在第一次 write(stdout) 时被冻结 (SIGSTOP)
# 你可以用 ps 查看:
#   ps aux | grep test_target   # 状态列应该显示 T (stopped)


======== 回到终端 1: 操作冻结的进程 ========

# 在 shadow-proc> 提示符下:
list                    # 查看被冻结的进程
continue <pid>          # 恢复进程 (会立即再次被拦截，因为恢复后syscall会重试)
discard <pid>           # 终止进程
checkpoint <pid>        # CRIU 快照 (需要安装 criu)


======== 测试单个拦截类型 ========

# 测试网络拦截:
./test_target 2         # TCP connect

# 测试 UDP:
./test_target 3         # UDP sendto

# 测试共享内存:
./test_target 4         # shmget

# 测试信号:
./test_target 5         # kill to pid 1


======== 清理 ========

sudo rmdir /sys/fs/cgroup/shadowproc_test

EOF
