# Penumbra

统一的推测执行（Speculative Execution）框架，将 **ShadowFS**（文件系统层）、**ShadowProc**（进程层）和 **ShadowObserve**（观测与执行层）整合为一个协调系统，对 cgroup 中进程的文件操作、进程间通信和系统调用进行拦截、审计、提交与回滚。

核心抽象：agent 在一个 **session** 中执行工具调用，每次调用是一个 **speculative epoch**——进程状态（环境变量、内存）和文件系统变更被原子地 commit 或 rollback，agent 只看到一个稳定的 `session_id`，永远不接触底层 pid。

## 架构概览

```
                         ┌──────────────────────────────┐
                         │   Python Orchestrator         │
                         │   (Unix socket JSON-line API) │
                         │   + Session Proxy             │
                         │   + Durable Journal           │
                         └──┬──────────┬──────────┬─────┘
                            │          │          │
                 ┌──────────▼──┐ ┌─────▼──────┐ ┌▼──────────────┐
                 │  ShadowFS   │ │ ShadowProc │ │ ShadowObserve │
                 │  (Go/FUSE)  │ │ (Rust/eBPF)│ │   (C++/eBPF)  │
                 │  文件系统层   │ │   进程层    │ │  观测与执行层   │
                 └─────────────┘ └────────────┘ └───────────────┘
```

| 组件 | 职责 | 技术栈 |
|------|------|--------|
| **ShadowFS** | 基于 FUSE 的覆盖文件系统，写时复制追踪文件操作，依赖图级联回滚，WAL 崩溃安全，epoch 生命周期管理 | Go, go-fuse v2 |
| **ShadowProc** | 基于 eBPF 的进程围栏，拦截网络/IPC/信号/ptrace/权限提升；COW 内存追踪（baseline/candidate fork 模型） | Rust, eBPF (LSM + fmod_ret), ptrace |
| **ShadowObserve** | eBPF 文件系统事件监控 + 规则审计引擎 + LSM 白名单强制执行 | C++, eBPF (tracepoint + LSM), libbpf |
| **Orchestrator** | 统一编排器 + Session Proxy，协调三组件的 commit/rollback/audit/enforce；持久化日志保证崩溃恢复确定性 | Python |

## 核心工作流

### 推测执行 Epoch（Session 模式）

```
agent → session_open → Orchestrator
     └─ 启动 bash 到监控 cgroup，返回 session_id

agent → session_begin_epoch(sid) → Orchestrator
     ├─ ShadowProc: 冻结当前 shell → 作为 pristine baseline
     ├─ ShadowProc: fork COW candidate → 恢复为 live shell
     └─ ShadowFS:   begin_epoch（标记 epoch 边界）

agent → session_run(sid, cmd) → Orchestrator
     └─ 命令在 candidate 上执行；输出为 SPECULATIVE，不释放给调用者

agent → session_commit_epoch(sid) → Orchestrator
     ├─ 1. ShadowProc: 冻结 candidate（可逆 quiesce）
     ├─ 2. ShadowFS:   commit（authorize + promote overlay → orig）
     ├─ 3. ShadowFS:   can_release 门控（fail-closed：未 Finalized 则中止）
     ├─ 4. Journal:    记录 fs_committed（决策点，崩溃恢复依据）
     ├─ 5. ShadowFS:   commit_epoch（关闭 epoch 标记）
     ├─ 6. ShadowProc: finalize_commit（丢弃 baseline，candidate 成为 canonical）
     └─ 7. ShadowFS:   ack_release（释放 Finalized 记录）

agent → session_rollback_epoch(sid) → Orchestrator
     ├─ ShadowFS:   rollback_epoch（撤销 epoch 内文件变更）
     ├─ ShadowProc: reject（丢弃 candidate，恢复 pristine baseline）
     └─ Journal:    记录 rollback
```

### 基础提交（Commit）

```
用户 → commit(cgroup_id) → Orchestrator
     ├─ 1. ShadowFS:   commit（authorize + quiesce mmap + promote）
     ├─ 2. can_release 门控（fail-closed）
     ├─ 3. ShadowProc: commit_by_cgroup（丢弃 baseline）+ continue（恢复进程）
     └─ 4. ShadowFS:   ack_release
```

### 基础回滚（Rollback）

```
用户 → rollback(cgroup_id) → Orchestrator
     ├─ 1. ShadowFS:   级联回滚文件变更，返回所有受影响的 cgroup 列表
     └─ 2. ShadowProc: 遍历 affected 列表，reject/kill 每个 cgroup 下的进程
```

### 策略提交（Submit Policy）——完整三组件协同

```
用户 → submit_policy(cgroup_id, allowed_ops) → Orchestrator
     ├─ 1. ShadowProc:      冻结该 cgroup 下所有进程 (SIGSTOP)
     ├─ 2. ShadowObserve:   停止观测，导出事件日志
     ├─ 3. ShadowObserve:   审计事件日志 vs 允许策略
     │     ├─ PASS → 安装白名单 eBPF → ShadowFS commit → ShadowProc resume
     │     └─ FAIL → ShadowFS rollback → ShadowProc kill（级联）
```

## 项目结构

```
speculative_shadow/
├── ShadowFS/                     # Go - FUSE 覆盖文件系统
│   ├── main.go                   # FUSE 入口，cgroup 识别
│   ├── socket_server.go          # Unix socket 控制 API
│   ├── backend/
│   │   ├── backend.go            # 核心后端：agent 状态机、依赖图、级联回滚、mmap quiesce
│   │   ├── operations.go         # 日志条目类型（Write/Mkdir/Unlink/Rmdir/Rename）
│   │   ├── overlay.go            # 覆盖文件系统操作（copy-up, whiteout, merge）
│   │   ├── overlay_linux.go      # Linux 平台特定覆盖操作
│   │   ├── persist.go            # 持久化状态与 WAL
│   │   └── persist_test.go
│   └── tests/
│
├── ShadowProc/                   # Rust - eBPF 进程围栏 + COW 内存追踪
│   ├── src/
│   │   ├── main.rs               # 主入口，事件循环
│   │   ├── bpf_loader.rs         # eBPF 程序加载，多 cgroup 管理
│   │   ├── process_manager.rs    # 进程管理（冻结/恢复/commit/reject/baseline-candidate）
│   │   ├── memory_tracker.rs     # COW 内存回滚（ptrace fork 注入 + 脏页追踪）
│   │   ├── event_handler.rs      # 拦截事件类型定义
│   │   ├── cli.rs                # 交互式 CLI
│   │   ├── socket_server.rs      # Unix socket 控制 API
│   │   └── bpf/
│   │       └── shadow_proc.bpf.c # eBPF C 代码（LSM + fmod_ret 钩子）
│   ├── Cargo.toml
│   └── build.rs
│
├── ShadowObserve/                # C++ - eBPF 观测、审计与白名单执行
│   ├── bpf/
│   │   ├── observ.bpf.c          # tracepoint 探针（OPEN/CREATE/DELETE/RENAME/...）
│   │   ├── observ_common.h       # 共享事件结构体定义
│   │   └── enforce.bpf.c         # LSM 白名单执行器（file_open/inode_create/...）
│   ├── src/
│   │   ├── observer.cpp           # BPF 加载、cgroup 过滤、ring buffer 轮询、JSONL 输出
│   │   ├── audit_engine.cpp       # 规则审计引擎（allowlist + denylist + default-deny）
│   │   ├── enforcer.cpp           # 白名单 eBPF 安装与管理
│   │   ├── socket_server.cpp      # Unix socket daemon API
│   │   ├── daemon.cpp             # daemon 入口
│   │   └── demo.cpp               # 端到端演示
│   ├── include/ghostbpf-observ/   # 公共头文件
│   ├── third_party/               # libbpf, bpftool, vmlinux.h（vendored）
│   ├── CMakeLists.txt
│   └── demo.py
│
├── orchestrator/                  # Python - 统一编排器
│   ├── shadow_orchestrator.py     # 编排器核心 + Unix socket API 服务
│   ├── session_proxy.py           # Session Proxy：baseline/candidate 管理 + 乐观输出释放
│   ├── test_finalization.py       # finalization 路径单元测试
│   ├── test_journal.py            # 持久化日志单元测试
│   ├── test_log_integrity.py      # 日志完整性测试
│   └── test_release_path.py       # 释放路径测试
│
├── demo/                          # 端到端演示
│   ├── run_demo.sh                # 【已禁用】依赖已删除的 cgroup 级 API，待重设计
│   ├── run_demo_full.sh           # 完整 demo（三组件协同：审计通过/失败）
│   ├── session_demo.sh            # Session Proxy demo（commit/reject 证明）
│   ├── session_integrated_demo.sh # 统一 epoch demo（进程状态 + 文件系统原子 commit/rollback）
│   ├── orch_client.py             # 编排器 CLI 客户端
│   └── test_programs/             # 测试用程序
│       ├── agent_worker.c         # 模拟 agent：写文件 + 触发 IPC
│       ├── cgroup_exec.c          # 在指定 cgroup 中执行程序
│       ├── cgroup_exec_hold.c     # cgroup 执行 + Exit Hold 支持
│       ├── file_reader_writer.c   # 文件读写测试
│       ├── file_mutator.c         # 文件修改测试（已有文件覆写）
│       ├── ipc_shm.c              # SysV 共享内存 IPC 测试
│       ├── mem_modifier.c         # 内存修改测试（COW 回滚验证）
│       ├── priv_escalator.c       # 权限提升测试（setuid 拦截验证）
│       └── exit_hold_lib.c        # Exit Hold LD_PRELOAD 库源码
│
└── tests/
    └── integration_test.py        # 集成测试
```

## 依赖

### 系统依赖

- Linux 内核 >= 5.15（eBPF LSM + fmod_ret + ring buffer）
- FUSE 3
- BPF LSM 已启用（内核参数 `lsm=...,bpf`）
- cgroup v2

### 构建依赖

```bash
# ShadowFS (Go)
sudo apt install golang-go fuse3 libfuse3-dev

# ShadowProc (Rust)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# libbpf-cargo 由 build.rs 自动处理

# ShadowObserve (C++ / eBPF)
sudo apt install cmake clang llvm libelf-dev zlib1g-dev
# libbpf 和 bpftool 已 vendored 在 third_party/ 中

# Python 编排器
sudo apt install python3
# 无额外依赖（仅使用标准库）
```

## 构建

```bash
# 构建 ShadowFS
cd ShadowFS && go build -o shadowfs .

# 构建 ShadowProc
cd ShadowProc && cargo build --release

# 构建 ShadowObserve
cd ShadowObserve
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
# 产物: build/libghostbpf-observ.a, build/observ_demo, build/observ_daemon
```

## 使用方法

### 1. 准备 cgroup

```bash
sudo mkdir -p /sys/fs/cgroup/shadow
echo <PID> > /sys/fs/cgroup/shadow/cgroup.procs
```

### 2. 启动组件

```bash
# 创建必要目录
mkdir -p /tmp/staging /mnt/shadow

# 启动 ShadowFS
sudo ./ShadowFS/shadowfs \
  -staging /tmp/staging \
  -sock /tmp/shadowfs.sock \
  /mnt/shadow /path/to/orig

# 启动 ShadowProc
sudo ./ShadowProc/target/release/shadow-proc \
  --sock /tmp/shadowproc.sock

# 启动 ShadowObserve（可选）
sudo ./ShadowObserve/build/observ_daemon \
  --sock /tmp/shadowobserve.sock

# 启动编排器
sudo python3 orchestrator/shadow_orchestrator.py \
  --shadowfs-sock /tmp/shadowfs.sock \
  --shadowproc-sock /tmp/shadowproc.sock \
  --shadowobserve-sock /tmp/shadowobserve.sock \
  --listen /tmp/shadow-orch.sock
```

### 3. 通过编排器 API 操作

所有操作均通过 Unix socket 以 JSON-line 格式通信：

#### Session 推测执行（推荐模式）

```bash
# 打开 session
echo '{"action":"session_open"}' | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 在 session 中执行命令（非 epoch 期间，输出立即返回）
echo '{"action":"session_run","session_id":"<sid>","command":"echo hello"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 开始推测 epoch
echo '{"action":"session_begin_epoch","session_id":"<sid>"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# epoch 内执行（输出为 speculative，不释放）
echo '{"action":"session_run","session_id":"<sid>","command":"export VAR=modified"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 提交 epoch（进程状态 + 文件系统原子持久化）
echo '{"action":"session_commit_epoch","session_id":"<sid>"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 或回滚 epoch（无损恢复到 epoch 前状态）
echo '{"action":"session_rollback_epoch","session_id":"<sid>"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 获取已提交的输出（commit-gated：仅包含已 commit 的 epoch 输出）
echo '{"action":"session_get_output","session_id":"<sid>"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 关闭 session
echo '{"action":"session_close","session_id":"<sid>"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 基础操作

```bash
# 提交
echo '{"action":"commit","cgroup_id":"/shadow"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 回滚（级联）
echo '{"action":"rollback","cgroup_id":"/shadow"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 策略提交（三组件协同）
echo '{"action":"submit_policy","cgroup_id":"/shadow","allowed_ops":[
  {"event_type":"*","action":"allow","path_pattern":"/tmp/"},
  {"event_type":"CREATE","action":"deny","path_pattern":"/etc/"}
]}' | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 其他操作

```bash
# 查看活跃 agent
echo '{"action":"list_agents"}' | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 查看冻结进程
echo '{"action":"list_frozen"}' | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 查询回滚影响范围（dry-run）
echo '{"action":"get_affected","cgroup_id":"/shadow"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

# 启动/停止 eBPF 观测
echo '{"action":"start_observe","cgroup_id":"/shadow","cgroup_inode":12345}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
echo '{"action":"stop_observe","cgroup_id":"/shadow"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

### 4. 运行 Demo

```bash
# 统一 epoch demo（推荐：session 模型的主 demo）
sudo bash demo/session_integrated_demo.sh

# 三组件协同 demo（审计通过/失败）
sudo bash demo/run_demo_full.sh

# Session Proxy demo（commit/reject 证明）
sudo bash demo/session_demo.sh

# 统一 epoch demo（进程状态 + 文件系统原子 commit/rollback）
sudo bash demo/session_integrated_demo.sh
```

## 编排器 API 参考

| Action | 参数 | 说明 |
|--------|------|------|
| `session_open` | `agent_id`, `cgroup_name`（可选） | 打开 session，启动 bash 到监控 cgroup；`agent_id` 绑定所属 agent |
| `session_run` | `session_id`, `command` | 在 session 中执行命令（输出乐观释放，按 epoch 标记写入 transcript） |
| `session_begin_epoch` | `session_id`, `agent_id`（可选） | 开始推测 epoch（冻结 baseline，fork candidate）；同一 agent 串行化 |
| `session_commit_epoch` | `session_id`, `agent_id`（可选） | 提交 epoch（FS commit → 门控 → 进程 commit → 释放） |
| `session_rollback_epoch` | `session_id`, `agent_id`（可选） | 回滚 epoch（FS rollback → 进程 reject → 恢复 baseline） |
| `session_get_output` | `session_id` | 获取 canonical 输出（已提交的 epoch；被回滚的段已从 transcript 中剔除） |
| `session_close` | `session_id` | 关闭 session，释放 agent 槽位和资源 |
| `list_agents` | - | 列出 ShadowFS 中所有活跃的 agent |
| `list_frozen` | `cgroup_id`（可选） | 列出冻结进程，可按 cgroup 过滤 |
| `list_completed` | `cgroup_id`（可选） | 列出已完成执行并被挂起的进程 |
| `get_affected` | `cgroup_id` | 查询回滚将影响的 cgroup 列表（不执行） |
| `start_observe` | `cgroup_id`, `cgroup_inode` | 启动 ShadowObserve 对 cgroup 的 eBPF 观测 |
| `stop_observe` | `cgroup_id` | 停止观测 |
| `submit_policy` | `cgroup_id`, `allowed_ops` | 冻结→审计→根据结果 commit/rollback |

### ShadowFS 直连 API

| Action | 参数 | 说明 |
|--------|------|------|
| `commit` | `cgroup_id` | 授权 + quiesce mmap + promote（fail-closed） |
| `retry_finalize` | `cgroup_id` | 重试失败的 finalize（瞬态 I/O 错误恢复） |
| `get_lifecycle` | `cgroup_id` | 查询 agent 生命周期状态 |
| `can_release` | `cgroup_id` | 查询 agent 是否已 Finalized（可释放） |
| `ack_release` | `cgroup_id` | 确认释放，丢弃 Finalized 记录 |
| `rollback` | `cgroup_id` | 执行级联回滚 |
| `rollback_affected` | `cgroup_id` | 返回受影响的 agent 列表（不执行） |
| `list_agents` | - | 列出所有 agent |
| `begin_epoch` | `cgroup_id` | 标记 epoch 边界 |
| `commit_epoch` | `cgroup_id` | 关闭 epoch 标记 |
| `rollback_epoch` | `cgroup_id` | 撤销 epoch 内文件变更 |

### ShadowProc 直连 API

| Action | 参数 | 说明 |
|--------|------|------|
| `add_cgroup` | `cgroup_path` | 添加 cgroup 到 eBPF 监控 |
| `remove_cgroup` | `cgroup_path` | 移除 cgroup（释放 BPF map 槽位） |
| `list_all_frozen` | - | 列出所有冻结进程 |
| `list_frozen` | `cgroup_id` | 按 cgroup 列出冻结进程 |
| `list_completed` | `cgroup_id`（可选） | 列出已完成执行并被挂起的进程 |
| `continue_by_cgroup` | `cgroup_id` | 恢复该 cgroup 下所有冻结进程 |
| `kill_by_cgroup` | `cgroup_id` | 杀死该 cgroup 下所有冻结进程 |
| `continue_pid` | `pid` | 恢复指定进程 |
| `resume_pid` | `pid` | 临时恢复指定进程（下次拦截事件会再次冻结） |
| `resume_candidate` | `pid` | 恢复 candidate（ARMED，首次外部效果仍被拦截） |
| `kill_pid` | `pid` | 杀死指定进程 |
| `freeze_by_cgroup` | `cgroup_id` | 冻结该 cgroup 下所有进程 |
| `begin_speculative` | `cgroup_id` 或 `pid` | 启动 COW 内存追踪（冻结 baseline，fork candidate） |
| `spec_fork` | `pid` | 仅 fork 影子进程（不冻结） |
| `commit_by_cgroup` | `cgroup_id` | 提交该 cgroup 下所有进程的 COW 追踪（fail-closed） |
| `commit_pid` | `pid` | 提交指定进程的 COW 追踪（丢弃 baseline） |
| `reject_pid` | `pid` | 丢弃 candidate，恢复 pristine baseline 为 canonical |
| `reject_by_cgroup` | `cgroup_id` | 批量 reject 该 cgroup 下所有 speculative epoch |

### ShadowObserve 直连 API

| Action | 参数 | 说明 |
|--------|------|------|
| `start_observe` | `cgroup_id`, `log_path` | 启动 eBPF 事件观测 |
| `stop_observe` | `cgroup_id` | 停止观测 |
| `audit` | `log_path`, `rules` | 对事件日志执行规则审计 |
| `get_events` | `log_path`, `limit` | 获取已录制的事件 |
| `install_whitelist` | `cgroup_id`, `allowed_ops` | 安装白名单 eBPF LSM 过滤器 |
| `remove_whitelist` | `cgroup_id` | 移除白名单 |

## 关键设计

### 文件系统层 (ShadowFS)

- **写时复制**：所有写操作先复制到 overlay 层，orig 目录始终只读
- **依赖图**：当 agent B 读取了 agent A 写入的文件，建立 B→A 依赖边
- **级联回滚**：回滚 A 时，所有依赖 A 的 agent（及其传递依赖）也会被回滚
- **WAL + 检查点**：所有操作先写入预写日志，定期快照，支持崩溃恢复
- **生命周期状态机**：Active → AuthorizedPending → Finalizing → Finalized；只有 Finalized 才可释放
- **Fail-closed mmap quiesce**：commit 前从冻结进程内存中捕获所有 writable MAP_SHARED 脏页；任何区域捕获失败即中止 finalization
- **Epoch 追踪**：begin_epoch/commit_epoch/rollback_epoch 标记文件变更边界，支持 per-epoch 原子回滚
- **延迟释放**：下游 agent 提交后仍被围栏，直到所有上游依赖也 Finalized

### 进程层 (ShadowProc)

- **eBPF 拦截**：通过 LSM + fmod_ret 钩子拦截网络、IPC、信号、ptrace、权限提升、pipe/socket write、sendfile/splice/io_uring 等
- **进程冻结**：拦截后发送 SIGSTOP 冻结进程，通过环缓冲通知用户空间
- **Per-epoch 围栏**：进程在首次外部效果处冻结，commit 后完全释放；下一个 epoch 重新武装
- **Baseline/Candidate 模型**：begin_speculative 冻结原始进程为 baseline，fork COW candidate 执行推测操作；commit 丢弃 baseline，reject 丢弃 candidate 恢复 baseline
- **多 cgroup**：BPF cgroup_map 支持最多 64 个 cgroup 同时监控
- **COW 内存回滚**：通过 ptrace 注入 fork() 创建影子进程，利用内核 COW 语义保存原始内存页
- **Exit Hold**：通过 LD_PRELOAD + BPF 哨兵地址检测拦截 `exit_group`，进程完成后透明挂起
- **权限提升拦截**：通过 `bprm_check_security` 和 `task_fix_setuid` LSM 钩子拦截 setuid/setgid
- **Fail-closed commit**：commit_by_cgroup 任何进程提交失败即返回错误，不静默忽略部分失败

### 观测与执行层 (ShadowObserve)

- **eBPF 观测**：tracepoint 探针捕获 OPEN / CREATE / DELETE / RENAME 等文件系统事件 + 进程事件
- **cgroup 过滤**：仅记录已注册 cgroup 内的事件，通过 ring buffer 传输到用户态
- **审计引擎**：allowlist + denylist + default-deny 三层策略，路径前缀匹配，双资源操作（rename/link）两端点校验
- **白名单执行**：审计通过后，安装 LSM eBPF 程序限制 cgroup 仅执行白名单内操作
- **JSONL 事件日志**：所有事件写入 JSONL 文件，支持离线审计

### 编排层 (Orchestrator)

- **Session Proxy**：agent 通过 session_id 操作长生命周期 bash，底层 baseline/candidate 切换对 agent 透明
- **Commit-gated 输出**：epoch 内产生的输出为 speculative，不释放给调用者；commit 后合并到 committed transcript，reject 后丢弃
- **Fail-closed 多步提交**：FS commit → can_release 门控 → journal 决策点 → 进程 commit → ack_release；任何步骤失败即中止，baseline 保留
- **持久化日志（Journal）**：append-only + fsync，记录 session 生命周期和 commit 决策点；崩溃恢复时重放日志得到确定性结果
- **Journal 损坏 fail-closed**：仅允许最后一条记录损坏（torn tail）；中间记录损坏则拒绝启动
- **延迟释放**：上游依赖未 Finalized 时，已提交的下游进程保持冻结；后台线程定期重试
- **Ack-only 重试**：外部效果已释放后，仅重试 ack_release（幂等），不重复释放
- **Finalize 重试**：后台线程定期对 AuthorizedPending 的 agent 调用 retry_finalize，恢复瞬态 I/O 错误
- **级联感知**：rollback 时通过 ShadowFS 获取完整 affected 列表，确保进程层也执行级联清理

## 测试

```bash
# 集成测试（需要 root 权限）
sudo python3 tests/integration_test.py

# 统一 epoch demo（进程 + 文件原子 commit/rollback，含 agent 屏障）
sudo bash demo/session_integrated_demo.sh

# 三组件协同 demo
sudo bash demo/run_demo_full.sh

# Session Proxy demo
sudo bash demo/session_demo.sh

# 编排器单元测试
python3 -m pytest orchestrator/test_finalization.py
python3 -m pytest orchestrator/test_journal.py
python3 -m pytest orchestrator/test_log_integrity.py
python3 -m pytest orchestrator/test_release_path.py
```

## Demo 场景一览

### 当前主 demo：`demo/session_integrated_demo.sh`

| 场景 | 说明 |
|------|------|
| Epoch 回滚 | 同一 epoch 内修改环境变量 + 写文件 → rollback 同时撤销两者，session 存活 |
| Epoch 提交 | 同一 epoch 内修改两者 → commit 同时持久化，baseline 从未被扰动 |
| 乐观输出释放 | epoch 内命令的输出立即可见，不等 commit |
| 提交前不落盘 | epoch 内已写的文件尚未出现在后备存储 |
| agent 屏障 | 同一 agent 的两个 session 串行化；不同 agent 不互相阻塞 |

### 已禁用：`demo/run_demo.sh`

该脚本依赖已删除的 cgroup 级 API（`add_cgroup` / `register_output` /
`commit(cgroup_id)` / `rollback(cgroup_id)`），目前会直接报错退出。

它无法机械式迁移：其 11 个场景都建立在“启动一个一次性程序 → eBPF 在执行中途
将其冻结 → 按 cgroup 解决”这个形状上。而 `session_run` 等待完成哨兵，被冻结的
程序永不返回，只会超时。session 模型中围栏作用于 candidate shell 自身的首次外部
效应，由整个 epoch 的 commit/rollback 解决，调用方不会观察到第三方的冻结进程。

因此以下能力目前**没有可运行的 demo**（能力本身仍在，仅缺演示）：

| 能力 | 原场景 |
|------|--------|
| 执行中途围栏 + 先检查后解决 | Commit / Rollback |
| 跳 agent 级联回滚 | Cascade |
| 延迟释放 / 上游门控 | Deferred Release |
| agent 退出处透明挂起 | Exit Hold |
| 提权拦截 | Priv Escalation |
| POSIX shm 拦截 | Shm Intercept |
| 进程内存 COW commit/reject | Cow Commit / Bash Env Rollback |

重新启用任一场景需要设计 session 模型下的等价表达（例如一个“不等命令完成即可
检查/解决被围栏效应”的 API），而不是修改那个脚本。

## License

Apache License 2.0 — 详见 [LICENSE](LICENSE)

> **注意**：`ShadowObserve/third_party/` 中的 libbpf 和 bpftool 为 vendored 第三方库，
> 分别遵循 LGPL-2.1 / GPL-2.0 / BSD-2-Clause 许可证。
