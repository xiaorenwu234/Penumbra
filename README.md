# Penumbra

> 原名 Speculative Shadow，项目已正式更名为 **Penumbra**。

统一的推测执行（Speculative Execution）框架，将 **ShadowFS**（文件系统层）、**ShadowProc**（进程层）和 **ShadowObserve**（观测与执行层）整合为一个协调系统，对 cgroup 中进程的文件操作、进程间通信和系统调用进行拦截、审计、提交与回滚。

## 架构概览

```
                         ┌──────────────────────────────┐
                         │   Python Orchestrator         │
                         │   (Unix socket JSON-line API) │
                         └──┬──────────┬──────────┬─────┘
                            │          │          │
                 ┌──────────▼──┐ ┌─────▼──────┐ ┌▼──────────────┐
                 │  ShadowFS   │ │ ShadowProc  │ │ ShadowObserve │
                 │  (Go/FUSE)  │ │(Rust/eBPF)  │ │ (C++/eBPF)    │
                 │  文件系统层  │ │  进程层      │ │ 观测与执行层   │
                 └─────────────┘ └─────────────┘ └───────────────┘
```

| 组件 | 职责 | 技术栈 |
|------|------|--------|
| **ShadowFS** | 基于 FUSE 的覆盖文件系统，写时复制追踪文件操作，依赖图级联回滚，WAL 崩溃安全 | Go, go-fuse v2 |
| **ShadowProc** | 基于 eBPF 的进程通信拦截器，拦截网络/IPC/信号/ptrace；COW 内存追踪与回滚 | Rust, eBPF (LSM + fmod_ret), ptrace |
| **ShadowObserve** | eBPF 文件系统事件监控 + 规则审计引擎 + LSM 白名单强制执行 | C++, eBPF (tracepoint + LSM), libbpf |
| **Orchestrator** | 统一编排器，协调三组件的 commit/rollback/audit/enforce 操作 | Python |

## 核心工作流

### 基础提交（Commit）

```
用户 → commit(cgroup_id) → Orchestrator
     ├─ 1. ShadowProc: 恢复该 cgroup 下所有冻结进程 (SIGCONT)
     └─ 2. ShadowFS:   提交该 agent 的文件变更 (promote overlay → orig)
```

### 基础回滚（Rollback）

```
用户 → rollback(cgroup_id) → Orchestrator
     ├─ 1. ShadowFS:   级联回滚文件变更，返回所有受影响的 cgroup 列表
     └─ 2. ShadowProc: 遍历 affected 列表，杀死每个 cgroup 下被冻结的进程 (SIGKILL)
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
│   │   ├── backend.go            # 核心后端：agent 状态、依赖图、级联回滚
│   │   ├── operations.go         # 日志条目类型（Write/Mkdir/Unlink/Rmdir/Rename）
│   │   ├── overlay.go            # 覆盖文件系统操作（copy-up, whiteout, merge）
│   │   ├── overlay_linux.go      # Linux 平台特定覆盖操作
│   │   ├── persist.go            # 持久化状态与 WAL
│   │   └── persist_test.go
│   └── tests/
│
├── ShadowProc/                   # Rust - eBPF 进程通信拦截 + COW 内存追踪
│   ├── src/
│   │   ├── main.rs               # 主入口，事件循环
│   │   ├── bpf_loader.rs         # eBPF 程序加载，多 cgroup 管理
│   │   ├── process_manager.rs    # 冻结进程管理（冻结/恢复/杀死/检查点）
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
│   │   ├── observ.bpf.c          # tracepoint 探针（OPEN/CREATE/DELETE/RENAME）
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
│   └── shadow_orchestrator.py     # 编排器核心 + Unix socket API 服务
│
├── demo/                          # 端到端演示
│   ├── run_demo.sh                # 基础 demo（ShadowFS + ShadowProc）
│   ├── run_demo_full.sh           # 完整 demo（三组件协同：审计通过/失败）
│   ├── orch_client.py             # 编排器 CLI 客户端
│   └── test_programs/             # 测试用程序
│       ├── agent_worker.c         # 模拟 agent：写文件 + 触发 IPC
│       ├── cgroup_exec.c          # 在指定 cgroup 中执行程序
│       ├── file_reader_writer.c   # 文件读写测试
│       └── mem_modifier.c         # 内存修改测试（COW 回滚验证）
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
  --cgroup-path /sys/fs/cgroup/shadow \
  --sock /tmp/shadowproc.sock

# 启动 ShadowObserve
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

#### 提交

```bash
echo '{"action":"commit","cgroup_id":"/shadow"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 回滚（级联）

```bash
echo '{"action":"rollback","cgroup_id":"/shadow"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 策略提交（三组件协同）

```bash
echo '{"action":"submit_policy","cgroup_id":"/shadow","allowed_ops":[
  {"event_type":"*","action":"allow","path_pattern":"/tmp/"},
  {"event_type":"CREATE","action":"deny","path_pattern":"/etc/"}
]}' | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 其他操作

```bash
# 动态添加 cgroup
echo '{"action":"add_cgroup","cgroup_path":"/sys/fs/cgroup/shadow-agent2"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock

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

### 4. 运行完整 Demo

```bash
sudo bash demo/run_demo_full.sh
```

演示两个场景：
- **Scenario A**：审计通过 → 文件操作在策略范围内 → commit
- **Scenario B**：审计失败 → 文件操作违反策略 → rollback

## 编排器 API 参考

| Action | 参数 | 说明 |
|--------|------|------|
| `commit` | `cgroup_id` | 提交文件变更，恢复冻结进程 |
| `rollback` | `cgroup_id` | 级联回滚文件变更，杀死受影响冻结进程 |
| `add_cgroup` | `cgroup_path` | 动态添加 cgroup 到 ShadowProc 监控 |
| `list_agents` | - | 列出 ShadowFS 中所有活跃的 agent |
| `list_frozen` | `cgroup_id`（可选） | 列出冻结进程，可按 cgroup 过滤 |
| `get_affected` | `cgroup_id` | 查询回滚将影响的 cgroup 列表（不执行） |
| `start_observe` | `cgroup_id`, `cgroup_inode` | 启动 ShadowObserve 对 cgroup 的 eBPF 观测 |
| `stop_observe` | `cgroup_id` | 停止观测 |
| `submit_policy` | `cgroup_id`, `allowed_ops` | 冻结→审计→根据结果 commit/rollback |

### ShadowFS 直连 API

| Action | 参数 | 说明 |
|--------|------|------|
| `commit` | `cgroup_id` | 提交 agent |
| `rollback` | `cgroup_id` | 执行级联回滚 |
| `rollback_affected` | `cgroup_id` | 返回受影响的 agent 列表（不执行） |
| `list_agents` | - | 列出所有 agent |

### ShadowProc 直连 API

| Action | 参数 | 说明 |
|--------|------|------|
| `add_cgroup` | `cgroup_path` | 添加 cgroup |
| `list_all_frozen` | - | 列出所有冻结进程 |
| `list_frozen` | `cgroup_id` | 按 cgroup 列出冻结进程 |
| `continue_by_cgroup` | `cgroup_id` | 恢复该 cgroup 下所有冻结进程 |
| `kill_by_cgroup` | `cgroup_id` | 杀死该 cgroup 下所有冻结进程 |
| `continue_pid` | `pid` | 恢复指定进程 |
| `kill_pid` | `pid` | 杀死指定进程 |
| `freeze_by_cgroup` | `cgroup_id` | 冻结该 cgroup 下所有进程 |
| `begin_speculative` | `cgroup_id` 或 `pid` | 启动 COW 内存追踪（创建影子进程） |
| `rollback_by_cgroup` | `cgroup_id` | 回滚该 cgroup 下所有进程的内存 |
| `rollback_pid` | `pid` | 回滚指定进程的内存 |
| `commit_by_cgroup` | `cgroup_id` | 提交该 cgroup 下所有进程的 COW 追踪 |
| `commit_pid` | `pid` | 提交指定进程的 COW 追踪 |
| `restore_memory_pid` | `pid` | 仅恢复指定进程的内存页 |

### ShadowObserve 直连 API

| Action | 参数 | 说明 |
|--------|------|------|
| `start_observe` | `cgroup_id`, `log_path` | 启动 eBPF 事件观测 |
| `stop_observe` | `cgroup_id` | 停止观测 |
| `audit` | `log_path`, `rules` | 对事件日志执行规则审计 |
| `get_events` | `cgroup_id` | 获取已录制的事件 |
| `install_whitelist` | `cgroup_id`, `allowed_ops` | 安装白名单 eBPF LSM 过滤器 |
| `remove_whitelist` | `cgroup_id` | 移除白名单 |

## 关键设计

### 文件系统层 (ShadowFS)

- **写时复制**：所有写操作先复制到 overlay 层，orig 目录始终只读
- **依赖图**：当 agent B 读取了 agent A 写入的文件，建立 B→A 依赖边
- **级联回滚**：回滚 A 时，所有依赖 A 的 agent（及其传递依赖）也会被回滚
- **WAL + 检查点**：所有操作先写入预写日志，定期快照，支持崩溃恢复

### 进程层 (ShadowProc)

- **eBPF 拦截**：通过 LSM 钩子拦截网络、IPC、信号、ptrace 等系统调用
- **进程冻结**：拦截后发送 SIGSTOP 冻结进程，通过环缓冲通知用户空间
- **进程恢复**：清除 BPF map 后发送 SIGCONT，内核自动重启被拦截的系统调用
- **多 cgroup**：BPF cgroup_map 支持最多 64 个 cgroup 同时监控
- **COW 内存回滚**：通过 ptrace 注入 fork() 创建影子进程，利用内核 COW 语义保存原始内存页；回滚时扫描 soft-dirty 页，从影子进程恢复

### 观测与执行层 (ShadowObserve)

- **eBPF 观测**：tracepoint 探针捕获 OPEN / CREATE / DELETE / RENAME 等文件系统事件
- **cgroup 过滤**：仅记录已注册 cgroup 内的事件，通过 ring buffer 传输到用户态
- **审计引擎**：allowlist + denylist + default-deny 三层策略，路径前缀匹配
- **白名单执行**：审计通过后，安装 LSM eBPF 程序限制 cgroup 仅执行白名单内操作
- **JSONL 事件日志**：所有事件写入 JSONL 文件，支持离线审计

### 编排层 (Orchestrator)

- **Commit 顺序**：先恢复进程 → 再提交文件（确保进程可正常执行）
- **Rollback 顺序**：先回滚文件 → 再杀死进程（文件层先清理更干净）
- **级联感知**：rollback 时通过 ShadowFS 获取完整 affected 列表，确保进程层也执行级联清理
- **策略提交**：freeze → audit → 根据审计结果自动 commit 或 rollback

## 测试

```bash
# 集成测试（需要 root 权限）
sudo python3 tests/integration_test.py

# 完整 demo
sudo bash demo/run_demo_full.sh
```

## License

- `ShadowProc/src/bpf/`、`ShadowObserve/bpf/` — GPL-2.0（eBPF 组件）
- `ShadowObserve/src/`、`ShadowObserve/include/` — MIT
- 其余组件 — 项目特定许可证
# Speculative Shadow

统一的推测执行（Speculative Execution）框架，将 **ShadowFS**（文件系统层）和 **ShadowProc**（进程层）整合为一个协调系统，支持对 cgroup 中进程的文件操作和进程间通信进行拦截、提交与回滚。

## 架构概览

```
                          ┌──────────────────────────┐
                          │  Python Orchestrator     │
                          │  (Unix socket API)       │
                          └────┬───────────────┬─────┘
                               │               │
                    ┌──────────▼──┐    ┌───────▼──────────┐
                    │  ShadowFS   │    │   ShadowProc     │
                    │  (Go/FUSE)  │    │ (Rust/eBPF)      │
                    │  文件系统层  │    │  进程层           │
                    └─────────────┘    └──────────────────┘
```

| 组件 | 职责 | 技术栈 |
|------|------|--------|
| **ShadowFS** | 基于 FUSE 的覆盖文件系统，写时复制追踪文件操作，支持级联回滚 | Go, FUSE |
| **ShadowProc** | 基于 eBPF 的进程通信拦截器，拦截网络/IPC/信号等外部通信，冻结相关进程 | Rust, eBPF (LSM) |
| **Orchestrator** | 统一编排器，协调两者的 commit/rollback 操作 | Python |

## 核心工作流

### 提交（Commit）

```
用户 → commit(cgroup_id) → Orchestrator
     ├─ 1. ShadowProc: 恢复该 cgroup 下所有冻结的进程 (SIGCONT)
     └─ 2. ShadowFS:   提交该 agent 的文件变更 (promote overlay → orig)
```

### 回滚（Rollback）

```
用户 → rollback(cgroup_id) → Orchestrator
     ├─ 1. ShadowFS:   级联回滚文件变更，返回所有受影响的 cgroup 列表
     └─ 2. ShadowProc: 遍历 affected 列表，杀死每个 cgroup 下被冻结的进程 (SIGKILL)
```

## 项目结构

```
speculative_shadow/
├── ShadowFS/                    # Go - FUSE 覆盖文件系统
│   ├── main.go                  # FUSE 入口，cgroup 识别
│   ├── socket_server.go         # Unix socket 控制 API
│   ├── backend/
│   │   ├── backend.go           # 核心后端：agent 状态、依赖图、WAL、级联回滚
│   │   ├── operations.go        # 日志条目类型（Write/Mkdir/Unlink/Rmdir）
│   │   ├── overlay.go           # 覆盖文件系统操作（copy-up, whiteout, merge）
│   │   ├── persist.go           # 持久化状态与 WAL
│   │   └── persist_test.go
│   └── tests/
│
├── ShadowProc/                  # Rust - eBPF 进程通信拦截器
│   ├── src/
│   │   ├── main.rs              # 主入口，事件循环
│   │   ├── bpf_loader.rs        # eBPF 程序加载，多 cgroup 管理
│   │   ├── process_manager.rs   # 冻结进程管理（冻结/恢复/杀死/检查点）
│   │   ├── event_handler.rs     # 拦截事件类型定义
│   │   ├── cli.rs               # 交互式 CLI
│   │   ├── socket_server.rs     # Unix socket 控制 API
│   │   └── bpf/
│   │       └── shadow_proc.bpf.c # eBPF C 代码（LSM + fmod_ret 钩子）
│   ├── Cargo.toml
│   └── build.rs
│
├── orchestrator/                # Python - 统一编排器
│   └── shadow_orchestrator.py   # 编排器核心 + 对外 API 服务
│
└── tests/
    └── integration_test.py      # 集成测试
```

## 依赖

### 系统依赖

- Linux 内核 >= 5.15（支持 eBPF LSM + fmod_ret）
- FUSE 3
- BPF LSM 已启用（内核参数 `lsm=...,bpf`）

### 构建依赖

```bash
# ShadowFS (Go)
sudo apt install golang-go fuse3 libfuse3-dev

# ShadowProc (Rust)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install libbpf-cargo   # 或已在 build.rs 中处理

# Python 编排器
sudo apt install python3
# 无额外依赖（仅使用标准库）
```

## 构建

```bash
# 构建 ShadowFS
cd ShadowFS
go build -o shadowfs .

# 构建 ShadowProc
cd ../ShadowProc
cargo build --release
```

## 使用方法

### 1. 准备 cgroup

```bash
# 创建 cgroup
sudo mkdir -p /sys/fs/cgroup/shadow

# 将进程加入 cgroup
sudo cgexec -g "memory" shadow -- your_command &
# 或
echo <PID> > /sys/fs/cgroup/shadow/cgroup.procs
```

### 2. 启动组件

```bash
# 创建必要目录
mkdir -p /tmp/staging /mnt/shadow
export ORIG_DIR=/path/to/your/data

# 启动 ShadowFS（挂载 FUSE + 启动 socket）
sudo ./ShadowFS/shadowfs \
  -staging /tmp/staging \
  -sock /tmp/shadowfs.sock \
  /mnt/shadow \
  $ORIG_DIR

# 启动 ShadowProc（eBPF 监控 + 启动 socket）
sudo ./ShadowProc/target/release/shadow-proc \
  --cgroup-path /sys/fs/cgroup/shadow \
  --sock /tmp/shadowproc.sock

# 启动编排器
sudo python3 orchestrator/shadow_orchestrator.py \
  --shadowfs-sock /tmp/shadowfs.sock \
  --shadowproc-sock /tmp/shadowproc.sock \
  --listen /tmp/shadow-orch.sock
```

### 3. 通过编排器 API 操作

所有操作均通过 Unix socket 以 JSON-line 格式通信：

#### 提交

```bash
echo '{"action":"commit","cgroup_id":"/shadow"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 回滚（级联）

```bash
echo '{"action":"rollback","cgroup_id":"/shadow"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 动态添加 cgroup

```bash
echo '{"action":"add_cgroup","cgroup_path":"/sys/fs/cgroup/shadow-agent2"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 查看活跃 agent

```bash
echo '{"action":"list_agents"}' | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 查看冻结进程

```bash
echo '{"action":"list_frozen"}' | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

#### 查询回滚影响范围（dry-run）

```bash
echo '{"action":"get_affected","cgroup_id":"/shadow"}' \
  | socat - UNIX-CONNECT:/tmp/shadow-orch.sock
```

## 编排器 API 参考

| Action | 参数 | 说明 |
|--------|------|------|
| `commit` | `cgroup_id` | 提交指定 agent 的文件变更，恢复其冻结进程 |
| `rollback` | `cgroup_id` | 级联回滚文件变更，杀死所有受影响 cgroup 中的冻结进程 |
| `add_cgroup` | `cgroup_path` | 动态添加新的 cgroup 到 ShadowProc 监控 |
| `list_agents` | - | 列出 ShadowFS 中所有活跃的 agent |
| `list_frozen` | `cgroup_id`（可选） | 列出冻结进程，可按 cgroup 过滤 |
| `get_affected` | `cgroup_id` | 查询回滚将影响的 cgroup 列表（不执行） |

### ShadowFS 直连 API

| Action | 参数 | 说明 |
|--------|------|------|
| `commit` | `cgroup_id` | 提交 agent |
| `rollback` | `cgroup_id` | 执行级联回滚 |
| `rollback_affected` | `cgroup_id` | 返回受影响的 agent 列表（不执行） |
| `list_agents` | - | 列出所有 agent |

### ShadowProc 直连 API

| Action | 参数 | 说明 |
|--------|------|------|
| `add_cgroup` | `cgroup_path` | 添加 cgroup |
| `list_all_frozen` | - | 列出所有冻结进程 |
| `list_frozen` | `cgroup_id` | 按 cgroup 列出冻结进程 |
| `continue_by_cgroup` | `cgroup_id` | 恢复该 cgroup 下所有冻结进程 |
| `kill_by_cgroup` | `cgroup_id` | 杀死该 cgroup 下所有冻结进程 |
| `continue_pid` | `pid` | 恢复指定进程 |
| `kill_pid` | `pid` | 杀死指定进程 |

## 关键设计

### 文件系统层 (ShadowFS)

- **写时复制**：所有写操作先复制到 overlay 层，orig 目录始终只读
- **依赖图**：当 agent B 读取了 agent A 写入的文件，建立 B→A 依赖边
- **级联回滚**：回滚 A 时，所有依赖 A 的 agent（及其传递依赖）也会被回滚
- **WAL + 检查点**：所有操作先写入预写日志，定期快照，支持崩溃恢复

### 进程层 (ShadowProc)

- **eBPF 拦截**：通过 LSM 钩子拦截网络、IPC、信号、ptrace 等系统调用
- **进程冻结**：拦截后发送 SIGSTOP 冻结进程，通过环缓冲通知用户空间
- **进程恢复**：清除 BPF map 后发送 SIGCONT，内核自动重启被拦截的系统调用
- **多 cgroup**：BPF cgroup_map 支持最多 64 个 cgroup 同时监控

### 编排层 (Orchestrator)

- **Commit 顺序**：先恢复进程 → 再提交文件（确保进程可正常执行）
- **Rollback 顺序**：先回滚文件 → 再杀死进程（文件层先清理更干净）
- **级联感知**：rollback 时通过 ShadowFS 获取完整 affected 列表，确保进程层也执行级联清理

## 测试

```bash
# 集成测试（需要 root 权限）
sudo python3 tests/integration_test.py
```

## License

GPL-2.0 (eBPF components) / Project-specific licenses apply.
