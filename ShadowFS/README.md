# ShadowFS

基于 go-fuse v2 的覆盖文件系统（overlay filesystem），以 cgroup 为单元追踪文件操作，支持**多 agent 级联回滚**、**依赖图**、**WAL + 检查点**崩溃安全。

## 用途

在 FUSE 挂载点内进行的文件操作（创建、修改、删除、重命名等）被透明地记录到 overlay 层，orig 目录始终只读。每个 cgroup 被视为一个独立的 agent，agent 之间的文件读写自动建立依赖关系。回滚某个 agent 时，所有依赖它的 agent 也会被级联回滚。

## 架构

```
┌──────────────────────────────────────┐
│ 用户操作 (ls, rm, echo >, …)          │
├──────────────────────────────────────┤
│ FUSE 内核模块                         │
├──────────────────────────────────────┤
│ ShadowNode (main.go)                 │ ← FUSE 层，cgroup 识别，操作拦截
│   └─ LoopbackNode (go-fuse)          │
├──────────────────────────────────────┤
│ SocketServer (socket_server.go)      │ ← Unix socket 控制 API
├──────────────────────────────────────┤
│ Backend (backend/)                   │ ← 核心逻辑
│   ├── agents (map[cgroupID]AgentState)│   agent 状态 + undo 日志
│   ├── dependents / dependsOn         │   依赖图（级联回滚）
│   ├── fileDirty                      │   脏文件追踪
│   ├── WAL + checkpoint               │   预写日志 + 定期快照
│   └── staging/ (overlay 目录)         │   写时复制目标
├──────────────────────────────────────┤
│ 真实文件系统 (orig, 只读)              │
└──────────────────────────────────────┘
```

### 文件结构

```
main.go               — FUSE 挂载、ShadowNode、cgroup 识别
socket_server.go      — Unix socket 控制 API（commit/rollback/list_agents/…，唯一控制接口）
backend/
  backend.go          — Backend 结构体：agent 状态、依赖图、WAL、级联回滚、检查点
  operations.go       — LogEntry 接口 + 各 overlay 操作类型的 Rollback / Promote
  overlay.go          — 覆盖文件系统操作（copy-up, whiteout, merge view）
  overlay_linux.go    — Linux 平台特定覆盖操作
  persist.go          — 持久化状态（JSON 快照）与 WAL（append-only log）
  persist_test.go     — 持久化单元测试
  backend_test.go     — 后端逻辑单元测试
Makefile              — 编译 + 本地 demo 启动
```

## 实现方法

### 1. 拦截层（main.go）

`ShadowNode` 嵌入 `fs.LoopbackNode`，覆写 FUSE 操作接口，在透传到 overlay 层的同时按 cgroup 记录操作：

| 接口 | 拦截的 FUSE 操作 |
|------|-----------------|
| `NodeMkdirer` | 创建目录 |
| `NodeRmdirer` | 删除目录 |
| `NodeCreater` | 创建文件 |
| `NodeOpener` | 打开文件（读 → 依赖追踪；写 → copy-up） |
| `NodeUnlinker` | 删除文件 |
| `NodeRenamer` | 重命名 |
| `NodeReleaser` | 关闭文件描述符 |

所有子节点通过 `WrapChild` 自动获得追踪能力。写打开时自动执行 copy-up，确保 orig 不被修改。

### 2. 控制接口

控制接口只有 **ShadowFS Unix 控制 socket**（`socket_server.go`）。之前挂载点
根目录下的虚拟文件 `.shadow.ctl` 已被**移除**：它对任何能写入挂载点的进程
（包括被沙箱隔离的 agent 本身）暴露了 commit/rollback，等于让 agent 自行
驱动 finalization。socket 不经由文件系统视图暴露，且通过 `SO_PEERCRED`
只接受 orchestrator（daemon 自身 uid）的连接，socket 文件为 `0600`、
所在目录为 `0700`。

commit/rollback 通过 socket 的 JSON 行协议下发（由 orchestrator 调用），
例如 `{"action":"rollback","cgroup_id":"/shadow-demo"}`。

### 3. Overlay 层（backend/overlay.go）

写操作不直接修改 orig，而是在 staging 目录中创建 overlay 副本：

- **Copy-up**：写打开时，将 orig 文件复制到 `staging/<orig_path>`
- **Whiteout**：删除操作创建 `.shadow.wh.<basename>` 标记文件，在合并视图中隐藏 orig 文件
- **合并视图**：FUSE Lookup 时优先返回 overlay 文件，检查 whiteout 决定是否隐藏

### 4. 回滚后端（backend/backend.go）

`Backend` 维护每个 agent 的 undo 日志栈（`[]LogEntry`），每种操作对应 `Rollback()` 和 `Promote()` 方法：

| Entry | Rollback 时 | Promote 时 |
|-------|------------|------------|
| `OverlayWriteEntry` | 删除 overlay 文件，恢复 whiteout | overlay → orig（rename） |
| `OverlayMkdirEntry` | 删除 overlay 目录，恢复 whiteout | orig 创建目录 |
| `OverlayUnlinkEntry` | 删除 whiteout（恢复可见性） | orig 删除文件 |
| `OverlayRmdirEntry` | 删除 whiteout（恢复可见性） | orig 删除目录树 |

### 5. 依赖图与级联回滚

当 agent B 读取了 agent A 写入（脏）的文件，自动建立 B→A 依赖边。回滚 A 时，DFS 遍历依赖图，所有可达的 agent 均被回滚：

```
回滚 A → 影响 B（B 读了 A 的文件） → 影响 C（C 读了 B 的文件）
```

回滚按全局 seq 逆序执行，确保最新操作先撤销。

### 6. WAL + 检查点

所有变更操作先写入 WAL（append-only JSON-line），再由专用 worker 批量 fsync（group commit）。后台定期做全量快照并截断 WAL，支持崩溃恢复。

## Unix Socket API

通过 `-sock` 参数启动后，ShadowFS 在指定路径提供 JSON-line 协议的控制 API：

| Action | 参数 | 说明 |
|--------|------|------|
| `commit` | `cgroup_id` | 提交 agent（promote overlay → orig） |
| `rollback` | `cgroup_id` | 执行级联回滚，返回 affected 列表 |
| `rollback_affected` | `cgroup_id` | 查询回滚将影响的 agent 列表（dry-run） |
| `list_agents` | - | 列出所有活跃 agent |

```bash
echo '{"action":"list_agents"}' | socat - UNIX-CONNECT:/tmp/shadowfs.sock
echo '{"action":"commit","cgroup_id":"/shadow"}' | socat - UNIX-CONNECT:/tmp/shadowfs.sock
```

## 使用

```bash
# 编译
make build
# 或
go build -o shadowfs .

# 启动 demo（挂载 .demo/orig 到 .demo/mnt）
make demo

# 在另一个终端操作
cd .demo/mnt
echo hello > a.txt
mkdir -p x/y
rm -r x

# 回滚 / 提交：通过控制 socket 下发（不再有 .shadow.ctl 文件）
#   {"action":"rollback","cgroup_id":"<cgroup>"}   # 恢复 x/y/ 和 a.txt
#   {"action":"commit","cgroup_id":"<cgroup>"}     # 提交

# 退出
make clean              # 卸载 + 清理
```

或手动启动：

```bash
./shadowfs -staging /tmp/staging -sock /tmp/shadowfs.sock /mnt/point /original/dir
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `-staging <dir>` | overlay 暂存目录（必需） |
| `-sock <path>` | Unix socket 控制 API 路径（可选） |
| `-allow-other` | 允许其他用户访问挂载点 |
| 位置参数 1 | FUSE 挂载点 |
| 位置参数 2 | 原始目录（只读） |

## 依赖

- Go >= 1.21
- FUSE 3 (`fuse3`, `libfuse3-dev`)
- Linux 内核支持 FUSE

## 许可证

Apache License 2.0（作为 Penumbra 项目的组成部分）
