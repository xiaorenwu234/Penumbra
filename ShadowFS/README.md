# shadowfs

基于 go-fuse v2 的 loopback 文件系统，支持目录和文件操作的**回滚（rollback）**。

## 用途

在挂载点内进行的文件操作（创建、修改、删除、重命名等）会被透明地记录。通过写入虚拟控制文件 `.shadow.ctl`，可以**撤销**（`r`）或**提交**（`c`）这些操作。

典型使用场景：在一个目录上做实验性批量操作，出错后可一键回滚到初始状态。

## 架构

```
┌─────────────────────────────┐
│ 用户操作 (ls, rm, echo >…)   │
├─────────────────────────────┤
│ FUSE 内核模块                │
├─────────────────────────────┤
│ ShadowNode (main.go)        │  ← FUSE 层，拦截操作
│   └─ LoopbackNode (go-fuse) │
├─────────────────────────────┤
│ Backend (backend/)          │  ← 回滚逻辑，与 FUSE 无关
│   ├── undoLog ([]LogEntry)  │
│   └── staging/ (备份目录)    │
├─────────────────────────────┤
│ 真实文件系统                  │
└─────────────────────────────┘
```

### 文件结构

```
main.go               — FUSE 挂载、ShadowNode、控制文件 .shadow.ctl
backend/
  operations.go       — LogEntry 接口 + 各操作类型的 Rollback 实现
  backend.go          — Backend 结构体、Record*/Rollback/Commit
  backend_test.go     — 单元测试
Makefile              — 编译 + 本地 demo 启动
```

## 实现方法

### 1. 拦截层（main.go）

`ShadowNode` 嵌入 `fs.LoopbackNode`，覆写 FUSE 操作接口，在透传到真实文件系统的同时记录操作：

| 接口 | 拦截的 FUSE 操作 |
|------|-----------------|
| `NodeMkdirer` | 创建目录 |
| `NodeRmdirer` | 删除目录 |
| `NodeCreater` | 创建文件（含覆写检测） |
| `NodeOpener` | 打开文件（写 + trunc / 写无 trunc） |
| `NodeUnlinker` | 删除文件 |
| `NodeRenamer` | 重命名（区分目录/文件） |

所有子节点通过 `WrapChild` 自动获得回滚能力。

### 2. 控制文件

挂载点根目录下自动创建虚拟文件 `.shadow.ctl`：

```bash
echo r > .shadow.ctl   # 回滚全部已记录操作
echo c > .shadow.ctl   # 提交（丢弃记录 + 清理暂存区）
```

### 3. 回滚后端（backend/）

`Backend` 维护一个 undo 日志栈（`[]LogEntry`），每种操作对应一个实现了 `Rollback()` 方法的 entry：

| Entry | 记录时 | Rollback 时 |
|-------|--------|------------|
| `MkdirEntry` | — | `os.Remove` |
| `RmdirEntry` | `os.Remove` | `os.Mkdir` |
| `CreateEntry` | — | `os.Remove` |
| `OverwriteEntry` | `os.Rename` → staging | staging → orig |
| `UnlinkEntry` | `os.Rename` → staging | staging → orig |
| `WriteOpen` | `io.Copy` → staging | staging → orig |
| `RenameEntry` | — | rename back (+ 有目标时 `os.Mkdir`) |
| `FileRenameEntry` | 有目标时 → staging | rename back + 恢复目标 |

回滚时逆序执行全部 entry 的 `Rollback()`，`Commit` 清空日志并清理 staging 目录。

## 使用

```bash
# 编译
make build

# 启动 demo（挂载 .demo/orig 到 .demo/mnt）
make demo

# 在另一个终端操作
cd .demo/mnt
echo hello > a.txt
mkdir -p x/y
rm -r x

# 回滚
echo r > .shadow.ctl    # 恢复 x/y/ 和 a.txt
echo c > .shadow.ctl    # 提交

# 退出
make clean              # 卸载 + 清理
```

或手动启动：

```bash
./shadowfs -staging /tmp/staging /mnt/point /original/dir
```
