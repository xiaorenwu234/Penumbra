#!/usr/bin/env python3
"""
demo.py — 完整演示 ghostbpf-observ 的工作流程。

流程：
  1. 创建一个临时 cgroup (cgroup v2)
  2. 启动 FsObserver 在后台记录文件事件
  3. 在目标 cgroup 内执行一系列文件操作 (touch, chmod, rm, mv 等)
  4. 停止录制
  5. 加载审计规则并审计 JSONL 日志
  6. 打印审计报告

要求以 root 权限运行：
    sudo python3 demo.py
"""

import subprocess
import os
import sys
import time
import stat
import json
import tempfile
import shutil
import textwrap
from pathlib import Path


# ── 配置 ────────────────────────────────────────────────────────────────────

DEMO_BIN      = Path(__file__).parent / "build" / "observ_demo"
CGROUP_ROOT   = Path("/sys/fs/cgroup")
CGROUP_NAME   = "ghostbpf_observ_demo"
DURATION_SEC  = 8   # 录制时长（秒）
EVENTS_FILE   = "events.jsonl"


# ── cgroup 操作 ─────────────────────────────────────────────────────────────

def cgroup_create(name: str) -> Path:
    """在 cgroup v2 根下创建一个子 cgroup，返回其路径。"""
    cg = CGROUP_ROOT / name
    if cg.exists():
        print(f"  [cgroup] 删除已存在的 {cg}")
        cgroup_delete(name)

    cg.mkdir()
    print(f"  [cgroup] 已创建 {cg}")
    return cg


def cgroup_delete(name: str) -> None:
    """删除一个子 cgroup（必须先移出其中的进程）。"""
    cg = CGROUP_ROOT / name
    if not cg.exists():
        return
    # 将所有进程移回根 cgroup
    try:
        procs = (cg / "cgroup.procs").read_text().strip().split("\n")
        root_procs = CGROUP_ROOT / "cgroup.procs"
        for pid in procs:
            if pid:
                root_procs.write_text(pid)
                time.sleep(0.01)
    except Exception:
        pass
    cg.rmdir()
    print(f"  [cgroup] 已删除 {cg}")


def cgroup_move_self(name: str) -> None:
    """将当前进程移入指定 cgroup。"""
    cg = CGROUP_ROOT / name
    (cg / "cgroup.procs").write_text(str(os.getpid()))
    print(f"  [cgroup] 当前进程 (pid={os.getpid()}) 已移入 {cg}")


def cgroup_get_inode(name: str) -> int:
    """获取 cgroup 目录的 inode 号。"""
    cg = CGROUP_ROOT / name
    return os.stat(cg).st_ino


def cgroup_has_controllers(name: str) -> bool:
    """确保子 cgroup 继承了父 cgroup 的控制器。"""
    cg = CGROUP_ROOT / name
    controllers = (cg / "cgroup.controllers").read_text().strip()
    return len(controllers) > 0


# ── 文件操作模拟 ────────────────────────────────────────────────────────────

def run_file_operations(work_dir: Path) -> None:
    """在 work_dir 中执行一系列文件操作，以触发 BPF 探针。"""
    print("\n  >>> 开始文件操作模拟 ...")

    # 切换到工作目录
    os.chdir(work_dir)

    # 1. OPEN + CREATE: 新建文件
    f1 = work_dir / "hello.txt"
    f1.write_text("Hello from ghostbpf-observ!\n")
    print(f"  [op] CREATE + OPEN: {f1}")

    # 2. OPEN (读): 读取文件
    content = f1.read_text()
    print(f"  [op] OPEN (read):  {f1}  →  {content.strip()}")

    # 3. OPEN (写/追加): 追加写入
    with open(f1, "a") as f:
        f.write("Appended line.\n")
    print(f"  [op] OPEN (write): {f1}")

    # 4. 创建更多文件
    for name in ["config.ini", "data.log", "notes.txt"]:
        f = work_dir / name
        f.write_text(f"content of {name}\n")
        print(f"  [op] CREATE: {f}")

    # 5. RENAME
    src, dst = work_dir / "notes.txt", work_dir / "notes.bak"
    src.rename(dst)
    print(f"  [op] RENAME: {src.name} → {dst.name}")

    # 6. DELETE
    (work_dir / "data.log").unlink()
    print(f"  [op] DELETE: data.log")

    # 7. 在子目录中操作
    sub = work_dir / "subdir"
    sub.mkdir()
    (sub / "deep.txt").write_text("nested\n")
    print(f"  [op] CREATE: {sub}/deep.txt")
    (sub / "deep.txt").unlink()
    print(f"  [op] DELETE: {sub}/deep.txt")

    print("  <<< 文件操作模拟结束。\n")


# ── 审计规则展示 ────────────────────────────────────────────────────────────

def print_rules() -> None:
    """打印演示使用的审计规则。"""
    rules = textwrap.dedent("""\
    ┌─────────────────────────────────────────────────────────┐
    │ 审计规则                                                 │
    ├──────────┬────────────────────┬─────────────────────────┤
    │ 动作     │ 事件类型            │ 路径模式                 │
    ├──────────┼────────────────────┼─────────────────────────┤
    │ ALLOW    │ 任意 (-1)           │ /tmp/                   │
    │ ALLOW    │ 任意 (-1)           │ /home/                  │
    │ DENY     │ DELETE              │ /etc/                   │
    │ DENY     │ OPEN                │ /etc/shadow             │
    │ 默认     │ —                  │ default-deny (无匹配)     │
    └──────────┴────────────────────┴─────────────────────────┘
    """)
    print(rules)


# ── 主流程 ──────────────────────────────────────────────────────────────────

def main():
    # 权限检查
    if os.geteuid() != 0:
        print("❌ 需要 root 权限。请使用: sudo python3 demo.py")
        sys.exit(1)

    # 检查 demo 二进制
    if not DEMO_BIN.exists():
        print(f"❌ 找不到 {DEMO_BIN}，请先执行 cmake --build build/")
        sys.exit(1)

    print("=" * 60)
    print("  ghostbpf-observ 完整演示")
    print("=" * 60)
    print()

    # ── Step 1: 创建临时工作目录和 cgroup ────────────────────────────────
    print("[Step 1] 创建临时工作目录和 cgroup")
    work_dir = Path(tempfile.mkdtemp(prefix="observ_demo_"))
    print(f"  [work] 工作目录: {work_dir}")

    cg = cgroup_create(CGROUP_NAME)

    # 确保控制器可用（需要在含有 subtree_control 的层级写入）
    if not cgroup_has_controllers(CGROUP_NAME):
        # 尝试启用控制器
        try:
            (CGROUP_ROOT / "cgroup.subtree_control").write_text(
                "+memory +pids +cpu"
            )
            time.sleep(0.1)
        except Exception:
            print("  ⚠ 无法启用控制器 (非致命)")

    cgroup_id = cgroup_get_inode(CGROUP_NAME)
    print(f"  [cgroup] cgroup_id (inode) = {cgroup_id}")

    # ── Step 2: 启动 observ_demo 在后台录制 ─────────────────────────────
    print(f"\n[Step 2] 启动观察器录制 ({DURATION_SEC} 秒)...")
    print(f"  命令: {DEMO_BIN} {cgroup_id} {DURATION_SEC}")
    print(f"  输出: {EVENTS_FILE}")

    # 以子进程方式启动 observ_demo，捕获其 stdout/stderr
    demo_proc = subprocess.Popen(
        [str(DEMO_BIN), str(cgroup_id), str(DURATION_SEC)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # 给 BPF 程序一点时间挂载
    time.sleep(1.0)

    # ── Step 3: 在 cgroup 内执行文件操作 ─────────────────────────────────
    print(f"[Step 3] 在 cgroup 内执行文件操作")

    # fork 一个子进程放入目标 cgroup，在子进程中执行文件操作
    child_pid = os.fork()
    if child_pid == 0:
        # 子进程：移入 cgroup → 执行文件操作 → 退出
        try:
            (cg / "cgroup.procs").write_text(str(os.getpid()))
        except Exception:
            pass
        run_file_operations(work_dir)
        os._exit(0)
    else:
        # 父进程：等待子进程完成
        os.waitpid(child_pid, 0)
        print("  [cgroup] 子进程文件操作已完成")

    # ── Step 4: 等待 observ_demo 完成 ────────────────────────────────────
    print(f"\n[Step 4] 等待 FsObserver 录制完成...")
    stdout, stderr = demo_proc.communicate(timeout=DURATION_SEC + 5)

    print(f"  observ_demo 退出码: {demo_proc.returncode}")
    if stderr:
        # 过滤掉 BPF map 删除的预期错误
        for line in stderr.strip().split("\n"):
            line = line.strip()
            if line and "bpf_map__delete_elem" not in line:
                print(f"  [stderr] {line}")

    # ── Step 5: 查看录制的 JSONL 事件 ────────────────────────────────────
    print(f"\n[Step 5] 录制的事件 ({EVENTS_FILE})")

    events_path = Path(EVENTS_FILE)
    if events_path.exists():
        lines = events_path.read_text().strip().split("\n")
        print(f"  共录制 {len(lines)} 个事件 (FS + PROC):\n")
        for line in lines:
            try:
                evt = json.loads(line)
                print(
                    f"  [{evt.get('event','?'):8s}] "
                    f"pid={evt.get('pid',0):6d}  "
                    f"comm={evt.get('comm','?'):16s}  "
                    f"path={evt.get('path','?'):50s}"
                    + (f"  → {evt['new_path']}" if evt.get("new_path") else "")
                )
            except json.JSONDecodeError:
                print(f"  (parse error) {line[:80]}")
    else:
        print("  ⚠ 未生成 events.jsonl")

    # ── Step 6: 审计报告 ────────────────────────────────────────────────
    print()
    print_rules()

    print("[Step 6] 审计报告 (来自 observ_demo 输出)")
    print("-" * 60)

    # observ_demo 的 stdout 包含完整的审计报告
    in_report = False
    for line in stdout.split("\n"):
        if "AUDIT REPORT" in line:
            in_report = True
        if in_report:
            print(line)

    # ── 清理 ─────────────────────────────────────────────────────────────
    print("\n[清理]")
    cgroup_delete(CGROUP_NAME)
    if events_path.exists():
        events_path.unlink()
    shutil.rmtree(work_dir, ignore_errors=True)
    print("  临时文件已清理。")

    print("\n" + "=" * 60)
    print("  演示完成 ✓")
    print("=" * 60)


if __name__ == "__main__":
    main()
