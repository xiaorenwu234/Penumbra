#!/usr/bin/env python3
"""多个 agent 共享同一套 Penumbra 后端。

四个子命令：

    # ① 以 root 拉起后端并常驻
    sudo -E python3 penumbra/examples/multi_agent_shared_backend.py bootstrap

    # ② 每个 agent 一个进程（agent_id 必须不同）
    python3 penumbra/examples/multi_agent_shared_backend.py agent researcher --hold 30
    python3 penumbra/examples/multi_agent_shared_backend.py agent coder --hold 30

    # ③ 单进程两线程扮演两个 agent
    python3 penumbra/examples/multi_agent_shared_backend.py parallel

    # ④ 查看后端当前的 session / agent
    python3 penumbra/examples/multi_agent_shared_backend.py verify

默认接本地 vLLM，可用 PENUMBRA_LLM_BASE_URL / PENUMBRA_LLM_MODEL / PENUMBRA_LLM_API_KEY 覆盖。

手动清理后端：
    sudo pkill -f shadow_orchestrator.py; sudo pkill -f shadow-proc
    sudo pkill -f shadowfs; sudo pkill -f observ_daemon
    sudo umount -l /tmp/penumbra/workspace
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

import penumbra
from penumbra import LLMPolicyGenerator
from penumbra.client import OrchestratorClient

WORKSPACE = os.environ.get("PENUMBRA_WORKSPACE", "/tmp/penumbra/workspace")
ORCH_SOCK = os.environ.get("PENUMBRA_ORCH_SOCK", "/tmp/penumbra/orch.sock")

LLM_BASE_URL = os.environ.get("PENUMBRA_LLM_BASE_URL", "http://localhost:8000/v1")
LLM_MODEL = os.environ.get("PENUMBRA_LLM_MODEL", "qwen3-14b")

SECURITY_GUIDELINES = (
    "你是一个 AI agent 工具调用的安全策略引擎。每次工具调用都已在沙箱里推测执行，"
    "其文件/进程副作用被暂时挂起，等你裁决是提交(allow)还是回滚(deny)。\n"
    "准则：最小权限；只放行 workspace 目录内的文件操作；工具报错、声明了 workspace "
    "之外的路径、或行为与其用途明显不符时一律 deny；拿不准就 deny。\n"
    "allow 时必须给出授权这次调用效果所需的全部规则（没有 allow 规则 == 拒绝），"
    "通常是 workspace 前缀的文件操作，加上会话把输出写回管道所需的 WRITE_OUT/"
    "PIPE_WRITE/UNIX_WRITE。"
)


def make_policy():
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise SystemExit(
            "需要 langchain-openai：pip install langchain langchain-openai"
        ) from exc
    api_key = (os.environ.get("PENUMBRA_LLM_API_KEY")
               or os.environ.get("OPENAI_API_KEY") or "EMPTY")
    llm = ChatOpenAI(model=LLM_MODEL, base_url=LLM_BASE_URL,
                     api_key=api_key, temperature=0)
    return LLMPolicyGenerator(model=llm, system_prompt=SECURITY_GUIDELINES)


def write_note_cmd(agent_dir: str, filename: str, text: str) -> str:
    """在 agent 自己的子目录里写一个文件（返回 shell 命令）。"""
    path = penumbra.workspace_path(f"{agent_dir}/{filename}")
    return (f"mkdir -p {shlex.quote(os.path.dirname(path))} && "
            f"printf '%s\\n' {shlex.quote(text)} > {shlex.quote(path)} && "
            f"echo wrote {shlex.quote(path)}")


def list_notes_cmd(agent_dir: str) -> str:
    """列出 agent 自己子目录下的文件（返回 shell 命令）。"""
    path = penumbra.workspace_path(agent_dir)
    return f"ls -1 {shlex.quote(path)} 2>/dev/null | wc -l"


def cmd_bootstrap() -> int:
    if os.geteuid() != 0:
        raise SystemExit("bootstrap 需要 root（FUSE 挂载 / eBPF / cgroup 写入）：\n"
                         "  sudo -E python3 " + " ".join(sys.argv))
    penumbra.start(workspace=WORKSPACE, orch_sock=ORCH_SOCK,
                   stop_on_exit=False)
    status = penumbra.status()
    print("=== 后端已就绪（常驻）===")
    print(f"  attached      : {status['attached']}（False 表示本次是新拉起的）")
    print(f"  workspace     : {status['workspace']}")
    print(f"  已挂载        : {status['workspace_mounted']}")
    print(f"  orch_sock     : {status['orch_sock']}")
    for d in status["daemons"]:
        print(f"  daemon {d['name']:<14} pid={d['pid']:<8} alive={d['alive']}  "
              f"log={d['log']}")
    print("\n现在可以在其他终端以不同 agent_id 接入：")
    print("  python3 penumbra/examples/multi_agent_shared_backend.py agent researcher --hold 30")
    print("  python3 penumbra/examples/multi_agent_shared_backend.py agent coder --hold 30")
    return 0


def attach(agent_id: str | None = None):
    """attach 到共享后端。autostart=False：只允许 attach，避免多进程各自拉起 daemon。"""
    kwargs = dict(policy=make_policy(), workspace=WORKSPACE,
                  orch_sock=ORCH_SOCK, autostart=False, strict=False)
    if agent_id:
        kwargs["agent_id"] = agent_id
    try:
        return penumbra.start(**kwargs)
    except penumbra.StartupError as exc:
        raise SystemExit(
            f"无法接入共享后端：{exc}\n\n"
            f"先以 root 拉起后端：\n"
            f"  sudo -E python3 {sys.argv[0]} bootstrap") from exc


def cmd_agent(agent_id: str, hold: float) -> int:
    runtime = attach(agent_id)
    status = runtime.status()
    print(f"=== agent {agent_id} 已接入共享后端 ===")
    print(f"  attached : {status['attached']}（True 表示复用了已有后端）")

    guarded_write = penumbra.guard(write_note_cmd)
    guarded_list = penumbra.guard(list_notes_cmd)

    session = runtime.session_for(agent_id)
    print(f"  session  : {session.session_id}")
    print(f"  cgroup   : {session.cgroup_id}")

    print(f"\n[{agent_id}] 写文件（受监控 + LLM 策略裁决）……")
    out = guarded_write(agent_id, "note.txt", f"hello from {agent_id}")
    print(f"  → {out.strip()}")

    print(f"[{agent_id}] 统计自己目录下的文件数……")
    print(f"  → {guarded_list(agent_id).strip()}")

    backing = runtime.config.backing_path(f"{agent_id}/note.txt")
    print(f"[{agent_id}] 已落盘到 backing store: {os.path.exists(backing)}  ({backing})")

    if hold > 0:
        print(f"\n[{agent_id}] 保持 session 存活 {hold:.0f}s —— 现在可在另一个终端跑：")
        print("  python3 penumbra/examples/multi_agent_shared_backend.py verify")
        time.sleep(hold)

    penumbra.stop()
    print(f"[{agent_id}] 已退出（共享后端与其他 agent 不受影响）")
    return 0


def cmd_parallel() -> int:
    runtime = attach()
    print("=== 单进程内两个 agent 并行（各自独立 session / cgroup）===")
    results = {}
    lock = threading.Lock()

    def worker(agent_id: str):
        # @guard 的 agent_id 是静态的，所以这里用 guarded_call 按调用传入。
        t0 = time.time()
        out = runtime.guarded_call(
            write_note_cmd, tool_name="write_note",
            agent_id=agent_id, args=(agent_id, "parallel.txt",
                                     f"written by {agent_id}"))
        session = runtime.session_for(agent_id)
        with lock:
            results[agent_id] = {
                "session": session.session_id,
                "cgroup": session.cgroup_id,
                "elapsed": time.time() - t0,
                "output": out.strip(),
            }

    threads = [threading.Thread(target=worker, args=(aid,))
               for aid in ("agent-alpha", "agent-beta")]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.time() - t0

    for agent_id, info in sorted(results.items()):
        print(f"\n  {agent_id}")
        print(f"    session : {info['session']}")
        print(f"    cgroup  : {info['cgroup']}")
        print(f"    耗时    : {info['elapsed']:.2f}s")
        print(f"    输出    : {info['output']}")

    sessions = {i["session"] for i in results.values()}
    cgroups = {i["cgroup"] for i in results.values()}
    print(f"\n  session 互不相同: {len(sessions) == len(results)}")
    print(f"  cgroup  互不相同: {len(cgroups) == len(results)}")
    total = sum(i["elapsed"] for i in results.values())
    print(f"  墙钟 {wall:.2f}s vs 串行累加 {total:.2f}s "
          f"→ 不同 agent 未被 barrier 串行化: {wall < total}")

    penumbra.stop()
    return 0


def cmd_verify() -> int:
    client = OrchestratorClient(ORCH_SOCK, timeout=10.0)
    if not client.is_listening():
        raise SystemExit(f"后端未运行（{ORCH_SOCK} 无人监听）。先跑 bootstrap。")
    print("=== 共享后端当前状态 ===")
    print(f"  活跃 session : {client.session_list()}")
    print(f"  ShadowFS agent: {client.list_agents()}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="多个 agent 共享同一套 Penumbra 后端的示例")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("bootstrap", help="以 root 拉起后端并常驻")
    p_agent = sub.add_parser("agent", help="一个进程一个 agent，attach 到共享后端")
    p_agent.add_argument("agent_id", help="该进程的 agent 身份（必须唯一）")
    p_agent.add_argument("--hold", type=float, default=0.0,
                         help="跑完后保持 session 存活的秒数，便于 verify 观察")
    sub.add_parser("parallel", help="单进程两线程扮演两个 agent")
    sub.add_parser("verify", help="查看后端当前的 session / agent")
    args = parser.parse_args()

    if args.cmd == "bootstrap":
        return cmd_bootstrap()
    if args.cmd == "agent":
        return cmd_agent(args.agent_id, args.hold)
    if args.cmd == "parallel":
        return cmd_parallel()
    return cmd_verify()


if __name__ == "__main__":
    raise SystemExit(main())
