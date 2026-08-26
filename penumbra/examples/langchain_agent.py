#!/usr/bin/env python3
"""LangChain ReAct Agent，工具全部受 Penumbra 监控，策略由 LLM 生成。

运行（真实监控需要 root）：
    sudo -E env "PATH=$PATH" python3 penumbra/examples/langchain_agent.py "把 workspace 里的文件数量写进 summary.txt"

依赖：pip install langchain langchain-openai
默认接本地 vLLM，可用 PENUMBRA_LLM_BASE_URL / PENUMBRA_LLM_MODEL / PENUMBRA_LLM_API_KEY 覆盖。
"""

from __future__ import annotations

import os
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

os.environ.setdefault("PENUMBRA_LOG", "info")

import penumbra
from penumbra import LLMPolicyGenerator

LLM_BASE_URL = os.environ.get("PENUMBRA_LLM_BASE_URL", "http://localhost:8000/v1")
LLM_MODEL = os.environ.get("PENUMBRA_LLM_MODEL", "qwen3-14b")
LLM_TIMEOUT = float(os.environ.get("PENUMBRA_LLM_TIMEOUT", "180"))


def make_llm(*, thinking: bool = True):
    """构造聊天模型。thinking=False 关掉 Qwen3 思维链，让策略裁决更快。"""
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise SystemExit(
            "需要 langchain-openai：pip install langchain langchain-openai"
        ) from exc
    api_key = (os.environ.get("PENUMBRA_LLM_API_KEY")
               or os.environ.get("OPENAI_API_KEY") or "EMPTY")
    kwargs = dict(model=LLM_MODEL, base_url=LLM_BASE_URL, api_key=api_key,
                  temperature=0, timeout=LLM_TIMEOUT)
    if not thinking:
        kwargs["extra_body"] = {
            "chat_template_kwargs": {"enable_thinking": False}}
    return ChatOpenAI(**kwargs)


llm = make_llm()
policy_llm = make_llm(thinking=False)

SECURITY_GUIDELINES = (
    "你是一个 AI agent 工具调用的安全策略引擎。每次工具调用都已在沙箱里推测执行，"
    "其文件/进程副作用被暂时挂起，等你裁决是提交(allow)还是回滚(deny)。\n"
    "准则：最小权限；只放行 workspace 目录内的文件操作；工具报错、声明了 workspace "
    "之外的路径、或行为与其用途明显不符时一律 deny；拿不准就 deny。\n"
    "allow 时必须给出授权这次调用效果所需的全部规则（没有 allow 规则 == 拒绝），"
    "通常是 workspace 前缀的文件操作，加上会话把输出写回管道所需的 WRITE_OUT/"
    "PIPE_WRITE/UNIX_WRITE。"
)

policy = LLMPolicyGenerator(model=policy_llm, system_prompt=SECURITY_GUIDELINES)

penumbra.start(
    policy=policy,
    workspace=os.environ.get("PENUMBRA_WORKSPACE", "/tmp/penumbra/workspace"),
    agent_id="langchain-react-agent",
    strict=False,
)


def build_tools():
    from langchain_core.tools import tool

    @penumbra.guard()
    @tool
    def write_file(filename: str, content: str) -> str:
        """把内容写入 workspace 下的某个文件。filename 应为相对路径。"""
        path = penumbra.workspace_path(filename)
        return (f"printf %s {shlex.quote(content)} > {shlex.quote(path)} "
                f"&& echo wrote {shlex.quote(path)} "
                f"\\({len(content)} bytes\\)")

    @penumbra.guard()
    @tool
    def count_lines(filename: str) -> str:
        """统计 workspace 下某个文件的行数。"""
        return f"wc -l {shlex.quote(penumbra.workspace_path(filename))}"

    @penumbra.guard()
    @tool
    def list_workspace() -> str:
        """列出 workspace 里现有的文件。"""
        path = penumbra.workspace_path()
        return (f"ls -1 {shlex.quote(path)} | grep . "
                f"|| echo '(empty)'")

    return [write_file, count_lines, list_workspace]


AGENT_SYSTEM_PROMPT = (
    "你是一个在受管控 workspace 里干活的助手。需要读写文件或统计信息时，"
    "请调用提供的工具，不要凭空编造结果。写文件请用相对路径。"
    "完成后用一句话报告你做了什么。"
)


def build_agent(tools):
    from langchain.agents import create_agent

    return create_agent(model=llm, tools=tools,
                        system_prompt=AGENT_SYSTEM_PROMPT)


def _print_transcript(messages):
    labels = {"human": "用户", "ai": "模型", "tool": "工具返回"}
    for msg in messages:
        for call in (getattr(msg, "tool_calls", None) or []):
            print(f"  [调用工具] {call.get('name')}({call.get('args')})", flush=True)
        text = getattr(msg, "content", "")
        if text:
            kind = getattr(msg, "type", "?")
            print(f"  [{labels.get(kind, kind)}] {str(text).strip()[:500]}",
                  flush=True)


def main() -> int:
    print("penumbra status:", penumbra.status())

    tools = build_tools()
    agent = build_agent(tools)

    task = sys.argv[1] if len(sys.argv) > 1 else (
        "在 workspace 里创建 note.txt，内容为 'hello penumbra'，然后统计它的行数。")
    print(f"\n=== 运行 LangChain Agent ===\n任务：{task}\n")
    try:
        final = None
        shown = 0
        for chunk in agent.stream(
                {"messages": [{"role": "user", "content": task}]},
                stream_mode="values"):
            messages = chunk.get("messages") or []
            _print_transcript(messages[shown:])
            shown = len(messages)
            if messages:
                final = messages[-1]
        print("\n=== Agent 最终回答 ===")
        print(getattr(final, "content", final))
    finally:
        penumbra.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
