#!/usr/bin/env python3
"""最小示例：受 Penumbra 监控的工具，策略由自定义 PolicyGenerator 生成。

运行（真实监控需要 root）：
    sudo python3 penumbra/examples/agent_example.py
"""

from __future__ import annotations

import os
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

import penumbra
from penumbra import (PolicyDecision, PolicyGenerator, PolicyRequest,
                      filesystem_rules, shell_plumbing_rules, allow)


class ReportWriterPolicy(PolicyGenerator):
    """放行 workspace 内的文件写入，其余一律 deny。"""

    def generate(self, request: PolicyRequest) -> PolicyDecision:
        if request.failed:
            return PolicyDecision.deny(f"tool raised: {request.error}")

        outside = request.paths_outside_workspace()
        if outside:
            return PolicyDecision.deny(f"writes outside workspace: {outside}")

        rules = filesystem_rules(request.workspace) + shell_plumbing_rules()
        if request.tool_name == "network_probe":
            rules.append(allow("CONNECT",
                               endpoint={"family": 2, "port": 443}))
        return PolicyDecision.allow(rules, reason="report-writer policy")


penumbra.start(
    policy=ReportWriterPolicy(),
    workspace=os.environ.get("PENUMBRA_WORKSPACE", "/tmp/penumbra/workspace"),
    strict=False,
)


@penumbra.guard(paths=["report.md"])
def write_report(title: str, body: str) -> str:
    """Write a markdown report into the guarded workspace."""
    path = penumbra.workspace_path("report.md")
    return (f"printf '# %s\\n\\n%s\\n' {shlex.quote(title)} "
            f"{shlex.quote(body)} > {shlex.quote(path)} "
            f"&& echo wrote {shlex.quote(path)}")


@penumbra.guard()
def count_files(directory: str = ".") -> str:
    """Count files under a directory (runs as a guarded shell command)."""
    return f"ls -1 {shlex.quote(directory)} | wc -l"


def unguarded_ping() -> str:
    return "pong"


def build_langchain_agent():
    try:
        from langchain_core.tools import tool as lc_tool
    except ImportError:
        return None

    @penumbra.guard(paths=["notes.txt"])
    @lc_tool
    def save_note(text: str) -> str:
        """Save a note into the guarded workspace."""
        path = penumbra.workspace_path("notes.txt")
        return (f"printf '%s\\n' {shlex.quote(text)} >> {shlex.quote(path)} "
                f"&& echo appended to {shlex.quote(path)}")

    return [save_note]


def main() -> int:
    print("penumbra status:", penumbra.status())

    print(write_report("Q3 summary", "All green."))
    print("file count:", count_files(penumbra.workspace_path()))

    tools = build_langchain_agent()
    if tools:
        note_tool = tools[0]
        print(note_tool.invoke({"text": "remember to file the report"}))
    else:
        print("(langchain not installed — skipped the LangChain tool demo)")

    penumbra.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
