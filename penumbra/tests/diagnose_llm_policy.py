#!/usr/bin/env python3
"""诊断 LLM 策略生成：模型是否真的支持结构化输出，返回了什么。

不需要 root，不需要 Penumbra 后端 —— 只打模型。用来定位
"policy model returned decision ''" 这类问题出在哪一层。

默认接本地 vLLM：
    python3 penumbra/tests/diagnose_llm_policy.py

接其他服务：
    PENUMBRA_LLM_BASE_URL=... PENUMBRA_LLM_MODEL=... PENUMBRA_LLM_API_KEY=sk-... \
        python3 penumbra/tests/diagnose_llm_policy.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from penumbra.policy import (LLMPolicyGenerator, PolicyRequest,
                             _policy_decision_schema)

BASE_URL = os.environ.get("PENUMBRA_LLM_BASE_URL", "http://localhost:8000/v1")
MODEL = os.environ.get("PENUMBRA_LLM_MODEL", "qwen3-14b")

# 一个典型的待裁决请求：在 workspace 内写文件，应当 allow。
REQUEST = PolicyRequest(
    tool_name="write_file",
    tool_description="把内容写入 workspace 下的某个文件。",
    agent_id="diag", session_id="s1", epoch_id="e1",
    mode="fork", workspace="/tmp/penumbra/workspace",
    args=("summary.txt", "3"), declared_paths=("*",),
)


def show(label: str, value: object, limit: int = 400) -> None:
    text = value if isinstance(value, str) else repr(value)
    if len(text) > limit:
        text = text[:limit] + f"… (共 {len(text)} 字符)"
    print(f"  {label}: {text}")


def main() -> int:
    api_key = (os.environ.get("PENUMBRA_LLM_API_KEY")
               or os.environ.get("OPENAI_API_KEY") or "EMPTY")
    from langchain_openai import ChatOpenAI

    print(f"model = {MODEL}   base_url = {BASE_URL}\n")
    llm = ChatOpenAI(model=MODEL, base_url=BASE_URL, api_key=api_key,
                     temperature=0)

    # ① 模型本身通不通。
    print("① 裸调用（确认模型名/端点/key 可用）")
    try:
        show("返回", llm.invoke("只回复两个字：正常").content)
    except Exception as exc:
        print(f"  ✗ 失败：{type(exc).__name__}: {exc}")
        print("  → 模型名或端点或 key 有问题，后面都不用看了。")
        return 1

    # ② 模型是否支持 tool-calling（结构化输出的前提）。
    print("\n② tool-calling 支持（结构化输出依赖它）")
    schema = _policy_decision_schema()
    try:
        bound = llm.bind_tools([schema])
        msg = bound.invoke("判断这次调用是否安全，用工具回答。")
        show("tool_calls", getattr(msg, "tool_calls", None))
        show("content", getattr(msg, "content", ""))
        if not getattr(msg, "tool_calls", None):
            print("  ⚠ 没有产生 tool_call —— 该模型可能不支持 function-calling。")
    except Exception as exc:
        print(f"  ✗ bind_tools 失败：{type(exc).__name__}: {exc}")

    # ③ 三种 method 分别试：哪种能拿到合规对象。
    print("\n③ with_structured_output 各 method 实测")
    prompt = LLMPolicyGenerator(model=llm).build_prompt(REQUEST)
    for method in (None, "function_calling", "json_mode", "json_schema"):
        label = method or "(默认)"
        try:
            runnable = (llm.with_structured_output(schema) if method is None
                        else llm.with_structured_output(schema, method=method))
        except Exception as exc:
            print(f"  {label:<18} 绑定失败: {type(exc).__name__}: {exc}")
            continue
        try:
            result = runnable.invoke(prompt)
        except Exception as exc:
            print(f"  {label:<18} 调用失败: {type(exc).__name__}: {exc}")
            continue
        kind = type(result).__name__
        if result is None:
            print(f"  {label:<18} ✗ 返回 None")
            continue
        data = (dict(result) if isinstance(result, dict)
                else result.model_dump() if hasattr(result, "model_dump") else result)
        decision = data.get("decision") if isinstance(data, dict) else None
        flag = "✓" if decision in ("allow", "deny") else "✗"
        print(f"  {label:<18} {flag} 类型={kind} decision={decision!r}")
        if isinstance(data, dict):
            show("    完整返回", json.dumps(data, ensure_ascii=False))

    # ④ 走一遍真实的策略生成（含回退与 fail-closed）。
    print("\n④ LLMPolicyGenerator.generate() 端到端")
    gen = LLMPolicyGenerator(model=llm)
    print(f"  结构化输出已绑定: {gen._get_structured() is not None}")
    decision = gen.generate(REQUEST)
    print(f"  decision : {decision.decision}")
    print(f"  reason   : {decision.reason}")
    print(f"  rules    : {len(decision.rules)} 条")
    for rule in decision.rules:
        print(f"    - {rule.event_type} {rule.action} {rule.path_pattern!r}")
    print(f"  metadata : {decision.metadata}")
    if decision.decision == "deny":
        print("\n  ⚠ 结果是 deny。若 ③ 里某个 method 是 ✓，说明该用那个 method；")
        print("    若全是 ✗，说明该模型的结构化输出不可用，需要换模型或走文本路径。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
