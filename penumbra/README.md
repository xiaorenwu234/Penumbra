# Penumbra ↔ LangChain 集成

把 Penumbra 的推测执行 + 策略管控接入 LangChain 代码。三个集成点：

1. `penumbra.start()` —— 一行启动整套系统
2. `LLMPolicyGenerator` —— 策略由 LLM 生成，输入输出格式固定
3. `@penumbra.guard()` —— 给工具加一个注解即纳入监控

底层 ShadowFS / ShadowProc / ShadowObserve / Orchestrator 无需改动，本集成只通过
Orchestrator 的 Unix socket JSON-line API 通信。

## 上手

```python
import penumbra
from penumbra import LLMPolicyGenerator
from langchain_openai import ChatOpenAI

# ① 策略：用 LLM 生成
policy = LLMPolicyGenerator(
    model=ChatOpenAI(model="qwen3-14b", base_url="http://localhost:8000/v1",
                     api_key="EMPTY", temperature=0),
    system_prompt="你是安全策略引擎：只放行 workspace 内的文件操作，越界写或报错则 deny。",
)

# ② 一行启动（首次调用会拉起或接管整套 daemon）
penumbra.start(policy=policy, workspace="/srv/agent-workspace")

# ③ 加注解 = 纳入监控。碰 workspace 的工具必须加（含只读）。
@penumbra.guard()
def write_report(title: str, body: str) -> str:
    path = penumbra.workspace_path("report.md")
    return f"printf '# %s\\n\\n%s\\n' {shlex.quote(title)} {shlex.quote(body)} > {shlex.quote(path)}"
```

每次调用都会变成一个**推测 epoch**：副作用先被拦住 → 模型裁决 → `allow` 原子提交，
`deny` 无损回滚。

## 启动

```python
penumbra.start(
    policy=MyPolicy(),                # 默认 WorkspacePolicy
    workspace="/srv/agent-workspace", # 受管控 FUSE 挂载点
)
```

- `orch_sock` 上已有 Orchestrator → 直接接管，不启动进程；
- 否则（`autostart=True`）依次拉起 ShadowFS → ShadowProc → ShadowObserve → Orchestrator；
- 本进程启动的 daemon 在退出时自动清理（`stop_on_exit`）。

拉起真实内核栈需要 **root**。无 root 时让别人先起好 daemon 再 `start()` 接管，或用
`strict=False` 降级。

常用配置（均可用 `PENUMBRA_<FIELD>` 环境变量覆盖）：

| 字段 | 含义 | 默认 |
|------|------|------|
| `workspace` | 受管控 FUSE 挂载点 | `/tmp/penumbra/workspace` |
| `backing_dir` | 提交落盘的真实目录 | `/tmp/penumbra/backing` |
| `orch_sock` | Orchestrator socket | `/tmp/penumbra/orch.sock` |
| `agent_id` | 代理身份（同一 agent 的工具调用串行化） | `langchain-agent` |
| `autostart` / `attach_if_running` | 无人监听时自启 / 有人监听时接管 | `True` / `True` |
| `strict` | 无法进程级监控时是否拒绝（而非降级 inline） | `True` |

## 策略

输入固定 `PolicyRequest`，输出固定 `PolicyDecision`。默认用 LLM 生成：

```python
policy = LLMPolicyGenerator(
    model=ChatOpenAI(model="qwen3-14b", base_url="http://localhost:8000/v1",
                     api_key="EMPTY", temperature=0),
    system_prompt="……你的业务安全准则……",   # 可选
)
```

任何 OpenAI 兼容服务都能接（vLLM / OpenAI / DeepSeek）。可用
`PENUMBRA_LLM_MODEL` / `PENUMBRA_LLM_BASE_URL` / `PENUMBRA_LLM_API_KEY` 覆盖。

- **结构化输出**：默认走 `with_structured_output` 硬约束输出与 `PolicyDecision` 对齐。
  不传 `structured_method` 时按 `json_schema → function_calling → json_mode` 自动探测降级。
- **fail-closed**：模型异常、输出不合规、规则编译不过，一律降级为 `deny` 回滚。
- 想自定义提示词，继承 `LLMPolicyGenerator` 重载 `build_prompt(request)`。

诊断 transport（不需 root / 后端）：

```bash
python3 penumbra/tests/diagnose_llm_policy.py
```

也可用非 LLM 的内置策略：`WorkspacePolicy` / `AllowAllPolicy` / `DenyAllPolicy`，
或直接传函数 `def policy(request) -> PolicyDecision`。

## 注解

```python
@penumbra.guard()                       # 默认 shell 模式
def tool_a(...): return f"wc -l {shlex.quote(path)}"

@penumbra.guard(paths=["out.txt"],      # 声明意图写的路径
                policy=SpecialPolicy()) # 该工具的独立策略
def tool_c(...): ...
```

执行模式（`mode`）：

- `shell`（**默认**）——工具**返回**命令字符串，在受管会话里执行。唯一在真实内核栈
  上能端到端跑通的模式。插值一律用 `shlex.quote()`。
- `fork`——工具体在受管 cgroup 的子进程里执行。一旦产生受管副作用就会死锁，只适合
  无受管副作用的工具体。
- `inline`——在当前进程执行，只括起 epoch。当前进程不在受管 cgroup，直接碰 workspace
  会 EIO。

对 LangChain 工具同样适用：

```python
from langchain_core.tools import tool

@penumbra.guard()
@tool
def save_note(text: str) -> str:
    ...

tools = penumbra.wrap_tools([save_note, run_query])
agent = create_agent(model=llm, tools=tools)
```

`@guard` 保留工具的 name / description / args schema，只把执行重定向进 epoch。

> ⚠️ 碰 workspace 的工具必须加 `@guard`，连只读也不例外。workspace 按 cgroup + 活跃
> epoch 归属，未归属的进程访问它会 fail-closed 返回 EIO。

## 诊断

默认静默。卡住时用 `PENUMBRA_LOG` 打开进度日志：

```bash
sudo -E env "PATH=$PATH" PENUMBRA_LOG=info python3 your_agent.py
```

```
[penumbra  405ms] epoch begin: tool=list_workspace mode=shell
[penumbra  406ms] session_run: ls -1 /tmp/penumbra/workspace
[penumbra  406ms] session_run done: exit=0 (0.0s) 16 bytes out
[penumbra  406ms] generating policy for list_workspace via LLMPolicyGenerator…
[penumbra 8321ms] policy decided: allow (7.9s) — operation within workspace
[penumbra 8402ms] epoch resolved: tool=list_workspace committed=True
```

| 最后一行 | 含义 |
|---|---|
| `epoch begin` 后无下文 | 卡在开 epoch（看 orchestrator.log） |
| `session_run` 后不返回 | 命令在受管会话里被阻住，`command_timeout` 到点才报错 |
| `generating policy` 后不返回 | 在等模型，thinking 模型单次可能几十秒 |
| `policy decided: deny` | 模型判了 deny，reason 写了原因 |

进程被 `kill` 后 FUSE 挂载会残留成 stale mount。启动时会报出来并提示：

```
sudo umount -l /tmp/penumbra/workspace
```

## 手动 epoch

```python
with penumbra.epoch("db-migration", policy=MyPolicy()):
    penumbra.run("./migrate.sh")
```

## 测试

```bash
python3 penumbra/tests/test_integration.py          # 离线，无需 root
```

端到端（需 root + 已构建的三组件）：

```bash
sudo python3 penumbra/examples/agent_example.py
sudo -E env "PATH=$PATH" python3 penumbra/examples/langchain_agent.py "在 workspace 里创建 note.txt 并统计行数"
```

## 文件一览

| 文件 | 职责 |
|------|------|
| [`penumbra/__init__.py`](penumbra/__init__.py) | 公开 API：`start` / `stop` / `guard` / `run` / `epoch` / `wrap_tools` |
| [`penumbra/config.py`](penumbra/config.py) | `PenumbraConfig` |
| [`penumbra/policy.py`](penumbra/policy.py) | `PolicyGenerator` / `PolicyRequest` / `PolicyDecision` / `LLMPolicyGenerator` |
| [`penumbra/supervisor.py`](penumbra/supervisor.py) | 一行启动/接管四个 daemon |
| [`penumbra/runtime.py`](penumbra/runtime.py) | 会话、epoch 括号、三种执行模式 |
| [`penumbra/guard.py`](penumbra/guard.py) | `@guard` 注解 + LangChain 工具包装 |
| [`penumbra/client.py`](penumbra/client.py) | Orchestrator socket 客户端 |
| [`penumbra/examples/`](penumbra/examples/) | 示例：最小 / LangChain Agent / 多 agent 共享后端 |
| [`penumbra/tests/test_integration.py`](penumbra/tests/test_integration.py) | 离线测试 |
