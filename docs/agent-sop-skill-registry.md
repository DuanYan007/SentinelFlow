# Agent 的 SOP / Skill 注册机制

## 本轮目标

这一轮的目标是把 Agent 从“硬编码分支判断”推进到“注册表驱动”的形态，为后续接入 OpenAI 决策层做准备。

当前不是直接让大模型控制整个工作流，而是先标准化三件事：

- 有哪些可选 skill
- 有哪些可选 SOP
- LLM 未来基于什么输入做选择

## 当前结构

当前 Agent 侧新增了一个注册模块：

- `src/agent/registry.py`

该模块维护两类注册信息：

1. `skill registry`
2. `sop registry`

这样后续无论是规则决策还是 LLM 决策，都不再直接操作散落的字符串，而是面向统一的定义对象。

## Skill Registry

当前内部 skill 注册表包含以下条目：

- `project-memory`
- `threat-intel-triage`
- `static-pe-triage`
- `dynamic-behavior-triage`
- `safe-replay-loader`
- `verdict-summarizer`

这些 skill 目前仍然是“工作流内部能力标签”，不是 Codex 外部自动调用的系统 skill。

它们当前主要用于：

- 给 Agent 计划提供可解释标签
- 给后续 LLM 决策提供可选能力清单
- 给后续 SOP 编排提供稳定标识

## SOP Registry

当前 SOP 注册表包含以下条目：

### 1. `hash_intel_enrichment`

阶段：

- `hash_intel`

作用：

- 先做 hash intelligence 归一化，再继续进入静态分析

### 2. `static_to_safe_replay`

阶段：

- `static_analysis`

作用：

- 当静态证据较强时，要求进入安全动态回放路径

### 3. `static_minimum_dynamic_path`

阶段：

- `static_analysis`

作用：

- 当静态证据较弱时，仍然保持最小动态路径

### 4. `dynamic_replay_to_verdict`

阶段：

- `dynamic_analysis`

作用：

- 读取 replay / event log 动态证据，然后进入 verdict

### 5. `final_verdict_emit`

阶段：

- `final_verdict`

作用：

- 产出最终结论

## 当前选择方式

目前 SOP 选择仍然是规则驱动，但已经从“直接 if/else 写死”变成了：

1. 从注册表取出当前阶段的候选 SOP
2. 根据当前证据选择其中一个 SOP
3. 将该选择写入 `agent_execution.stage_plans`

也就是说，当前虽然还没有接 OpenAI，但工作流已经具备了：

- 候选 SOP 集合
- 被选中的 SOP
- 候选 skill / tool
- 标准化执行指令

## LLM Ready 输入

当前 planner 已经为后续大模型决策准备了标准输入：

- `llm_ready_prompt_input`

该结构包含：

- 当前阶段
- 样本基础信息
- VT 摘要
- 静态分析摘要
- 动态分析摘要
- 当前阶段的候选 SOP 列表

这意味着后续接入 OpenAI 时，最小实现可以直接是：

`llm_ready_prompt_input -> OpenAI -> 选择 sop_id -> 写回 execution plan`

而不是重新设计整条 agent 接口。

## 当前限制

当前这一轮仍然没有做以下事情：

- 没有真正调用 OpenAI 决策
- 没有把每个 skill 实现成独立可执行插件
- 没有做多步自动重规划
- 没有做失败后的 SOP 切换策略

因此当前状态应定义为：

- 已完成：SOP/skill 的注册与结构化表达
- 已完成：规则驱动下的 SOP 选择
- 已完成：面向后续 OpenAI 的标准输入准备
- 未完成：真正的 LLM 决策器与 skill 执行器

## 下一步建议

后续如果继续推进 Agent 核心能力，最自然的顺序是：

1. 增加 `agent/decision_engine.py`
   - 输入 `llm_ready_prompt_input`
   - 输出 `selected_sop_id`

2. 增加 `skill executor`
   - 让某些 skill 不只是标签，而是可真正触发模块动作

3. 增加 `replan`
   - 当某个 adapter 不可用时，根据候选 SOP 重新选择

当前这一轮的意义是：先把 Agent 的决策空间和执行空间标准化，后续再接 OpenAI 做真正的分析与决策。
