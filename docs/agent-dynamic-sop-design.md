# Agent 驱动的动态分析 SOP 设计

## 设计目标

本轮实现的目标不是直接在宿主机或真实沙箱中执行勒索软件样本，而是先把以下链路打通：

- Agent 在静态分析结束后形成可执行的动态分析请求
- Workflow 能读取该请求
- Dynamic analysis 模块能按照请求选择适配器
- 适配器能优先读取安全的动态回放工件
- 即使没有工件，链路也不会中断，而是以 `partial` 形式保留上下文并继续进入 verdict

这一步的核心价值是先验证“决策-编排-执行-记录”链路，而不是直接追求真实恶意样本运行。

## 当前 SOP

当前已经固化的最小 SOP 如下：

`VT -> Agent -> Static -> Agent -> Dynamic Request -> Dynamic Adapter Selection -> Verdict`

其中动态分析阶段的最小可执行策略如下：

1. Agent 在静态分析结束后生成 `dynamic_request`
2. `dynamic_request` 默认声明：
   - `execution_mode = safe_replay`
   - `allow_sample_execution = false`
   - `preferred_adapter = sample_replay_adapter`
   - `fallback_adapters = [event_log_adapter]`
3. Dynamic analysis 模块按顺序尝试：
   - `sample_replay_adapter`
   - `event_log_adapter`
4. 如果没有可用动态工件：
   - 结果记为 `partial`
   - 保留原因、候选适配器、输入工件路径
   - workflow 继续进入 verdict

## 关键输入输出

### Agent 输出

Agent 现在不只写 `agent_trace`，还会写入 `agent_execution`。

`agent_execution` 中的关键字段：

- `current_strategy`
- `active_stage`
- `stage_plans`
- `dynamic_request`

其中 `dynamic_request` 是真正供 dynamic 模块执行的结构化指令。

### Dynamic 输入

Dynamic analysis 现在读取两类输入：

- 配置输入：
  - `configs/dynamic-analysis.yaml`
- Agent 输入：
  - `context.agent_execution.dynamic_request`

### Dynamic 输出

Dynamic analysis 现在额外输出：

- `adapter_selected`
- `adapter_candidates`
- `input_artifact_path`

这样后续就能清晰追踪：

- agent 想调用什么
- dynamic 实际尝试了什么
- 最终成功或失败在哪里

## 当前适配器策略

### 1. `sample_replay_adapter`

用途：

- 从 `staging/dynamic-replay/` 下读取与样本哈希对应的安全 JSON 工件

输入：

- `replay_artifact_dir`
- `input_artifact_path`

输出：

- `process_events`
- `file_events`

适用阶段：

- 当前 phase 1 最小可执行动态链路验证

### 2. `event_log_adapter`

用途：

- 读取显式配置的动态事件日志 JSON

输入：

- `event_log_path`

输出：

- `process_events`
- `file_events`

适用阶段：

- 后续可用于接第三方沙箱导出的统一事件日志

## 当前限制

当前版本仍然有明确边界：

- 不在宿主机执行 PE
- 不自动启动 VM
- 不自动拉起沙箱
- 不自动抓取真实动态行为

因此当前实现属于：

- Agent 编排链路验证完成
- Dynamic 适配层接口完成
- 安全回放路径完成
- 真实动态执行器尚未接入

## 下一步衔接

后续要把这条链路升级为真实可分析决策的 Agent，需要继续补三类内容：

1. 动态工件生产器
   - 例如从 VM/沙箱导出统一 JSON

2. SOP 注册表
   - 将不同分析路线抽象成可枚举 skill/SOP

3. LLM 决策层
   - 基于当前 `agent_execution` 和 `stage_plans` 调用 OpenAI 进行选择与解释

当前这一轮的意义是：先把安全前提下的执行骨架固定住，后续真实接沙箱时只需要补适配器与工件生产，不需要重写工作流。
