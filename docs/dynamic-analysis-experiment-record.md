# 动态分析实验记录

## 实验目的

本次实验的目标是验证当前项目中的动态分析链路是否已经可以独立运行，而不依赖完整的 `VT -> static -> verdict` 主工作流。

本轮实验的重点不是运行真实恶意样本，而是验证以下内容：

- 动态回放工件是否可以被动态分析模块独立读取
- 动态工件 schema 是否可以被校验
- 动态行为是否可以被归一化和打分
- 动态实验结果是否可以批量落盘并汇总

## 当前安全边界

本次实验严格遵守以下边界：

- 不在宿主机执行 PE
- 不自动启动样本
- 不自动拉起虚拟机
- 只分析安全的动态回放 JSON 工件

因此本次实验属于：

- 动态分析链路验证
- 回放工件分析验证
- 不是“真实样本运行实验”

## 输入约定

当前动态实验输入目录约定为：

- `staging/dynamic-replay/`

当前每个动态回放工件建议使用：

- 文件名：`<sha256>.dynamic.json`

当前 JSON 顶层字段约定为：

- `schema_version`
- `process_events`
- `file_events`

其中：

- `process_events` 用于描述进程行为
- `file_events` 用于描述文件行为

## 执行链路

当前动态专用实验链路如下：

`artifact JSON -> ingest -> dynamic_analysis -> result JSON -> summary JSON`

当前涉及的核心模块：

- `batch.dynamic_experiment.run_dynamic_experiment()`
- `dynamic_analysis.run_dynamic_analysis()`
- `dynamic_analysis.adapters`

## 输出产物

单个动态实验结果文件格式：

- `results/dynamic-<batch_id>/<batch_id>__<sha256_prefix>__dynamic.json`

批次汇总文件格式：

- `results/summaries/<batch_id>__summary.json`

## 当前动态结果增强字段

当前动态分析结果中新增并重点保留的字段包括：

- `adapter_selected`
- `adapter_candidates`
- `input_artifact_path`
- `artifact_schema_version`
- `artifact_validation`
- `behavior_summary`
- `matched_features`
- `risk_score`
- `score_breakdown`

这些字段的目的，是把动态链路中的“输入工件质量、适配器选择、行为摘要、最终风险判断”完整保留下来。

## 当前实验意义

这一步的意义不是证明动态检测能力已经完整，而是先把以下最关键的底层链路打通：

- 有统一动态输入格式
- 有安全可复现的动态输入来源
- 有可批量运行的动态分析入口
- 有结果落盘和实验汇总能力

后续如果接入真实沙箱或虚拟机，需要继续补：

- 动态工件生产器
- 工件导出规范
- 真实行为采集 SOP

但当前这一轮已经可以把“动态分析”从主 workflow 中独立出来单独实验和迭代。
