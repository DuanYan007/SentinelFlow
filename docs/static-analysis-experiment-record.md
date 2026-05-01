# 静态分析实验记录

## 实验目的

本次实验的目标是对本地勒索软件样本库中的全部样本执行静态分析，并将分析结果完整保存到磁盘。

本次实验的范围如下：

- 只进行静态分析
- 不进行动态分析
- 不在宿主机上执行样本
- 为每个样本保存一份静态分析结果 JSON
- 为整批实验保存一份 summary JSON

## 数据集范围

- 输入目录：`ransomware/`
- 预期文件类型：PE 样本
- 对非文件输入自动跳过

本次实际运行观测到：

- 目录总条目数：`170`
- 实际处理的文件样本数：`169`
- 跳过的非文件条目数：`1`
- 被跳过的条目：`.obsidian/`

## 执行路径

逻辑执行链路如下：

`样本文件 -> ingest -> static_analysis -> JSON落盘`

本次实际涉及的模块如下：

- `ingest.run_ingest()`
- `static_analysis.run_static_analysis()`
- `batch.static_experiment.run_static_experiment()`

## 输出产物

单样本结果文件格式：

- `results/static-experiments/<batch_id>/<batch_id>__<sha256_prefix>__static.json`

批次汇总文件格式：

- `results/static-experiments/summaries/<batch_id>__summary.json`

本次实验实际产物：

- 批次编号：`static-batch-20260501T074257Z-c91307`
- 结果目录：
  - `results/static-experiments/static-batch-20260501T074257Z-c91307`
- 汇总文件：
  - `results/static-experiments/summaries/static-batch-20260501T074257Z-c91307__summary.json`

## 记录字段

每个单样本 JSON 中包含以下主要字段：

- `sample`
- `static_analysis`
- `runtime`
- `workflow_status`

其中 `static_analysis` 块包含：

- 现有 v1 静态分析结果字段
- 并行保存的 `static_analysis.v2` 结构（若成功生成）

## 说明

- 本次实验结果中故意不包含 VT、Agent、dynamic analysis 和 verdict。
- 这样做的目的是把静态分析单独隔离出来，便于观察静态链路本身的稳定性、输出结构和解释能力。

## 本次运行结果汇总

运行时间信息：

- 开始时间：`2026-05-01T15:42:57+08:00`
- 结束时间：`2026-05-01T15:57:53+08:00`
- 总耗时：`896.0` 秒

静态分析结果分布：

- `ok`: `168`
- `error`: `1`

V2 结果情况：

- `static_analysis.v2` 成功出现在 `168` 个结果中
- v2 平均静态风险分数：`0.294`

结果解释：

- 当前静态分析链路已经能够较稳定地覆盖绝大多数本地勒索软件样本。
- 仍然存在 `1` 个样本未能成功完成静态分析，后续应单独排查原因。
- 从批量结果看，v2 静态分析管线已经具备实际可用性，但整体吞吐仍受到重复字符串提取以及带超时保护的 `DIE` 探测影响。
