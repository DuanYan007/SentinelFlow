# SentinelFlow

`SentinelFlow` 是一个面向加密勒索软件检测研究的智能体式分析系统原型。

项目当前重点不是做“最终产品”，而是把一个可持续演进的研究型检测框架先落成可运行系统，并逐步验证以下能力：

- 多阶段分析链路是否可跑通
- 静态分析、动态分析、情报查询能否被统一组织
- Agent 是否能够基于结构化证据做下一步决策
- 实验过程是否具备可追踪、可复现、可扩展的工程基础

## 项目定位

本项目当前属于“研究原型系统”，核心方向是：

- 加密勒索软件检测
- 多阶段分流分析
- Agent 驱动的分析路径决策
- 静态/动态分析证据统一建模
- 长期实验记录与记忆管理

当前系统的核心链路设计为：

`sample -> hash intelligence -> Agent -> static/dynamic analysis -> final classification`

其中，第一阶段当前已经推进到：

- 端到端流程验证
- 静态分析能力建设
- 真实动态采集链路打通
- Agent 决策输入准备
- Windows VM 采集面加固

## 当前已实现内容

### 1. 基础工作流

已实现单样本完整工作流骨架：

- 样本 ingest
- 哈希计算
- VirusTotal 查询
- Agent 决策 trace
- 静态分析
- 动态分析接入口
- verdict 生成
- JSON 结果落盘

主要入口：

- [src/workflow_skeleton.py](/home/duan/ransom-lab/src/workflow_skeleton.py)

### 2. 静态分析 v1

已实现基于规则与启发式的第一版静态分析：

- `pefile` 解析 PE 结构
- `strings` 提取字符串
- 导入表特征提取
- PE 节区特征提取
- 字符串关键词匹配
- v1 静态风险分数计算

### 3. 静态分析 v2

已实现更适合 Agent 和实验解释的 v2 静态分析结构：

- `tool_outputs`
- `raw_evidence`
- `normalized_features`
- `score_breakdown`
- `summary`

当前 v2 已接入的工具包括：

- `pefile`
- `strings`
- `DIE` 最佳努力探测

当前 v2 已具备：

- section 规则匹配
- import 规则匹配
- 分类化 import 聚合
- 规则级分数贡献
- 模块级分数贡献
- 与 v1 并行输出

### 4. 动态分析链路

当前动态分析已不再只是占位，已经具备以下能力：

- `dynamic-replay.v1` 工件构建
- `dynamic-experiment` 批量动态评分
- `sample_replay_adapter`
- `event_log_adapter`
- `import-sysmon-log`
- `import-procmon-log`
- `import-real-run`
- `run-real-dynamic-pipeline`
- `collect-real-dynamic`

同时，项目已经完成一条真实 Windows VM 采集路线的关键闭环：

- VirtualBox + Guest Additions
- Windows Guest 内 Sysmon + Procmon
- Guest 日志导出
- Host 回传
- 原始日志到 replay artifact 的转换
- workflow 自动消费真实动态日志
- 第一阶段采集面加固

### 5. CLI

当前已实现的 CLI 能力：

- `validate-result`
- `single`

命令入口：

```bash
PYTHONPATH=src .venv/bin/python -m cli --help
```

### 6. 批量静态实验

项目已执行过一轮全样本静态分析实验。

实验范围：

- 输入目录：`ransomware/`
- 处理文件样本：`169`
- 跳过非文件：`1`

实验结果概况：

- 静态分析 `ok=168`
- 静态分析 `error=1`
- v2 成功生成：`168`
- v2 平均静态风险分数：`0.294`

相关实验文档见：

- [docs/static-analysis-experiment-record.md](/home/duan/ransom-lab/docs/static-analysis-experiment-record.md)
- [docs/static-analysis-single-sample-trace.md](/home/duan/ransom-lab/docs/static-analysis-single-sample-trace.md)
- [docs/virtualbox-download-deployment-guide.md](/home/duan/ransom-lab/docs/virtualbox-download-deployment-guide.md)
- [docs/virtualbox-real-dynamic-setup.md](/home/duan/ransom-lab/docs/virtualbox-real-dynamic-setup.md)
- [docs/windows-vm-dynamic-sop.md](/home/duan/ransom-lab/docs/windows-vm-dynamic-sop.md)
- [docs/windows-vm-phase1-hardening.md](/home/duan/ransom-lab/docs/windows-vm-phase1-hardening.md)

## 目录结构

```text
src/
  agent/               Agent 决策与 trace
  batch/               批处理与静态实验
  cli/                 命令行入口
  config/              配置模型与加载
  core/                通用常量、枚举、时间与路径工具
  dynamic_analysis/    动态分析评分、适配器与 replay 工件
  dynamic_collection/  真实日志导入、合并与 Host 编排
  ingest/              样本输入与哈希
  intel/               威胁情报查询
  models/              数据模型
  recorder/            结果与 summary 落盘、校验
  static_analysis/     静态分析 v1/v2
  verdict/             最终判定逻辑

configs/
  *.yaml               配置文件
  rules/               v2 静态分析规则

docs/
  *.md                 中文实验文档

project-memory/
  *.md                 长期记忆与决策记录
```

## 当前实验与安全边界

本仓库当前不会公开包含以下内容：

- 勒索软件样本本体
- 本地密钥与敏感配置
- 实验运行结果目录
- 本地第三方大体积工具二进制

已通过 `.gitignore` 排除：

- `ransomware/`
- `configs/secrets/`
- `results/`
- `.venv/`
- `tools/`

## 当前限制

当前系统仍处于研究原型阶段，主要限制包括：

- `DIE` 在当前环境中还不是稳定快速的信号源
- Agent 决策目前仍以规则与实验性建议为主
- 最终的“自主 SOP/skill 调度”还在持续设计中
- Windows VM 动态链路已打通，但仍在继续固化受保护日志目录、控制账户与自动化稳定性

## 后续方向

下一阶段的重点包括：

- 批量 CLI 完善
- 动态分析环境稳定化与自动化
- Agent SOP/skill 调度骨架
- 让 OpenAI 作为决策中枢，对多种分析路径进行编排
- 完善实验基准、回归与可复现性

## 说明

本项目用于网络安全研究与检测系统设计验证。

当前仓库公开内容仅包含：

- 代码
- 配置
- 实验文档
- 研究过程记忆

不包含恶意样本本体。
