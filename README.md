# SentinelFlow

`SentinelFlow` 当前只保留静态分析主线，以及独立整理的手动动态日志采集资料。

## 当前范围

- 静态分析工作流
- VirusTotal 查询
- 结果落盘与校验
- `dynamic-log-capture/` 下的手动动态日志采集资料

## 当前已实现内容

### 1. 基础工作流

当前单样本主线为：

- 样本 ingest
- 哈希计算
- VirusTotal 查询
- Agent 决策 trace
- 静态分析
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

### 4. 手动日志采集资料

动态日志采集资料已收口到：

- [dynamic-log-capture](/home/duan/ransom-lab/dynamic-log-capture)

### 5. CLI

当前已实现的 CLI 能力：

- `validate-result`
- `single`

命令入口：

```bash
PYTHONPATH=src .venv/bin/python -m cli --help
```

### 6. 批量静态实验

相关静态实验文档：

- [docs/static-analysis-experiment-record.md](/home/duan/ransom-lab/docs/static-analysis-experiment-record.md)
- [docs/static-analysis-single-sample-trace.md](/home/duan/ransom-lab/docs/static-analysis-single-sample-trace.md)
- [dynamic-log-capture](/home/duan/ransom-lab/dynamic-log-capture)

## 目录结构

```text
src/
  agent/               Agent 决策与 trace
  batch/               批处理与静态实验
  cli/                 命令行入口
  config/              配置模型与加载
  core/                通用常量、枚举、时间与路径工具
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

- `DIE` 仍然是最佳努力信号源
- Agent 决策仍以规则为主
- 动态日志采集当前只保留手动方案，且资料位于 `dynamic-log-capture/`

## 后续方向

- 批量 CLI 完善
- 静态分析规则与结果质量继续收敛
- `dynamic-log-capture/` 目录继续独立维护

## 说明

当前仓库公开内容仅包含：

- 代码
- 配置
- 实验文档
- 研究过程记忆

不包含恶意样本本体。
