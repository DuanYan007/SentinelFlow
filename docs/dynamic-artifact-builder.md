# 动态工件生产器说明

## 目标

当前项目中的动态分析模块并不直接消费任意外部日志格式，而是统一消费标准回放工件：

- `dynamic-replay.v1`

因此需要一个中间层，把外部原始日志转换为项目内部标准格式。

这就是当前新增的动态工件生产器。

## 当前链路

当前链路已经变成：

`raw dynamic log -> artifact builder -> dynamic replay artifact -> dynamic analysis`

对应 CLI：

1. 构建工件

```bash
PYTHONPATH=src .venv/bin/python -m cli build-dynamic-artifact \
  --raw-log staging/dynamic-raw-logs/<sample>.raw.json \
  --output-dir staging/dynamic-replay
```

2. 运行动态实验

```bash
PYTHONPATH=src .venv/bin/python -m cli dynamic-experiment \
  --input-dir staging/dynamic-replay \
  --config-dir configs/replay-validation \
  --output-dir results
```

## 当前原始日志最小格式

当前 builder 支持的最小原始格式如下：

```json
{
  "sample": {
    "sha256": "<sample_sha256>"
  },
  "process_events": [],
  "file_events": []
}
```

其中：

- `process_events` 中允许使用 `process_name`
- `file_events` 中允许使用 `path_hint`

builder 会将这些字段归一化到项目内部标准格式。

## 当前标准输出

builder 输出的标准工件格式为：

```json
{
  "schema_version": "dynamic-replay.v1",
  "source_format": "dynamic-raw-log.v1",
  "source_path": "...",
  "sample_sha256": "...",
  "process_events": [],
  "file_events": []
}
```

## 当前意义

这一步的意义很关键：

- 动态分析模块不再直接依赖某一个外部沙箱格式
- 后续接入不同 VM / sandbox / Procmon 导出时，只需要补 builder 适配
- 动态分析主链路可以保持稳定

也就是说，当前已经把动态能力拆成了两层：

1. 原始日志生产与转换层
2. 标准工件分析层

后续如果接入真实沙箱，优先要做的不是改 dynamic scoring，而是先把沙箱导出结果稳定映射到 builder 输入格式。
