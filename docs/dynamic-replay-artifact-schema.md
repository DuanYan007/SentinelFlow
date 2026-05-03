# 动态回放工件格式说明

## 目标

该文档用于说明当前 phase 1 中安全动态回放工件的最小输入格式。

当前格式的目的不是覆盖全部动态行为，而是支持最小可执行动态分析链路。

## 顶层结构

```json
{
  "schema_version": "dynamic-replay.v1",
  "process_events": [],
  "file_events": []
}
```

## 字段说明

### `schema_version`

输入：

- 字符串

作用：

- 标记当前动态工件格式版本

当前策略：

- 如果缺失，不直接报错
- 但会在校验结果中写入 warning

### `process_events`

输入：

- 列表

列表元素：

- 对象

当前已使用字段：

- `image`
- `pid`
- `parent_pid`
- `suspicious_spawn`

### `file_events`

输入：

- 列表

列表元素：

- 对象

当前已使用字段：

- `directory`
- `created_count`
- `modified_count`
- `renamed_count`
- `high_frequency_write`
- `target_extensions`

## 当前归一化逻辑

当前动态分析模块会基于这些字段推导：

- `process_execution_observed`
- `suspicious_child_process_spawn`
- `bulk_file_create`
- `bulk_file_modify`
- `bulk_file_rename`
- `high_frequency_write`
- `targeted_user_file_extensions`

## 当前校验逻辑

当前 schema 校验只做最小约束：

- 根对象必须是 object
- `process_events` 必须是 list
- `file_events` 必须是 list
- 两个列表中的每个元素必须是 object

当前不做更细字段强校验，原因是：

- phase 1 重点是先打通动态链路
- 后续真实沙箱接入后，字段稳定性还会继续变化

## 后续扩展方向

后续建议增加的字段包括：

- 注册表行为
- 服务创建行为
- 网络连接行为
- 卷影删除行为
- 加密 API 调用行为

但当前阶段先维持最小格式，便于快速迭代动态分析链路。
