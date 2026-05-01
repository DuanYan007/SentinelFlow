# 单样本静态分析详细跟踪

## 1. 文档目的

本文档用于详细跟踪一个样本从输入到静态分析结果输出的全过程。

本文档明确回答四个问题：

1. 每一步的输入是什么
2. 每一步实际执行了什么操作
3. 每一步输出了什么结果
4. 每一步的结果应该如何分析

目标样本：

- `ransomware/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498.exe`

对应结果文件：

- `results/static-experiments/static-batch-20260501T074257Z-c91307/static-batch-20260501T074257Z-c91307__fe81c5caa0e2__static.json`

## 2. 总体流程

本次处理链路为：

`样本文件 -> ingest -> 静态分析v1 -> 静态分析v2 -> JSON落盘`

本次链路只做静态分析，不包含：

- VT 查询
- Agent 决策
- 动态分析
- 最终 verdict

## 3. 步骤一：样本输入与 Ingest

### 3.0 代码模块

- `src/ingest/service.py`
- 入口函数：`run_ingest(context)`

### 3.1 输入

输入是一个本地 PE 文件路径：

- `ransomware/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498.exe`

输入字段表：

| 字段 | 值/来源 | 说明 |
|---|---|---|
| `context.sample.file_path` | `ransomware/fe81c5...0498.exe` | 待分析样本路径 |
| `context.sample.submitted_at` | 运行时自动生成 | 样本提交时间 |

### 3.2 操作

本步骤执行的操作：

1. 检查路径是否存在
2. 检查路径是否为普通文件
3. 读取文件头前两个字节，判断是否为 `MZ`
4. 计算：
   - `md5`
   - `sha1`
   - `sha256`
5. 填充样本元数据

### 3.3 输出

输出字段如下：

- `file_name = fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498.exe`
- `file_path = ransomware/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498.exe`
- `file_size = 350720`
- `file_type = PE`
- `md5 = 344c3f60bdccc98812b0dc5f9dc2f413`
- `sha1 = 70c377de5bf4d47cabc0a14c997f1104ca666c13`
- `sha256 = fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498`

输出字段表：

| 字段 | 实际输出 | 字段解释 |
|---|---|---|
| `sample.file_name` | `fe81c5...0498.exe` | 文件名，用于结果命名与展示 |
| `sample.file_path` | `ransomware/fe81c5...0498.exe` | 样本实际路径 |
| `sample.file_size` | `350720` | 文件字节数 |
| `sample.file_type` | `PE` | 基于文件头识别出的类型 |
| `sample.md5` | `344c3f...` | MD5，用于兼容旧系统或快速比对 |
| `sample.sha1` | `70c377...` | SHA1，用于辅助检索 |
| `sample.sha256` | `fe81c5...0498` | 主哈希，用于稳定标识样本 |

### 3.4 结果分析

这一阶段的结论是：

- 样本是有效文件，不是目录，也不是缺失文件
- 文件头符合 PE 常见形式，因此可以进入后续 PE 静态分析
- 哈希值已经完整生成，后续可以用于实验命名、样本定位和情报检索

这一阶段只做输入标准化，不做恶意性判断。

## 4. 步骤二：静态分析 v1

### 4.0 代码模块

- `src/static_analysis/service.py`
- 入口函数：`run_static_analysis(context, bundle)`

### 4.1 输入

输入是 ingest 完成后的样本对象，其中已包含：

- 文件路径
- 文件类型
- 文件大小
- 三种哈希

输入字段表：

| 字段 | 实际输入 | 说明 |
|---|---|---|
| `sample.file_path` | `ransomware/fe81c5...0498.exe` | 静态分析读取的文件路径 |
| `sample.file_type` | `PE` | 决定是否适合 PE 静态分析 |
| `bundle.static_analysis.entropy_threshold` | `7.2` | 高熵节区判定阈值 |
| `bundle.static_analysis.strings_binary` | `/usr/bin/strings` | 字符串提取工具 |

### 4.2 操作

v1 静态分析执行了以下操作：

1. 使用 `pefile` 解析 PE 结构
2. 使用 `strings` 提取可打印字符串
3. 计算 PE 特征
4. 计算导入表特征
5. 计算字符串特征
6. 基于已有启发式规则计算 v1 静态风险分数

### 4.3 输出

#### 4.3.1 PE 结构输出

- `section_count = 11`
- `high_entropy_sections = 1`
- `packed_or_obfuscated = false`
- `suspicious_timestamp = false`
- `entrypoint_anomaly = false`

#### 4.3.2 导入表输出

命中的关键 API 包括：

- 文件系统相关：
  - `FindNextFileW`
  - `MoveFileW`
  - `FindFirstFileW`
  - `CreateFileW`
  - `WriteFile`
- 进程相关：
  - `ShellExecuteW`
- 注册表相关：
  - `RegSetValueExW`

统计结果为：

- `crypto_api_count = 0`
- `filesystem_api_count = 5`
- `process_api_count = 1`
- `registry_api_count = 1`
- `shadowcopy_or_recovery_api_present = false`

#### 4.3.3 字符串输出

命中的关键词：

- `decrypt`

对应字段：

- `ransom_note_keywords = ['decrypt']`
- `extension_change_keywords = []`
- `cmd_keywords = []`
- `url_or_onion_indicators = []`
- `config_like_strings = []`

#### 4.3.4 v1 综合输出

- `matched_features = ['contains_ransom_note_keyword', 'imports_filesystem_api_cluster']`
- `risk_score = 0.17`
- 主要分数贡献项：
  - `imports_filesystem_api_cluster`
  - `contains_ransom_note_keyword`

v1 关键输出字段表：

| 字段 | 实际输出 | 字段解释 |
|---|---|---|
| `static_analysis.pe_features.section_count` | `11` | 节区总数 |
| `static_analysis.pe_features.high_entropy_sections` | `1` | 高熵节区数 |
| `static_analysis.import_features.filesystem_api_count` | `5` | 文件操作相关 API 数量 |
| `static_analysis.import_features.process_api_count` | `1` | 进程操作相关 API 数量 |
| `static_analysis.import_features.registry_api_count` | `1` | 注册表相关 API 数量 |
| `static_analysis.string_features.ransom_note_keywords` | `['decrypt']` | 命中的勒索说明关键词 |
| `static_analysis.matched_features` | `contains_ransom_note_keyword`, `imports_filesystem_api_cluster` | v1 归一化命中特征 |
| `static_analysis.risk_score` | `0.17` | v1 启发式静态风险分数 |

### 4.4 结果分析

这一阶段的结果可以拆开理解：

第一，PE 结构层面没有明显出现强加壳或强混淆特征。

- 只有 `1` 个高熵节区
- `packed_or_obfuscated = false`
- 时间戳和入口点没有触发明显异常

第二，导入表层面出现了比较强的文件操作能力。

这说明样本具备：

- 文件遍历能力
- 文件创建能力
- 文件写入能力
- 文件移动能力

第三，字符串层面命中了 `decrypt`。

这个词单独看不能证明恶意，但它和大规模文件操作 API 同时出现时，解释力度明显增强。

因此，v1 的整体结论是：

- 已经观察到与勒索软件相关的静态信号
- 但因为 v1 规则集合较小，所以分数仍然偏保守
- `0.17` 更适合被理解为“发现了相关证据，但表达还不够结构化”

## 5. 步骤三：v2 的 PE 结构化提取

### 5.0 代码模块

- `src/static_analysis/pefile_extractor.py`
- 入口函数：`extract_pefile_v2(sample_path, config, config_dir=...)`

### 5.1 输入

输入仍然是同一个 PE 文件。

区别在于，此时的目标不是直接打分，而是先把分析结果结构化保存。

输入字段表：

| 字段 | 实际输入 | 说明 |
|---|---|---|
| `sample_path` | `ransomware/fe81c5...0498.exe` | v2 提取器直接读取的样本路径 |
| `config.entropy_threshold` | `7.2` | 节区熵阈值 |
| `config.die_binary` | `.../die` | DIE 工具路径 |
| `config.strings_binary` | `/usr/bin/strings` | strings 工具路径 |

### 5.2 操作

本步骤执行：

1. 再次使用 `pefile` 解析 PE
2. 将结果写入 `tool_outputs.pefile`
3. 保存：
   - 基础头部信息
   - 节区信息
   - 导入表信息
   - 异常节区

### 5.3 输出

关键输出包括：

- `machine = i386`
- `pe32_or_pe32plus = pe32`
- `entry_point = 251344`
- `subsystem = windows_gui`
- `compile_time = 2023-11-21T16:56:17+00:00`
- `image_size = 405504`

典型节区包括：

- `.text`
- `.data`
- `.bss`
- `.tls`
- `.rsrc`

其中异常节区为：

- `.bss`
  - `empty_or_tiny`
- `.tls`
  - `empty_or_tiny`
- `.rsrc`
  - `high_entropy`

PE 结构化关键输出字段表：

| 字段 | 实际输出 | 字段解释 |
|---|---|---|
| `v2.tool_outputs.pefile.parser_meta.parse_status` | `ok` | pefile 解析是否成功 |
| `v2.tool_outputs.pefile.basic_headers.machine` | `i386` | PE 架构 |
| `v2.tool_outputs.pefile.basic_headers.pe32_or_pe32plus` | `pe32` | PE 位数类型 |
| `v2.tool_outputs.pefile.basic_headers.subsystem` | `windows_gui` | 子系统类型 |
| `v2.tool_outputs.pefile.sections[3].name` | `.bss` | 具体节区名称 |
| `v2.tool_outputs.pefile.sections[3].anomalies` | `['empty_or_tiny']` | 节区异常标签 |
| `v2.tool_outputs.pefile.sections[10].name` | `.rsrc` | 资源节名称 |
| `v2.tool_outputs.pefile.sections[10].entropy` | `7.828` | 节区熵值 |

### 5.4 结果分析

这一步的重点不是直接判定恶意，而是把样本拆成可以解释的结构对象。

例如：

- `.bss` 和 `.tls` 的异常说明布局不正常
- `.rsrc` 的高熵说明资源区可能包含压缩、加密或嵌入数据

这使得 v2 可以明确回答：

- 哪个节区异常
- 异常类型是什么
- 后续会命中哪类规则

## 6. 步骤四：v2 的 section 规则匹配

### 6.0 代码模块

- 规则文件：`configs/rules/static-section-rules.yaml`
- 加载模块：`src/static_analysis/rule_loader.py`
- 匹配模块：`src/static_analysis/rule_matcher.py`

### 6.1 输入

输入是结构化后的节区列表，每个节区都包含：

- 名称
- 大小
- 熵
- 权限
- 异常标签

输入字段表：

| 输入字段 | 示例值 | 说明 |
|---|---|---|
| `section.name` | `.bss` | 节区名称 |
| `section.raw_size` | `0` | 原始数据大小 |
| `section.virtual_size` | `25324` | 虚拟大小 |
| `section.entropy` | `0.0 / 7.828` | 节区熵 |
| `section.permissions` | `['read', 'write']` | 节区权限 |

### 6.2 操作

本步骤执行：

- 空节/超小节匹配
- 高熵节匹配
- 权限异常匹配
- 可疑节名匹配

### 6.3 输出

本样本命中的 section 规则为：

- `.bss -> SEC-TINY-001`
- `.tls -> SEC-TINY-001`
- `.rsrc -> SEC-HE-001`

对应摘要为：

- `sections=11, high_entropy=1, wx=0, suspicious_names=0`

section 规则输出字段表：

| 字段 | 实际输出 | 字段解释 |
|---|---|---|
| `section-rule-3-SEC-TINY-001` | `.bss` 命中 | `.bss` 被判为空/超小节 |
| `section-rule-7-SEC-TINY-001` | `.tls` 命中 | `.tls` 被判为空/超小节 |
| `section-rule-10-SEC-HE-001` | `.rsrc` 命中 | `.rsrc` 被判为高熵节 |
| `v2.normalized_features.section_features.summary` | `sections=11, high_entropy=1, wx=0, suspicious_names=0` | section 层聚合摘要 |

### 6.4 结果分析

这些命中的意义如下：

- `.bss` 和 `.tls` 命中 `SEC-TINY-001`，说明节区大小或布局异常
- `.rsrc` 命中 `SEC-HE-001`，说明资源节存在高熵内容

这一步的价值是把“可疑”细化成：

- 哪个位置可疑
- 哪条规则命中
- 为什么命中

因此解释性明显强于 v1。

## 7. 步骤五：v2 的 import 规则匹配

### 7.0 代码模块

- 规则文件：`configs/rules/static-import-rules.yaml`
- 加载模块：`src/static_analysis/rule_loader.py`
- 匹配模块：`src/static_analysis/rule_matcher.py`

### 7.1 输入

输入是结构化导入表，每项至少包含：

- `dll`
- `api`
- `ordinal`

输入字段表：

| 输入字段 | 示例值 | 说明 |
|---|---|---|
| `import.dll` | `kernel32.dll` | 导入来源 DLL |
| `import.api` | `WriteFile` | 具体 API 名称 |
| `import.ordinal` | 具体序号或 `None` | 导入序号 |

### 7.2 操作

本步骤执行：

1. 按 `DLL + API` 规则匹配
2. 将命中回写到导入项：
   - `category`
   - `matched_rule_id`
   - `risk_weight`
   - `evidence_ref`
3. 对命中结果进行分类聚合

### 7.3 输出

本样本命中的 import 分类为：

- `filesystem`
- `process`
- `registry`
- `service`

聚合摘要为：

- `categorized_import_hits=9; categories=filesystem,process,registry,service`

典型命中包括：

- `FindNextFileW -> filesystem / IMP-FS-001`
- `MoveFileW -> filesystem / IMP-FS-001`
- `FindFirstFileW -> filesystem / IMP-FS-001`
- `CreateFileW -> filesystem / IMP-FS-001`
- `WriteFile -> filesystem / IMP-FS-001`

import 规则输出字段表：

| 字段 | 实际输出 | 字段解释 |
|---|---|---|
| `imports[*].category` | `filesystem/process/registry/service` | 命中的行为类别 |
| `imports[*].matched_rule_id` | `IMP-FS-001` 等 | 命中的具体规则 |
| `imports[*].risk_weight` | 规则设定值 | 该命中的风险权重 |
| `v2.normalized_features.import_features.summary` | `categorized_import_hits=9; categories=filesystem,process,registry,service` | import 聚合摘要 |

### 7.4 结果分析

这是当前样本静态分析里最重要的证据之一。

原因在于：

- `filesystem` 分类直接对应遍历、打开、写入、移动文件
- 这是勒索软件执行加密前必须具备的核心能力

同时还出现了：

- `process`
- `registry`
- `service`

这说明样本除了文件能力外，还可能具备：

- 启动外部进程的能力
- 修改注册表的能力
- 操作服务的能力

这些能力组合在一起时，对勒索软件的静态解释会明显加强。

## 8. 步骤六：v2 的 strings 分析

### 8.0 代码模块

- `src/static_analysis/pefile_extractor.py`
- 内部 strings 集成逻辑：`_integrate_strings_v2(...)`

### 8.1 输入

输入是样本二进制文件本身。

输入字段表：

| 输入字段 | 实际值 | 说明 |
|---|---|---|
| `sample_path` | `ransomware/fe81c5...0498.exe` | strings 读取的文件 |
| `config.strings_binary` | `/usr/bin/strings` | strings 命令路径 |
| `config.string_keyword_sets` | 配置中的关键词集合 | 关键词匹配规则来源 |

### 8.2 操作

本步骤执行：

1. 调用 `strings`
2. 提取可打印字符串
3. 按关键词类别匹配
4. 将命中写入：
   - `tool_outputs.strings`
   - `raw_evidence`
   - `summary.key_hits`

### 8.3 输出

本样本 strings 输出摘要为：

- `strings_ok count=3531 matched_categories=ransom_note`

命中的 strings 类别为：

- `ransom_note`

典型关键词仍然是：

- `decrypt`

strings 输出字段表：

| 字段 | 实际输出 | 字段解释 |
|---|---|---|
| `v2.tool_outputs.strings.status` | `ok` | strings 是否执行成功 |
| `v2.tool_outputs.strings.raw_data.string_count` | `3531` | 提取出的字符串总数 |
| `v2.tool_outputs.strings.summary` | `strings_ok count=3531 matched_categories=ransom_note` | strings 聚合摘要 |
| `v2.raw_evidence` 中 `strings-*` 证据 | `decrypt` 等 | 写入证据池的字符串命中 |

### 8.4 结果分析

这一结果说明：

- 样本中存在大量可打印字符串，总量为 `3531`
- 其中至少命中了勒索说明相关类别

这一步的解释价值在于：

- 如果只有文件操作 API，没有勒索说明类字符串，解释会偏向“可疑文件处理程序”
- 当文件操作 API 与 `decrypt` 同时出现时，解释更接近勒索软件

因此，`strings` 当前是 v2 中稳定且高价值的证据源。

## 9. 步骤七：v2 的 DIE 探测

### 9.0 代码模块

- `src/static_analysis/pefile_extractor.py`
- 内部 DIE 集成逻辑：`_integrate_die_v2(...)`

### 9.1 输入

输入包括：

- 样本文件
- 本地 `DIE` 可执行文件路径

输入字段表：

| 输入字段 | 实际值 | 说明 |
|---|---|---|
| `sample_path` | `ransomware/fe81c5...0498.exe` | DIE 读取的样本 |
| `config.die_binary` | `.../tools/bin/.../die` | DIE 二进制路径 |
| `timeout` | `5` 秒 | 超时保护阈值 |

### 9.2 操作

本步骤执行：

1. 调用本地 `DIE`
2. 设置 `5` 秒超时保护
3. 若超时或失败，则记录状态但不阻塞主链路

### 9.3 输出

本样本的输出为：

- `tool_outputs.die.status = partial`
- `tool_outputs.die.summary = die execution timed out`

DIE 输出字段表：

| 字段 | 实际输出 | 字段解释 |
|---|---|---|
| `v2.tool_outputs.die.status` | `partial` | DIE 未完整成功，但主链路继续 |
| `v2.tool_outputs.die.summary` | `die execution timed out` | DIE 当前失败原因摘要 |
| `v2.tool_outputs.die.errors` | 超时错误信息 | 便于后续排障 |

### 9.4 结果分析

这说明：

- DIE 在当前环境中没有稳定快速返回
- 但系统没有因此失败
- v2 将其作为补充信号源，而不是主链路依赖

这是合理的工程策略，因为辅助工具不应拖垮静态主链路。

## 10. 步骤八：v2 分数聚合

### 10.0 代码模块

- `src/static_analysis/pefile_extractor.py`
- 分数构建逻辑：`_populate_v2_score_breakdown(result)`

### 10.1 输入

输入是前面已经得到的结构化命中结果，包括：

- section 规则命中
- import 规则命中
- strings 证据
- PE 基础头部信息

输入字段表：

| 输入来源 | 具体内容 | 作用 |
|---|---|---|
| `section` 命中 | `.bss/.tls/.rsrc` 规则命中 | 构造 section 模块分 |
| `import` 命中 | `filesystem/process/registry/service` | 构造 import 模块分 |
| `pe_basic` | 头部异常字段 | 构造 pe_basic 模块分 |
| `raw_evidence` | 规则和工具证据 | 回填解释引用 |

### 10.2 操作

本步骤执行：

1. 生成规则级 `score_breakdown`
2. 生成模块级 `score_breakdown`
3. 根据模块上限和权重进行归一化
4. 生成最终 `v2 risk_score`

### 10.3 输出

关键输出如下：

- `v2 risk_score = 0.401`
- 归一化策略：
  - `rule_hits_to_modules_then_weighted_caps`
- 规则级贡献项数量：
  - `7`

模块级贡献如下：

- `pe_basic`
  - `raw_score = 0.0`
  - `final_contribution = 0.0`
- `section`
  - `raw_score = 0.36`
  - `final_contribution = 0.126`
- `import`
  - `raw_score = 0.6100000000000001`
  - `final_contribution = 0.2745000000000001`

分数输出字段表：

| 字段 | 实际输出 | 字段解释 |
|---|---|---|
| `v2.score_breakdown.normalization_strategy` | `rule_hits_to_modules_then_weighted_caps` | 分数归一化方式 |
| `v2.score_breakdown.rule_scores` | `7` 条 | 规则级贡献明细 |
| `v2.score_breakdown.module_scores[pe_basic]` | `0.0` | PE 头部模块最终贡献 |
| `v2.score_breakdown.module_scores[section]` | `0.126` | 节区模块最终贡献 |
| `v2.score_breakdown.module_scores[import]` | `0.2745000000000001` | 导入模块最终贡献 |
| `v2.risk_score` | `0.401` | v2 最终静态分数 |

### 10.4 结果分析

这一阶段解释了“为什么最终 v2 分数是 `0.401`”。

从模块贡献可以看出：

- `pe_basic` 几乎没有贡献，说明头部本身并不异常
- `section` 提供了中等强度的风险证据
- `import` 提供了最大的风险贡献

这意味着当前样本被 v2 拉高分数的主要原因不是“像被加壳”，而是：

- 存在结构化文件操作能力
- 同时存在进程、注册表、服务等辅助能力

这类解释比单一数值更适合后续接入 Agent 决策。

## 11. 最终结果总结

### 11.1 最终输出

该样本当前的核心静态结果为：

- v1 静态分数：`0.17`
- v2 静态分数：`0.401`
- v2 工具覆盖：
  - `pefile`
  - `strings`
- v2 import 分类：
  - `filesystem`
  - `process`
  - `registry`
  - `service`
- v2 strings 分类：
  - `ransom_note`
- v2 `raw_evidence` 数量：
  - `26`

### 11.2 总体结果分析

如果只看 v1，结论会比较保守：

- 它已经发现勒索软件相关信号
- 但分数只有 `0.17`

如果看 v2，结论会更强：

- v2 将静态风险提升到 `0.401`
- 提升原因不是单一特征，而是多个结构化证据叠加：
  - 节区异常
  - 文件系统 API 聚类
  - 进程/注册表/服务相关 API
  - 勒索说明关键词

因此，对这个样本更合理的静态层解释是：

- 它已经表现出明显的勒索软件相关静态能力特征
- 但当前证据仍然属于静态层面
- 如果后续进入动态分析，应重点验证：
  - 是否真的遍历并修改文件
  - 是否存在加密或重命名行为
  - 是否创建勒索说明文件

### 11.3 为什么必须写“输入 / 操作 / 输出 / 结果分析”

因为只有这样，后续无论是写论文、写实验报告，还是设计 Agent，都能清楚回答：

- 这个结论是从哪里来的
- 这一阶段到底做了什么
- 结果为什么是现在这样
- 这个结果的可信度和局限在哪里

这也是把静态分析从“简单调用工具”提升为“可解释实验流程”的关键。
