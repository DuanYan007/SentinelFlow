# Windows Guest 采集脚本说明

## 目标

这份文档说明当前仓库中提供的最小 Guest 侧采集脚本如何使用。

这些脚本的作用是：

- 启动 Procmon 采集
- 停止 Procmon 采集
- 导出 Sysmon / Procmon 日志

## 脚本位置

仓库中的模板位于：

- [guest-tools/virtualbox/start_capture.bat](/home/duan/ransom-lab/guest-tools/virtualbox/start_capture.bat:1)
- [guest-tools/virtualbox/stop_capture.bat](/home/duan/ransom-lab/guest-tools/virtualbox/stop_capture.bat:1)
- [guest-tools/virtualbox/export_logs.bat](/home/duan/ransom-lab/guest-tools/virtualbox/export_logs.bat:1)
- [guest-tools/virtualbox/export_logs.ps1](/home/duan/ransom-lab/guest-tools/virtualbox/export_logs.ps1:1)

建议复制到 Windows Guest：

- `C:\Tools\`

## 前置目录

Guest 中需要存在：

- `C:\Tools`
- `C:\Tools\Procmon`
- `C:\Tools\Sysmon`
- `C:\AnalysisLogs`

其中：

- `Procmon64.exe` 或 `Procmon.exe` 放在 `C:\Tools\Procmon\`
- Sysmon 已安装到系统中

## 参数约定

当前三个脚本都使用：

- `logs_dir`
- `sample_sha256`

例如：

```bat
C:\Tools\start_capture.bat C:\AnalysisLogs fe81...0498
C:\Tools\stop_capture.bat C:\AnalysisLogs fe81...0498
C:\Tools\export_logs.bat C:\AnalysisLogs fe81...0498
```

输出目录会是：

```text
C:\AnalysisLogs\<sample_sha256>\
```

## 脚本行为

### `start_capture.bat`

作用：

- 创建本轮日志目录
- 清理旧的 Procmon 输出
- 启动 Procmon 并写入 `procmon.pml`

### `stop_capture.bat`

作用：

- 终止当前 Procmon 采集

### `export_logs.bat`

作用：

- 调用 `export_logs.ps1`

### `export_logs.ps1`

作用：

- 导出 Sysmon EVTX
- 将 Sysmon 事件转换为 JSON
- 将 Procmon PML 转成 CSV
- 再将 Procmon CSV 转成 JSON

## 当前输出文件

当前最小输出包括：

- `procmon.pml`
- `procmon.csv`
- `procmon.json`
- `sysmon.evtx`
- `sysmon.json`

## 手工验证顺序

建议先在 Guest 内手工验证：

1. 执行：

```bat
C:\Tools\start_capture.bat C:\AnalysisLogs testsample
```

2. 手工运行一个无害程序，例如：

- 记事本
- 命令行 `cmd /c dir`

3. 执行：

```bat
C:\Tools\stop_capture.bat C:\AnalysisLogs testsample
```

4. 执行：

```bat
C:\Tools\export_logs.bat C:\AnalysisLogs testsample
```

5. 检查：

```text
C:\AnalysisLogs\testsample\
```

是否出现上述 5 个文件。

## 当前限制

当前脚本是最小版本，仍有几个限制：

- Procmon 字段提取较粗
- Sysmon 事件只做了基础映射
- 没做高级过滤
- 没做更强的可疑行为判定

但它已经足够支持当前项目的下一步：

- 导出真实日志
- 导入 `import-real-run`
- 继续进入 replay artifact 和 dynamic scoring
