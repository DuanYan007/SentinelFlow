# Windows Guest Tools

该目录存放需要复制到 Windows 虚拟机 `C:\Tools\` 下的最小脚本模板。

建议复制后的目标结构：

```text
C:\Tools\
  start_capture.bat
  stop_capture.bat
  export_logs.bat
  export_logs.ps1
  Procmon\
    Procmon64.exe
  Sysmon\
    sysmon64.exe
```

当前脚本约定：

- `start_capture.bat <logs_dir> <sample_sha256>`
- `stop_capture.bat <logs_dir> <sample_sha256>`
- `export_logs.bat <logs_dir> <sample_sha256>`

示例：

```bat
C:\Tools\start_capture.bat C:\AnalysisLogs fe81...0498
C:\Tools\stop_capture.bat C:\AnalysisLogs fe81...0498
C:\Tools\export_logs.bat C:\AnalysisLogs fe81...0498
```

输出目录：

```text
C:\AnalysisLogs\<sample_sha256>\
```

其中会生成：

- `procmon.pml`
- `procmon.csv`
- `procmon.json`
- `sysmon.evtx`
- `sysmon.json`

第一阶段加固脚本：

- `harden_phase1.bat`
- `harden_phase1.ps1`

用于创建 `collector` 账户并保护：

- `C:\Tools`
- `C:\ProgramData\SentinelFlow\Runs`
