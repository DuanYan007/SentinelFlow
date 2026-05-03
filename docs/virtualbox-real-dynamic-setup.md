# VirtualBox 真实动态执行环境配置

## 目标

该文档用于把当前项目中的“真实动态执行”路线收敛为：

- Host：Ubuntu 24.04
- 虚拟化：VirtualBox
- Guest：Windows 10 / 11
- 采集：Sysmon + Procmon
- 编排：`VBoxManage`

## 为什么先选 VirtualBox

当前项目已经打通了一条可执行的真实动态采集闭环，当前重点转为把这条链路稳定化和权限隔离化，而不是继续扩张平台复杂度。

VirtualBox 的优势在于：

- `snapshot restore`
- `startvm`
- `guestcontrol copyto`
- `guestcontrol run`
- `guestcontrol copyfrom`

这些能力正好覆盖当前项目 Host 编排层的最小要求。

## Guest 侧准备

Windows VM 内当前建议固定以下目录：

- `C:\Samples`
- `C:\ProgramData\SentinelFlow\Runs`
- `C:\Tools`

当前仓库里已经提供了最小脚本模板，位置：

- [guest-tools/virtualbox/start_capture.bat](/home/duan/ransom-lab/guest-tools/virtualbox/start_capture.bat:1)
- [guest-tools/virtualbox/stop_capture.bat](/home/duan/ransom-lab/guest-tools/virtualbox/stop_capture.bat:1)
- [guest-tools/virtualbox/export_logs.bat](/home/duan/ransom-lab/guest-tools/virtualbox/export_logs.bat:1)
- [guest-tools/virtualbox/export_logs.ps1](/home/duan/ransom-lab/guest-tools/virtualbox/export_logs.ps1:1)

建议把它们复制到：

- `C:\Tools\`

建议准备以下文件：

- `C:\Tools\start_capture.bat`
- `C:\Tools\stop_capture.bat`
- `C:\Tools\export_logs.bat`

这些脚本当前的职责是：

- 启动 Procmon 采集
- 停止 Procmon 采集
- 将 Sysmon / Procmon 导出到受保护目录

同时还需要确保：

- `C:\Tools\Procmon\Procmon64.exe`
- 或 `C:\Tools\Procmon\Procmon.exe`

存在于 Guest 中。

## Host 侧配置目录

当前已经提供一套专用配置目录：

- `configs/virtualbox-lab/`
- `configs/virtualbox-live/`

其中最关键的是：

- `configs/virtualbox-lab/dynamic-analysis.yaml`
- `configs/virtualbox-live/dynamic-analysis.yaml`

区别如下：

- `virtualbox-lab`
  - 适合 dry-run
  - 命令前缀仍然是 `echo`

- `virtualbox-live`
  - 已写成真实 `VBoxManage` 命令
  - 当前已加入 `collector/analyst` 分权字段与受保护日志目录约定
  - 默认仍然不会执行真实样本

## 当前使用方式

### 1. dry-run

```bash
PIPELINE_CONFIG_DIR=configs/virtualbox-lab \
bash bin/run-real-dynamic-pipeline.sh <sample_path> <sample_sha256>
```

这一步不会控制 VM，只会展开并打印命令模板。

### 1.1 Guest 脚本手工验证

在真正通过 Host 编排调用前，建议先在 Windows Guest 内手工验证：

```bat
C:\Tools\start_capture.bat C:\ProgramData\SentinelFlow\Runs testsample
```

然后再执行：

```bat
C:\Tools\stop_capture.bat C:\ProgramData\SentinelFlow\Runs testsample
```

最后执行：

```bat
C:\Tools\export_minimal.bat C:\ProgramData\SentinelFlow\Runs testsample
```

如果成功，应该看到：

- `C:\ProgramData\SentinelFlow\Runs\testsample\procmon.pml`
- `C:\ProgramData\SentinelFlow\Runs\testsample\procmon.csv`
- `C:\ProgramData\SentinelFlow\Runs\testsample\sysmon.evtx`

注意：

- `<sample_path>` 应该是真实待分析的 PE 样本路径
- 不应使用当前仓库中的 JSON 日志样例代替样本执行

### 2. 切换到真实执行

建议不要直接改 `virtualbox-lab`。

请改用：

- `configs/virtualbox-live/dynamic-analysis.yaml`

并显式开启：

```yaml
allow_sample_execution: true
enable_real_vm_execution: true
```

然后执行：

```bash
PIPELINE_CONFIG_DIR=configs/virtualbox-live \
bash bin/run-real-dynamic-pipeline.sh <sample_path> <sample_sha256> --execute
```

或者直接运行新的闭环命令：

```bash
PYTHONPATH=src .venv/bin/python -m cli collect-real-dynamic \
  --sample <sample_path> \
  --sample-sha256 <sample_sha256> \
  --config-dir configs/virtualbox-live \
  --execute
```

## 建议的验证顺序

不要一上来就执行样本。先分步验证：

1. `restore_snapshot`
2. `start_vm`
3. `copy_sample`
4. `start_capture`
5. 用无害程序替代样本验证 `execute_sample`
6. `stop_capture`
7. `export_logs`
8. `collect_logs`

只有这 8 步都稳定后，再进入真实样本执行。

## 当前状态

当前这份配置和文档已经对应到以下真实进度：

- VirtualBox 路线已实现
- Guest 侧脚本已实现并实际使用
- Guest 日志导出与 Host 回传已完成验证
- 动态 replay artifact 构建已验证
- workflow 自动消费真实动态日志已验证
- 第一阶段采集面加固已落地：
  - `collector`
  - `analyst`
  - `C:\Tools`
  - `C:\ProgramData\SentinelFlow\Runs`

当前下一轮补强重点是：

- 继续收敛 `collector`/`analyst` 分权自动化
- 把受保护日志目录完全接入所有动态脚本与命令
- 固化回传后的 `data/<sample_sha256>/` 目录规范
