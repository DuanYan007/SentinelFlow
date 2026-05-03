# Windows 虚拟机实验环境准备

## 目标

这一步不进入动态分析主链路，只用于在 Windows Guest 中先把实验环境准备好。

当前准备动作只有两项：

- 确保样本目录存在：`C:\Samples`
- 在当前用户桌面创建一批测试文件，供模拟程序访问、修改、重命名或覆盖

## 脚本位置

- [guest-tools/virtualbox/prepare_workspace.bat](/home/duan/ransom-lab/guest-tools/virtualbox/prepare_workspace.bat:1)
- [guest-tools/virtualbox/prepare_workspace.ps1](/home/duan/ransom-lab/guest-tools/virtualbox/prepare_workspace.ps1:1)

建议复制到 Guest：

- `C:\Tools\prepare_workspace.bat`
- `C:\Tools\prepare_workspace.ps1`

## 执行效果

执行后默认会创建：

- `C:\Samples`
- `%Desktop%\SentinelFlowTestData`

并在 `SentinelFlowTestData` 目录下生成 30 个测试文件，扩展名轮换为：

- `.txt`
- `.docx`
- `.xlsx`
- `.pdf`
- `.jpg`
- `.png`

## 在 Guest 中手工执行

```bat
C:\Tools\prepare_workspace.bat
```

执行成功后，PowerShell 会输出一段 JSON 摘要，包含：

- `sample_workspace`
- `desktop_dir`
- `desktop_file_count`
- `extensions`

## 适用场景

这一步适合在真正开始采集日志之前使用，尤其适合以下情况：

- 模拟程序依赖桌面或用户目录中的现成文件
- 需要稳定复现实验输入
- 需要先验证“样本是否真的会触碰用户文件”

## 建议顺序

建议每次恢复快照后都按以下顺序做：

1. 启动 Windows VM
2. 执行 `prepare_workspace.bat`
3. 确认桌面测试文件已经生成
4. 再启动 Procmon / Sysmon 采集
5. 再运行模拟程序
