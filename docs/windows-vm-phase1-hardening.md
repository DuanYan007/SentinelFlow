# Windows 虚拟机第一阶段加固方案

## 目标

第一阶段不改变你的整体实验方法，只做最小保护：

- 新增采集账户 `collector`
- 保护 `C:\Tools`
- 新建受保护日志目录 `C:\ProgramData\SentinelFlow\Runs`
- 保持样本仍由 `analyst` 运行

## 脚本

- [guest-tools/virtualbox/harden_phase1.bat](/home/duan/ransom-lab/guest-tools/virtualbox/harden_phase1.bat:1)
- [guest-tools/virtualbox/harden_phase1.ps1](/home/duan/ransom-lab/guest-tools/virtualbox/harden_phase1.ps1:1)

## 脚本做了什么

执行后会：

1. 创建本地账户 `collector`
2. 将 `collector` 密码设置为 `7566`
3. 创建目录：
   - `C:\ProgramData\SentinelFlow\Runs`
4. 重设 `C:\Tools` 权限：
   - `Administrators` 全权限
   - `SYSTEM` 全权限
   - `collector` 只读执行
   - `analyst` 只读执行
5. 重设 `C:\ProgramData\SentinelFlow\Runs` 权限：
   - `Administrators` 全权限
   - `SYSTEM` 全权限
   - `collector` 可修改
   - `analyst` 拒绝写入

## 执行方式

请在 Windows Guest 中，用管理员 `cmd` 执行：

```bat
C:\Tools\harden_phase1.bat
```

## 第一阶段后的建议目录分工

- `C:\Tools`
  - 放脚本与采集工具
- `C:\Samples`
  - 放模拟样本
- `C:\ProgramData\SentinelFlow\Runs`
  - 放日志
- `%USERPROFILE%\Desktop\SentinelFlowTestData`
  - 放可被模拟程序访问和修改的测试文件

## 第一阶段后的运行约定

第一阶段完成后，建议立即切换到以下分工：

- `collector`
  - 启动采集
  - 停止采集
  - 导出日志
  - 回传日志
- `analyst`
  - 只负责运行模拟样本

日志目录不再建议使用：

- `C:\AnalysisLogs`

而是改为：

- `C:\ProgramData\SentinelFlow\Runs`

也就是说，后续采集建议使用：

```bat
C:\Tools\start_capture.bat C:\ProgramData\SentinelFlow\Runs <sample_sha256>
```

停止与导出也对应改为：

```bat
C:\Tools\stop_capture.bat C:\ProgramData\SentinelFlow\Runs <sample_sha256>
```

```bat
C:\Tools\export_minimal.bat C:\ProgramData\SentinelFlow\Runs <sample_sha256>
```

## 第一阶段的使用建议

此阶段先不强制改造全部自动化命令。

建议先手工验证：

1. `analyst` 无法修改 `C:\Tools`
2. `analyst` 无法向 `C:\ProgramData\SentinelFlow\Runs` 写入
3. `collector` 可以写入 `C:\ProgramData\SentinelFlow\Runs`
4. 样本仍然只以 `analyst` 身份运行

## 后续阶段

第二阶段再考虑：

- `VBoxManage guestcontrol` 分别使用 `collector` 与 `analyst`
- 采集脚本落地到受保护日志目录
- 导出后自动回传宿主机
