# 手动日志采集部署文档

## 1. 环境要求

宿主机：

- Linux
- 已安装 `VirtualBox`
- 已安装 `VBoxManage`

虚拟化：

- `VirtualBox`

Guest：

- Windows 10 x64 或 Windows 11 x64
- 已安装 `Guest Additions`

Windows 镜像：

- 使用任意可正常安装的官方 Windows 10/11 x64 ISO

样本类型：

- 单个 Windows PE 可执行文件
- 示例样本名：
  - `fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498.exe`
- 示例 SHA256：
  - `fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498`

## 2. 目标

本方案只覆盖手动采集：

- `admin` 启动采集
- `analyst` 手工运行样本
- `admin` 停止采集
- 宿主机回传 `procmon.pml`

不包含自动化闭环测试。

## 3. Guest 布局

虚拟机默认名称：

- `ransom-lab`

账户：

- `admin`
- `analyst`

目录：

- `C:\admin`
- `C:\admin\Procmon`
- `C:\admin\Control`
- `C:\analyst`

用途：

- `C:\admin`
  - `start_capture.bat`
  - `stop_capture.bat`
  - 日志目录 `<sha256>\procmon.pml`
- `C:\admin\Procmon`
  - `Procmon64.exe` 或 `Procmon.exe`
- `C:\admin\Control`
  - `procmon.active`
- `C:\analyst`
  - 样本
  - 测试文件

## 4. 文件部署

复制以下文件到 Guest：

- [start_capture.bat](/home/duan/ransom-lab/dynamic-log-capture/start_capture.bat) -> `C:\admin\start_capture.bat`
- [stop_capture.bat](/home/duan/ransom-lab/dynamic-log-capture/stop_capture.bat) -> `C:\admin\stop_capture.bat`
- `Procmon64.exe` -> `C:\admin\Procmon\Procmon64.exe`

## 5. ACL 设计

目标：

- `admin` 管脚本和日志
- `analyst` 管样本和测试文件
- `Administrators` 与 `SYSTEM` 保留完全控制

### 4.1 `C:\admin`

在提升后的管理员 `cmd` 中执行：

```bat
icacls C:\admin /inheritance:r
icacls C:\admin /remove:g analyst Users "Authenticated Users" Everyone
icacls C:\admin /grant:r Administrators:(OI)(CI)F SYSTEM:(OI)(CI)F admin:(OI)(CI)F
```

### 4.2 `C:\analyst`

```bat
icacls C:\analyst /inheritance:r
icacls C:\analyst /remove:g admin Users "Authenticated Users" Everyone
icacls C:\analyst /grant:r Administrators:(OI)(CI)F SYSTEM:(OI)(CI)F analyst:(OI)(CI)F
```

### 4.3 验证

```bat
icacls C:\admin
icacls C:\analyst
```

期望：

- `C:\admin`
  - `admin:(OI)(CI)(F)`
  - `SYSTEM:(OI)(CI)(F)`
  - `Administrators:(OI)(CI)(F)`
- `C:\analyst`
  - `analyst:(OI)(CI)(F)`
  - `SYSTEM:(OI)(CI)(F)`
  - `Administrators:(OI)(CI)(F)`

## 6. UAC 要求

`admin` 必须具备完整管理员权限，否则无法结束 `Procmon64.exe`。

在提升后的管理员 `cmd` 中执行：

```bat
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
shutdown /r /t 0 /f
```

## 7. 快照前检查

确认：

- `C:\admin\start_capture.bat` 存在
- `C:\admin\stop_capture.bat` 存在
- `C:\admin\Procmon\Procmon64.exe` 存在
- `C:\admin\Control` 存在
- `C:\analyst` 存在
- 没有运行中的 `Procmon`
- `C:\admin\Control\procmon.active` 不存在
- `C:\admin` 下没有旧日志目录

然后制作快照：

- 快照名：`exp`

## 8. 手工采集命令

示例变量：

- VM 名称：`ransom-lab`
- 快照名：`exp`
- 控制账户：`admin`
- 控制密码：`7566`
- 样本账户：`analyst`
- 文件名：`fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498.exe`
- SHA256：`fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498`

### 7.1 恢复快照并启动

```bash
VBoxManage controlvm "ransom-lab" poweroff
VBoxManage snapshot "ransom-lab" restore "exp"
sleep 5
VBoxManage startvm "ransom-lab" --type gui
```

### 7.2 复制样本到 Guest

```bash
VBoxManage guestcontrol "ransom-lab" copyto "/home/duan/ransom-lab/ransomware/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498.exe" "C:/analyst/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498.exe" --username "admin" --password "7566"
```

### 7.3 启动采集

```bash
VBoxManage guestcontrol "ransom-lab" start --exe "C:\\Windows\\System32\\cmd.exe" --username "admin" --password "7566" -- cmd.exe /c "C:\admin\start_capture.bat C:\admin fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498"
```

### 7.4 Guest 内检查采集状态

在 `analyst` 桌面执行：

```bat
tasklist | find /I "Procmon"
type C:\admin\Control\procmon.active
dir C:\admin\fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498
```

### 7.5 `analyst` 手工运行样本

```bat
C:\analyst\fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498.exe
```

### 7.6 停止采集

```bash
VBoxManage guestcontrol "ransom-lab" run --exe "C:\\Windows\\System32\\cmd.exe" --username "admin" --password "7566" -- cmd.exe /c "C:\admin\stop_capture.bat C:\admin fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498"
```

### 7.7 回传日志

```bash
mkdir -p "/home/duan/ransom-lab/data/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498"
VBoxManage guestcontrol "ransom-lab" copyfrom "C:/admin/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498" "/home/duan/ransom-lab/data/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498" --recursive --username "admin" --password "7566"
```

### 7.8 检查结果

```bash
ls -la "/home/duan/ransom-lab/data/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498"
```

应至少看到：

```text
procmon.pml
```

## 9. 需要替换的值

每次复现时，至少需要按实际环境替换：

1. 虚拟机名称
2. 快照名称
3. `admin` 密码
4. `analyst` 密码
5. 宿主机样本路径
6. 样本文件名
7. 样本 SHA256

如果不使用本文默认布局，还需要同步替换：

1. `C:\admin`
2. `C:\admin\Procmon`
3. `C:\admin\Control`
4. `C:\analyst`
