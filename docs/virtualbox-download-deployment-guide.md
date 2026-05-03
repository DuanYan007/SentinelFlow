# VirtualBox 真实动态分析下载与部署指南

## 文档目标

这份文档的目标是让你在当前机器上完成一套可落地的真实动态分析实验环境准备。

适用范围：

- Host：Ubuntu 24.04
- 虚拟化：VirtualBox
- Guest：Windows 10 / 11
- 日志采集：Sysmon + Procmon
- 项目：`SentinelFlow`

当前文档的重点不是直接执行恶意样本，而是先把：

- 下载
- 安装
- 目录准备
- Guest 工具准备
- 项目配置接入
- dry-run 验证

全部整理成一条完整路径。

## 总体结构

最终环境结构如下：

1. Ubuntu Host 上安装 VirtualBox
2. 创建 Windows VM
3. 在 Windows VM 中安装 Guest Additions
4. 在 Windows VM 中安装 Sysmon 与 Procmon
5. 在 Windows VM 中准备固定目录与批处理脚本
6. 在项目中填写 `configs/virtualbox-lab/`
7. 在 Host 上先做 dry-run
8. 准备好后切换到真实执行

## 一、Host 侧准备

### 1. 系统更新

先更新当前 Ubuntu 24.04：

```bash
sudo apt update
sudo apt upgrade -y
```

### 2. 安装 VirtualBox 依赖

建议先安装常见构建依赖和内核头文件：

```bash
sudo apt install -y build-essential dkms linux-headers-$(uname -r)
```

说明：

- VirtualBox 在 Linux Host 上需要内核模块
- 如果缺少头文件或构建工具，安装后可能无法正确加载 `vboxdrv`

### 3. 下载 VirtualBox

下载入口使用 Oracle 官方 Linux 下载页面。

当前官方页面提供 Linux Host 安装包，并列出 Ubuntu 24.04 对应包。

建议做法：

1. 打开官方页面
2. 下载适用于 `Ubuntu 24.04` 的 VirtualBox 安装包

如果你是图形界面下载，建议把文件放到：

```text
~/Downloads/
```

### 4. 安装 VirtualBox

假设你下载的是 `.deb` 安装包，可以这样安装：

```bash
cd ~/Downloads
sudo apt install ./virtualbox-*.deb
```

说明：

- 这里用 `apt install ./xxx.deb` 是为了让依赖自动解析
- 实际文件名以你下载的包为准

### 5. 验证安装

验证 `VBoxManage` 是否可用：

```bash
VBoxManage --version
```

如果能输出版本号，说明 Host 侧核心工具已经装好。

## 二、下载 Windows 安装镜像

Windows Guest 建议使用微软官方安装介质。

建议：

- Windows 10 或 Windows 11
- x86_64 版本

要求：

- 不要使用来源不明镜像
- 安装完成后尽量保持干净环境

## 三、创建 Windows VM

### 1. 建议资源

最小建议：

- CPU：2 核
- 内存：4 GB 以上
- 磁盘：64 GB 以上

### 2. 建议网络

建议先使用：

- `Host-Only`
- 或者隔离网络

不要让分析 VM 直接暴露到普通工作网络。

### 3. Guest 名称与快照名

建议统一使用：

- VM 名称：`windows-lab`
- 快照名：`clean-baseline`

这与你项目里的默认模板一致。

## 四、安装 Guest Additions

Guest Additions 很重要，因为后续 `VBoxManage guestcontrol` 依赖它来：

- 拷贝文件到 Guest
- 在 Guest 中启动程序
- 从 Guest 回传日志

建议顺序：

1. 启动 Windows VM
2. 在 VirtualBox 菜单中挂载 Guest Additions 镜像
3. 在 Windows 中运行安装程序
4. 安装完成后重启 Guest

## 五、Windows Guest 内部准备

### 1. 创建目录

在 Guest 中创建以下目录：

```text
C:\Samples
C:\AnalysisLogs
C:\Tools
```

作用：

- `C:\Samples`：放待分析样本
- `C:\AnalysisLogs`：放导出日志
- `C:\Tools`：放采集脚本和辅助工具

### 2. 建议创建本地分析账户

建议准备一个专门用于 GuestControl 的 Windows 用户，例如：

- 用户名：`analyst`

并确保：

- 有登录权限
- 有访问 `C:\Samples`、`C:\AnalysisLogs`、`C:\Tools` 的权限

### 3. 在项目配置中填写账户信息

对应文件：

- [configs/virtualbox-lab/dynamic-analysis.yaml](/home/duan/ransom-lab/configs/virtualbox-lab/dynamic-analysis.yaml:1)

需要填写：

- `vm_username`
- `vm_password`
- `vm_guest_sample_dir`
- `vm_guest_logs_dir`
- `vm_guest_tools_dir`

## 六、下载并安装 Sysmon

### 1. 下载 Sysmon

Sysmon 使用微软官方 Sysinternals 下载页。

它的作用是：

- 记录进程创建
- 记录网络连接
- 记录文件创建时间变化

这些都是你当前实验链路里最关键的基础动态证据。

### 2. 安装 Sysmon

建议把下载后的内容放在：

```text
C:\Tools\Sysmon\
```

安装时通常使用：

```powershell
sysmon64.exe -accepteula -i
```

如果你后面准备使用自定义配置文件，可以改为：

```powershell
sysmon64.exe -accepteula -i <config.xml>
```

### 3. 验证 Sysmon

可以用下面命令确认是否已安装：

```powershell
sysmon64.exe -s
```

或者在事件查看器中检查 Sysmon 事件日志。

## 七、下载并安装 Procmon

### 1. 下载 Procmon

Procmon 使用微软官方 Sysinternals 下载页。

它的作用是采集：

- 文件系统活动
- 注册表活动
- 进程/线程活动

### 2. 准备 Procmon

建议把 Procmon 放到：

```text
C:\Tools\Procmon\
```

后续由批处理脚本调用它开始和停止采集。

### 3. 验证 Procmon

先在 Windows 里手工启动一次，确认：

- 可以打开
- 可以开始采集
- 可以保存日志

## 八、准备 Guest 侧脚本

在：

```text
C:\Tools
```

下至少准备 3 个脚本：

- `start_capture.bat`
- `stop_capture.bat`
- `export_logs.bat`

职责如下：

### `start_capture.bat`

负责：

- 清理上一次实验残留
- 启动 Procmon 静默采集

### `stop_capture.bat`

负责：

- 停止 Procmon 采集

### `export_logs.bat`

负责：

- 将本轮日志导出到
  `C:\AnalysisLogs\<sha256>\`
- 至少包括：
  - Sysmon 导出
  - Procmon 导出

注意：

- 当前项目已经有日志导入器，但真实导出字段格式要和你导出的 JSON 保持一致或可映射

## 九、创建干净快照

当 Guest 内以下内容都准备好之后，再创建快照：

- Windows 已安装完
- Guest Additions 已安装
- Sysmon 已安装
- Procmon 已准备好
- `C:\Samples`
- `C:\AnalysisLogs`
- `C:\Tools`
- 采集脚本已放好

快照名建议固定为：

```text
clean-baseline
```

## 十、项目配置接入

项目里已经准备了 VirtualBox 专用配置目录：

- [configs/virtualbox-lab/](/home/duan/ransom-lab/configs/virtualbox-lab/dynamic-analysis.yaml:1)

你主要需要修改：

### `dynamic-analysis.yaml`

重点字段：

- `vm_name`
- `vm_guest_ip`
- `vm_username`
- `vm_password`
- `vm_guest_sample_dir`
- `vm_guest_logs_dir`
- `vm_guest_tools_dir`
- `snapshot_name`

### 当前默认行为

当前模板中的 `vm_*_command` 前缀还是：

```text
echo VBoxManage ...
```

这表示：

- 只做 dry-run
- 不会真的控制 VM

## 十一、dry-run 验证

在真正执行前，先跑 dry-run：

```bash
PIPELINE_CONFIG_DIR=configs/virtualbox-lab \
bash bin/run-real-dynamic-pipeline.sh <sample_path> <sample_sha256>
```

这一步应该输出：

- `restore_snapshot`
- `start_vm`
- `copy_sample`
- `start_capture`
- `execute_sample`
- `stop_capture`
- `export_logs`
- `collect_logs`

对应的渲染后 `VBoxManage` 命令。

这一步的目的只是验证：

- 配置是否完整
- 路径是否合理
- 命令模板是否符合你的 Guest 目录结构

## 十二、切到真实执行

只有在以下条件全部满足后，才建议切换真实执行：

- VirtualBox 安装正常
- Guest Additions 安装正常
- `guestcontrol` 可用
- Windows 用户名密码正确
- Guest 目录已存在
- Guest 脚本已能手工跑通
- 快照已存在

然后把：

- `configs/virtualbox-lab/dynamic-analysis.yaml`

中每个 `vm_*_command` 前面的 `echo` 去掉。

之后执行：

```bash
PIPELINE_CONFIG_DIR=configs/virtualbox-lab \
bash bin/run-real-dynamic-pipeline.sh <sample_path> <sample_sha256> --execute
```

注意：

- `<sample_path>` 必须是真实 PE 文件路径
- 不要拿仓库里的 JSON 样例替代真实样本路径

## 十三、推荐验证顺序

不要一上来就跑真实恶意样本。

建议按这个顺序：

1. 验证 `VBoxManage --version`
2. 验证 VM 能启动
3. 验证快照恢复
4. 验证 `guestcontrol copyto`
5. 验证 `guestcontrol run`
6. 用无害程序验证执行流程
7. 验证 Guest 日志导出
8. 验证 `copyfrom`
9. 再进入真实样本实验

## 十四、准备完成的判断标准

当以下条件全部满足时，说明环境准备完成：

- Host 已安装 VirtualBox
- Guest 已安装 Windows
- Guest Additions 正常
- Sysmon 已安装
- Procmon 已准备好
- Guest 目录和脚本已存在
- `clean-baseline` 快照已创建
- `configs/virtualbox-lab/` 已填好
- dry-run 命令输出正确

这时你就可以进入下一步：

- 把 VirtualBox 命令模板切成真实执行版本
- 开始第一次真实闭环采集

## 参考来源

- VirtualBox Linux 下载页
- VirtualBox 手册中的 Linux 安装说明
- VirtualBox `VBoxManage` 手册
- Sysmon 官方下载与命令文档
- Procmon 官方下载页
