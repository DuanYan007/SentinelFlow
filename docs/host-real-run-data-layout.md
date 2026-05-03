# 宿主机真实动态日志目录约定

## 目标

当前项目将 Windows Guest 回传到 Ubuntu 宿主机的真实动态日志，统一落在项目根目录下的：

- `data/`

而不是旧的：

- `staging/real-dynamic-runs/`

## 目录规则

推荐结构：

- `data/<sample_sha256>/`

例如：

- `data/fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498/`

目录内至少可以包含：

- `sysmon.evtx`
- `sysmon.json`
- `procmon.pml`
- `procmon.csv`
- `procmon.json`

## Guest 与 Host 的分工

Guest 内目录当前有两种状态：

- 历史链路：`C:\AnalysisLogs\<sample_sha256>\`
- 第一阶段加固后建议链路：`C:\ProgramData\SentinelFlow\Runs\<sample_sha256>\`

Host 内回传目录改为：

- `/home/duan/ransom-lab/data/<sample_sha256>/`

这样可以把：

- Guest 采集路径
- Host 持久化路径

分开管理。

## 回传示例

```bash
mkdir -p /home/duan/ransom-lab/data
VBoxManage guestcontrol "windows-lab" copyfrom "C:\ProgramData\SentinelFlow\Runs\fe81c5caa0e269c1cbbd0aca9557677c4f57829d621f2f21768728c92e4f0498" "/home/duan/ransom-lab/data" --username "collector" --password "7566"
```

## 与项目工作流的关系

当前项目中 `real_runs_dir` 已调整为 `data`，因此后续：

- `prepare_real_dynamic_artifacts`
- `single_sample_workflow`
- `collect-real-dynamic`

都会默认从 `data/<sample_sha256>/` 查找：

- `sysmon.json`
- `procmon.json`
