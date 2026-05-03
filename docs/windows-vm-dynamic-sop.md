# Windows VM 真实动态执行 SOP

## 目标

该 SOP 的目标是记录当前已经落地的 Windows VM 真实动态采集链路，以及后续如何继续稳定化。

## 最小环境

- Host：Ubuntu 24.04
- Guest：Windows 10 / 11 VM
- 网络：host-only / isolated
- 快照：clean baseline
- 工具：
  - Sysmon
  - Procmon

## 最小执行流程

1. 在 Windows VM 中准备：
   - 安装 Sysmon
   - 安装 Procmon
   - 关闭不必要的软件
   - 创建干净快照

2. 投递样本：
   - 将目标 PE 放入 VM 内临时目录

3. 启动采集：
   - 启动 Sysmon 事件记录
   - 启动 Procmon 采集

4. 执行样本：
   - 仅在隔离 VM 中执行

5. 停止采集并导出：
   - 当前稳定导出目标优先为：
     - `sysmon.evtx`
     - `procmon.pml`
     - `procmon.csv`
   - `json` 导出仍保留，但不再假定每次都一次成功

6. 将日志带回 Host：
   - 当前宿主机目录统一为：
     - `data/<sample_sha256>/`

7. 在项目中导入：

```bash
PYTHONPATH=src .venv/bin/python -m cli import-sysmon-log \
  --sysmon-log data/<sample_sha256>/sysmon.json \
  --output data/raw/<sample>.raw.json
```

```bash
PYTHONPATH=src .venv/bin/python -m cli import-procmon-log \
  --procmon-log data/<sample_sha256>/procmon.json \
  --output data/raw/<sample>.raw.json
```

当前实现说明：

- 现在已经支持：
  - `import-sysmon-log`
  - `import-procmon-log`
  - `import-real-run`

推荐优先使用：

```bash
PYTHONPATH=src .venv/bin/python -m cli import-real-run \
  --sysmon-log data/<sample_sha256>/sysmon.json \
  --procmon-log data/<sample_sha256>/procmon.json \
  --output data/raw/<sample>.merged.raw.json
```

如果你已经将真实导出整理到：

- `data/<sample_sha256>/sysmon.json`
- `data/<sample_sha256>/procmon.json`

则主 workflow 在进入 dynamic 阶段前会自动尝试把这两份真实日志转换为 replay artifact。

8. 将 unified raw log 转为 replay artifact：

```bash
PYTHONPATH=src .venv/bin/python -m cli build-dynamic-artifact \
  --raw-log data/raw/<sample>.merged.raw.json \
  --output-dir staging/dynamic-replay
```

9. 运行动态实验：

```bash
PYTHONPATH=src .venv/bin/python -m cli dynamic-experiment \
  --input-dir staging/dynamic-replay \
  --config-dir configs/replay-validation \
  --output-dir results
```

## 当前限制

当前 SOP 对应的当前状态是：

- Host 编排层已经落到真实 `VBoxManage`
- Guest 侧采集脚本已经落地并验证
- 真实日志回传已完成验证
- workflow 自动消费真实动态日志已完成验证
- 第一阶段已经新增 `collector` 与受保护日志目录

当前限制是：

1. 受保护日志目录还在继续收敛进全部脚本与命令
2. `json` 导出仍可能受 Guest 权限和工具状态影响
3. 自动化稳定性仍需继续回归

## 下一步

后续最值得继续补的是：

1. 在 `configs/replay-validation/dynamic-analysis.yaml` 中填入真实 Host 编排命令
2. 使用：

```bash
bin/run-real-dynamic-pipeline.sh <sample_path> <sample_sha256>
```

先做 dry-run 规划

3. 确认无误后再使用：

```bash
bin/run-real-dynamic-pipeline.sh <sample_path> <sample_sha256> --execute
```
