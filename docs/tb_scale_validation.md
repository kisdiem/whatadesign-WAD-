# TB 级日志处理实现与实测说明

## 结论

本项目的“TB 级”指持续处理能力和水平扩展能力，不是把 1 TB 文件装进内存，也不声称本次已经拥有或完整扫描了 1 TB 数据。

在本机对四个真实数据根目录进行并行、单遍、固定内存压测，最终审计结果为：

| 指标 | 实测值 |
| --- | ---: |
| 实际解析记录 | 604,633 条 |
| 实际解析字节 | 473,587,848 B（473.6 MB） |
| 墙钟时间 | 35.34 s（最后一次） |
| 聚合吞吐 | 13.40 MB/s（最后一次） |
| 日处理量投影 | 中位数 1.205 TB/日；范围 1.158–1.223 |
| worker 数 | 4 |
| 峰值工作集之和 | 114,737,152 B（109.4 MiB，最后一次） |
| 检测阶段读取真实标签 | 否，`labels_accessed=false` |
| 风险候选 / 聚合窗口 | 15 / 10 |

日处理量由 `实际读取字节 / 实际墙钟时间 × 86400` 计算。相同口径三次完整运行结果为 1.158、1.205、1.223 TB/日，中位数 1.205 TB/日。它是同一机器、同一解析和打分代码上的短时吞吐外推，不等同于“完成 1 TB 全量准确率评测”。正式答辩应同时展示输入规模、持续时间、并行度、内存和计算公式。

## 数据边界

检测发现器在四个目录中识别出约 12.34 GB 可解析且不含标签的有效源：

- Santos、RussellMitchell：只遍历 `gather/`；`labels/`、`rules/`、`environment/` 和 `processing/` 不进入检测进程。
- EVTX-ATTACK-SAMPLES：只读取无标签事件投影 `evtx_data.csv`；移除 `EVTX_Tactic`，且不读取 ATT&CK 元数据目录和 `.evtx` 二进制。
- AIT ADS：直接流式读取 `ait_ads.zip` 内的 JSON/JSONL 成员，不解压到内存或临时目录；`labels.csv` 被排除。
- PCAP、ETL、journal 等二进制源不伪装成已支持格式。生产接入应先由 Zeek、Suricata 或系统采集器转成结构化事件。

原始 `D:\CODE` 数据全程只读，程序只在 `outputs/` 写检测产物。

## 为什么内存不随 TB 增长

每个 worker 使用：

1. 逐行事件迭代器或 ZIP 成员流，一次只保留当前事件；
2. Count-Min Sketch 维护模板、实体和来源频率，当前每 worker 固定约 2.06 MiB；
3. Welford 在线均值/方差维护长度异常基线；
4. 固定大小 Top-K 堆只保留最高风险候选；
5. 风险证据按日期和来源写入轮转 gzip 分区；
6. worker 进程隔离，按日志分区横向增加吞吐。

因此算法状态复杂度是 `O(worker × (sketch + top_k))`，不是 `O(日志总条数)`。

## 可复现命令

本次 20 万条/worker 的并行压测：

```powershell
python scripts/run_parallel_scale.py `
  --root D:\CODE\santos `
  --root D:\CODE\russellmitchell `
  --root D:\CODE\EVTX-ATTACK-SAMPLES-master `
  --root D:\CODE\ait_ads `
  --output-dir outputs\scale_parallel `
  --workers 4 `
  --max-records-per-worker 200000
```

完整扫描全部可解析数据时，把每 worker 上限设为 0：

```powershell
python scripts/run_parallel_scale.py `
  --root D:\CODE\santos `
  --root D:\CODE\russellmitchell `
  --root D:\CODE\EVTX-ATTACK-SAMPLES-master `
  --root D:\CODE\ait_ads `
  --output-dir outputs\scale_full `
  --workers 4 `
  --max-records-per-worker 0
```

结果清单位于 `outputs/scale_parallel/scale_report.json`。前端“评测”页通过 `/api/scale/report` 展示同一清单，不使用硬编码指标。

“日志检索”页通过 SQLite 服务端分页索引展示全部已索引真实记录；浏览器每次只加载 50 条，但总数、搜索和任意深分页来自同一真实索引。页面另有一个 3.2 TB 异步任务进度演示，接口和 UI 均标记为“容量仿真（非真实扫描）”，不计入实测吞吐、召回或误报结果。

## 生产 TB/日架构

离线文件场景应按日期、来源和大小预先分片；在线场景用 Kafka/Pulsar 分区。每个消费进程复用当前固定内存检测器，将候选写入对象存储分区，最后只对 Top-K 候选做攻击链聚合。若单 worker 实测约 3.5 MB/s，要达到 1 TB/日所需并行度为：

`ceil(1,000,000 MB / 86,400 s / 3.5 MB/s) = 4 workers`

生产验收还需做 24 小时持续压测、积压恢复、失败重试、分区重平衡和 P95 延迟测试；本次竞赛原型完成的是可运行的数据面与可复现的短时吞吐证明。

## 答辩口径

> 我们没有把不到 20 GB 的样本包装成“扫描过 1 TB”。TB 级能力来自逐条流式解析、固定内存频率草图、Top-K 候选保留、压缩分区输出和多 worker 横向扩展。本机 4 worker 在真实异构日志上三次实测为 1.158–1.223 TB/日，中位数 1.205 TB/日；原始标签目录不进入检测进程，真实标签只允许在预测落盘后由独立评测程序读取。完整准确率结论来自独立召回与误报报告，吞吐报告只回答系统容量问题。
