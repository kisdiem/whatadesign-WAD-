# WAD 链影寻踪：海量安全日志风险识别与攻击链调查平台

WAD（What A Design）面向“基于海量日志数据的网络风险识别技术”赛题，提供从异构日志接入、无标签风险评分、攻击链聚合、案件调查、证据溯源，到召回/误报/消融/吞吐评测的完整原型。

当前版本重点解决了三个工程问题：

1. 打通真实日志端到端链路，检测主流程不再隐式回退到 Mock；
2. 明确实现弱监督标签函数与无监督异常基线，真实标签仅在预测落盘后用于评测；
3. 用流式处理、固定内存状态和多 worker 分片验证 TB/日级持续处理能力，并如实区分“实测数据量”“吞吐外推”和“容量仿真”。

> 项目定位是可运行、可复现、可审计的竞赛原型，不声称当前样本已经完整扫描 1 TB，也不把小型演示集上的准确率当作生产指标。

## 1. 赛题目标与系统能力

本项目从 Syslog、Windows/ETW/EVTX 投影、WAF、DNS、Suricata/网络 JSONL 等安全日志中识别罕见攻击行为或异常模式，主要能力包括：

- 异构日志发现、逐条解析与统一事件模型；
- 可审计的弱监督标签函数投票；
- 不依赖真实标签的频率隔离异常基线；
- 事件风险融合、短时间窗攻击链聚合和多案件自动建案；
- 真实日志服务端分页、搜索、时间范围过滤和原始行号溯源；
- 召回率、误报率、PR-AUC、攻击链恢复率、消融和吞吐评测；
- 固定内存流式检测、压缩候选分区和多 worker 水平扩展；
- React 调查控制台，覆盖总览、发现、实体、案件、日志、数据源与评测页面。

## 2. 总体架构

项目保留了原有 M0–M6 研究架构，并增加了一条可直接运行的竞赛工程链路。

### 2.1 M0–M6 研究管线

```text
M0 日志解析
  -> M1 跨源语义归一化
  -> M2 实体解析与对齐
  -> M3 时序事件图
  -> M4 当前事件条件化 Q-Former
  -> M5 长时间跨度窗口关联
  -> M6 冻结特征分层融合
```

该部分用于表达跨域语义图、时序关系和长程攻击链研究设计。仓库中包含接口契约、数据泄漏审计、发布门禁、单元测试和精简模型组件；真实训练数据、最终模型检查点和正式盲测指标不随仓库发布。

### 2.2 可运行竞赛链路

```text
真实无标签日志
  -> Source Adapter 流式解析
  -> WeakSupervisor 标签函数投票
  -> FrequencyIsolation / StreamingFrequency 无监督基线
  -> 风险分数融合
  -> 共享实体 + 时间窗聚合 Finding
  -> 稳定实体 + 7 天邻近聚合 Investigation
  -> JSON/JSONL/SQLite 检测产物
  -> FastAPI
  -> React 调查控制台

独立真实标签文件
  -> 仅在预测完成后读取
  -> 召回、误报、PR-AUC、攻击链恢复率与消融报告
```

核心实现位于：

| 模块 | 作用 |
| --- | --- |
| `src/detection/sources.py` | 数据源发现、标签目录排除、CSV/JSONL/ZIP 流式适配 |
| `src/detection/schema.py` | 统一日志事件结构、输入校验和序列化 |
| `src/detection/weak_supervision.py` | 可审计弱监督标签函数及投票结果 |
| `src/detection/unsupervised.py` | 离线频率隔离基线、在线 Count-Min Sketch 基线 |
| `src/detection/engine.py` | 风险融合、Finding 聚合、案件生成及检测清单 |
| `src/detection/log_index.py` | SQLite 全日志索引、分页搜索和场景回放时间轴 |
| `agent_service/app.py` | 检测产物、日志检索、评测与规模报告 API |
| `frontend/src/MissionControlApp.tsx` | 调查控制台和案件交互 |

## 3. 本版本完成的重点优化

### 3.1 真实日志端到端闭环，取消检测主流程隐式 Mock

旧演示容易出现“接口无数据时仍展示静态样例”的情况，无法证明页面内容来自检测引擎。当前版本改为 API-first：

- 检测器读取无标签真实日志并生成 `logs.jsonl`、`windows.json`、`investigations.json`、`detection_manifest.json` 等产物；
- FastAPI 直接加载指定检测产物目录；
- 前端默认请求真实 API，接口失败或返回空结果时不会自动伪造检测结果；
- 只有显式设置 `VITE_USE_MOCKS=true` 或 `WAD_AGENT_USE_MOCKS=true` 才会启用旧演示数据；
- Finding 内保留事件 ID、来源类型、实体、风险分量、`source_file:line` 和原始证据引用。

这使答辩时可以从页面上的一条 Finding 一直追溯到真实输入文件及行号。

### 3.2 弱监督标签生成 + 无监督基线

检测阶段不读取真实攻击标签，而是组合两类信号：

**弱监督信号**

- 由安全专家定义标签函数；
- 标签函数输出规则 ID、触发原因、置信度和 ATT&CK tactic；
- 多规则投票形成噪声伪标签分数；
- 每次命中都可审计，不等同于真实 ground truth。

**无监督信号**

- 模板频率稀有度；
- 实体频率稀有度；
- 来源分布稀有度；
- 日志长度中位数/MAD 偏离；
- 非常用时段异常；
- 大规模在线模式下使用固定大小 Count-Min Sketch 与在线统计量。

默认融合权重为弱监督 `0.62`、无监督 `0.38`，事件阈值为 `0.61`。阈值和权重位于 `DetectionConfig`，可在正式验证集上重新校准。

### 3.3 真实标签物理隔离，只用于评测

为防止标签泄漏，项目实现了以下边界：

- 检测输入中出现 `label`、`ground_truth`、`target` 或 `is_attack` 等字段会被拒绝；
- 检测引擎接口没有标签参数；
- 数据源发现器主动排除 `labels/`、`rules/`、`environment/`、`processing/` 等目录及 `labels.csv`；
- EVTX 样本只读取无标签 CSV 事件投影，并移除 `EVTX_Tactic`；
- AIT ZIP 只流式读取 JSON/JSONL 成员，`labels.csv` 不进入检测进程；
- 检测清单固定记录 `labels_accessed=false`；
- `evaluate_detection.py` 先产生并封存预测，再打开独立标签文件计算指标。

答辩时可以使用如下表述：

> 弱监督标签是专家标签函数生成的带置信度噪声伪标签，不是真实攻击标签。无监督基线只学习日志自身的行为分布。真实标签在文件和执行顺序上与检测过程隔离，只在预测落盘后由独立评测程序读取，用于计算召回率和误报率，不参与特征、阈值、规则或案件生成。

### 3.4 从单事件告警升级为 Finding 和 Investigation

检测器不会直接把每个高分事件都交给人工，而是分两级聚合：

1. **Finding 聚合**：高风险事件按共享实体和 30 分钟邻近性组成风险窗口；
2. **Investigation 聚合**：Finding 按稳定共享实体和 7 天时间邻近性自动建案。

案件聚合会忽略 `cmd.exe`、DLL、脚本路径等通用进程锚点，避免不同主机或不同时期的无关风险被强行合成一个案件。当前真实样本产物包含 10 个风险窗口，聚合为 5 个案件；每个案件保留窗口列表、锚点实体、聚合方法和 `labels_accessed=false`。

### 3.5 全量日志检索与服务端分页

前端不再只显示 Finding 内少量事件。`build_log_index.py` 会把已解析日志写入 SQLite：

- 已建立索引的真实记录：604,633 条；
- 已发现日志源：616 个；
- 服务端分页，默认每页 50 条；
- 支持来源类型、实体、关键字、起止时间和 1h/24h/7d/30d 范围过滤；
- 浏览器仅加载当前页，数据量不会随总日志数线性占用前端内存；
- 可查看回放时间、原始证据时间和原始日志引用；
- 可疑可执行载荷在 UI 索引中做安全摘要与哈希隔离，不直接持久化为可复制执行字符串。

### 3.6 更真实的非均匀场景回放时间轴

不同数据集原始年份和时间跨度差异很大，直接展示会导致近 1 小时、24 小时、7 天没有可比较数据。当前版本增加显式的 `scenario_replay` 时间层：

- 原始时间戳保存为 `original_timestamp`，不覆盖原始证据；
- 回放时间由事件 ID 确定性生成，同一索引构建内可复现；
- 引入工作日/周末差异、工作时间峰值、夜间低谷、批处理尖峰、安静日和攻击突发日；
- API 和 UI 均标记时间模式为场景回放；
- 1h/24h/7d/30d 切换会返回真实 SQLite 范围统计，而不是前端修改一个标签。

当前索引在回放时间轴上的范围统计为：

| 时间范围 | 事件数 |
| --- | ---: |
| 过去 1 小时 | 510 |
| 过去 24 小时 | 24,647 |
| 过去 7 天 | 181,508 |
| 过去 30 天 | 604,633 |

30 天日桶最低 1,617、最高 52,752；24 小时时桶最低 95、最高 2,067，能够体现明显峰谷。上述数字属于当前场景回放索引，不代表日志原始采集时间分布。

### 3.7 TB/日级流式处理能力

本项目的“TB 级”指持续处理能力和水平扩展能力，而不是将 1 TB 文件一次性载入内存。大规模路径采用：

- 逐行文件或 ZIP 成员流式读取；
- 固定大小 Count-Min Sketch 保存模板、实体和来源频率；
- Welford 在线均值/方差；
- 固定大小 Top-K 堆保留高风险候选；
- 按日期和来源写入 gzip 候选分区；
- 多 worker 按数据根目录或生产分区并行；
- 最终只对保留候选进行 Finding 与案件聚合。

其内存复杂度为：

```text
O(worker × (sketch + top_k))
```

不会随历史总日志条数线性增长。

### 3.8 可复现评测与结果边界

项目输出两类报告：

1. **准确性评测**：召回率、精确率、F1、FPR、每百万事件误报、PR-AUC、攻击链恢复率、误报/漏报事件列表；
2. **消融与性能评测**：完整模型、仅无监督、仅弱监督、去除实体稀有度、去除攻击链聚合，以及检测吞吐。

内置 16 条演示集结果为：

| 配置 | Recall | FPR | PR-AUC | Chain Recovery |
| --- | ---: | ---: | ---: | ---: |
| 完整融合 | 1.000 | 0.000 | 1.000 | 1.000 |
| 仅无监督 | 0.714 | 0.222 | 0.826 | 0.500 |
| 仅弱监督 | 1.000 | 0.000 | 1.000 | 1.000 |
| 去除实体稀有度 | 1.000 | 0.000 | 1.000 | 1.000 |
| 去除攻击链聚合 | 1.000 | 0.000 | 1.000 | 0.000 |

这些数字只用于证明评测脚本和消融流程可复现。样本规模很小，不能作为生产泛化性能结论。

## 4. 实测规模与 TB 级口径

当前规模报告使用四个真实数据根目录，每个 worker 最多解析 20 万条：

| 指标 | 实测值 |
| --- | ---: |
| 实际解析记录 | 604,633 条 |
| 实际解析字节 | 473,587,848 B（473.6 MB） |
| 最后一次墙钟时间 | 35.34 s |
| 最后一次聚合吞吐 | 13.40 MB/s |
| 日处理量投影 | 1.158 TB/日（最后一次） |
| 三次完整运行范围 | 1.158–1.223 TB/日 |
| 三次中位数 | 1.205 TB/日 |
| worker 数 | 4 |
| 峰值工作集之和 | 114,737,152 B（约 109.4 MiB） |
| 风险候选 / Finding | 15 / 10 |
| 检测阶段读取真实标签 | 否 |

日处理量按以下公式外推：

```text
实际读取字节 / 实际墙钟时间 × 86,400 / 1,000,000,000,000
```

因此正确表述是“在当前机器和当前异构日志解析链路上，短时实测吞吐外推达到约 1.2 TB/日”，而不是“已经完整扫描了 1 TB”。完整说明见 `docs/tb_scale_validation.md`。

前端还提供一个明确标记为“容量仿真（非真实扫描）”的 3.2 TB 任务进度，用于展示异步作业交互。该仿真不计入实测吞吐、召回或误报结果。

## 5. 数据适配与安全边界

当前可直接读取的输入包括：

- 普通 `.log`、`.txt`、`.json`、`.jsonl`；
- Suricata `eve.json`；
- DNS、WAF、流量类结构化 JSONL；
- EVTX 导出的无标签 CSV 事件投影；
- AIT ADS ZIP 内的 JSON/JSONL 成员流。

当前不会把 PCAP、原始 EVTX、ETL、journal 等二进制文件伪装成已支持格式。生产环境应先通过 Zeek、Suricata、Winlogbeat、Fluent Bit 或系统采集器转换为结构化事件。

原始数据根目录只读，所有检测产物写入 `outputs/`。大型 SQLite 索引、原始日志、ZIP、PCAP、EVTX 和临时运行状态默认不提交到 Git。

## 6. 快速开始

### 6.1 环境要求

- Python 3.11 或更高版本；
- Node.js 18 或更高版本；
- Windows PowerShell（脚本已提供），Linux/macOS 可直接运行对应 Python 命令。

安装后端依赖：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

安装前端依赖：

```powershell
cd frontend
npm install
cd ..
```

### 6.2 一键运行内置真实日志闭环

```powershell
.\scripts\run_competition_demo.ps1
```

该脚本会：

1. 对 `data/demo/real_logs.jsonl` 运行无标签检测；
2. 将检测产物写入 `outputs/demo_state`；
3. 在预测完成后读取 `data/demo/evaluation_labels.json`；
4. 生成 `outputs/evaluation/evaluation_report.json` 和 Markdown 报告。

### 6.3 启动后端

使用内置演示产物：

```powershell
$env:WAD_DETECTION_DATA_DIR = "outputs/demo_state"
python -m uvicorn agent_service.app:app --host 127.0.0.1 --port 8000
```

使用真实规模检测产物和 SQLite 日志索引：

```powershell
$env:WAD_DETECTION_DATA_DIR = "outputs/scale_parallel"
$env:WAD_LOG_INDEX = "outputs/scale_parallel/all_logs.sqlite"
python -m uvicorn agent_service.app:app --host 127.0.0.1 --port 8000
```

### 6.4 启动前端

另开一个终端：

```powershell
cd frontend
npm run dev
```

打开 `http://127.0.0.1:5173`。Vite 默认将 `/api` 代理到 `http://127.0.0.1:8000`。

## 7. 使用自有日志

### 7.1 单个无标签 JSONL

```powershell
python scripts/run_real_detection.py `
  --input D:\logs\events.jsonl `
  --output-dir outputs\my_detection
```

输入至少应提供时间、消息和来源信息；不同结构会由适配器归一化为统一事件。检测输入不得包含真实标签字段。

### 7.2 多目录并行流式检测

```powershell
python scripts/run_parallel_scale.py `
  --root D:\logs\endpoint `
  --root D:\logs\network `
  --root D:\logs\waf `
  --output-dir outputs\scale_run `
  --workers 3 `
  --max-records-per-worker 200000 `
  --top-k-per-worker 5000 `
  --aggregate-top-k 10000
```

`--max-records-per-worker 0` 表示扫描全部可解析记录。正式运行前应确认磁盘空间、候选分区保留策略和数据目录权限。

### 7.3 构建分页日志索引

```powershell
python scripts/build_log_index.py `
  --root D:\logs\endpoint `
  --root D:\logs\network `
  --database outputs\scale_run\all_logs.sqlite `
  --max-records-per-root 200000
```

完整索引时将 `--max-records-per-root` 设为 `0`。

### 7.4 独立评测

```powershell
python scripts/evaluate_detection.py `
  --input data\demo\real_logs.jsonl `
  --labels data\demo\evaluation_labels.json `
  --output-dir outputs\evaluation
```

标签文件应与检测输入分离，且只在预测完成后交给评测脚本。

## 8. 主要输出产物

| 文件 | 内容 |
| --- | --- |
| `logs.jsonl` | 事件风险分数、异常分量、弱监督命中和溯源引用 |
| `windows.json` / `findings.json` | 聚合风险窗口及其证据 |
| `investigations.json` | 自动生成的案件、Finding 列表和锚点实体 |
| `weak_rules.json` | 弱监督规则清单 |
| `detection_manifest.json` | 输入摘要、执行模式、标签隔离和吞吐清单 |
| `scale_report.json` | 多 worker 规模、内存和 TB/日投影 |
| `evaluation_report.json` | 召回、误报、消融和评分吞吐 |
| `all_logs.sqlite` | 全日志分页检索索引，默认不提交到 Git |

## 9. 前端页面

- **总览**：范围事件数、风险发现、研判压缩、数据源和时间趋势；
- **发现**：Finding 列表、风险分量、关联实体和证据；
- **实体调查**：实体画像、历史行为与基线；
- **案件调查**：多案件列表、攻击链图、主链/候选/排除看板和证据时间线；
- **日志检索**：真实 SQLite 日志分页、搜索、筛选和原始时间查看；
- **数据源**：真实源目录和索引状态；
- **评测**：准确率、误报、消融、吞吐以及容量边界；
- **小影助手**：在配置模型服务后，基于 Finding、案件和实体上下文辅助研判。

## 10. 测试与复现

运行本次检测与索引相关测试：

```powershell
python -m pytest `
  tests/unit/test_detection_engine.py `
  tests/unit/test_log_index.py `
  tests/unit/test_scalable_detection.py `
  tests/integration/test_real_detection_evaluation.py -q
```

构建前端：

```powershell
cd frontend
npm run build
```

测试覆盖标签字段拒绝、弱监督/无监督无标签执行、真实产物溯源、固定内存草图、标签目录排除、非均匀回放、多案件拆分、SQLite 分页和评测复现。

## 11. 当前限制与后续工作

- 内置准确率数据集规模很小，需要在正式盲测集上重新报告召回与误报；
- 当前 TB/日结论是 473.6 MB 短时实测吞吐外推，仍需补充 24 小时稳定性、积压恢复和 P95 延迟测试；
- 二进制 PCAP/EVTX 依赖外部解析器转换；
- Count-Min Sketch 存在可控碰撞误差，生产环境需结合流量规模调整宽度；
- Top-K 策略适合控制研判量，但可能截断低分长链，需要结合分区配额和动态阈值；
- 弱监督规则需要持续版本化、冲突分析和领域迁移校准；
- 场景回放只服务于前端演示，取证与正式评测必须使用保存的原始时间戳；
- 生产化还需接入 Kafka/Pulsar、对象存储、任务编排、失败重试、权限控制和审计留痕。

## 12. 相关文档

- `docs/competition_demo.md`：最小闭环、标签隔离和答辩口径；
- `docs/tb_scale_validation.md`：TB 级实现、实测方法和边界；
- `docs/v3_compliance_audit.md`：原 M0–M6 合规审计；
- `docs/data_deviation_v3.md`：数据源偏差与训练/评测边界；
- `outputs/evaluation/evaluation_report.md`：当前演示集评测报告。

## 13. 分支说明

- `scx`：竞赛原型与当前优化基线；
- 后续发布分支可在完成 README、代码和产物范围检查后从 `scx` 创建。
