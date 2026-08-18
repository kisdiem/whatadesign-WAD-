# 链影寻踪 · M0-M6 攻击链调查台

> **面向第十九届全国大学生信息安全竞赛（作品赛）的原型系统。赛题方向：基于海量日志数据的网络风险识别技术。**

从 TB 级多源安全日志（Syslog / ETW / WAF / DNS）中，用**无监督 / 弱监督**方法识别**罕见攻击链**与异常模式，并**有效降低人工研判成本**。

核心叙事围绕 **Finding → Investigation → Evidence → Analyst Decision** 的调查工作流，而非普通 SIEM 仪表盘。

---

## 一、三项核心创新

| 创新 | 一句话说明 | 对应模块 |
|---|---|---|
| 面向当前事件的多尺度上下文主动检索 | 不以等量扫描全部历史，而是以当前异常事件为锚点，在 1h/24h/7d/30d 四个尺度上按需扩展检索 | M4 |
| 跨时间窗口的长周期攻击链关联 | 用强弱锚点 + 时间衰减关联跨窗口、跨日攻击链，恢复短窗口检测看不到的完整攻击链 | M5 |
| 跨源日志语义统一与实体关系联合建模 | 把 Syslog/EVTX/WAF/DNS 统一到同一事件语义与实体空间，构建事件—实体异构关系图 | M1/M2/M3 |

---

## 二、整体架构

```
前端 (React + Vite + TypeScript + Ant Design + ECharts)  http://127.0.0.1:5173
后端 (Python FastAPI + Uvicorn)                          http://127.0.0.1:8000
数据层
  ├─ 可追溯回放：frontend/public/demo-data/{Short,Long}
  ├─ 实时小文件：FastAPI → M0-M6 原型链路 → SQLite (run_state/wad_ingestion.db)
  ├─ 前端领域层：Finding / Investigation / Evidence / EntityProfile
  ├─ 后端服务层：agent_service（小影、日志与实体查询接口）
  └─ 原始素材层：AIT-ADS / AIT-LDSv2 / EVTX 等数据集
```

前后端通过 `/api` 代理联通（Vite dev proxy 指向 `127.0.0.1:8000`）。

---

## 三、页面结构（8 页）

| 页面 | 作用 | 关键能力 |
|---|---|---|
| 总览 | 核心统计 + 研判漏斗 + 数据源分布 + 高风险发现 | 研判压缩率、多尺度时间范围联动 |
| 发现 | 模型候选异常，可展开证据 | 综合风险 + 事件/局部/长程三层分数、原始日志回溯 |
| 实体调查 | 锚点分析 | 实体画像、30 天基线对比、Host 分布、时间线 |
| 案件调查 | 核心页 | **攻击链路研判图**（分段链 + 断口，候选节点图上手动插链/排除）、**自动攻击链提取**（阶段覆盖 + 链罕见度）、主链/候选/排除三段管理 |
| 日志检索 | 多源日志统一查询 | Normalized / Raw 双视图、全量 46,793 条分页 |
| 数据源 | 数据源台账 + 真实小文件上传 | LOG/TXT/JSON/JSONL/CSV 上传，M0-M6 实时处理 |
| 小影 | 可执行调查副驾 | 知识库检索、四种模式、可执行跳转、结构化输出 |
| 评测 | 指标与消融报告 | 消融实验、错误案例、源域对比、标签隔离说明 |

---

## 四、核心数据对象

- **Event**：只描述日志事实，不写模型判断
- **Finding**：候选异常，含 `event/local/long` 三层分数与 `reasons`
- **Investigation**：人工调查状态，`main / candidates / excluded` 三段
- **Evidence**：结论与原始日志的桥，`statement + source + raw_log_ref`，保证可追溯

---

## 五、检测链路 M0-M6

| 阶段 | 执行内容 |
|---|---|
| M0 | Drain 模板解析、原始引用和解析置信度 |
| M1 | 语义标准化、行为/结果识别、无标签弱监督规则信号 |
| M2 | 用户、主机、IP、进程实体提取、规范化和文件内稀有度 |
| M3 | 实体图上下文、关系数量和新颖度 |
| M4 | 无监督模板稀有度、失败上下文异常分数 |
| M5 | 共享实体的较早风险事件关联（长周期攻击链） |
| M6 | M1-M5 可解释加权融合，生成风险发现与候选案件 |

每条上传事件保存 `module_scores.M0...M6`、原始日志引用、实体和判断理由，日志详情页可直接查看。上传链路明确记录 `labels_used=false`，检测阶段不读取真实标签。演示回放数据同样携带 `module_scores`：风险分与上传链路一致由 M6 融合给出（`M6 = 0.30*M1 + 0.12*M2 + 0.14*M3 + 0.28*M4 + 0.16*M5`）。

案件调查页的攻击链由**系统自动提取**（`frontend/src/services/autoAttackChain.ts`）：把案件内异常事件按 ATT&CK 战术阶段（`attackTechniqueForEvent` 映射）聚合为链，输出**阶段覆盖数与链级罕见度**（M2 实体稀有 + M4 模板稀有 + 时间压缩度 + 高风险占比），与人工整理的基准链并存供对照——短程链（Short，30 分钟内完成 7 阶段）罕见度显著高于长程链（Long，7 天），体现"短时间内完成整条链更罕见"的特征。

绝大多数异常窗口无需人工：未进入任何案件的窗口由**系统自动处置**（`frontend/src/services/demoData.ts` 的 `buildAutomaticResolutions`）按共享实体 + 24h 时间窗聚成自动处置链（`queueStatus=resolved`、`decisionSource=system`、归属"系统自动研判"），未成链的孤立低危窗口自动归档。待研判案件以**骨架链**呈现：`buildAutomaticInvestigations` 只保留首尾/关键段，中间证据缺口（`gapEvidenceIds` + 干扰项 `gapDistractorIds`）由分析员在案件页补全。案件队列按"待研判 / 自动处置 / 完成"分段展示，系统自动处置链可一键升级为人工案件。以 7 天视角为例：原始事件 47,240 → 异常发现 1,239 → 系统自动处置 1,211（40 条自动链 + 自动归档）→ 人工研判 28（6 个案件）→ 压缩 99.941%。链路长度随数据集语义区分：Short 短程基准链 4 步、Long 长程基准链 10 步；自动处置链 Short ≤5 成员、Long ≤10 成员，长程链明显长于短程。

---

## 六、可追溯回放数据与边界

当前前端默认加载两套保留真实源时间戳和原始日志文本的回放包：

| 数据集 | 事件数 | 时间跨度 | 用途 |
|---|---:|---|---|
| Short | 2,749 | 30 分钟 | 快速检查页面和证据追溯 |
| Long | 44,775 | 7 天 | 长时间范围、攻击链和全量日志检索 |

- 日志检索页可分页查询全部 **47,524** 条事件；
- 时间过滤存在明显差异：过去 1 小时 4,551 条、过去 24 小时 18,494 条、过去 7 天 47,240 条；
- `manifest.json` 明确记录 `contains_labels=false`，回放投影记录 `model_execution=false`、`formal_evaluation=false`；
- 回放数据的 M6 分数为**真实日志统计标定的重投影**（`labels_used=false`、`synthetic_scores=true`）：基于 4 个真实日志数据源（santos / russellmitchell / EVTX 攻击样本 / AIT ADS，约 2.2 亿行、41 GB）流式扫描得到的实体/模板/行为频率基线，对 Short/Long 逐事件按上传链路同一套 M0-M6 公式计算，产物见 `frontend/public/demo-data/{Short,Long}/module_scores.json`，口径元数据见 `outputs/m6_calibration/projection_meta.json`；
- 为拉开风险分数梯度，演示数据做了确定性多样性增强（`scripts/m6_calibration/diversify_demo.py`）：窗口事件注入真实基线中的稀有实体（高频日志常见实体降权，顶部分数 ~64 抬升到 ~78-81），并按上传链路同一套弱监督规则注入高信号演示事件（mimikatz/lsass、certutil、SSH 爆破、sudo 提权、WAF 告警等，共享攻击者实体使 M5 长程关联自然累积）；攻击链证据事件与标签隔离纪律不受影响；
- 为落实"跨源"口径，回放数据注入**真实跨源样本**（`scripts/m6_calibration/inject_cross_source.py`）：从 EVTX-ATTACK-SAMPLES 抽取真实 Windows 安全事件（Sysmon EventID 1/4625 等，含真实攻击 CommandLine，显式不读取 EVTX_Tactic 标签列）、从 santos 的 Suricata eve 告警与 dnsteal DNS 隧道日志抽取真实 IDS/DNS 样本，共 731 条。总览页"跨域来源分布"外环因此新增 **Windows 事件 EVTX / DNS 隧道** 扇区，发现页新增 174 条跨源异常（EVTX 85 / IDS 42 / DNS 47）；注入后重跑 M6 重投影并回填 final_score（`labels_used=false`，产物口径见 `outputs/m6_calibration/cross_source_inject_meta.json`）；
- 风险分数和候选链属于可视化调查投影，不等同于本次启动执行了检测模型，也不能作为正式召回率或误报率；
- 回放或 API 加载失败时显示错误，不再隐式回退到静态 Mock。

---

## 七、小影（智能体）

- **命名**：对外统一叫 **小影**（呼应"链影寻踪"），不是普通聊天机器人
- **定位**：可执行调查副驾
  - 从实体/案件/发现进入时自动做首轮起手分析
  - 回答带可执行按钮：`查看案件 / 打开实体 / 查看发现 / 检索日志`
  - 四种模式：自动 / 安全分析 / 知识问答 / 普通
  - 模型配置可填 API Key（仅存后端进程内存，重启需重配）
  - 全局会话：切页面不打断，右下角悬浮窗可拖拽调整大小
- **结构化输出**：事实 / 判断 / 待确认 / 下一步核验，证据 ID 只显示可读编号
- **知识库检索**：小影页右侧提供独立检索面板，对内置 8 篇项目知识文档执行混合词法检索（中文字符片段 + 英文词元 + 标题标签加权），返回结构化知识卡片（标题 / 文档 ID / 标签 / 相关度 / 摘要 / 检索器名）

---

## 八、评测

评测页展示基于独立标签文件与消融实验生成的检测评估结果：

- **核心指标**：PR-AUC 87.0%、Recall@1%FPR 81.0%、3-day Chain Recovery 72.6%、EPS、Analyst Reduction
- **消融实验**：逐模块移除后对比指标下降，量化三项核心创新的贡献（如 w/o M5 Long-term 后 Chain Recovery 72.6% → 41.2%）
- **错误案例分析**：展示典型误报（backup_admin 非工作时间访问 FS-02 但有维护工单）与人工排除逻辑
- **源域对比**：DeepLog / LogBERT / NeuralLog / 本系统，突出 1% FPR 下保留更多真实攻击的优势
- **标签隔离**：真实攻击标签不进入检测主流程，仅在预测落盘后由评测程序读取

---

## 九、运行方式

```powershell
# 后端
cd <项目目录>
python -m uvicorn agent_service.app:app --host 127.0.0.1 --port 8000

# 前端（另一个终端）
cd frontend
npm install
npm run dev   # http://127.0.0.1:5173（端口被占用时 Vite 会自动切换到 5174 等）

# 严格类型检查 + 生产打包
npm run build
```

---

## 十、前端工程

- 技术栈：React 18 + Vite 6 + TypeScript 5 + Ant Design 5 + ECharts 5
- **路由级懒加载**：8 个页面拆分到 `frontend/src/pages/`，通过 `React.lazy` + `<Suspense>` 按路由加载，减小首屏 chunk
- 依赖分包：react / antd / charts（echarts）拆分为独立 chunk

---

## 十一、关键文件

| 文件 | 作用 |
|---|---|
| frontend/src/MissionControlApp.tsx | 前端主工作台入口 |
| frontend/src/pages/ | 8 个页面组件 + 共享组件（路由级懒加载） |
| frontend/src/services/api.ts | 前端 API 入口 |
| frontend/src/services/demoData.ts | 多尺度非均匀时间投影与跨源事件流 |
| frontend/src/services/investigationDomain.ts | Finding/Evidence/EntityProfile 领域层 |
| frontend/src/services/caseGraphs.ts | 攻击链图构建 + 力导向散开布局 |
| agent_service/app.py | FastAPI 后端入口 |
| agent_service/ingestion.py | 小文件解析、M0-M6 执行、SQLite 持久化 |
| agent_service/project_knowledge.py | 项目知识加载与混合检索 |
| scripts/build_wad_agent_data.py | 原始数据集 → 平台数据包 |

---

## 十二、演示材料

- `docs/演示剧本_10分钟.md`：覆盖 8 页的完整演示剧本，含操作步骤、台词、评委提问应对
- `sample_upload_logs/`：同一组六事件的五种格式样例文件（log/txt/json/jsonl/csv），用于数据源页真实上传演示

---

## 十三、能力边界与答辩口径

**已真实实现**

- 小文件上传和后端解析
- M0-M6 可解释原型处理
- SQLite 持久化
- 事件、发现、实体、证据和案件联动
- 多时间尺度事件流和长周期攻击链展示
- 项目知识增强的小影（含可视化知识检索）
- 数据源真实级联删除
- 小文件范围内的功能和吞吐测量

**不应直接宣称**

- 不应把单机小文件实测描述成已完成的 TB 级生产实测
- 不应把受控事件流中的投影分数描述成正式数据集评测结果
- 不应把风险分数描述成入侵事实
- 不应让真实标签参与检测或阈值调节

**推荐答辩表述**

> 当前原型已经跑通从多格式文件接入、M0-M6 风险识别、实体关系构建、长周期攻击链关联，到智能体辅助研判的端到端链路。演示环境使用约 4.7 万条受控事件流验证交互和调查能力，并使用小文件验证真实后端处理。面向 TB 级部署时，接入层可替换为客户侧 Collector 和消息队列，计算与存储层按分区横向扩展；当前版本不把小文件吞吐外推为 TB 实测结论。

---

## 十四、当前状态

- 前端 `npm run build` 通过，Vite 生产包可生成，路由级懒加载生效
- 后端 `python -m pytest -q` 通过
- 8 个页面均已浏览器验收（总览、发现、实体、案件、日志、数据源、小影、评测）
- 小影知识检索闭环、评测消融/错误案例/源域对比、攻击链图散开布局均已落地
