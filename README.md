# 链影寻踪 · M0-M6 攻击链调查台

面向**第十九届全国大学生信息安全竞赛（作品赛）**的原型系统。赛题方向：**基于海量日志数据的网络风险识别技术**。

> 从 TB 级多源安全日志（Syslog / ETW / WAF / DNS）中，用**无监督/弱监督**方法识别**罕见攻击链**与异常模式，并**有效降低人工研判成本**。

核心叙事围绕 **Finding → Investigation → Evidence → Analyst Decision** 的调查工作流，而非普通 SIEM 仪表盘。

## 整体架构

```
前端 (React + Vite + TS + Ant Design + ECharts)  http://127.0.0.1:5173
后端 (Python FastAPI + Uvicorn)                http://127.0.0.1:8000
数据层
  ├─ 前端展示层：src/mocks/data.ts + generatedDataset.json（演示主视觉）
  ├─ 后端真实层：outputs/wad_agent_data/（日志检索、实体回查、证据追溯备用）
  └─ 原始素材层：十几 GB 数据集（AIT-ADS / AIT-LDSv2 / EVTX）
```

## 页面结构（8 页）

| 页面 | 作用 |
|---|---|
| 总览 | 核心统计、研判漏斗（Events→Anomalous→Findings→Reviewed→Main-chain）、数据源分布、高风险发现 |
| 发现 | 模型候选异常，展示综合风险及事件/局部/长程三层分数，可展开证据 |
| 实体调查 | 锚点分析：实体画像、30 天基线对比、Host 分布、时间线 |
| 案件调查 | 核心页：攻击链图置顶（红橙告警色）、主链/候选/排除三段管理、时间线 |
| 日志检索 | 多源日志统一查询，Normalized / Raw 双视图 |
| 数据源 | 数据源台账 + 文件导入入口（EVTX/LOG/JSON/JSONL/CSV） |
| 小影 | 可执行调查副驾（见下文） |
| 评测 | Recall@1%FPR、跨域、长程关联、消融实验、错误案例、处理效率 |

## 核心数据对象

- **Event**：只描述日志事实，不写模型判断
- **Finding**：候选异常，含 `event/local/long` 三层分数与 `reasons`
- **Investigation**：人工调查状态，`main / candidates / excluded` 三段
- **Evidence**：结论与原始日志的桥，`statement + source + raw_log_ref`，保证可追溯

## 数据策略（三层混合）

原则：**展示绝对优先**。

| 层 | 内容 | 用途 |
|---|---|---|
| 展示层 | data.ts + generatedDataset.json | 页面主视觉，稳定美观 |
| 真实数据层 | outputs/wad_agent_data/（20 窗口、2 案件、20 findings、133 实体、3900 条日志） | 检索/回查备用 |
| 原始素材层 | 十几 GB 数据集 | 仅作拓宽 mock 的素材库 |

十几 G 数据通过 `scripts/build_wad_agent_data.py` 提炼、`scripts/export_mock_extension.py` 时间平移后并入前端 mock；前端默认 `VITE_PREFER_DEMO_DATA` 演示模式，真实 API 已接但降级备用。

## 小影（智能体）

- **命名**：对外统一叫 **小影**（呼应“链影寻踪”），不是普通聊天机器人
- **定位**：可执行调查副驾
  - 从实体/案件/发现进入时自动做首轮起手分析，并先问候
  - 回答带可执行按钮：`查看案件 / 打开实体 / 查看发现 / 检索日志`，跳转后继续输出分析
  - 四种模式：自动 / 安全分析 / 知识问答 / 普通
  - 模型配置可填 API Key，未配置时自动降级为演示分析
  - 全局会话：切页面不打断，右下角悬浮窗可拖拽调整大小
- **结构化输出**：事实 / 判断 / 待确认 / 你可能想问，证据 ID 只显示可读编号
- **知识库**（现状口径）：知识问答模式 + 预置知识文档雏形，尚未做成完整 RAG

## 运行方式

```powershell
# 后端
cd d:\CODE\whatadesign-WAD--agent-splunk-mission-control-ui
python -m uvicorn agent_service.app:app --host 127.0.0.1 --port 8000

# 前端（另一个终端）
cd frontend
npm.cmd run dev   # http://127.0.0.1:5173
```

## 关键文件

| 文件 | 作用 |
|---|---|
| frontend/src/MissionControlApp.tsx | 前端主工作台，8 个页面 |
| frontend/src/mission-control.css | 深蓝简约主题、对比度、hover |
| frontend/src/services/api.ts | 前端 API 入口 |
| frontend/src/services/investigationDomain.ts | Finding/Evidence/EntityProfile 领域层 |
| agent_service/app.py | FastAPI 后端入口（含 /api/security/*） |
| agent_service/repository.py | JSON/JSONL 只读仓库 |
| scripts/build_wad_agent_data.py | 原始数据集 → 平台数据包 |
| scripts/export_mock_extension.py | 真实数据 → mock 扩展层（时间平移） |

## 已完成的优化

- UI：深蓝冷色底、全局提亮、hover 反馈、图表轴标签留白、链图红橙告警色
- 简洁化：去除解释型副标题，英文标签中文化（研判漏斗、数据源分布、消融实验等）
- 交互：时间范围联动过滤、发现页不自动展开、案件链图置顶、智能体可执行按钮
- 性能：antd/echarts/react 分包，Agent/Charts/DataSource 按需懒加载
- 清理：后端健康接口不再暴露内部仓库类名

## 当前状态

- 前端构建通过，后端核心测试 `9 passed`
- 展示层 demo 优先，真实数据层备用

## 后续建议

1. 小影升级为 RAG 知识库 + 工具调用（任务型知识卡：攻击阶段/调查方法/实体基线/案例复盘）
2. 实体列表页增加后端全量实体列表接口
3. 评测页对接报告中的真实消融数据口径
4. 首屏懒加载（antd/echarts 大 chunk 仍偏大）
