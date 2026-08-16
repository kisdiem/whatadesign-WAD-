# 链影寻踪 · M0-M6 攻击链调查台

面向**第十九届全国大学生信息安全竞赛（作品赛）**的原型系统。赛题方向：**基于海量日志数据的网络风险识别技术**。

> 从 TB 级多源安全日志（Syslog / ETW / WAF / DNS）中，用**无监督/弱监督**方法识别**罕见攻击链**与异常模式，并**有效降低人工研判成本**。

核心叙事围绕 **Finding → Investigation → Evidence → Analyst Decision** 的调查工作流，而非普通 SIEM 仪表盘。

## 整体架构

```
前端 (React + Vite + TS + Ant Design + ECharts)  http://127.0.0.1:5173
后端 (Python FastAPI + Uvicorn)                http://127.0.0.1:8000
数据层
  ├─ 可追溯回放：frontend/public/demo-data/{Short,Long}
  ├─ 前端领域层：Finding / Investigation / Evidence / EntityProfile
  ├─ 后端服务层：agent_service（小影、日志与实体查询接口）
  └─ 原始素材层：AIT-ADS / AIT-LDSv2 / EVTX 等数据集
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
| 评测 | 指标与消融报告界面，并显式展示标签和评测边界 |

## 核心数据对象

- **Event**：只描述日志事实，不写模型判断
- **Finding**：候选异常，含 `event/local/long` 三层分数与 `reasons`
- **Investigation**：人工调查状态，`main / candidates / excluded` 三段
- **Evidence**：结论与原始日志的桥，`statement + source + raw_log_ref`，保证可追溯

## 可追溯回放数据与边界

当前前端默认加载两套保留真实源时间戳和原始日志文本的回放包：

| 数据集 | 事件数 | 时间跨度 | 用途 |
|---|---:|---|---|
| Short | 2,570 | 30 分钟 | 快速检查页面和证据追溯 |
| Long | 44,175 | 7 天 | 长时间范围、攻击链和全量日志检索 |

- 日志检索页可分页查询全部 **46,745** 条事件，不再只展示 Finding 内的候选事件；
- 已验证时间过滤存在明显差异：过去 1 小时 501 条、过去 24 小时 6,359 条、过去 7 天 46,745 条；
- `manifest.json` 明确记录 `contains_labels=false`，回放投影记录 `model_execution=false`、`formal_evaluation=false`；
- 风险分数和候选链属于可视化调查投影，不等同于本次启动执行了检测模型，也不能作为正式召回率或误报率；
- 回放或 API 加载失败时显示错误，不再隐式回退到静态 Mock。

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
cd <项目目录>
python -m uvicorn agent_service.app:app --host 127.0.0.1 --port 8000

# 前端（另一个终端）
cd frontend
npm install
npm run dev   # http://127.0.0.1:5173

# 严格类型检查 + 生产打包
npm run build
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

- 修复：补齐缺失的攻击链报告下载模块，前端不再停留在 Vite 错误页
- 构建：修复 Severity、实体历史和 ECharts 事件类型，严格 TypeScript 构建通过
- 数据：修复小时桶截断导致的“原始事件 0”，总览正确展示 46,745 条回放事件
- 日志：接入 Short / Long 全量事件、时间范围过滤、关键词/来源筛选和 50 条分页
- 边界：取消静态 Mock 隐式兜底，明确无标签回放与正式模型评测的区别
- 报告：攻击链报告可下载为 UTF-8 Markdown 文件
- UI：深蓝冷色底、全局提亮、hover 反馈、图表轴标签留白、链图红橙告警色
- 简洁化：去除解释型副标题，英文标签中文化（研判漏斗、数据源分布、消融实验等）
- 交互：时间范围联动过滤、发现页不自动展开、案件链图置顶、智能体可执行按钮
- 性能：antd/echarts/react 分包，Agent/Charts/DataSource 按需懒加载
- 清理：后端健康接口不再暴露内部仓库类名

## 当前状态

- 修复分支：`scx-minimal-fix`
- `npm run build` 已通过；Vite 生产包可生成
- `python -m pytest -q` 已通过：104 项测试全部通过
- 前端和后端可分别在 `5173`、`8000` 端口启动
- 浏览器已验收总览、发现、案件、全量日志检索和评测边界说明，控制台无报错

## 后续建议

1. 小影升级为 RAG 知识库 + 工具调用（任务型知识卡：攻击阶段/调查方法/实体基线/案例复盘）
2. 实体列表页增加后端全量实体列表接口
3. 评测页对接报告中的真实消融数据口径
4. 首屏懒加载（antd/echarts 大 chunk 仍偏大）
