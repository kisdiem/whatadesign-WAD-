# 链影寻踪 Agent Service

独立的多模式安全 Agent 服务，不修改现有 M0-M6 检测管线。

## 模式

- `auto`：先用确定性规则路由，无法确定时再调用结构化 Router。
- `security`：只读调用 Finding、日志、Entity、历史、Baseline、Timeline、Investigation、Knowledge 工具。
- `knowledge`：优先检索知识库，不读取内部日志工具。
- `general`：普通对话，不具备内部安全数据权限。

## 项目知识增强

小影将外部模型作为可替换的推理层，项目特性由本仓库提供，而不是写在某个模型名称里：

- `project_knowledge.json` 内置链影寻踪 M0-M6、三项核心创新、`weak_fusion_v2`、评测隔离协议、TB 级架构和调查工作流。
- `hybrid_lexical_cjk_v1` 同时使用英文词元、中文字符片段、标题和标签权重，支持不带空格的中文检索。
- 当前环境问题必须先调用 Finding、Investigation、Entity、Timeline 或 Log 工具；方法解释同时检索项目知识库。
- 返回结果携带知识文档标题、文档 ID、版本和安全证据引用。
- 安全分析结构化输出 `facts`、`assessments`、`uncertainties`、`recommended_queries`，高风险结论可进入独立证据核验器。
- 项目知识库在未配置模型 Key 时仍可检索；未配置安全数据仓库时不会伪造当前环境事实。

## 安装与启动

在仓库根目录：

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r agent_service/requirements.txt

# 服务端环境变量，禁止写入前端
export OPENAI_API_KEY="..."
uvicorn agent_service.app:app --host 127.0.0.1 --port 8000 --reload
```

Windows PowerShell：

```powershell
$env:OPENAI_API_KEY="..."
uvicorn agent_service.app:app --host 127.0.0.1 --port 8000 --reload
```

前端 Vite 已将 `/api` 代理到 `127.0.0.1:8000`。

## 小文件实时导入

数据源页支持将 LOG、TXT、JSON、JSONL、CSV 小文件真实上传到后端。默认上限 8 MiB：

```text
POST /api/ingest/files
GET  /api/ingest/snapshot
GET  /api/ingest/jobs
DELETE /api/ingest/sources/{source_id}
GET  /api/detection/manifest
GET  /api/log-index/overview
GET  /api/scale/report
GET  /api/evaluation/report
```

上传文件经过可解释的 `m0-m6-prototype-v1` 链路并写入 `run_state/wad_ingestion.db`。删除上传数据源时，会在同一事务中级联清理对应任务、事件、发现和案件。检测链路不读取真实标签。EVTX 二进制文件需要先导出为 XML/JSON/CSV，或后续安装 `python-evtx` 适配器。

这条链路用于竞赛原型和小数据演示；`/api/scale/report` 会明确标注为小文件功能实测，不代表 TB 实测结果。

## 数据仓库

生产模式不允许隐式 mock 回退。

如果现有检测/存储层能够导出结构化状态，设置：

```bash
export WAD_AGENT_DATA_DIR=/path/to/agent-data
```

支持以下文件，均为只读：

- `findings.json`
- `entities.json`
- `investigations.json`
- `baselines.json`
- `knowledge.json`
- `logs.jsonl`

后续 PostgreSQL 存储分支合并时，实现 `SecurityRepository` 即可，无需修改 Agent 工具和前端协议。

仅在明确演示时可启用：

```bash
export WAD_AGENT_USE_MOCKS=true
```

正式部署不得设置该变量。

## 模型配置

默认：

```text
WAD_ROUTER_MODEL=gpt-5.4-mini
WAD_ANALYST_MODEL=gpt-5.6-sol
WAD_GENERAL_MODEL=gpt-5.4-mini
WAD_VERIFIER_MODEL=gpt-5.6-sol
```

均可通过环境变量覆盖。

## API

### `POST /api/agent/query`

```json
{
  "conversation_id": "CONV-001",
  "mode": "auto",
  "message": "HOST-18 为什么风险高？",
  "context": {
    "finding_ids": ["WIN-20260809-1422"],
    "investigation_id": null,
    "entity_ids": ["HOST-18"],
    "time_range": null
  }
}
```

### `POST /api/agent/query/stream`

SSE 事件类型：`route`、`status`、`citation`、`final`、`error`。

### `GET /api/agent/health`

返回 Agent 服务、OpenAI 配置状态和 Repository 类型，不返回任何密钥。

### `POST /api/knowledge/search`

不依赖模型调用的项目知识检索接口：

```json
{
  "query": "为什么综合风险评分要结合多尺度和长周期关联？",
  "top_k": 3,
  "scope": ["project"]
}
```

## 安全边界

- Agent 无 SQL、Shell、任意 HTTP 工具。
- 日志查询单次最大 200 条。
- 当前环境事实必须来自内部工具证据。
- 高风险结论触发 Evidence Verifier。
- API Key 只存在服务端。
- 数据仓库不可用时明确失败，不用假数据替代。
