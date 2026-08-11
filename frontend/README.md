# WAD Frontend

独立前端目录，不修改仓库现有 Python pipeline、训练脚本或数据处理结构。

## 本地运行

```bash
cd frontend
npm install
npm run dev
```

默认仍可使用内置 Dashboard 演示数据浏览 Mission Control 页面。

## Agent 服务

AI 页面已使用独立多模式 Agent 接口：

```text
自动 / 安全分析 / 知识问答 / 普通
```

Agent 默认不会跟随 Dashboard 自动回落到 mock。启动真实 Agent：

```bash
# 在仓库根目录
pip install -r agent_service/requirements.txt
export OPENAI_API_KEY="..."
uvicorn agent_service.app:app --host 127.0.0.1 --port 8000 --reload
```

Windows PowerShell：

```powershell
pip install -r agent_service/requirements.txt
$env:OPENAI_API_KEY="..."
uvicorn agent_service.app:app --host 127.0.0.1 --port 8000 --reload
```

开发服务器默认把 `/api` 代理到 `http://127.0.0.1:8000`，可以通过 `WAD_API_PROXY` 修改。

Agent 接口：

- `GET /api/agent/health`
- `POST /api/agent/query`
- `POST /api/agent/query/stream`

只有明确演示 Agent 时才设置：

```bash
VITE_AGENT_USE_MOCKS=true
```

生产前端不得启用该变量。

## 其他后端接口

将 Dashboard 也切换为真实 API 时：

```bash
VITE_USE_MOCKS=false
VITE_API_BASE=/api
```

当前预留：

- `GET /api/windows`
- `GET /api/investigations`
- `GET /api/settings/log-sources`
- `GET /api/knowledge/documents`
- `POST /api/settings/log-sources`
- `POST /api/settings/log-sources/test`
- `POST /api/assistant/query`（旧兼容入口）

OpenAI API Key 和日志源 Token 必须只保存在服务端，浏览器端不持久化密钥。
