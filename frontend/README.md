# WAD Frontend

独立前端目录，不修改仓库现有 Python pipeline、训练脚本或数据处理结构。

## 本地运行

```bash
cd frontend
npm install
npm run dev
```

默认使用内置界面数据，可以直接浏览全部页面。

## 接入后端

后端提供接口后，将环境变量切换为真实 API：

```bash
VITE_USE_MOCKS=false
VITE_API_BASE=/api
```

开发服务器默认把 `/api` 代理到 `http://127.0.0.1:8000`，可以通过 `WAD_API_PROXY` 修改。

当前前端预留接口：

- `GET /api/windows`
- `GET /api/investigations`
- `GET /api/settings/log-sources`
- `GET /api/knowledge/documents`
- `POST /api/assistant/query`

GPT 调用应由服务端完成，浏览器端不保存 OpenAI API Key。
