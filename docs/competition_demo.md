# 赛题最小闭环演示

## 一键复现

Windows PowerShell：

```powershell
./scripts/run_competition_demo.ps1
uvicorn agent_service.app:app --host 127.0.0.1 --port 8000
cd frontend
npm install
npm run dev
```

Linux/macOS 可依次运行：

```bash
python scripts/run_real_detection.py --input data/demo/real_logs.jsonl --output-dir outputs/demo_state
python scripts/evaluate_detection.py --input data/demo/real_logs.jsonl --labels data/demo/evaluation_labels.json --output-dir outputs/evaluation
```

打开 `http://127.0.0.1:5173`。主界面默认请求真实 API，不会在接口失败或空结果时自动切回 Mock。需要旧演示数据时必须显式设置 `VITE_USE_MOCKS=true`。

## 数据流

1. `data/demo/real_logs.jsonl`：不含标签的 Syslog、ETW、WAF、DNS JSONL。
2. `WeakSupervisor`：多个可审计标签函数投票，输出规则、原因、置信度和 ATT&CK tactic；这些是噪声伪标签，不是真实标签。
3. `FrequencyIsolationBaseline`：仅从日志本身学习模板频率、实体频率、来源分布、长度中位数/MAD和时间稀有度。
4. `DetectionEngine`：融合弱监督分数与无监督异常分数，按共享实体和 30 分钟窗口聚合攻击链，保留 `source_file:line` 溯源。
5. API 与前端：读取 `outputs/demo_state`，展示真实流水线产物。
6. `evaluate_detection.py`：预测完成后才读取独立标签文件，生成召回、FPR、PR-AUC、攻击链恢复率、误报事件、消融和吞吐报告。

## 标签隔离保证

- 检测输入出现 `label`、`ground_truth`、`target` 或 `is_attack` 会立即失败。
- `DetectionEngine` 的接口没有标签参数。
- 检测清单固定记录 `labels_accessed=false`。
- 评测标签位于独立文件，评测脚本先产生预测，随后才打开标签文件。
- 单元测试覆盖输入泄漏拒绝，集成测试覆盖完整检测与独立评测顺序。

## 答辩口径

> 我们的检测模型不读取真实攻击标签。弱监督阶段使用安全专家编写的标签函数产生带置信度的噪声伪标签；无监督基线只学习日志自身的行为分布。真实标签被物理分离在评测文件中，预测落盘后才由独立评测程序读取，用于计算召回率和误报率，不参与特征、阈值或规则生成。代码还会主动拒绝带标签字段的检测输入。

内置数据集很小，只用于证明闭环和复现方式。报告中的演示指标不得表述成生产性能或 TB 级实测；替换为正式盲测集后，使用同一评测命令生成正式结果。
