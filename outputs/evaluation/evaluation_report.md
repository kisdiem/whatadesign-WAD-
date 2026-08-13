# WAD 可复现评测报告

生成命令：`python scripts/evaluate_detection.py --input data/demo/real_logs.jsonl --labels data/demo/evaluation_labels.json --output-dir outputs/evaluation`

> 结果来自仓库内的有标签演示集，仅证明端到端评测链路可复现，不代表生产数据集性能。真实标签在预测完成后由本脚本独立读取。

## 核心指标

| Precision | Recall | F1 | FPR | PR-AUC | 攻击链恢复率 |
|---:|---:|---:|---:|---:|---:|
| 1.000 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 |

## 消融实验

| 版本 | Recall | FPR | PR-AUC | 攻击链恢复率 |
|---|---:|---:|---:|---:|
| full | 1.000 | 0.000 | 1.000 | 1.000 |
| unsupervised_only | 0.714 | 0.222 | 0.826 | 0.500 |
| weak_only | 1.000 | 0.000 | 1.000 | 1.000 |
| without_entity_rarity | 1.000 | 0.000 | 1.000 | 1.000 |
| without_chain_aggregation | 1.000 | 0.000 | 1.000 | 0.000 |

## 吞吐

固定 10,000 条重复样例的单进程内存打分中位数：**28401 EPS**。该数字不包含磁盘读取，不外推为 TB 级实测。

## 误报

完整方案 FP=0，TN=9，每百万正常日志误报数=0。
无监督单模块误报事件：EVT-002, EVT-003；这些样本由弱监督投票帮助抑制。
