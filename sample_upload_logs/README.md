# 小文件上传样本

本目录的五个日志文件包含同一组 6 条事件，只是编码格式不同，可用于验证上传、解析、实体抽取与 M0-M6 分析链路。

- `wad_small_chain.log`：逐行原始日志。
- `wad_small_chain.txt`：纯文本逐行日志。
- `wad_small_chain.json`：包含 `events` 数组的 JSON 文档。
- `wad_small_chain.jsonl`：每行一个 JSON 对象。
- `wad_small_chain.csv`：带字段表头的 CSV。

事件链依次包含认证失败、权限上下文变化、编码 PowerShell、账户创建和外联。所有事件时间都位于 `2026-08-16 10:00:00Z` 至 `10:04:40Z`。
