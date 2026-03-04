# Coverage Round Operator Guide

本手册用于执行图片覆盖 round，关注两件事：生成可执行的 `open_tasks.md`，并记录可追踪的 `report.md`（report round）。

## 统一命令

```bash
python -m tools.image_coverage.run_round --dry-run
python -m tools.image_coverage.run_round
```

可选：测试或隔离目录时可加 `--base`，例如：

```bash
python -m tools.image_coverage.run_round --dry-run --base ./work/image_coverage_test
```

## Round 工件

每次执行都会创建 `work/image_coverage/round-YYYYMMDD-HHMM`（同分钟冲突时自动追加 `-01`、`-02`）。

目录内关键工件：

- `open_tasks.md`：本轮人工打开图片任务（按优先级）
- `report.md`：本轮 report round 记录（含 `dry_run` 与 `round_dir`）

## 常见流程

1. 执行 dry-run，确认 round 目录、`open_tasks.md`、`report.md` 都生成。
2. 读取 `open_tasks.md`，在微信中按任务打开历史图片并进行 key 捕获。
3. 执行正式 round，更新 `report.md` 的结论和下一轮优先级。
4. 对剩余未覆盖部分重复下一轮。

## 常见问题

- `round-*` 已存在：脚本会自动追加后缀，无需手动清理。
- 需要测试不污染正式目录：使用 `--base` 指向临时目录。
- 只想先验证流程不做外部动作：使用 `--dry-run`。
