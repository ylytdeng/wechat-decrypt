# Image Decryption Coverage Implementation Plan

> Date: 2026-03-04
> Scope: `tools/image_coverage/*`, tests, operator docs

## Objective

实现可重复执行的图片覆盖 round 流程，让每轮都稳定产出：

- `open_tasks.md`（待打开图片任务）
- `report.md`（本轮报告）

并保证可通过自动化测试验证核心行为。

## Work Items

1. Round 目录与工件
- 新建 `round-YYYYMMDD-HHMM` 目录（同分钟冲突自动后缀）。
- 写出 `open_tasks.md` 与 `report.md`。

2. 未解密分析接入
- 接入 `summarize_unresolved` 统计 `by_hash` / `by_month`。
- 将 `by_hash` 转换为 open tasks rows：
  - `chat_name`: hash 值
  - `count`: hash 计数
  - `focus_months`: `by_month` 前 2 个月份（按数量排序）

3. CLI 入口
- 支持 `python -m tools.image_coverage.run_round`。
- 参数：
  - `--dry-run`
  - `--base`
  - `--decrypted-images-dir`

4. 报告增强
- 在 `report.md` 写入 source 目录（`source_decrypted_images_dir`）。
- source 不存在时写入 warning。

5. 文档与操作脚本
- README 与 operator 文档统一命令为 `python -m ...`。
- `fix_remaining_images.sh` 使用可配置解释器：
  - `PYTHON_BIN=${PYTHON_BIN:-python}`

## Verification

最小验收命令：

```bash
.venv/bin/python -m pytest tests/image_coverage -q
```

`test_run_round_dry_run.py` 应覆盖：

- round 工件生成
- 同分钟目录冲突处理
- dry_run 标记
- 自定义 `decrypted_images_dir` 输入生效
