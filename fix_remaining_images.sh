#!/usr/bin/env bash
set -euo pipefail

# Round helper for remaining image coverage.
# Artifacts: open_tasks.md + report.md (report round).

PYTHON_BIN="${PYTHON_BIN:-python}"
mode="${1:---dry-run}"

case "$mode" in
  --dry-run)
    "$PYTHON_BIN" -m tools.image_coverage.run_round --dry-run
    ;;
  --run)
    "$PYTHON_BIN" -m tools.image_coverage.run_round
    ;;
  --help|-h)
    cat <<'USAGE'
Usage:
  ./fix_remaining_images.sh --dry-run
  ./fix_remaining_images.sh --run

Equivalent commands:
  python -m tools.image_coverage.run_round --dry-run
  python -m tools.image_coverage.run_round
USAGE
    ;;
  *)
    echo "Unknown mode: $mode" >&2
    echo "Use --dry-run, --run, or --help." >&2
    exit 2
    ;;
esac
