import argparse
from pathlib import Path

from .analyze_unresolved import summarize_unresolved
from .generate_open_tasks import build_open_tasks
from .paths import build_round_dir


def _create_unique_round_dir(base_round_dir: Path) -> Path:
    suffix = 0

    while True:
        if suffix == 0:
            candidate = base_round_dir
        else:
            candidate = base_round_dir.with_name(f"{base_round_dir.name}-{suffix:02d}")
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        except FileExistsError:
            suffix += 1


def run_round(
    base: Path,
    dry_run: bool = True,
    decrypted_images_dir: Path | str = Path("./decrypted_images"),
) -> Path:
    """Create one round folder and minimal artifacts.

    ``dry_run`` controls whether to execute external actions. This minimal
    implementation only generates local artifacts, so no external actions
    are executed for either ``dry_run=True`` or ``dry_run=False``.
    """

    base_path = Path(base)
    round_dir = _create_unique_round_dir(build_round_dir(base_path))

    decrypted_images_path = Path(decrypted_images_dir)
    unresolved_summary = summarize_unresolved(decrypted_images_path)
    by_hash = unresolved_summary.get("by_hash", {})
    by_month = unresolved_summary.get("by_month", {})

    month_items = (
        by_month.items() if isinstance(by_month, dict) else []
    )
    top_months = [
        month
        for month, _count in sorted(
            month_items,
            key=lambda item: (-item[1], item[0]),
        )[:2]
    ]
    focus_months = ",".join(top_months)

    rows = []
    if isinstance(by_hash, dict):
        for hash_value, count in by_hash.items():
            rows.append(
                {
                    "chat_name": str(hash_value),
                    "count": int(count),
                    "focus_months": focus_months,
                }
            )

    open_tasks_path = round_dir / "open_tasks.md"
    open_tasks_path.write_text(build_open_tasks(rows), encoding="utf-8")

    report_path = round_dir / "report.md"
    report_lines = [
        "# Round Report",
        "",
        f"dry_run: {str(dry_run).lower()}",
        (
            "dry_run controls whether to execute external actions "
            "(this minimal implementation only generates local artifacts)."
        ),
        f"round_dir: {round_dir}",
        f"source_decrypted_images_dir: {decrypted_images_path}",
    ]
    if not decrypted_images_path.exists():
        report_lines.append("warning: decrypted_images_dir does not exist")

    report_path.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    return round_dir


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create one image coverage round with open_tasks/report artifacts."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only generate round artifacts locally without external actions.",
    )
    parser.add_argument(
        "--base",
        type=Path,
        default=Path("work/image_coverage"),
        help="Base directory for round folders (default: work/image_coverage).",
    )
    parser.add_argument(
        "--decrypted-images-dir",
        type=Path,
        default=Path("./decrypted_images"),
        help="Source directory used for unresolved image analysis (default: ./decrypted_images).",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    round_dir = run_round(
        args.base,
        dry_run=args.dry_run,
        decrypted_images_dir=args.decrypted_images_dir,
    )
    print(f"round_dir: {round_dir}")
    print(f"open_tasks: {round_dir / 'open_tasks.md'}")
    print(f"report_round: {round_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
