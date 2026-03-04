from pathlib import Path

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


def run_round(base: Path, dry_run: bool = True) -> Path:
    """Create one round folder and minimal artifacts.

    ``dry_run`` controls whether to execute external actions. This minimal
    implementation only generates local artifacts, so no external actions
    are executed for either ``dry_run=True`` or ``dry_run=False``.
    """

    base_path = Path(base)
    round_dir = _create_unique_round_dir(build_round_dir(base_path))

    open_tasks_path = round_dir / "open_tasks.md"
    open_tasks_path.write_text(build_open_tasks([]), encoding="utf-8")

    report_path = round_dir / "report.md"
    report_path.write_text(
        "\n".join(
            [
                "# Round Report",
                "",
                f"dry_run: {str(dry_run).lower()}",
                (
                    "dry_run controls whether to execute external actions "
                    "(this minimal implementation only generates local artifacts)."
                ),
                f"round_dir: {round_dir}",
            ]
        ),
        encoding="utf-8",
    )

    return round_dir
