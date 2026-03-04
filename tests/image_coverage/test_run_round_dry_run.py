import re
from pathlib import Path

from tools.image_coverage.generate_open_tasks import build_open_tasks
from tools.image_coverage.run_round import run_round


def test_run_round_dry_run_writes_artifacts(tmp_path: Path) -> None:
    round_dir = run_round(tmp_path, dry_run=True)

    assert round_dir.exists()
    assert round_dir.is_dir()
    assert re.fullmatch(r"round-\d{8}-\d{4}(?:-\d{2})?", round_dir.name)

    open_tasks_path = round_dir / "open_tasks.md"
    report_path = round_dir / "report.md"

    assert open_tasks_path.exists()
    assert report_path.exists()
    assert open_tasks_path.read_text(encoding="utf-8") == build_open_tasks([])

    report = report_path.read_text(encoding="utf-8")
    assert "dry_run: true" in report
    assert f"round_dir: {round_dir}" in report
    assert (
        "dry_run controls whether to execute external actions "
        "(this minimal implementation only generates local artifacts)."
        in report
    )


def test_run_round_same_minute_does_not_conflict(tmp_path: Path, monkeypatch) -> None:
    fixed_round_dir = tmp_path / "round-20260304-0905"
    monkeypatch.setattr(
        "tools.image_coverage.run_round.build_round_dir",
        lambda _base: fixed_round_dir,
    )

    first_round = run_round(tmp_path, dry_run=True)
    second_round = run_round(tmp_path, dry_run=True)
    third_round = run_round(tmp_path, dry_run=True)

    assert first_round.name == "round-20260304-0905"
    assert second_round.name == "round-20260304-0905-01"
    assert third_round.name == "round-20260304-0905-02"
    assert first_round.exists()
    assert second_round.exists()
    assert third_round.exists()


def test_run_round_report_marks_non_dry_run(tmp_path: Path) -> None:
    round_dir = run_round(tmp_path, dry_run=False)
    report = (round_dir / "report.md").read_text(encoding="utf-8")

    assert "dry_run: false" in report
    assert (
        "dry_run controls whether to execute external actions "
        "(this minimal implementation only generates local artifacts)."
        in report
    )
