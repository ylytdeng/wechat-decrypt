import re
from pathlib import Path

from tools.image_coverage.generate_open_tasks import build_open_tasks
from tools.image_coverage.run_round import run_round


def test_run_round_dry_run_writes_artifacts(tmp_path: Path) -> None:
    decrypted_images_dir = tmp_path / "decrypted_images"
    round_dir = run_round(
        tmp_path,
        dry_run=True,
        decrypted_images_dir=decrypted_images_dir,
    )

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
    assert f"source_decrypted_images_dir: {decrypted_images_dir}" in report
    assert "warning: decrypted_images_dir does not exist" in report


def test_run_round_same_minute_does_not_conflict(tmp_path: Path, monkeypatch) -> None:
    fixed_round_dir = tmp_path / "round-20260304-0905"
    monkeypatch.setattr(
        "tools.image_coverage.run_round.build_round_dir",
        lambda _base: fixed_round_dir,
    )

    decrypted_images_dir = tmp_path / "decrypted_images"
    first_round = run_round(
        tmp_path,
        dry_run=True,
        decrypted_images_dir=decrypted_images_dir,
    )
    second_round = run_round(
        tmp_path,
        dry_run=True,
        decrypted_images_dir=decrypted_images_dir,
    )
    third_round = run_round(
        tmp_path,
        dry_run=True,
        decrypted_images_dir=decrypted_images_dir,
    )

    assert first_round.name == "round-20260304-0905"
    assert second_round.name == "round-20260304-0905-01"
    assert third_round.name == "round-20260304-0905-02"
    assert first_round.exists()
    assert second_round.exists()
    assert third_round.exists()


def test_run_round_report_marks_non_dry_run(tmp_path: Path) -> None:
    decrypted_images_dir = tmp_path / "decrypted_images"
    round_dir = run_round(
        tmp_path,
        dry_run=False,
        decrypted_images_dir=decrypted_images_dir,
    )
    report = (round_dir / "report.md").read_text(encoding="utf-8")

    assert "dry_run: false" in report
    assert (
        "dry_run controls whether to execute external actions "
        "(this minimal implementation only generates local artifacts)."
        in report
    )


def test_run_round_generates_open_tasks_from_unresolved_hashes(tmp_path: Path) -> None:
    decrypted_images_dir = tmp_path / "custom_decrypted_images_dir"

    first = decrypted_images_dir / "attach" / "hash_alpha" / "2026-01" / "Img" / "a.bin"
    second = (
        decrypted_images_dir / "attach" / "hash_bravo" / "2026-02" / "Img" / "b_t.bin"
    )

    first.parent.mkdir(parents=True, exist_ok=True)
    second.parent.mkdir(parents=True, exist_ok=True)
    first.write_bytes(b"x")
    second.write_bytes(b"x")

    round_dir = run_round(
        tmp_path,
        dry_run=True,
        decrypted_images_dir=decrypted_images_dir,
    )
    open_tasks = (round_dir / "open_tasks.md").read_text(encoding="utf-8")
    report = (round_dir / "report.md").read_text(encoding="utf-8")

    assert open_tasks != build_open_tasks([])
    assert "chat_name: hash_alpha" in open_tasks
    assert "chat_name: hash_bravo" in open_tasks
    assert f"source_decrypted_images_dir: {decrypted_images_dir}" in report
    assert "warning: decrypted_images_dir does not exist" not in report
