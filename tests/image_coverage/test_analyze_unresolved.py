from pathlib import Path

from tools.image_coverage.analyze_unresolved import summarize_unresolved


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")


def test_summarize_unresolved_counts_total_and_hash(tmp_path: Path) -> None:
    decrypted_images_dir = tmp_path / "decrypted_images"

    _touch(
        decrypted_images_dir
        / "attach"
        / "hash_a"
        / "2026-01"
        / "Img"
        / "aaa.bin"
    )
    _touch(
        decrypted_images_dir
        / "attach"
        / "hash_a"
        / "2026-01"
        / "Img"
        / "bbb_t.bin"
    )
    _touch(
        decrypted_images_dir
        / "attach"
        / "hash_a"
        / "2026-02"
        / "Img"
        / "ccc_h.bin"
    )
    _touch(
        decrypted_images_dir
        / "attach"
        / "hash_b"
        / "2026-02"
        / "Img"
        / "ddd.bin"
    )

    summary = summarize_unresolved(decrypted_images_dir)

    assert summary["total_unresolved"] == 4
    assert summary["by_hash"] == {"hash_a": 3, "hash_b": 1}


def test_summarize_unresolved_counts_month_and_type(tmp_path: Path) -> None:
    decrypted_images_dir = tmp_path / "decrypted_images"

    _touch(
        decrypted_images_dir
        / "attach"
        / "hash_a"
        / "2026-01"
        / "Img"
        / "aaa.bin"
    )
    _touch(
        decrypted_images_dir
        / "attach"
        / "hash_a"
        / "2026-01"
        / "Img"
        / "bbb_t.bin"
    )
    _touch(
        decrypted_images_dir
        / "attach"
        / "hash_b"
        / "2026-02"
        / "Img"
        / "ccc_h.bin"
    )

    summary = summarize_unresolved(decrypted_images_dir)

    assert summary["by_month"] == {"2026-01": 2, "2026-02": 1}
    assert summary["by_type"] == {"orig": 1, "thumb": 1, "hd": 1}
