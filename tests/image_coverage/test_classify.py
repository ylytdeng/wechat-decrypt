from tools.image_coverage.classify import classify_magic


def test_classify_magic_jpeg() -> None:
    assert classify_magic(bytes.fromhex("ffd8ffe000104a46")) == "jpg"


def test_classify_magic_unknown() -> None:
    assert classify_magic(bytes.fromhex("258e3648706c447a")) == "unknown"
